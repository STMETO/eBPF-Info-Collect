// collector.cpp — 通用的 uprobe 收集器实现（配置驱动，零硬编码）
//
// 所有行为由 file_group 结构驱动。新增 hook 或模块只需改 hooks.json。

#include "collector.h"

extern "C" {
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
}

#include "../../common/vsomeip_event.h"
#include "../../hook_config.h"
#include "../stats_collector.h"
#include "../output/log_writer.h"

#include <cstdio>
#include <cstring>

// ═══════════════════════════════════════════════════════════════════════
// 构造 / 析构
// ═══════════════════════════════════════════════════════════════════════

Collector::Collector(const struct file_group* group)
    : group_(group)
{
}

Collector::~Collector()
{
    destroy();
}

const char* Collector::name() const
{
    return group_->name;
}

// ═══════════════════════════════════════════════════════════════════════
// ringbuf_callback — 事件回调
//
// 从 group_->hook_names[event->hook_id] 直接索引 hook 名，
// 不需要任何前缀匹配、module_id 查找、哈希表查询。
// 因为 hook_id 是按 hooks[] 数组顺序从 0 连续编号的。
// ═══════════════════════════════════════════════════════════════════════

int Collector::ringbuf_callback(void *ctx, void *data, size_t size)
{
    if (size < sizeof(struct vsomeip_event))
        return 0;

    auto* self  = static_cast<Collector*>(ctx);
    auto* event = static_cast<const struct vsomeip_event*>(data);

    if (!self->event_ctx_)
        return 0;

    // ★ 直接索引：hook_names[hook_id] ★
    const char* hook_name = "unknown";
    if (event->hook_id < self->group_->hook_count)
        hook_name = self->group_->hook_names[event->hook_id];

    // 推给统计和日志
    self->event_ctx_->stats->process_event(*event, hook_name);
    self->event_ctx_->writer->write(*event, hook_name);

    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
// init — 从嵌入的字节码加载 BPF 对象
//
// ★ 和之前的关键区别：
//   之前：bpf_object__open("/usr/lib/ebpf/routing.bpf.o") — 读文件
//   现在：bpf_object__open_mem(group_->embed_data, group_->embed_size, NULL)
//         — 从编译时嵌入的字节数组加载
//
//   优点：只产出一个可执行文件，部署时不需要复制 .bpf.o 到目标机器。
// ═══════════════════════════════════════════════════════════════════════

int Collector::init()
{
    fprintf(stdout, "[%s] 初始化 (%d hooks, %u bytes embedded)\n",
            group_->name, group_->hook_count, group_->embed_size);

    // bpf_object__open_mem 和 bpf_object__open 的语义完全相同，
    // 只是数据来源从文件变成了内存中的字节数组。
    obj_ = bpf_object__open_mem(group_->embed_data, group_->embed_size, NULL);
    if (!obj_) {
        fprintf(stderr, "[%s] 从嵌入数据打开 BPF 对象失败\n", group_->name);
        return -1;
    }

    if (bpf_object__load(obj_) != 0) {
        fprintf(stderr, "[%s] 加载 BPF 对象失败（verifier 拒绝）\n", group_->name);
        bpf_object__close(obj_);
        obj_ = nullptr;
        return -1;
    }

    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
// attach — 遍历 file_group->hooks[]，SEC 名 = hook 名，直接查找并挂载
//
// SEC 命名约定：SEC("uprobe/<hook_name>") 或 SEC("uretprobe/<hook_name>")
// 程序名 = hook_name，不需要任何前缀。
// 例如 hooks.json 中 name="rm_send_entry" → SEC("uprobe/rm_send_entry")
//                                      → bpf_object__find_program_by_name(obj, "rm_send_entry")
// ═══════════════════════════════════════════════════════════════════════

int Collector::attach(int target_pid)
{
    if (!obj_) {
        fprintf(stderr, "[%s] 未初始化\n", group_->name);
        return -1;
    }
    if (attached_) detach();

    int ok = 0;

    // ── 遍历本组的 hook，直接按名查找 BPF 程序 ────────────────────────
    for (int i = 0; i < group_->hook_count; i++) {
        const struct hook_cfg* cfg = &group_->hooks[i];

        // SEC 名 = hook 名，无需前缀
        struct bpf_program* prog =
            bpf_object__find_program_by_name(obj_, cfg->name);
        if (!prog) {
            fprintf(stderr, "[%s] 找不到 BPF 程序: %s\n",
                    group_->name, cfg->name);
            continue;
        }

        DECLARE_LIBBPF_OPTS(bpf_uprobe_opts, opts,
            .retprobe = cfg->retprobe,
        );

        struct bpf_link* link = bpf_program__attach_uprobe_opts(
            prog, target_pid, cfg->target_path, cfg->offset, &opts);

        if (!link) {
            fprintf(stderr, "[%s] 挂载失败: %s @ %s+0x%lx\n",
                    group_->name, cfg->name, cfg->target_path,
                    (unsigned long)cfg->offset);
            continue;
        }

        links_.push_back(link);
        ok++;
    }

    // ── 创建 ring buffer consumer ────────────────────────────────────
    struct bpf_map* rb_map =
        bpf_object__find_map_by_name(obj_, group_->ringbuf_map);
    if (!rb_map) {
        fprintf(stderr, "[%s] 找不到 ringbuf map '%s'\n",
                group_->name, group_->ringbuf_map);
        return -1;
    }

    ringbuf_ = ring_buffer__new(
        bpf_map__fd(rb_map), ringbuf_callback, this, nullptr);
    if (!ringbuf_) {
        fprintf(stderr, "[%s] 创建 ring buffer 失败\n", group_->name);
        return -1;
    }

    ringbuf_fd_ = ring_buffer__epoll_fd(ringbuf_);
    attached_ = true;

    fprintf(stdout, "[%s] 挂载完成：%d/%d hooks\n",
            group_->name, ok, group_->hook_count);
    return ok;
}

// ═══════════════════════════════════════════════════════════════════════
// detach / destroy / ringbuf_fd / poll
// ═══════════════════════════════════════════════════════════════════════

int Collector::detach()
{
    for (auto* l : links_) bpf_link__destroy(l);
    links_.clear();
    if (ringbuf_) { ring_buffer__free(ringbuf_); ringbuf_ = nullptr; ringbuf_fd_ = -1; }
    attached_ = false;
    return 0;
}

void Collector::destroy()
{
    detach();
    if (obj_) { bpf_object__close(obj_); obj_ = nullptr; }
}

int Collector::ringbuf_fd() const { return ringbuf_fd_; }

int Collector::poll(int /*timeout_ms*/)
{
    if (!ringbuf_) return 0;
    return ring_buffer__consume(ringbuf_);
}
