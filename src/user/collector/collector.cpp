// collector.cpp — 通用的 uprobe 收集器实现
//
// 这是整个用户态唯一的 collector 实现类。
// 所有行为都由 module_meta 和 hook_configs 配置驱动，
// 不包含任何硬编码的模块名、hook 名或 map 名。
//
// 新增模块只需在 hooks.json 中加一条 modules[] 条目 + 对应的 hook 条目。
//
// ★ 和之前三个 collector 的关键区别：
//   之前：ringbuf_callback 中写死了 hook_names[] 静态数组
//   现在：从 hook_name_tables[module_id][hook_id] 动态查找
//         module_id 来自事件本身的 module_id 字段
//         hook_id   来自事件本身的 hook_id 字段

#include "collector.h"

extern "C" {
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
}

#include "../../common/vsomeip_event.h"
#include "../../common/vsomeip_types.h"
#include "../../hook_config.h"
#include "../stats_collector.h"
#include "../output/log_writer.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

// ═══════════════════════════════════════════════════════════════════════
// 构造 / 析构
// ═══════════════════════════════════════════════════════════════════════

Collector::Collector(const struct module_meta* meta)
    : meta_(meta)
{
}

Collector::~Collector()
{
    destroy();
}

// ═══════════════════════════════════════════════════════════════════════
// ringbuf_callback — ★ 事件回调（配置驱动版本）
//
// 和之前每个 collector 各自写一份的唯一区别：
//   从 hook_name_tables[event->module_id][event->hook_id] 查名称，
//   而不是从硬编码的 static const char*[] 里查。
//
// 这行代码是重构的核心价值所在——不管新增多少模块，
// 这里的逻辑永远不变。
// ═══════════════════════════════════════════════════════════════════════

int Collector::ringbuf_callback(void *ctx, void *data, size_t size)
{
    // ── 安全检查 ────────────────────────────────────────────────────
    if (size < sizeof(struct vsomeip_event))
        return 0;   // 数据不完整，丢弃（不应该发生）

    auto* self  = static_cast<Collector*>(ctx);
    auto* event = static_cast<const struct vsomeip_event*>(data);

    if (!self->event_ctx_)
        return 0;   // EventContext 还没注入

    // ── ★ 查找 hook 名（配置驱动，不硬编码）★ ────────────────────────
    // event->module_id: MODULE_ROUTING=1, MODULE_APP=2, MODULE_SD=3
    // event->hook_id:   模块内部编号，从 0 开始
    //
    // hook_name_tables 在 hook_config.h 中自动生成：
    //   hook_name_tables[1] = hook_names_routing  (5 个)
    //   hook_name_tables[2] = hook_names_app      (3 个)
    //   hook_name_tables[3] = hook_names_sd       (4 个)
    //
    // 查找：hook_name_tables[module_id][hook_id] → 人类可读名称
    const char* hook_name = "unknown";
    if (event->module_id >= 1 && event->module_id <= 3) {
        const char** table = hook_name_tables[event->module_id];
        if (table) {
            int max_id = 0;
            // 通过遍历 modules[] 找到本模块的 hook_count
            for (int i = 0; i < NUM_MODULES; i++) {
                if (modules[i].module_id == event->module_id) {
                    max_id = modules[i].hook_count;
                    break;
                }
            }
            if (event->hook_id < max_id)
                hook_name = table[event->hook_id];
        }
    }

    // ── ★ 推送事件到统计和日志 ★ ─────────────────────────────────────
    // process_event: 计数器累加 + 时延匹配
    self->event_ctx_->stats->process_event(*event, hook_name);
    // write: 格式化输出
    self->event_ctx_->writer->write(*event, hook_name);

    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
// init — 加载 BPF 对象
//
// bpf_dir 是存放 .bpf.o 文件的目录（如 /usr/lib/ebpf/）。
// 具体加载哪个文件由 meta_->bpf_obj 决定。
// 例如：meta_->bpf_obj = "routing.bpf.o" → 加载 /usr/lib/ebpf/routing.bpf.o
//
// 步骤：
//   1. 拼接路径：<bpf_dir>/<meta_->bpf_obj>
//   2. bpf_object__open()  → 解析 ELF
//   3. bpf_object__load()  → 加载到内核
//   4. filter_own_hooks()  → 筛选属于自己的 hook
// ═══════════════════════════════════════════════════════════════════════

int Collector::init(const char* bpf_dir)
{
    // 拼接 BPF 对象文件完整路径
    char bpf_path[512];
    snprintf(bpf_path, sizeof(bpf_path), "%s/%s", bpf_dir, meta_->bpf_obj);

    fprintf(stdout, "[%s] 初始化: %s\n", meta_->name, bpf_path);

    obj_ = bpf_object__open(bpf_path);
    if (!obj_) {
        fprintf(stderr, "[%s] 打开 BPF 对象失败: %s\n"
                "  请检查文件是否存在\n", meta_->name, bpf_path);
        return -1;
    }

    if (bpf_object__load(obj_) != 0) {
        fprintf(stderr, "[%s] 加载 BPF 对象失败（verifier 拒绝了程序）\n",
                meta_->name);
        bpf_object__close(obj_);
        obj_ = nullptr;
        return -1;
    }

    filter_own_hooks();

    fprintf(stdout, "[%s] 初始化完成，%d 个 hook 待挂载\n",
            meta_->name, hook_count_);
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
// filter_own_hooks — 从全局 hook_configs[] 筛选本模块的 hook
//
// 筛选规则：hook 名以 meta_->hook_prefix 开头
//   routing: hook_prefix = "rm_"  → 筛出 rm_send_entry, rm_send_ret, ...
//   app:     hook_prefix = "app_" → 筛出 app_send_entry, app_send_ret, ...
//   sd:      hook_prefix = "sd_"  → 筛出 sd_send, sd_process_offer, ...
//
// ★ 这是配置的关键：prefix 来自 modules[] 配置，不是硬编码 ★
// ═══════════════════════════════════════════════════════════════════════

void Collector::filter_own_hooks()
{
    own_hooks_.clear();
    size_t prefix_len = strlen(meta_->hook_prefix);

    for (int i = 0; i < NUM_HOOKS; i++) {
        if (strncmp(hook_configs[i].name, meta_->hook_prefix, prefix_len) == 0)
            own_hooks_.push_back(&hook_configs[i]);
    }

    hook_count_ = (int)own_hooks_.size();
}

// ═══════════════════════════════════════════════════════════════════════
// find_bpf_program — 根据 hook 名查找 BPF 程序
//
// 所有模块都遵循统一的 SEC 命名约定：
//   SEC("uprobe/hook_<hook_name>")      → 程序名 "hook_<hook_name>"
//   SEC("uretprobe/hook_<hook_name>")   → 程序名 "hook_<hook_name>"
//
// 入口和返回探测使用同一个程序名，libbpf 根据 opts.retprobe 区分。
// ═══════════════════════════════════════════════════════════════════════

struct bpf_program* Collector::find_bpf_program(const char* hook_name)
{
    char prog_name[64];
    snprintf(prog_name, sizeof(prog_name), "hook_%s", hook_name);
    return bpf_object__find_program_by_name(obj_, prog_name);
}

// ═══════════════════════════════════════════════════════════════════════
// attach — 挂载 hooks + 创建 ringbuf consumer
//
// 分两步：
//   1. 遍历 own_hooks_，用偏移量挂载 uprobe（不依赖符号表）
//   2. 找到 ringbuf map（map 名来自 meta_->ringbuf_map），创建 consumer
//      → ring_buffer__new(ringbuf_fd, ringbuf_callback, this, ...)
//      → 之后每次事件到达，ringbuf_callback 被自动调用
// ═══════════════════════════════════════════════════════════════════════

int Collector::attach(int target_pid)
{
    if (!obj_) {
        fprintf(stderr, "[%s] 未初始化，请先调用 init()\n", meta_->name);
        return -1;
    }

    if (attached_)
        detach();   // 先卸载旧挂载

    int attached_count = 0;

    // ── 第一步：逐个挂载 uprobe ──────────────────────────────────────
    for (const auto* cfg : own_hooks_) {
        struct bpf_program* prog = find_bpf_program(cfg->name);
        if (!prog) {
            fprintf(stderr, "[%s] 找不到 BPF 程序: hook_%s\n",
                    meta_->name, cfg->name);
            continue;
        }

        DECLARE_LIBBPF_OPTS(bpf_uprobe_opts, opts,
            .retprobe = cfg->retprobe,
        );

        // ★ 偏移量挂载：不依赖目标机器的符号表
        struct bpf_link* link = bpf_program__attach_uprobe_opts(
            prog, target_pid, cfg->target_path, cfg->offset, &opts);

        if (!link) {
            fprintf(stderr, "[%s] 挂载失败: %s @ %s+0x%lx\n",
                    meta_->name, cfg->name, cfg->target_path,
                    (unsigned long)cfg->offset);
            continue;
        }

        links_.push_back(link);
        attached_count++;
    }

    // ── 第二步：用配置的 map 名创建 ring buffer consumer ─────────────
    struct bpf_map* rb_map =
        bpf_object__find_map_by_name(obj_, meta_->ringbuf_map);
    if (!rb_map) {
        fprintf(stderr, "[%s] 找不到 ringbuf map '%s'\n",
                meta_->name, meta_->ringbuf_map);
        return -1;
    }

    ringbuf_ = ring_buffer__new(
        bpf_map__fd(rb_map),
        ringbuf_callback,   // ★ 通用回调（配置驱动版本）
        this,               // ctx = Collector*
        nullptr
    );

    if (!ringbuf_) {
        fprintf(stderr, "[%s] 创建 ring buffer consumer 失败\n",
                meta_->name);
        return -1;
    }

    ringbuf_fd_ = ring_buffer__epoll_fd(ringbuf_);
    attached_ = true;

    fprintf(stdout, "[%s] 挂载完成：%d/%d 个 hook 成功\n",
            meta_->name, attached_count, hook_count_);
    return attached_count;
}

// ═══════════════════════════════════════════════════════════════════════
// detach — 卸载所有 hook
// ═══════════════════════════════════════════════════════════════════════

int Collector::detach()
{
    for (auto* link : links_)
        bpf_link__destroy(link);
    links_.clear();

    if (ringbuf_) {
        ring_buffer__free(ringbuf_);
        ringbuf_ = nullptr;
        ringbuf_fd_ = -1;
    }

    attached_ = false;
    fprintf(stdout, "[%s] 已卸载所有 hook\n", meta_->name);
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
// 其余接口方法
// ═══════════════════════════════════════════════════════════════════════

void Collector::destroy()
{
    detach();
    if (obj_) {
        bpf_object__close(obj_);
        obj_ = nullptr;
    }
}

int  Collector::ringbuf_fd() const { return ringbuf_fd_; }

int  Collector::poll(int /*timeout_ms*/)
{
    if (!ringbuf_) return 0;
    return ring_buffer__consume(ringbuf_);
}
