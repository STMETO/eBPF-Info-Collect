// routing_collector.cpp — 路由管理器模块的实现

#include "routing_collector.h"

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

RoutingCollector::RoutingCollector() = default;
RoutingCollector::~RoutingCollector() { destroy(); }

// ═══════════════════════════════════════════════════════════════════════
// ringbuf_callback — BPF 事件到达时被 libbpf 调用的静态回调
//
// 这是整个数据流的"桥接点"：
//   内核态 BPF 在 hook 触发时把 vsomeip_event 推到 ringbuf
//   → libbpf 的 ring_buffer__consume 读出事件
//   → 调用这个回调函数
//   → 这里调用 stats->process_event() 和 writer->write()
//   → 完成 内核态 → 用户态 的完整数据通路
//
// 参数说明：
//   ctx  = ring_buffer__new() 时传入的 this 指针（RoutingCollector*）
//   data = vsomeip_event 的内存副本（已经从内核拷到用户态）
//   size = sizeof(vsomeip_event)，用于合法性检查
// ═══════════════════════════════════════════════════════════════════════

int RoutingCollector::ringbuf_callback(void *ctx, void *data, size_t size)
{
    if (size < sizeof(struct vsomeip_event))
        return 0;   // 数据不完整，丢弃

    auto* self = static_cast<RoutingCollector*>(ctx);
    auto* event = static_cast<const struct vsomeip_event*>(data);

    // 如果事件上下文还没注入（不应该发生，set_event_context 在 attach 之前调用），
    // 则不处理事件
    if (!self->event_ctx_)
        return 0;

    // 把 hook_id 转成人类可读的 hook 名称
    // 例如 HOOK_RM_SEND_ENTRY → "rm_send_entry"
    static const char* hook_names[] = {
        "rm_send_entry",    // HOOK_RM_SEND_ENTRY = 0
        "rm_send_ret",      // HOOK_RM_SEND_RET   = 1
        "rm_send_to_entry", // HOOK_RM_SEND_TO_ENTRY = 2
        "rm_send_to_ret",   // HOOK_RM_SEND_TO_RET = 3
        "rm_on_message",    // HOOK_RM_ON_MESSAGE = 4
    };
    const char* hook_name = (event->hook_id < 5)
        ? hook_names[event->hook_id] : "unknown";

    // 关键：把事件推给统计模块和日志模块 
    // process_event 内部会做：计数器累加 + pending 表更新 + 时延匹配
    self->event_ctx_->stats->process_event(*event, hook_name);
    // write 内部会把事件格式化成人类可读或 JSON 输出
    self->event_ctx_->writer->write(*event, hook_name);

    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
// init — 加载 BPF 对象
// ═══════════════════════════════════════════════════════════════════════

int RoutingCollector::init(const char* bpf_obj_path)
{
    obj_ = bpf_object__open(bpf_obj_path);
    if (!obj_) {
        fprintf(stderr, "[routing] 打开 BPF 对象失败: %s\n", bpf_obj_path);
        return -1;
    }

    if (bpf_object__load(obj_) != 0) {
        fprintf(stderr, "[routing] 加载 BPF 对象失败\n");
        bpf_object__close(obj_);
        obj_ = nullptr;
        return -1;
    }

    filter_own_hooks();
    fprintf(stdout, "[routing] 初始化完成，%d 个 hook 待挂载\n", hook_count_);
    return 0;
}

void RoutingCollector::filter_own_hooks()
{
    own_hooks_.clear();
    for (int i = 0; i < NUM_HOOKS; i++) {
        if (strncmp(hook_configs[i].name, "rm_", 3) == 0)
            own_hooks_.push_back(&hook_configs[i]);
    }
    hook_count_ = (int)own_hooks_.size();
}

struct bpf_program* RoutingCollector::find_bpf_program(const char* hook_name)
{
    char prog_name[64];
    snprintf(prog_name, sizeof(prog_name), "hook_%s", hook_name);
    return bpf_object__find_program_by_name(obj_, prog_name);
}

// ═══════════════════════════════════════════════════════════════════════
// attach — 挂载 hooks + 创建带回调的 ringbuf consumer
//
// 和之前的区别：ring_buffer__new() 现在传入了 ringbuf_callback 和 this，
// 这样当事件到达时回调函数会自动被调用，推给 stats 和 log。
// ═══════════════════════════════════════════════════════════════════════
int RoutingCollector::attach(int target_pid)
{
    if (!obj_) {
        fprintf(stderr, "[routing] 未初始化\n");
        return -1;
    }
    if (attached_) detach();

    int attached_count = 0;
    for (const auto* cfg : own_hooks_) {
        struct bpf_program* prog = find_bpf_program(cfg->name);
        if (!prog) continue;
        
        // 自动创建 struct bpf_uprobe_opts opts; 变量；
        // 结构体所有字段默认清零（0/NULL）；
        // 仅覆盖你显式写的 .retprobe = cfg->retprobe，其余字段保持 0；
        // 兼容 libbpf 高低版本，不会因结构体新增字段出现脏内存、未定义行为
        DECLARE_LIBBPF_OPTS(bpf_uprobe_opts, opts,
            .retprobe = cfg->retprobe,
        );
        struct bpf_link* link = bpf_program__attach_uprobe_opts(
            prog, target_pid, cfg->target_path, cfg->offset, &opts);
        if (!link) {
            fprintf(stderr, "[routing] 挂载失败: %s\n", cfg->name);
            continue;
        }
        links_.push_back(link);
        attached_count++;
    }

    // 创建 ringbuf consumer —— 传入回调函数，事件到达时自动处理
    struct bpf_map* rb_map = bpf_object__find_map_by_name(obj_, "routing_events");
    if (!rb_map) {
        fprintf(stderr, "[routing] 找不到 ringbuf map\n");
        return -1;
    }
    ringbuf_ = ring_buffer__new(
        bpf_map__fd(rb_map),
        ringbuf_callback,   // 静态回调：ringbuf_callback(ctx, data, size)
        this,               // ctx = this  (RoutingCollector*)，回调内部通过 this 拿到 event_ctx_
        nullptr);
    if (!ringbuf_) {
        fprintf(stderr, "[routing] 创建 ring buffer 失败\n");
        return -1;
    }
    ringbuf_fd_ = ring_buffer__epoll_fd(ringbuf_);
    attached_ = true;

    fprintf(stdout, "[routing] 挂载完成：%d/%d hooks\n",
            attached_count, hook_count_);
    return attached_count;
}

int RoutingCollector::detach()
{
    for (auto* link : links_) bpf_link__destroy(link);
    links_.clear();
    if (ringbuf_) { ring_buffer__free(ringbuf_); ringbuf_ = nullptr; ringbuf_fd_ = -1; }
    attached_ = false;
    fprintf(stdout, "[routing] 已卸载\n");
    return 0;
}

void RoutingCollector::destroy() { detach(); if (obj_) { bpf_object__close(obj_); obj_ = nullptr; } }
int  RoutingCollector::ringbuf_fd() const { return ringbuf_fd_; }

// ── poll() ────────────────────────────────────────────────────────────
// ring_buffer__consume() 内部会调用 ringbuf_callback() 处理每个事件。
// 不需要额外的循环，libbpf 已经帮我们做了。
int  RoutingCollector::poll(int timeout_ms)
{
    if (!ringbuf_) return 0;
    return ring_buffer__consume(ringbuf_);
}
