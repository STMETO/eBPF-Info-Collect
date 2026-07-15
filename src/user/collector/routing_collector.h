// routing_collector.h — 路由管理器模块的 uprobe 收集器
//
// 加载 routing.bpf.o，管理 5 个 hook 的挂载和事件消费。
// 这是最重要的 collector：所有 SOME/IP 消息的收发都经过这里。
//
// 数据流（attach 之后）：
//   BPF uprobe 触发
//     → ringbuf submit (routing.bpf.c)
//     → ring_buffer__consume (libbpf)
//     → ringbuf_callback() ← 静态 C 回调
//     → ctx->stats->process_event()  +  ctx->writer->write()
//
// ringbuf map 名称（在 routing.bpf.c 中定义）：
//   routing_events

#pragma once

#include "collector_base.h"
#include <cstddef>
#include <vector>

// 前向声明 libbpf 类型
struct bpf_object;
struct bpf_program;
struct bpf_link;
struct ring_buffer;
struct hook_cfg;            // 定义在 hook_config.h

class RoutingCollector : public IUprobeCollector {
public:
    RoutingCollector();
    ~RoutingCollector() override;

    // ── IUprobeCollector 接口 ────────────────────────────────────────
    const char* name() const override { return "routing"; }

    void set_event_context(EventContext* ctx) override { event_ctx_ = ctx; }
    int  init(const char* bpf_obj_path) override;
    int  attach(int target_pid) override;
    int  detach() override;
    void destroy() override;
    int  ringbuf_fd() const override;
    int  poll(int timeout_ms) override;
    int  hook_count() const override { return hook_count_; }
    bool is_attached() const override { return attached_; }

private:
    void filter_own_hooks();
    struct bpf_program* find_bpf_program(const char* hook_name);

    /**
     * ringbuf 静态回调函数（C 风格，由 libbpf 调用）
     *
     * libbpf 在 ring_buffer__consume() 时，每读到一个事件就调用这个函数。
     *
     * 参数：
     *   ctx  — ring_buffer__new() 时传入的上下文（这里传的是 collector 自己）
     *   data — BPF 提交的 vsomeip_event 数据
     *   size — 数据大小（sizeof(vsomeip_event)）
     *
     * 返回值：0 = 正常，非0 = libbpf 停止消费
     *
     * 内部逻辑：
     *   1. 把 ctx 转回 RoutingCollector*
     *   2. 从内部的 event_ctx_ 拿到 stats + writer
     *   3. 调用 stats->process_event() 处理（计数器 + 时延匹配）
     *   4. 调用 writer->write() 输出日志
     */
    static int ringbuf_callback(void *ctx, void *data, size_t size);

    // ── 成员变量 ─────────────────────────────────────────────────────
    EventContext*        event_ctx_ = nullptr;   // 事件处理上下文（stats + writer）
    struct bpf_object*   obj_ = nullptr;
    struct ring_buffer*  ringbuf_ = nullptr;
    int                  ringbuf_fd_ = -1;
    int                  hook_count_ = 0;
    bool                 attached_ = false;
    std::vector<const hook_cfg*> own_hooks_;
    std::vector<struct bpf_link*> links_;
};
