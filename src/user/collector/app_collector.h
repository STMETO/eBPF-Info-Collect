// app_collector.h — 应用层模块的 uprobe 收集器
//
// 加载 app.bpf.o，管理 3 个 hook 的挂载和事件消费。
//
// 和 routing 模块的关键区别：
//   routing 模块 hook 的是 routing_manager_impl 的函数，
//   这些函数的参数包含 byte* data（序列化后的 SOME/IP 报文），
//   所以 BPF 可以直接读取 SERVICE/IP header。
//
//   app 模块 hook 的是 application_impl 的函数，
//   参数是 C++ 对象（shared_ptr<message>），BPF 无法安全解引用，
//   所以事件的 SOME/IP 字段全为 0。
//   需要完整 header 信息的话，去 routing 模块的事件里找。
//
// 但这不意味着 app 模块没用：
//   - app_send_entry / app_send_ret → 统计应用层发送的成功率和耗时
//   - app_on_message → 统计消息从 routing 投递到应用的内部延迟
//     （rm_on_message 时间戳 vs app_on_message 时间戳的差值）
//
// BPF SEC 程序名 → hook 名的映射（在 app.bpf.c 中定义）：
//   hook_app_send_entry →  app_send_entry
//   hook_app_send_ret   →  app_send_ret
//   hook_app_on_message →  app_on_message
//
// ringbuf map 名称（在 app.bpf.c 中定义）：
//   app_events

#pragma once

#include "collector_base.h"
#include <cstddef>
#include <vector>

// libbpf 类型的 C 风格前向声明（避免把 libbpf.h 引入接口层）
struct bpf_object;
struct bpf_program;
struct bpf_link;
struct ring_buffer;

// hook_config.h 中的结构体
struct hook_cfg;

class AppCollector : public IUprobeCollector {
public:
    AppCollector();
    ~AppCollector() override;

    // ── IUprobeCollector 接口 ────────────────────────────────────────

    const char* name() const override { return "app"; }

    /**
     * 注入事件处理上下文
     * 在 attach() 之前由 CollectorManager 调用
     */
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
    /**
     * 从全局 hook_configs[] 中筛选 hook 名以 "app_" 开头的条目
     */
    void filter_own_hooks();

    /**
     * 根据 hook 名找到对应的 BPF 程序
     * 程序命名规则："hook_" + hook_name
     * 例如："app_send_entry" → SEC 名为 "hook_app_send_entry"
     */
    struct bpf_program* find_bpf_program(const char* hook_name);

    /**
     * ringbuf 事件回调（C 风格，由 libbpf 调用）
     *
     * 每从 ringbuf 消费到一个事件，libbpf 调用这个函数。
     * 内部把事件推给 stats->process_event() 和 writer->write()。
     *
     * @param ctx   ring_buffer__new() 时传入的 this 指针
     * @param data  vsomeip_event 数据
     * @param size  数据大小
     * @return 0 = 继续消费，非0 = 停止
     */
    static int ringbuf_callback(void *ctx, void *data, size_t size);

    // ── 成员变量 ─────────────────────────────────────────────────────

    EventContext*        event_ctx_ = nullptr;   //  stats + writer 指针
                                                 //   由 CollectorManager 在 attach 前注入
                                                 //   ringbuf 回调通过它把事件推给统计和日志

    struct bpf_object*   obj_ = nullptr;         // 已加载的 BPF 对象（包含程序和 map）
    struct ring_buffer*  ringbuf_ = nullptr;     // ring buffer consumer
    int                  ringbuf_fd_ = -1;       // ringbuf 的 epoll fd
    int                  hook_count_ = 0;        // 本模块管理的 hook 数量
    bool                 attached_ = false;      // 是否已完成挂载

    // 属于本模块的 hook 配置列表（从全局 hook_configs[] 筛选出来的指针）
    std::vector<const hook_cfg*> own_hooks_;

    // 每个 hook 挂载后产生的 bpf_link 句柄（detach 时逐个销毁）
    std::vector<struct bpf_link*> links_;
};
