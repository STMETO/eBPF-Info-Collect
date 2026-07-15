// sd_collector.h — 服务发现 (Service Discovery) 模块的 uprobe 收集器
//
// 加载 sd.bpf.o，管理 4 个 hook 的挂载和事件消费。
// SD 模块 hook 的是 libvsomeip3-sd.so（不是 libvsomeip3.so），
// target_path 在 hook_config.h 中单独配置。
//
// SD 模块的 4 个 hook 追踪一次完整的服务发现交互：
//
//   客户端                                    服务端
//   ─────                                     ─────
//   sd_send_subscription ────────────────────▶ sd_handle_subscription
//   (发送 SubscribeEventgroup)                 (收到订阅请求)
//
//   (等待 OfferService)  ◀─────────────────── sd_process_offer
//                                              (SD 模块解析 OfferService 条目)
//
//   sd_send ─────────────────────────────────▶ (SD 消息刷新到网络)
//   (定时器触发，把缓存的消息发出)
//
// 注意：和 app 模块一样，SD 模块的 hook 参数也是 C++ 对象
// （subscription、message_impl、serviceinfo 等），不是 byte*。
// 所以事件的 SOME/IP header 字段全为 0。
// SD 的功能统计（服务发现次数、订阅次数）通过 arg0/arg1/arg2 字段记录。
//
// BPF SEC 程序名 → hook 名的映射（在 sd.bpf.c 中定义）：
//   hook_sd_send                → sd_send
//   hook_sd_process_offer       → sd_process_offer
//   hook_sd_send_subscription   → sd_send_subscription
//   hook_sd_handle_subscription → sd_handle_subscription
//
// ringbuf map 名称（在 sd.bpf.c 中定义）：
//   sd_events

#pragma once

#include "collector_base.h"
#include <cstddef>
#include <vector>

// libbpf 类型的 C 风格前向声明
struct bpf_object;
struct bpf_program;
struct bpf_link;
struct ring_buffer;
struct hook_cfg;

class SdCollector : public IUprobeCollector {
public:
    SdCollector();
    ~SdCollector() override;

    // ── IUprobeCollector 接口 ────────────────────────────────────────

    const char* name() const override { return "sd"; }

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
     * 从全局 hook_configs[] 中筛选 hook 名以 "sd_" 开头的条目
     */
    void filter_own_hooks();

    /**
     * 根据 hook 名找到对应的 BPF 程序
     * 命名规则："hook_" + hook_name
     */
    struct bpf_program* find_bpf_program(const char* hook_name);

    /**
     * ★ ringbuf 事件回调（C 风格，由 libbpf 调用）
     *
     * @param ctx   ring_buffer__new() 时传入的 this 指针
     * @param data  vsomeip_event 数据
     * @param size  数据大小
     * @return 0 = 继续
     */
    static int ringbuf_callback(void *ctx, void *data, size_t size);

    // ── 成员变量 ─────────────────────────────────────────────────────

    EventContext*        event_ctx_ = nullptr;   // ★ stats + writer 指针
    struct bpf_object*   obj_ = nullptr;         // 已加载的 BPF 对象
    struct ring_buffer*  ringbuf_ = nullptr;     // ring buffer consumer
    int                  ringbuf_fd_ = -1;       // ringbuf 的 epoll fd
    int                  hook_count_ = 0;        // 本模块 hook 数量
    bool                 attached_ = false;      // 是否已完成挂载

    std::vector<const hook_cfg*> own_hooks_;        // 本模块的 hook 配置
    std::vector<struct bpf_link*> links_;            // 挂载后的 link 句柄
};
