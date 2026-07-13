// sd_collector.h — 服务发现 (Service Discovery) 模块的 uprobe 收集器
//
// 加载 sd.bpf.o，管理 4 个 hook：
//   sd_send               → SD 消息刷新
//   sd_process_offer      → 收到 OfferService
//   sd_send_subscription  → 发送 Subscribe
//   sd_handle_subscription→ 处理订阅请求
//
// SD 模块 hook 的是 libvsomeip3-sd.so（不是 libvsomeip3.so），
// target_path 在 hook_config.h 中单独配置。

#pragma once

#include "collector_base.h"
#include <vector>

struct bpf_object;
struct bpf_program;
struct bpf_link;
struct ring_buffer;
struct hook_cfg;

class SdCollector : public IUprobeCollector {
public:
    SdCollector();
    ~SdCollector() override;

    const char* name() const override { return "sd"; }

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

    struct bpf_object*   obj_ = nullptr;
    struct ring_buffer*  ringbuf_ = nullptr;
    int                  ringbuf_fd_ = -1;
    int                  hook_count_ = 0;
    bool                 attached_ = false;
    std::vector<const hook_cfg*> own_hooks_;
    std::vector<struct bpf_link*> links_;
};
