// app_collector.h — 应用层模块的 uprobe 收集器
//
// 加载 app.bpf.o，管理 3 个 hook：app_send_entry、app_send_ret、app_on_message。
// 挂载到 application_impl 的方法。
//
// 和 routing collector 的区别：
//   app 层无法直接从参数读取 SOME/IP header（参数是 shared_ptr<message>，
//   不是 byte*），所以事件中的 SOME/IP 字段为空。
//   需要完整的 header 信息的话，去 routing 模块的事件里找。

#pragma once

#include "collector_base.h"
#include <vector>

struct bpf_object;
struct bpf_program;
struct bpf_link;
struct ring_buffer;
struct hook_cfg;

class AppCollector : public IUprobeCollector {
public:
    AppCollector();
    ~AppCollector() override;

    const char* name() const override { return "app"; }

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
