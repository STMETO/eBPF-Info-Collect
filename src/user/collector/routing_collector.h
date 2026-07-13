// routing_collector.h — 路由管理器模块的 uprobe 收集器
//
// 加载 routing.bpf.o，管理 5 个 hook 的挂载和事件消费。
// 这是最重要的 collector：所有 SOME/IP 消息的收发都经过这里。
//
// BPF SEC 程序名 → hook 名的映射（在 routing.bpf.c 中定义）：
//   hook_rm_send_entry   →  rm_send_entry
//   hook_rm_send_ret     →  rm_send_ret
//   hook_rm_send_to_entry →  rm_send_to_entry
//   hook_rm_send_to_ret  →  rm_send_to_ret
//   hook_rm_on_message   →  rm_on_message
//
// ringbuf map 名称（在 routing.bpf.c 中定义）：
//   routing_events

#pragma once

#include "collector_base.h"
#include <vector>
#include <memory>

// 前向声明 libbpf 类型（避免引入 libbpf 头文件到接口层）
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
     * 从 hook_configs[] 全局数组中筛选出属于 "routing" 模块的条目。
     * 只保留 hook_config.name 以 "rm_" 开头的条目。
     */
    void filter_own_hooks();

    /**
     * 根据 hook 名找到对应的 BPF 程序
     *
     * BPF 程序名格式（在 .bpf.c 的 SEC("uprobe/<name>") 中定义）：
     *   "hook_" + hook_name
     * 例如："rm_send_entry" → SEC 名为 "hook_rm_send_entry"
     */
    struct bpf_program* find_bpf_program(const char* hook_name);

    // ── 成员变量 ─────────────────────────────────────────────────────
    struct bpf_object*   obj_ = nullptr;       // BPF 对象（包含所有程序和 map）
    struct ring_buffer*  ringbuf_ = nullptr;   // ring buffer consumer
    int                  ringbuf_fd_ = -1;     // ringbuf 对应的 epoll fd
    int                  hook_count_ = 0;      // 本模块 hook 数量
    bool                 attached_ = false;    // 是否已挂载

    // 本模块的 hook 配置（从全局 hook_configs[] 筛选出来的）
    // 每个条目包含：hook 名、目标库路径、偏移量、是否 retprobe
    std::vector<const hook_cfg*> own_hooks_;

    // 每个 hook 挂载后产生的 bpf_link（用于 detach 时销毁）
    // 索引与 own_hooks_ 一一对应
    std::vector<struct bpf_link*> links_;
};
