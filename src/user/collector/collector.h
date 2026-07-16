// collector.h — 通用的 uprobe 收集器（配置驱动，无硬编码）
//
// 每个 Collector 实例绑定一个 file_group（来自 hook_config.h）。
// file_group 包含了一个 .bpf.o 的全部信息：文件名、ringbuf map 名、hook 列表等。
//
// 新增模块或 hook：
//   只需在 hooks.json 的 files[].hooks[] 中加一条，重新 gen_hook_config.sh → 编译。
//
// 生命周期：
//   c = new Collector(&file_groups[i]);
//   c->set_event_context(&ctx);
//   c->init();               // 从嵌入字节码加载 BPF
//   c->attach(pid);          // 遍历 hooks → SEC 名直接查找程序 → 偏移挂载 → 创建 ringbuf

#pragma once

#include "collector_base.h"
#include "../../gen/hook_config.h"
#include <cstddef>
#include <vector>

struct bpf_object;
struct bpf_program;
struct bpf_link;
struct ring_buffer;
struct hook_cfg;
struct file_group;      // hook_config.h（自动生成）

class Collector : public IUprobeCollector {
public:
    explicit Collector(const struct file_group* group);
    ~Collector() override;

    const char* name() const override;          // 返回逻辑名称，如 "routing"
    void set_event_context(EventContext* ctx) override { event_ctx_ = ctx; }    // 已经实现
    int  init() override;
    int  attach(int target_pid) override;
    int  detach() override;
    void destroy() override;
    int  ringbuf_fd() const override;
    int  poll(int timeout_ms) override;
    int  hook_count() const override { return group_->hook_count; }
    bool is_attached() const override { return attached_; }

private:
    /**
     * ringbuf 事件回调（C 风格，libbpf 调用）
     *
     * hook 名通过 group_->hook_names[event->hook_id] 直接索引，无需任何前缀匹配。
     */
    static int ringbuf_callback(void *ctx, void *data, size_t size);

    // ── 成员变量 ─────────────────────────────────────────────────────
    const struct file_group* group_ = nullptr;   // 文件分组配置（构造注入）
    EventContext*        event_ctx_ = nullptr;   // stats + writer
    struct bpf_object*   obj_ = nullptr;         // BPF 对象
    struct ring_buffer*  ringbuf_ = nullptr;     // ring buffer consumer
    int                  ringbuf_fd_ = -1;
    bool                 attached_ = false;
    std::vector<struct bpf_link*> links_;        // 每个 hook 的 bpf_link
};
