// collector.h — 通用的 uprobe 收集器（配置驱动）
//
// 这是整个用户态的唯一 collector 实现。
// 它不包含任何硬编码的模块信息——所有差异都来自 module_meta 配置。
//
// 新增模块只需在 hooks.json 中加一条 modules[] 条目，
// 无需修改任何 C++ 代码。
//
// 三个模块的 BPF 对象分别有各自的 hook 前缀和 ringbuf map 名，
// 这些信息都在 module_meta 中配置，运行时由 Collector 按配置执行。
//
// 生命周期（和其他 collector 一样）：
//   c = new Collector(&modules[i]);        // 绑定模块配置
//   c->set_event_context(&ctx);            // 注入 stats + writer
//   c->init(bpf_dir);                      // 加载 <bpf_dir>/<meta->bpf_obj>
//   c->attach(pid);                        // 筛选 hook → 偏移挂载 → 创建 ringbuf
//   c->ringbuf_fd()                        // 获取 epoll fd
//   c->poll(0)                             // 消费 ringbuf（epoll 唤醒后调用）
//   c->detach()                            // 卸载
//   c->destroy()                           // 释放

#pragma once

#include "collector_base.h"
#include <cstddef>
#include <vector>

// libbpf 类型的 C 风格前向声明
struct bpf_object;
struct bpf_program;
struct bpf_link;
struct ring_buffer;

struct hook_cfg;        // hook_config.h
struct module_meta;     // hook_config.h（自动生成）

class Collector : public IUprobeCollector {
public:
    /**
     * 构造 collector，绑定到一个模块的配置
     *
     * @param meta  指向 modules[] 数组中的条目（由 hook_config.h 自动生成）
     *              包含了本模块的所有元信息：名称、BPF 文件名、hook 前缀等
     */
    explicit Collector(const struct module_meta* meta);
    ~Collector() override;

    // ── IUprobeCollector 接口 ────────────────────────────────────────

    const char* name() const override { return meta_->name; }

    void set_event_context(EventContext* ctx) override { event_ctx_ = ctx; }
    int  init(const char* bpf_dir) override;
    int  attach(int target_pid) override;
    int  detach() override;
    void destroy() override;
    int  ringbuf_fd() const override;
    int  poll(int timeout_ms) override;
    int  hook_count() const override { return hook_count_; }
    bool is_attached() const override { return attached_; }

private:
    /**
     * 从全局 hook_configs[] 中筛选本模块的 hook
     *
     * 筛选规则：hook 名以 meta_->hook_prefix 开头
     * 例如 hook_prefix = "rm_" 时，筛出 "rm_send_entry"、"rm_send_ret" 等
     */
    void filter_own_hooks();

    /**
     * 根据 hook 名找到对应的 BPF 程序
     *
     * BPF 程序命名规则：所有 .bpf.c 都用统一的 SEC 命名约定
     *   SEC("uprobe/hook_<hook_name>")
     * 所以程序名 = "hook_" + hook_name
     * 这个约定对所有模块都一样，不需要配置。
     */
    struct bpf_program* find_bpf_program(const char* hook_name);

    /**
     * ★ ringbuf 事件回调（C 风格静态函数，libbpf 调用）
     *
     * 从 ringbuf 读出一个事件后，自动推给 stats->process_event()
     * 和 writer->write()。
     *
     * hook 名称通过 hook_name_tables[module_id][hook_id] 查找，
     * 完全由配置驱动，不依赖硬编码的数组。
     */
    static int ringbuf_callback(void *ctx, void *data, size_t size);

    // ── 成员变量 ─────────────────────────────────────────────────────

    const struct module_meta* meta_ = nullptr;     // ★ 模块配置（构造时注入，从不改变）
    EventContext*        event_ctx_ = nullptr;      // ★ stats + writer（attach 前注入）
    struct bpf_object*   obj_ = nullptr;            // 已加载的 BPF 对象
    struct ring_buffer*  ringbuf_ = nullptr;        // ring buffer consumer
    int                  ringbuf_fd_ = -1;           // ringbuf 的 epoll fd
    int                  hook_count_ = 0;           // 本模块管理的 hook 数量
    bool                 attached_ = false;          // 是否已挂载

    // 本模块的 hook 配置（从全局 hook_configs[] 按前缀筛选出来）
    std::vector<const hook_cfg*> own_hooks_;

    // 每个 hook 挂载后产生的 bpf_link 句柄（detach 时逐个销毁）
    std::vector<struct bpf_link*> links_;
};
