// collector_base.h — Uprobe 收集器的抽象接口
//
// CollectorManager 通过这个接口统一管理所有收集器的生命周期：
//   init() → attach() → poll() → detach() → destroy()
//
// 设计思路：
//   每个 collector 拥有自己独立的 BPF skeleton 和 ringbuffer。
//   CollectorManager 用 epoll 多路复用所有 collector 的 ringbuf fd，
//   哪个有数据就调用哪个的 poll()，以此实现非阻塞的并发事件消费。

#pragma once

#include <cstdint>

class  StatsCollector;      // 前向声明，定义在 user/stats_collector.h
class  ILogWriter;          // 前向声明，定义在 user/output/log_writer.h

// ── 事件处理上下文 ────────────────────────────────────────────────────
// 每个 collector 在创建 ringbuf 时都会持有这个结构体的指针。
// 当 ringbuf 中有新事件到达时，libbpf 调用静态回调函数，
// 回调函数通过这个上下文把事件推给统计模块和日志模块。
//
// 为什么用结构体而不是直接传两个裸指针？
//   1. collector 不需要知道 StatsCollector/ILogWriter 的具体实现
//   2. 未来可能添加更多消费者（如网络上报、DDS 桥接），只需扩展这个结构体

struct EventContext {
    StatsCollector* stats;      // 统计收集器（计数器 + 时延匹配）
    ILogWriter*     writer;     // 日志输出（终端 / 文件）
};

/**
 * IUprobeCollector — 一个 uprobe 模块的抽象接口
 *
 * 生命周期：
 *   1. collector = new RoutingCollector();
 *   2. collector->set_event_context(&ctx);   // 注入事件处理上下文
 *   3. collector->init(bpf_obj_path);        // 加载 BPF object
 *   4. collector->attach(target_pid);        // 遍历 hooks 数组，逐个挂载 uprobe
 *   5. collector->ringbuf_fd();              // 获取 ringbuf fd，注册到 epoll
 *   6. epoll_wait() → collector->poll();      // 有数据时调用 poll() 消费
 *   7. collector->detach();                  // 销毁所有 bpf_link（可重新 attach）
 *   8. collector->destroy();                 // 完全释放资源
 */
class IUprobeCollector {
public:
    virtual ~IUprobeCollector() = default;

    /**
     * 获取收集器名称（如 "routing", "app", "sd"）
     */
    virtual const char* name() const = 0;

    /**
     * 注入事件处理上下文（stats + writer）
     *
     * 必须在 attach() 之前调用，因为 attach() 中创建 ringbuf consumer
     * 时就需要把这个上下文传给 libbpf 的回调函数。
     *
     * @param ctx  包含 stats 和 writer 指针的结构体
     */
    virtual void set_event_context(EventContext* ctx) = 0;

    /**
     * 初始化：从嵌入的字节码加载 BPF object（bpf_object__open_mem）
     * BPF 字节码在编译时 xxd -i 嵌入到可执行文件中，无需额外文件部署
     *
     * @return 0=成功, <0=失败
     */
    virtual int init() = 0;

    /**
     * 挂载所有 uprobe hook
     *
     * 遍历 hook_configs[] 数组中属于本模块的条目，
     * 用 bpf_program__attach_uprobe_opts() 按偏移量挂载。
     *
     * @param target_pid  目标进程 PID（-1 = 所有进程）
     * @return 成功挂载的 hook 数量，<0=失败
     */
    virtual int attach(int target_pid) = 0;

    /**
     * 卸载所有 uprobe hook（销毁 bpf_link）
     */
    virtual int detach() = 0;

    /**
     * 完全释放资源
     */
    virtual void destroy() = 0;

    /**
     * 获取 ringbuffer 的 epoll fd
     */
    virtual int ringbuf_fd() const = 0;

    /**
     * 消费 ringbuffer 中的事件（由 epoll 唤醒后调用）
     */
    virtual int poll(int timeout_ms) = 0;

    virtual int  hook_count() const = 0;
    virtual bool is_attached() const = 0;
};
