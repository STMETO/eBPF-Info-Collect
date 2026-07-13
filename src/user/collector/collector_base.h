// collector_base.h — Uprobe 收集器的抽象接口
//
// 每个模块（routing / app / sd）都实现这个接口。
// CollectorManager 通过这个接口统一管理所有收集器的生命周期：
//   init() → attach() → poll() → detach() → destroy()
//
// 设计思路：
//   每个 collector 拥有自己独立的 BPF skeleton 和 ringbuffer。
//   CollectorManager 用 epoll 多路复用所有 collector 的 ringbuf fd，
//   哪个有数据就调用哪个的 poll()，以此实现非阻塞的并发事件消费。

#pragma once

#include <string>
#include <cstdint>

struct vsomeip_event;       // 前向声明，定义在 common/vsomeip_event.h

/**
 * IUprobeCollector — 一个 uprobe 模块的抽象接口
 *
 * 生命周期：
 *   1. collector = new RoutingCollector();
 *   2. collector->init(bpf_obj_path);     // 加载 BPF skeleton
 *   3. collector->attach(target_pid);     // 遍历 hooks 数组，逐个挂载 uprobe
 *   4. collector->ringbuf_fd();           // 获取 ringbuf fd，注册到 epoll
 *   5. epoll_wait() → collector->poll();   // 有数据时调用 poll() 消费
 *   6. collector->detach();               // 销毁所有 bpf_link（可重新 attach）
 *   7. collector->destroy();              // 完全释放资源
 */
class IUprobeCollector {
public:
    virtual ~IUprobeCollector() = default;

    /**
     * 获取收集器名称（如 "routing", "app", "sd"）
     * 用于日志标识和 CLI 启停控制
     */
    virtual const char* name() const = 0;

    /**
     * 初始化：打开并加载 BPF skeleton
     *
     * @param bpf_obj_path  编译好的 .bpf.o 文件路径
     *                      例如 "/usr/lib/ebpf/routing.bpf.o"
     * @return 0=成功, <0=失败
     */
    virtual int init(const char* bpf_obj_path) = 0;

    /**
     * 挂载所有 uprobe hook
     *
     * 遍历 hook_configs[] 数组中属于本模块的条目，
     * 用 bpf_program__attach_uprobe_opts() 按偏移量挂载。
     *
     * @param target_pid  目标进程 PID
     *                    -1 = 所有进程
     *                     0 = 自身
     *                    >0 = 指定 PID
     * @return 成功挂载的 hook 数量，<0=失败
     */
    virtual int attach(int target_pid) = 0;

    /**
     * 卸载所有 uprobe hook（销毁 bpf_link）
     *
     * detach 后可以再次 attach，用于运行时切换目标进程
     * @return 0=成功
     */
    virtual int detach() = 0;

    /**
     * 完全释放资源（skeleton、ringbuf、links）
     * 调用后 collector 不可再使用
     */
    virtual void destroy() = 0;

    /**
     * 获取 ringbuffer 的文件描述符
     *
     * CollectorManager 把这个 fd 注册到 epoll，
     * 当 ringbuf 有数据可读时，epoll_wait 返回，
     * 然后调用 poll() 消费数据。
     */
    virtual int ringbuf_fd() const = 0;

    /**
     * 消费 ringbuffer 中的事件
     *
     * 每收到一个事件，调用 event_callback 处理。
     * event_callback 由 CollectorManager 注入（指向 stats_collector + log_writer）。
     *
     * @param timeout_ms  最大等待时间（毫秒），-1=阻塞等待
     * @return 本轮消费的事件数量
     */
    virtual int poll(int timeout_ms) = 0;

    /**
     * 获取本模块的 hook 数量（来自 hook_configs[]）
     */
    virtual int hook_count() const = 0;

    /**
     * 是否已挂载
     */
    virtual bool is_attached() const = 0;
};
