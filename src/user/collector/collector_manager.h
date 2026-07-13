// collector_manager.h — 收集器管理器
//
// 核心职责：
//   1. 管理所有 IUprobeCollector 的生命周期
//   2. 用 epoll 多路复用所有 collector 的 ringbuf fd
//   3. epoll_wait 返回后，哪个 collector 有数据就调用其 poll()
//   4. 支持运行时通过 collector 名称独立启停
//   5. 统一把事件推给 stats_collector 和 log_writer
//
// epoll 事件循环流程：
//   ┌── epoll_wait() ─────────────────────────────┐
//   │                                              │
//   │  routing.ringbuf_fd() 就绪 → routing.poll()  │
//   │  app.ringbuf_fd()     就绪 → app.poll()      │
//   │  sd.ringbuf_fd()      就绪 → sd.poll()       │
//   │                                              │
//   └── 循环（直到收到 SIGINT/SIGTERM）────────────┘
//
// 使用示例：
//   CollectorManager mgr;
//   mgr.add_collector(new RoutingCollector());
//   mgr.add_collector(new AppCollector());
//   mgr.add_collector(new SdCollector());
//   mgr.init_all("/usr/lib/ebpf");      // 加载所有 .bpf.o
//   mgr.attach_all(1234);               // 挂载到 PID 1234
//   mgr.run_loop();                     // 进入事件循环（阻塞）
//   mgr.shutdown();                     // 清理

#pragma once

#include <vector>
#include <memory>
#include <string>

class IUprobeCollector;
class ILogWriter;

class CollectorManager {
public:
    CollectorManager();
    ~CollectorManager();

    // ── 收集器注册 ───────────────────────────────────────────────────

    /**
     * 注册一个收集器（必须在 init_all 之前调用）
     * CollectorManager 接管所有权
     */
    void add_collector(IUprobeCollector* collector);

    /**
     * 按名称查找收集器（用于运行时控制）
     * @return 找到的 collector 指针，不存在返回 nullptr
     */
    IUprobeCollector* find(const char* name);

    // ── 生命周期 ─────────────────────────────────────────────────────

    /**
     * 初始化所有已注册的收集器
     *
     * @param bpf_dir  存放 .bpf.o 文件的目录
     *                 每个 collector 会加载 <bpf_dir>/<name>.bpf.o
     *                 例如 routing collector 加载 <bpf_dir>/routing.bpf.o
     * @return 成功初始化的 collector 数量
     */
    int init_all(const char* bpf_dir);

    /**
     * 挂载所有收集器的 uprobe
     * @param target_pid  目标进程 PID（-1 = 所有进程）
     */
    void attach_all(int target_pid);

    // ── 事件循环 ─────────────────────────────────────────────────────

    /**
     * 进入主事件循环（阻塞，直到收到停止信号）
     *
     * 内部使用 epoll_wait 等待任意 collector 的 ringbuf 有数据，
     * 然后调用对应 collector 的 poll() 消费事件。
     */
    void run_loop();

    /**
     * 停止事件循环（可从信号处理函数中调用）
     */
    void stop();

    // ── 日志和统计 ───────────────────────────────────────────────────

    /**
     * 设置日志输出（所有 collector 共享）
     */
    void set_log_writer(ILogWriter* writer);

    /**
     * 设置统计输出间隔（秒），0 = 关闭统计
     */
    void set_stats_interval(int seconds);

    // ── 清理 ─────────────────────────────────────────────────────────

    /**
     * 卸载所有 collector 并释放资源
     */
    void shutdown();

    /**
     * 返回是否正在运行
     */
    bool is_running() const { return running_; }

private:
    /**
     * 在 epoll 循环中处理单个 collector 的事件
     */
    void handle_collector_event(IUprobeCollector* collector);

    // ── 成员变量 ─────────────────────────────────────────────────────
    std::vector<std::unique_ptr<IUprobeCollector>> collectors_;
    ILogWriter* log_writer_ = nullptr;
    int  epoll_fd_ = -1;
    int  stats_interval_sec_ = 10;   // 默认每 10 秒输出一次统计
    bool running_ = false;
};
