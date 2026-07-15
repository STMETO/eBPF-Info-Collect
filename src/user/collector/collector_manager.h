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

#include "collector_base.h"
#include <vector>
#include <memory>
#include <string>

class CollectorManager {
public:
    CollectorManager();
    ~CollectorManager();

    // ── 收集器注册 ───────────────────────────────────────────────────

    void add_collector(IUprobeCollector* collector);
    IUprobeCollector* find(const char* name);

    // ── 生命周期 ─────────────────────────────────────────────────────

    int  init_all();

    /**
     * 挂载所有收集器的 uprobe
     *
     * 挂载前会把 EventContext（stats + writer）注入到每个 collector，
     * 确保 ringbuf 回调函数能把事件推给统计和日志模块。
     */
    void attach_all(int target_pid);

    // ── 事件循环 ─────────────────────────────────────────────────────

    void run_loop();
    void stop();

    // ── 日志和统计 ───────────────────────────────────────────────────

    void set_log_writer(ILogWriter* writer);

    /**
     * 设置事件处理上下文（stats + writer）
     *
     * 必须在 attach_all() 之前调用。
     * attach_all() 内部会把 EventContext 注入到每个 collector，
     * collector 的 ringbuf 回调函数通过 EventContext 把事件
     * 推给 stats_collector（做统计和时延匹配）和 log_writer（做日志输出）。
     */
    void set_event_context(StatsCollector* stats, ILogWriter* writer);
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
    EventContext event_ctx_ = {};       // 事件上下文（stats + writer）
    int  stats_interval_sec_ = 10;
    bool running_ = false;
};
