// collector_manager.cpp — 收集器管理器的实现

#include "collector_manager.h"
#include "../output/log_writer.h"
#include "../stats_collector.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <sys/epoll.h>
#include <signal.h>

// ── 全局标志：用于信号处理 ────────────────────────────────────────────
// 设置为 volatile sig_atomic_t，确保在信号处理函数中修改是安全的
static volatile sig_atomic_t g_running = 1;

/**
 * SIGINT / SIGTERM 信号处理函数
 *
 * 收到 Ctrl+C 或 kill 信号时把 g_running 设为 0，
 * run_loop() 中的主循环检测到后退出。
 */
static void signal_handler(int sig)
{
    (void)sig;
    g_running = 0;
    fprintf(stdout, "\n收到停止信号，正在退出...\n");
}

// ═══════════════════════════════════════════════════════════════════════
// 构造 / 析构
// ═══════════════════════════════════════════════════════════════════════

CollectorManager::CollectorManager()
{
    // 安装信号处理函数
    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);
    // 忽略 SIGPIPE（防止写入已关闭的管道时进程崩溃）
    signal(SIGPIPE, SIG_IGN);
}

CollectorManager::~CollectorManager()
{
    shutdown();
}

// ═══════════════════════════════════════════════════════════════════════
// 收集器注册
// ═══════════════════════════════════════════════════════════════════════
void CollectorManager::add_collector(IUprobeCollector* collector)
{
    collectors_.emplace_back(collector);
}

IUprobeCollector* CollectorManager::find(const char* name)
{
    for (auto& c : collectors_) {
        if (strcmp(c->name(), name) == 0)
            return c.get();
    }
    return nullptr;
}

// ═══════════════════════════════════════════════════════════════════════
// init_all — 初始化所有 collector
// ═══════════════════════════════════════════════════════════════════════
int CollectorManager::init_all()
{
    int success = 0;

    for (auto& c : collectors_) {
        fprintf(stdout, "初始化: %s\n", c->name());

        if (c->init() == 0) {
            success++;
        } else {
            fprintf(stderr, "初始化 %s 失败！\n", c->name());
        }
    }

    return success;
}

// ═══════════════════════════════════════════════════════════════════════
// attach_all — 注入 EventContext 后挂载所有收集器
//
// 关键流程：
//   1. set_event_context(&event_ctx_) → 把 stats + writer 注入每个 collector
//   2. collector->attach() → 创建 ringbuf consumer 时，
//      把 ringbuf_callback + this 传给 ring_buffer__new()
//   3. 之后每次 ring_buffer__consume() 读出事件，
//      ringbuf_callback 自动把事件推给 stats 和 writer
// ═══════════════════════════════════════════════════════════════════════
void CollectorManager::attach_all(int target_pid)
{
    for (auto& c : collectors_) {
        // 注入事件上下文：让 collector 的 ringbuf 回调知道往哪推事件
        c->set_event_context(&event_ctx_);

        int n = c->attach(target_pid);
        if (n > 0) {
            fprintf(stdout, "%s: %d/%d hooks 挂载成功\n",
                    c->name(), n, c->hook_count());
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// set_event_context — 设置 EventContext
// ═══════════════════════════════════════════════════════════════════════
void CollectorManager::set_event_context(StatsCollector* stats, ILogWriter* writer)
{
    event_ctx_.stats  = stats;
    event_ctx_.writer = writer;
}

// ═══════════════════════════════════════════════════════════════════════
// run_loop — epoll 事件循环
//
// 核心逻辑：
//   1. 创建 epoll 实例
//   2. 把每个 collector 的 ringbuf fd 注册到 epoll
//   3. 循环：
//      a) epoll_wait() 阻塞等待任意 fd 就绪
//      b) 遍历就绪的 fd，找到对应的 collector
//      c) 调用该 collector 的 poll() 消费 ring buffer
//      d) 如果是统计数据事件，输出统计报告
//   4. 收到停止信号后清理退出
// ═══════════════════════════════════════════════════════════════════════

void CollectorManager::run_loop()
{
    // 步骤 1：创建 epoll 实例
    epoll_fd_ = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd_ < 0) {
        fprintf(stderr, "创建 epoll 失败: %s\n", strerror(errno));
        return;
    }

    // 步骤 2：把每个 collector 的 ringbuf fd 注册到 epoll
    // 注意：只注册已挂载的 collector（ringbuf_fd() >= 0）
    for (auto& c : collectors_) {
        if (!c->is_attached())
            continue;

        int fd = c->ringbuf_fd();
        if (fd < 0)
            continue;

        struct epoll_event ev = {};
        ev.events = EPOLLIN;                // 监听可读事件
        ev.data.ptr = c.get();              // 把 collector 指针存到 event 里，
                                            // epoll_wait 返回时可以直接找到是哪个 collector

        if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &ev) < 0) {
            fprintf(stderr, "epoll_ctl 失败 (collector=%s, fd=%d): %s\n",
                    c->name(), fd, strerror(errno));
            continue;
        }
    }

    // 步骤 3：主事件循环
    fprintf(stdout, "进入事件循环（Ctrl+C 退出）...\n");
    running_ = true;
    g_running = 1;

    const int MAX_EVENTS = 16;  // 单次 epoll_wait 最多返回的事件数

    while (g_running) {
        struct epoll_event events[MAX_EVENTS];

        // 阻塞等待，超时 1 秒（确保定期检查 g_running 标志）
        int nfds = epoll_wait(epoll_fd_, events, MAX_EVENTS, 1000);

        if (nfds < 0) {
            // epoll_wait 可能被信号中断（EINTR），这是正常的
            if (errno == EINTR)
                continue;
            fprintf(stderr, "epoll_wait 错误: %s\n", strerror(errno));
            break;
        }

        // 处理所有就绪的 fd
        for (int i = 0; i < nfds; i++) {
            // events[i].data.ptr 存的是 collector 指针
            auto* collector = static_cast<IUprobeCollector*>(events[i].data.ptr);
            handle_collector_event(collector);
        }
    }

    fprintf(stdout, "事件循环已停止\n");
    running_ = false;
}

// ═══════════════════════════════════════════════════════════════════════
// handle_collector_event — 处理单个 collector 的 ringbuf 事件
// ═══════════════════════════════════════════════════════════════════════

void CollectorManager::handle_collector_event(IUprobeCollector* collector)
{
    // ring_buffer__consume() 内部调用 ringbuf_callback()
    // → stats->process_event() + writer->write()
    collector->poll(0);
}

// ═══════════════════════════════════════════════════════════════════════
// 辅助方法
// ═══════════════════════════════════════════════════════════════════════

void CollectorManager::stop()
{
    g_running = 0;
}

void CollectorManager::set_log_writer(ILogWriter* writer)
{
    log_writer_ = writer;
}

void CollectorManager::set_stats_interval(int seconds)
{
    stats_interval_sec_ = seconds;
}

// ═══════════════════════════════════════════════════════════════════════
// shutdown — 清理所有资源
// ═══════════════════════════════════════════════════════════════════════

void CollectorManager::shutdown()
{
    if (epoll_fd_ >= 0) {
        close(epoll_fd_);
        epoll_fd_ = -1;
    }

    for (auto& c : collectors_) {
        c->destroy();
    }
    collectors_.clear();

    running_ = false;
}
