// stats_collector.h — 统计收集 + 时延匹配
//
// 核心功能：
//   1. 统计每个 hook 的调用次数、成功/失败次数
//   2. 按 message_type 分类统计
//   3. 时延匹配：把 REQUEST 的发送时间和 RESPONSE 的接收时间配对，
//      计算往返时延 (RTT)
//   4. 逐秒/逐 N 秒输出统计摘要
//
// 时延匹配算法：
//   ┌── 收到 SEND 事件 (REQUEST 类型) ──┐
//   │  key = (svc_id, method_id,        │
//   │         client_id, session_id)     │
//   │  pending[key] = timestamp_ns       │  存入"待匹配"哈希表
//   └────────────────────────────────────┘
//
//   ┌── 收到 RECV 事件 (RESPONSE 类型) ──┐
//   │  key = (svc_id, method_id,         │
//   │         client_id, session_id)     │
//   │  if key in pending:                │  在哈希表中找到对应的 REQUEST
//   │    latency = ts - pending[key]     │  计算时延
//   │    delete pending[key]             │  删除已匹配的条目
//   │    → 输出 [LATENCY] 事件           │
//   └────────────────────────────────────┘
//
//   如果某个 key 超过 30 秒仍未匹配（REQUEST 发出后没收到 RESPONSE），
//   视为超时，从 pending 中删除并输出 [TIMEOUT] 事件。

#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <cstdint>
#include <cstdio>

struct vsomeip_event;
class ILogWriter;

class StatsCollector {
public:
    StatsCollector();
    ~StatsCollector();

    /**
     * 设置日志 writer（用于输出统计和时延事件）
     */
    void set_log_writer(ILogWriter* writer) { log_writer_ = writer; }

    /**
     * 设置统计摘要输出间隔（秒），0 = 关闭
     */
    void set_report_interval(int seconds) { report_interval_sec_ = seconds; }

    /**
     * 处理一个 BPF 事件
     *
     * 这是所有 collector 共用的事件入口。
     * 内部会：
     *   1. 累加计数器（按 hook 名、按 message_type）
     *   2. 如果是 SEND + REQUEST 类型 → 存入 pending 表
     *   3. 如果是 RECV + RESPONSE 类型 → 查找 pending 表，计算时延
     */
    void process_event(const vsomeip_event& event, const char* hook_name);

    /**
     * 输出统计摘要（由 CollectorManager 的定时器调用）
     *
     * 输出格式：
     *   [METRICS t+10s] routing: send=5000(succ=4950,fail=50) recv=4800
     *     REQUEST=1000 REQ_NORET=500 RESPONSE=1000 ERROR=50
     *     latency(us): avg=234 p50=150 p99=850 max=5000
     */
    void flush_report();

    /**
     * 清理过期的 pending 条目（超过 30 秒未匹配的）
     * 由 CollectorManager 在 epoll 循环中定时调用
     */
    void evict_expired();

private:
    // ── 计数器 ───────────────────────────────────────────────────────
    // 按键值: hook_name → 计数
    struct HookStats {
        uint64_t total     = 0;       // 总调用次数
        uint64_t success   = 0;       // 成功次数（retval == 0）
        uint64_t fail      = 0;       // 失败次数（retval != 0）
        uint64_t by_type[6] = {0};    // 按 message_type 分类
    };
    std::unordered_map<std::string, HookStats> hook_stats_;

    // 按模块统计
    struct ModuleStats {
        uint64_t send_total = 0;
        uint64_t recv_total = 0;
    };
    ModuleStats module_stats_[4];  // 索引 1=routing, 2=app, 3=sd

    // ── 时延匹配 ─────────────────────────────────────────────────────
    // pending 表的 key = (service_id << 48) | (method_id << 32) |
    //                    (client_id << 16)  | session_id
    struct PendingEntry {
        uint64_t send_timestamp_ns;
        uint64_t arg0;              // 附加信息（便于排查）
    };
    std::unordered_map<uint64_t, PendingEntry> pending_;

    // 时延统计（用于统计摘要）
    std::vector<uint64_t> latency_samples_;  // 本周期收集的时延样本（纳秒）

    // ── 时间 ─────────────────────────────────────────────────────────
    uint64_t last_report_ns_ = 0;
    int      report_interval_sec_ = 10;

    ILogWriter* log_writer_ = nullptr;

    // ── 辅助方法 ─────────────────────────────────────────────────────
    uint64_t make_key(const vsomeip_event& e);
    const char* message_type_name(uint8_t mt);
    void    update_counters(const vsomeip_event& event, const char* hook_name);
    void    try_match_latency(const vsomeip_event& event);
    void    record_pending(const vsomeip_event& event);
};
