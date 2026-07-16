// stats_collector.h — 统计收集 + 时延匹配

#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <cstdint>

// 前向声明各模块事件类型
struct routing_event;
struct app_event;
struct sd_event;
class ILogWriter;

class StatsCollector {
public:
    StatsCollector();
    ~StatsCollector();

    void set_log_writer(ILogWriter* w) { log_writer_ = w; }
    void set_report_interval(int sec) { report_interval_sec_ = sec; }

    // ── 按类型处理事件 ────────────────────────────────────────────────
    void process_routing(const routing_event& e, const char* hook);
    void process_app(const app_event& e, const char* hook);
    void process_sd(const sd_event& e, const char* hook);

    void flush_report();
    void evict_expired();

private:
    struct HookStats { uint64_t total=0,succ=0,fail=0; uint64_t by_type[6]={}; };
    std::unordered_map<std::string,HookStats> hook_stats_;
    uint64_t mod_send_[4]={}, mod_recv_[4]={};

    // ── 时延匹配 ──────────────────────────────────────────────────
    struct PendingEntry { uint64_t send_ts; };
    std::unordered_map<uint64_t,PendingEntry> pending_;
    std::vector<uint64_t> latency_samples_;
    uint64_t last_report_ns_ = 0;
    int report_interval_sec_ = 10;
    ILogWriter* log_writer_ = nullptr;

    uint64_t make_key(uint16_t svc, uint16_t method, uint16_t client, uint16_t session);
    void update_counter(const char* hook, bool ret, int64_t retval);
    void record_pending(const routing_event& e);
    void try_match(const routing_event& e);
};
