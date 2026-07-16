// stats_collector.h — 统计收集（★ 解耦后只有通用入口）

#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <cstdint>

struct event_header;
class ILogWriter;

class StatsCollector {
public:
    StatsCollector();
    ~StatsCollector();

    void set_log_writer(ILogWriter* w) { log_writer_ = w; }
    void set_report_interval(int sec) { report_interval_sec_ = sec; }

    // ── ★ 通用事件处理（新增模块不需加方法）★ ─────────────────────────
    //
    // 处理 event_header 能覆盖的所有逻辑：
    //   - 计数器（total/succ/fail）
    //   - 按 module 分组统计收发量
    //
    // 类型相关的逻辑（时延匹配）通过 on_latency 回调完成。
    // routing 模块的 handler 调用时传 latency 回调，其他模块传 nullptr。

    typedef void (*on_latency_fn)(const void* data, const char* hook,
                                   StatsCollector* self);

    /**
     * @param hdr         公共头
     * @param payload     模块特定数据（可为 nullptr）
     * @param hook        hook 名
     * @param retval      uretprobe 返回值（入口 probe 传 0）
     * @param on_latency  可选的时延匹配回调（只有 routing 需要）
     */
    void process_event(const event_header* hdr, const void* payload,
                       const char* hook, int64_t retval,
                       on_latency_fn on_latency);

    // ── 时延匹配（被 routing handler 的回调调用）─────────────────────
    void record_pending(uint16_t svc, uint16_t method,
                        uint16_t client, uint16_t session, uint64_t ts);
    void try_match(uint16_t svc, uint16_t method,
                   uint16_t client, uint16_t session,
                   uint64_t recv_ts, uint8_t msg_type);

    // ── 定期输出 ────────────────────────────────────────────────────
    void flush_report();
    void evict_expired();

private:
    struct HookStats { uint64_t total=0,succ=0,fail=0; };
    std::unordered_map<std::string,HookStats> hook_stats_;
    uint64_t mod_send_[4]={}, mod_recv_[4]={};

    struct PendingEntry { uint64_t send_ts; };
    std::unordered_map<uint64_t,PendingEntry> pending_;
    std::vector<uint64_t> latency_;
    uint64_t last_report_ns_=0;
    int report_interval_sec_=10;
    ILogWriter* log_writer_=nullptr;
};
