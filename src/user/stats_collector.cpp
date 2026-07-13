// stats_collector.cpp — 统计收集 + 时延匹配实现

#include "stats_collector.h"
#include "../common/vsomeip_event.h"
#include "../common/vsomeip_types.h"
#include "output/log_writer.h"

#include <cstdio>
#include <cinttypes>
#include <cstring>
#include <cstdlib>
#include <algorithm>

// ── 超时阈值：30 秒（纳秒）───────────────────────────────────────────
// pending 表中超过此时间的条目视为超时
static const uint64_t TIMEOUT_NS = 30ULL * 1000 * 1000 * 1000;

StatsCollector::StatsCollector()
{
    // 初始化 4 个模块的统计（索引 0 未用）
    for (int i = 0; i < 4; i++) {
        module_stats_[i] = {};
    }
}

StatsCollector::~StatsCollector() = default;

// ═══════════════════════════════════════════════════════════════════════
// make_key — 从事件字段构造 pending 表的 key
//
// key 编码（64 位）：
//   [63:48] service_id  (16 bit)
//   [47:32] method_id   (16 bit)
//   [31:16] client_id   (16 bit)
//   [15:0]  session_id  (16 bit)
//
// 这 4 个字段唯一标识一次 SOME/IP 通信会话。
// ═══════════════════════════════════════════════════════════════════════

uint64_t StatsCollector::make_key(const vsomeip_event& e)
{
    return ((uint64_t)e.service_id << 48) |
           ((uint64_t)e.method_id  << 32) |
           ((uint64_t)e.client_id  << 16) |
           (uint64_t)e.session_id;
}

// ═══════════════════════════════════════════════════════════════════════
// process_event — 事件处理入口
// ═══════════════════════════════════════════════════════════════════════

void StatsCollector::process_event(const vsomeip_event& event, const char* hook_name)
{
    // 1. 累加计数器
    update_counters(event, hook_name);

    // 2. 时延匹配（只对 routing 模块的事件，因为只有它能读到 header）
    if (event.module_id == MODULE_ROUTING) {
        // SEND 方向：记录到 pending 表
        if (event.direction == DIR_SEND && !event.is_retprobe) {
            if (event.message_type == SOMEIP_MT_REQUEST ||
                event.message_type == SOMEIP_MT_REQUEST_NO_RETURN) {
                record_pending(event);
            }
        }

        // RECV 方向：尝试匹配
        if (event.direction == DIR_RECV && !event.is_retprobe) {
            if (event.message_type == SOMEIP_MT_RESPONSE ||
                event.message_type == SOMEIP_MT_ERROR ||
                event.message_type == SOMEIP_MT_NOTIFICATION) {
                try_match_latency(event);
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// record_pending — 把发出的 REQUEST 记入待匹配表
// ═══════════════════════════════════════════════════════════════════════

void StatsCollector::record_pending(const vsomeip_event& event)
{
    uint64_t key = make_key(event);

    // 如果这个 key 已经存在（比如上层重发了同一个 request），
    // 只保留最早的时间戳（更保守的时延估计）
    if (pending_.find(key) != pending_.end())
        return;

    pending_[key] = {event.timestamp_ns, event.arg0};
}

// ═══════════════════════════════════════════════════════════════════════
// try_match_latency — 收到 RESPONSE 时，在 pending 表中找对应的 REQUEST
// ═══════════════════════════════════════════════════════════════════════

void StatsCollector::try_match_latency(const vsomeip_event& event)
{
    uint64_t key = make_key(event);

    auto it = pending_.find(key);
    if (it == pending_.end()) {
        // 没有匹配的 REQUEST —— 可能是启动前就发出的请求，
        // 或者 request_no_return 类型不需要匹配
        return;
    }

    // 计算时延
    uint64_t latency_ns = event.timestamp_ns - it->second.send_timestamp_ns;

    // 合理性检查：时延为负或 > 60 秒视为异常，丢弃
    if (latency_ns > 60ULL * 1000 * 1000 * 1000) {
        pending_.erase(it);
        return;
    }

    // 收集时延样本（用于统计摘要中的 p50/p99/max）
    latency_samples_.push_back(latency_ns);

    // 输出时延事件
    if (log_writer_) {
        char buf[256];
        snprintf(buf, sizeof(buf),
            "{"
            "\"svc\":%u,\"method\":%u,\"client\":%u,\"session\":%u,"
            "\"type\":\"%s\","
            "\"send_ts\":%" PRIu64 ",\"recv_ts\":%" PRIu64 ","
            "\"latency_us\":%.1f"
            "}",
            event.service_id, event.method_id,
            event.client_id, event.session_id,
            message_type_name(event.message_type),
            it->second.send_timestamp_ns, event.timestamp_ns,
            (double)latency_ns / 1000.0        // 纳秒 → 微秒
        );
        log_writer_->write_latency(buf);
    }

    // 已匹配，从 pending 表删除
    pending_.erase(it);
}

// ═══════════════════════════════════════════════════════════════════════
// update_counters — 更新计数器
// ═══════════════════════════════════════════════════════════════════════

void StatsCollector::update_counters(const vsomeip_event& event, const char* hook_name)
{
    // 按 hook 名统计
    auto& hs = hook_stats_[hook_name];
    hs.total++;

    // 如果是 return probe，根据返回值判断成功/失败
    if (event.is_retprobe) {
        if (event.retval == 0)
            hs.success++;
        else
            hs.fail++;
    }

    // 按 message_type 分类（只有非 retprobe 且 header 有效时）
    if (!event.is_retprobe && event.message_type != 0) {
        int idx = 0;
        switch (event.message_type) {
            case SOMEIP_MT_REQUEST:           idx = 0; break;
            case SOMEIP_MT_REQUEST_NO_RETURN: idx = 1; break;
            case SOMEIP_MT_NOTIFICATION:      idx = 2; break;
            case SOMEIP_MT_REQUEST_ACK:       idx = 3; break;
            case SOMEIP_MT_RESPONSE:          idx = 4; break;
            case SOMEIP_MT_ERROR:             idx = 5; break;
            default:                          idx = 5; break;
        }
        hs.by_type[idx]++;
    }

    // 按模块统计收发量
    if (event.module_id >= 1 && event.module_id <= 3) {
        if (event.direction == DIR_SEND && !event.is_retprobe)
            module_stats_[event.module_id].send_total++;
        if (event.direction == DIR_RECV && !event.is_retprobe)
            module_stats_[event.module_id].recv_total++;
    }
}

// ═══════════════════════════════════════════════════════════════════════
// flush_report — 输出统计摘要
// ═══════════════════════════════════════════════════════════════════════

void StatsCollector::flush_report()
{
    uint64_t now_ns = 0;  // 由调用者传入
    // 获取当前时间（简单方式）
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    now_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

    double elapsed_sec = 0;
    if (last_report_ns_ > 0) {
        elapsed_sec = (double)(now_ns - last_report_ns_) / 1e9;
    }
    last_report_ns_ = now_ns;

    if (!log_writer_)
        return;

    // ── 构建统计 JSON ────────────────────────────────────────────────

    // 1. 按模块的收发量
    for (int mod = 1; mod <= 3; mod++) {
        const char* mod_name =
            mod == MODULE_ROUTING ? "routing" :
            mod == MODULE_APP     ? "app"     :
            mod == MODULE_SD      ? "sd"      : "?";

        auto& ms = module_stats_[mod];
        if (ms.send_total == 0 && ms.recv_total == 0)
            continue;

        char buf[512];
        snprintf(buf, sizeof(buf),
            "{"
            "\"module\":\"%s\","
            "\"elapsed\":%.1f,"
            "\"send_total\":%" PRIu64 ","
            "\"recv_total\":%" PRIu64
            "}",
            mod_name, elapsed_sec,
            ms.send_total, ms.recv_total
        );
        log_writer_->write_stats(buf);

        // 重置计数器
        ms = {};
    }

    // 2. 时延统计（p50/p99/max）
    if (!latency_samples_.empty()) {
        std::sort(latency_samples_.begin(), latency_samples_.end());

        size_t n = latency_samples_.size();
        uint64_t p50_us = latency_samples_[n * 50 / 100] / 1000;
        uint64_t p99_us = latency_samples_[n * 99 / 100] / 1000;
        uint64_t max_us = latency_samples_[n - 1] / 1000;
        // 平均值
        uint64_t sum = 0;
        for (auto v : latency_samples_) sum += v;
        uint64_t avg_us = (sum / n) / 1000;

        char buf[256];
        snprintf(buf, sizeof(buf),
            "{"
            "\"type\":\"latency\","
            "\"samples\":%zu,"
            "\"avg_us\":%" PRIu64 ","
            "\"p50_us\":%" PRIu64 ","
            "\"p99_us\":%" PRIu64 ","
            "\"max_us\":%" PRIu64
            "}",
            n, avg_us, p50_us, p99_us, max_us
        );
        log_writer_->write_stats(buf);

        latency_samples_.clear();
    }

    // 3. 按 hook 的调用次数（verbose 模式下）
    for (auto& [name, hs] : hook_stats_) {
        if (hs.total == 0) continue;
        char buf[256];
        snprintf(buf, sizeof(buf),
            "{"
            "\"type\":\"hook\","
            "\"hook\":\"%s\","
            "\"total\":%" PRIu64 ","
            "\"succ\":%" PRIu64 ","
            "\"fail\":%" PRIu64
            "}",
            name.c_str(), hs.total, hs.success, hs.fail
        );
        log_writer_->write_stats(buf);

        // 重置
        hs = {};
    }
}

// ═══════════════════════════════════════════════════════════════════════
// evict_expired — 清理超时的 pending 条目
// ═══════════════════════════════════════════════════════════════════════

void StatsCollector::evict_expired()
{
    // 获取当前时间
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

    auto it = pending_.begin();
    while (it != pending_.end()) {
        uint64_t elapsed = now_ns - it->second.send_timestamp_ns;
        if (elapsed > TIMEOUT_NS) {
            if (log_writer_) {
                // 输出超时事件
                uint64_t svc   = (it->first >> 48) & 0xFFFF;
                uint64_t method = (it->first >> 32) & 0xFFFF;
                uint64_t client = (it->first >> 16) & 0xFFFF;
                uint64_t session= it->first & 0xFFFF;

                char buf[256];
                snprintf(buf, sizeof(buf),
                    "{"
                    "\"type\":\"timeout\","
                    "\"svc\":%" PRIu64 ",\"method\":%" PRIu64 ","
                    "\"client\":%" PRIu64 ",\"session\":%" PRIu64 ","
                    "\"elapsed_ms\":%" PRIu64
                    "}",
                    svc, method, client, session,
                    elapsed / 1000000
                );
                log_writer_->write_stats(buf);
            }
            it = pending_.erase(it);
        } else {
            ++it;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// message_type_name — 辅助函数
// ═══════════════════════════════════════════════════════════════════════

const char* StatsCollector::message_type_name(uint8_t mt)
{
    switch (mt) {
        case SOMEIP_MT_REQUEST:           return "REQUEST";
        case SOMEIP_MT_REQUEST_NO_RETURN: return "REQ_NORET";
        case SOMEIP_MT_NOTIFICATION:      return "NOTIFICATION";
        case SOMEIP_MT_REQUEST_ACK:       return "REQ_ACK";
        case SOMEIP_MT_RESPONSE:          return "RESPONSE";
        case SOMEIP_MT_ERROR:             return "ERROR";
        default:                          return "UNKNOWN";
    }
}
