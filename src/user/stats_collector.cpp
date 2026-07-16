// stats_collector.cpp — 统计收集实现

#include "stats_collector.h"
#include "../common/event_header.h"
#include "../common/routing_event.h"
#include "../common/app_event.h"
#include "../common/sd_event.h"
#include "../common/vsomeip_types.h"
#include "output/log_writer.h"
#include <cstdio>
#include <cinttypes>
#include <cstring>
#include <algorithm>

static const uint64_t TIMEOUT_NS = 30ULL * 1000 * 1000 * 1000;

StatsCollector::StatsCollector()  { for (int i=0;i<4;i++) { mod_send_[i]=0; mod_recv_[i]=0; } }
StatsCollector::~StatsCollector() = default;

// ── key 构造 ──────────────────────────────────────────────────────────

uint64_t StatsCollector::make_key(uint16_t svc, uint16_t method, uint16_t client, uint16_t session) {
    return ((uint64_t)svc<<48)|((uint64_t)method<<32)|((uint64_t)client<<16)|session;
}

void StatsCollector::update_counter(const char* hook, bool ret, int64_t retval) {
    auto& s = hook_stats_[hook];
    s.total++;
    if (ret) { if (retval==0) s.succ++; else s.fail++; }
}

// ═══════════════════════════════════════════════════════════════════════
// process_routing — ★ 唯一能做时延匹配的类型（有 SOME/IP header）
// ═══════════════════════════════════════════════════════════════════════

void StatsCollector::process_routing(const routing_event& e, const char* hook) {
    auto& h = e.hdr;
    bool ret = h.is_retprobe;

    // 计数器
    update_counter(hook, ret, e.retval);
    if (h.direction == DIR_SEND && !ret) mod_send_[h.module_id]++;
    if (h.direction == DIR_RECV && !ret) mod_recv_[h.module_id]++;

    // 按 message_type 分类
    if (!ret && e.message_type) {
        int idx = (e.message_type==SOMEIP_MT_REQUEST)?0:(e.message_type==SOMEIP_MT_REQUEST_NO_RETURN)?1:
            (e.message_type==SOMEIP_MT_NOTIFICATION)?2:(e.message_type==SOMEIP_MT_REQUEST_ACK)?3:
            (e.message_type==SOMEIP_MT_RESPONSE)?4:5;
        hook_stats_[hook].by_type[idx]++;
    }

    // ★ 时延匹配 ★
    if (!ret) {
        if (h.direction == DIR_SEND && (e.message_type == SOMEIP_MT_REQUEST || e.message_type == SOMEIP_MT_REQUEST_NO_RETURN))
            record_pending(e);
        if (h.direction == DIR_RECV && (e.message_type == SOMEIP_MT_RESPONSE || e.message_type == SOMEIP_MT_ERROR || e.message_type == SOMEIP_MT_NOTIFICATION))
            try_match(e);
    }
}

void StatsCollector::record_pending(const routing_event& e) {
    uint64_t k = make_key(e.service_id, e.method_id, e.client_id, e.session_id);
    if (pending_.find(k) == pending_.end())
        pending_[k] = {e.hdr.timestamp_ns};
}

void StatsCollector::try_match(const routing_event& e) {
    uint64_t k = make_key(e.service_id, e.method_id, e.client_id, e.session_id);
    auto it = pending_.find(k);
    if (it == pending_.end()) return;
    uint64_t lat = e.hdr.timestamp_ns - it->second.send_ts;
    if (lat > 60ULL*1000*1000*1000) { pending_.erase(it); return; }
    latency_samples_.push_back(lat);
    if (log_writer_) {
        char b[256];
        snprintf(b, sizeof(b), "{\"svc\":%u,\"method\":%u,\"client\":%u,\"session\":%u,\"type\":\"%s\","
                 "\"send_ts\":%" PRIu64 ",\"recv_ts\":%" PRIu64 ",\"latency_us\":%.1f}",
                 e.service_id, e.method_id, e.client_id, e.session_id,
                 e.message_type==SOMEIP_MT_RESPONSE?"RESPONSE":e.message_type==SOMEIP_MT_ERROR?"ERROR":"NOTIFICATION",
                 it->second.send_ts, e.hdr.timestamp_ns, (double)lat/1000.0);
        log_writer_->write_latency(b);
    }
    pending_.erase(it);
}

// ═══════════════════════════════════════════════════════════════════════
// process_app / process_sd — 只做计数，不做时延匹配（没有 header 信息）
// ═══════════════════════════════════════════════════════════════════════

void StatsCollector::process_app(const app_event& e, const char* hook) {
    update_counter(hook, e.hdr.is_retprobe, e.retval);
    if (e.hdr.direction == DIR_SEND && !e.hdr.is_retprobe) mod_send_[e.hdr.module_id]++;
    if (e.hdr.direction == DIR_RECV && !e.hdr.is_retprobe) mod_recv_[e.hdr.module_id]++;
}

void StatsCollector::process_sd(const sd_event& e, const char* hook) {
    update_counter(hook, false, 0);
    if (e.hdr.direction == DIR_SEND) mod_send_[e.hdr.module_id]++;
    else mod_recv_[e.hdr.module_id]++;
}

// ═══════════════════════════════════════════════════════════════════════
// flush_report / evict_expired
// ═══════════════════════════════════════════════════════════════════════

void StatsCollector::flush_report() {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now = (uint64_t)ts.tv_sec*1000000000ULL + ts.tv_nsec;
    double elapse = last_report_ns_ ? (now-last_report_ns_)/1e9 : 0;
    last_report_ns_ = now;
    if (!log_writer_) return;

    for (int m=1;m<=3;m++) {
        if (!mod_send_[m] && !mod_recv_[m]) continue;
        const char* nm = m==1?"routing":m==2?"app":"sd";
        char b[256];
        snprintf(b,sizeof(b),"{\"module\":\"%s\",\"elapsed\":%.1f,\"send\":%" PRIu64 ",\"recv\":%" PRIu64 "}",
                 nm, elapse, mod_send_[m], mod_recv_[m]);
        log_writer_->write_stats(b);
        mod_send_[m]=mod_recv_[m]=0;
    }
    if (!latency_samples_.empty()) {
        std::sort(latency_samples_.begin(), latency_samples_.end());
        size_t n=latency_samples_.size();
        uint64_t sum=0; for(auto v:latency_samples_) sum+=v;
        char b[256];
        snprintf(b,sizeof(b),"{\"type\":\"latency\",\"samples\":%zu,\"avg_us\":%" PRIu64 ",\"p50_us\":%" PRIu64 ",\"p99_us\":%" PRIu64 ",\"max_us\":%" PRIu64 "}",
                 n,(sum/n)/1000,latency_samples_[n*50/100]/1000,latency_samples_[n*99/100]/1000,latency_samples_[n-1]/1000);
        log_writer_->write_stats(b);
        latency_samples_.clear();
    }
    for(auto& p:hook_stats_) { p.second={}; /* reset */ }
}

void StatsCollector::evict_expired() {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now = (uint64_t)ts.tv_sec*1000000000ULL + ts.tv_nsec;
    auto it = pending_.begin();
    while (it != pending_.end()) {
        if (now - it->second.send_ts > TIMEOUT_NS) {
            if (log_writer_) {
                char b[128];
                snprintf(b,sizeof(b),"{\"type\":\"timeout\",\"key\":\"0x%" PRIx64 "\",\"elapsed_ms\":%" PRIu64 "}",
                         it->first, (now - it->second.send_ts)/1000000);
                log_writer_->write_stats(b);
            }
            it = pending_.erase(it);
        } else ++it;
    }
}
