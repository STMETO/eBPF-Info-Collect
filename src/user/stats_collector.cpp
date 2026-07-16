// stats_collector.cpp — 统计实现

#include "stats_collector.h"
#include "../common/event_header.h"
#include "../common/vsomeip_types.h"
#include "output/log_writer.h"
#include <cstdio>
#include <cinttypes>
#include <algorithm>

static const uint64_t TIMEOUT_NS = 30ULL*1000*1000*1000;

StatsCollector::StatsCollector()  { 
    for(int i=0;i<4;i++){
        mod_send_[i]=mod_recv_[i]=0;
    } 
}

StatsCollector::~StatsCollector() = default;

// ═══════════════════════════════════════════════════════════════════════
// process_event — 通用入口
// ═══════════════════════════════════════════════════════════════════════
void StatsCollector::process_event(const event_header* hdr, const void* payload,
                                    const char* hook, int64_t retval,
                                    on_latency_fn on_latency)
{
    bool is_ret = hdr->is_retprobe;

    // ── 计数器（所有模块通用）─────────────────────────────────────────
    auto& s = hook_stats_[hook];
    s.total++;
    if (is_ret) { 
        if (retval==0) 
            s.succ++; 
        else 
            s.fail++; 
    }

    // ── 收发量（所有模块通用）─────────────────────────────────────────
    if (!is_ret) {
        if (hdr->direction == DIR_SEND) 
            mod_send_[hdr->module_id]++;
        else 
            mod_recv_[hdr->module_id]++;
    }

    // ── 类型特定逻辑（只有 routing 需要时延匹配）───────────────────────
    if (on_latency)
        on_latency(payload, hook, this);
}

// ── 时延匹配（public，被 routing handler 的回调调用）─────────────────
void StatsCollector::record_pending(uint16_t svc, uint16_t method,
                                     uint16_t client, uint16_t session, uint64_t ts)
{
    uint64_t k = ((uint64_t)svc<<48)|((uint64_t)method<<32)|((uint64_t)client<<16)|session;
    if (pending_.find(k) == pending_.end())
        pending_[k] = {ts};
}

void StatsCollector::try_match(uint16_t svc, uint16_t method,
                                uint16_t client, uint16_t session,
                                uint64_t recv_ts, uint8_t msg_type)
{
    uint64_t k = ((uint64_t)svc<<48)|((uint64_t)method<<32)|((uint64_t)client<<16)|session;
    auto it = pending_.find(k);
    if (it == pending_.end()) 
        return;

    uint64_t lat = recv_ts - it->second.send_ts;
    if (lat > 60ULL*1000*1000*1000) { 
        pending_.erase(it); 
        return; 
    }

    latency_.push_back(lat);
    if (log_writer_) {
        char b[256];
        snprintf(b,sizeof(b),
            "{\"svc\":%u,\"method\":%u,\"client\":%u,\"session\":%u,"
            "\"type\":\"%s\",\"send_ts\":%" PRIu64 ",\"recv_ts\":%" PRIu64
            ",\"latency_us\":%.1f}",
            svc,method,client,session,
            msg_type==SOMEIP_MT_RESPONSE?"RESPONSE":msg_type==SOMEIP_MT_ERROR?"ERROR":"NOTIFICATION",
            it->second.send_ts,recv_ts,(double)lat/1000.0);
        log_writer_->write_latency(b);
    }
    pending_.erase(it);
}

// ── 定期输出 ──────────────────────────────────────────────────────────

void StatsCollector::flush_report()
{
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now=(uint64_t)ts.tv_sec*1000000000ULL+ts.tv_nsec;
    double elapse=last_report_ns_?(now-last_report_ns_)/1e9:0;
    last_report_ns_=now;

    if(!log_writer_)
        return;

    for(int m=1;m<=3;m++){
        if(!mod_send_[m]&&!mod_recv_[m])
            continue;
        
        const char* nm=m==1?"routing":m==2?"app":"sd";
        char b[256];snprintf(b,sizeof(b),"{\"module\":\"%s\",\"elapsed\":%.1f,\"send\":%" PRIu64 ",\"recv\":%" PRIu64 "}",nm,elapse,mod_send_[m],mod_recv_[m]);
        log_writer_->write_stats(b);mod_send_[m]=mod_recv_[m]=0;
    }
    if(!latency_.empty()){
        std::sort(latency_.begin(),latency_.end());
        size_t n=latency_.size();uint64_t sum=0;for(auto v:latency_)sum+=v;
        char b[256];snprintf(b,sizeof(b),"{\"type\":\"latency\",\"samples\":%zu,\"avg_us\":%" PRIu64 ",\"p50_us\":%" PRIu64 ",\"p99_us\":%" PRIu64 ",\"max_us\":%" PRIu64 "}",n,(sum/n)/1000,latency_[n*50/100]/1000,latency_[n*99/100]/1000,latency_[n-1]/1000);
        log_writer_->write_stats(b);latency_.clear();
    }
    for(auto& p:hook_stats_)p.second={};
}

void StatsCollector::evict_expired()
{
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now=(uint64_t)ts.tv_sec*1000000000ULL+ts.tv_nsec;
    auto it=pending_.begin();
    while(it!=pending_.end()){
        if(now-it->second.send_ts>TIMEOUT_NS){
            if(log_writer_){char b[128];snprintf(b,sizeof(b),"{\"type\":\"timeout\",\"key\":\"0x%" PRIx64 "\",\"elapsed_ms\":%" PRIu64 "}",it->first,(now-it->second.send_ts)/1000000);log_writer_->write_stats(b);}
            it=pending_.erase(it);
        }else ++it;
    }
}
