// stats_collector.cpp — 统计收集 + 时延匹配
//
// 职责分两层：
//
// 第一层 —— 通用统计（所有模块都需要）：
//   以 event_header 为输入，累加每个 hook 的调用次数、成功次数、失败次数，
//   以及每个模块的收发消息量。这部分代码永远不变，新增模块自动覆盖。
//
// 第二层 —— 时延匹配（只有 routing 模块需要，通过 on_latency 回调触发）：
//   REQUEST 发送时记录 (svc, method, client, session) → 时间戳 到 pending 表。
//   RESPONSE 接收时在 pending 表中查找匹配的 REQUEST，计算时延。
//   超过 30 秒未匹配的条目视为超时，输出 [TIMEOUT] 事件。
//
// 时延匹配的 key 为什么是这 4 个字段？
//   SOME/IP 协议规定同一个会话的 REQUEST 和 RESPONSE 共享相同的
//   Service ID、Method ID、Client ID、Session ID。
//   这 4 个 uint16_t 拼成一个 uint64_t，作为哈希表的 key。

#include "stats_collector.h"
#include "../common/event_header.h"
#include "../common/vsomeip_types.h"
#include "../output/log_writer.h"
#include <cstdio>
#include <cinttypes>
#include <algorithm>

// ── 超时阈值：30 秒（纳秒） ──────────────────────────────────────────
// pending 表中超过这个时间的条目会被 evict_expired() 清理，
// 意味着 REQUEST 发出后 30 秒内没有收到对应的 RESPONSE
static const uint64_t TIMEOUT_NS = 30ULL * 1000 * 1000 * 1000;

// ═══════════════════════════════════════════════════════════════════════
// 构造 / 析构
// ═══════════════════════════════════════════════════════════════════════
StatsCollector::StatsCollector()
{
    // 数组大小 = MAX_MODULE_ID + 1（见 gen/hook_config.h）
    // MAX_MODULE_ID 由 gen_hook_config.sh 根据 hooks.json 自动计算，
    // 新增模块后自动扩容
    for (int i = 0; i <= MAX_MODULE_ID; i++)
        mod_send_[i] = mod_recv_[i] = 0;
}

StatsCollector::~StatsCollector() = default;

// ═══════════════════════════════════════════════════════════════════════
// process_event — 通用事件入口
//
// 所有模块的 handler 都调用这个函数处理事件。
// 它只操作 event_header 中存在的通用字段，不需要知道具体是哪个模块的事件。
//
// 参数：
//   hdr         公共头（ts / pid / tid / comm / module_id / hook_id / dir）
//   payload     模块特定数据（routing_event* / app_event* / sd_event* 等）
//               本函数不碰这个指针，只透传给 on_latency 回调
//   hook        人类可读的 hook 名称（如 "rm_send_entry"），用作统计 key
//   retval      uretprobe 的返回值（入口 hook 传 0）
//   on_latency  时延匹配回调函数指针
//               routing handler 传入 on_latency 函数
//               app/sd handler 传入 nullptr（不需要时延匹配）
// ═══════════════════════════════════════════════════════════════════════
void StatsCollector::process_event(const event_header* hdr, const void* payload,
                                    const char* hook, int64_t retval,
                                    stats_callback_t on_latency)
{
    bool is_ret = hdr->is_retprobe;   // true = 这是函数返回点（uretprobe）

    // ── 第一层：计数器（所有模块通用） ───────────────────────────────
    //
    // 以 hook 名为 key，统计 total / succ / fail。
    // 例如 hook_stats_["rm_send_entry"] = {total:5000, succ:4950, fail:50}
    //
    // 注意：入口 probe（is_ret=false）时 retval 为 0，
    // total 累加但 succ/fail 不算——只有 uretprobe 才知道成功还是失败。
    auto& s = hook_stats_[hook];
    s.total++;
    if (is_ret) {
        if (retval == 0)
            s.succ++;
        else
            s.fail++;
    }

    // ── 第一层：收发量（所有模块通用） ───────────────────────────────
    //
    // 按 module_id 统计每个模块的发送/接收次数。
    // 只统计入口 probe（uretprobe 不算，避免重复计数）。
    // 例如 mod_send_[MODULE_ROUTING] = 5000
    if (!is_ret) {
        if (hdr->direction == DIR_SEND)
            mod_send_[hdr->module_id]++;
        else
            mod_recv_[hdr->module_id]++;
    }

    // ── 第二层：时延匹配（只有 routing 模块需要） ──────────────────
    //
    // routing handler 在调用 process_event 时会传入 on_latency 函数指针。
    // on_latency 内部做两件事：
    //   如果方向是 SEND 且 message_type 是 REQUEST  →  record_pending
    //   如果方向是 RECV 且 message_type 是 RESPONSE →  try_match
    //
    // app 和 sd 模块传 nullptr，跳过这步。
    if (on_latency)
        on_latency(payload, hook, this);
}

// ═══════════════════════════════════════════════════════════════════════
// record_pending — 把发出的 REQUEST 记入待匹配表
//
// 当 routing 模块的 handler 检测到 SEND 方向的 REQUEST 消息时，
// 调用这个函数记录时间戳。
//
// key = (service_id << 48) | (method_id << 32) | (client_id << 16) | session_id
// 这 4 个字段拼成一个 64 位整数，作为哈希表的 key。
// 同一个 REQUEST 和它对应的 RESPONSE 共享相同的 4 个字段值。
//
// 如果 key 已存在（上层重发了同一个 request），保留最早的时间戳，
// 不做覆盖——保守的时延估计。
// ═══════════════════════════════════════════════════════════════════════
void StatsCollector::record_pending(uint16_t svc, uint16_t method,
                                     uint16_t client, uint16_t session,
                                     uint64_t ts)
{
    uint64_t k = ((uint64_t)svc     << 48) |
                 ((uint64_t)method  << 32) |
                 ((uint64_t)client  << 16) |
                  (uint64_t)session;

    // 如果 key 已存在，保留最早的（不做覆盖）
    if (pending_.find(k) == pending_.end())
        pending_[k] = {ts};
}

// ═══════════════════════════════════════════════════════════════════════
// try_match — 收到 RESPONSE 时，在 pending 表中找匹配的 REQUEST
//
// 当 routing 模块的 handler 检测到 RECV 方向的 RESPONSE/ERROR/NOTIFICATION 时，
// 调用这个函数：
//   1. 构造同样的 64 位 key
//   2. 在 pending 表中查找对应的 REQUEST 发送时间戳
//   3. 如果找到：
//      a) 计算时延 = 接收时间 - 发送时间
//      b) 合理性检查：时延 > 60 秒视为异常，丢弃
//      c) 保存时延样本（用于统计摘要的 p50/p99/max）
//      d) 输出 [LATENCY] 事件
//      e) 从 pending 表中删除（已匹配）
//   4. 如果找不到：说明 REQUEST 是在启动监控之前发出的，正常跳过
// ═══════════════════════════════════════════════════════════════════════
void StatsCollector::try_match(uint16_t svc, uint16_t method,
                                uint16_t client, uint16_t session,
                                uint64_t recv_ts, uint8_t msg_type)
{
    uint64_t k = ((uint64_t)svc     << 48) |
                 ((uint64_t)method  << 32) |
                 ((uint64_t)client  << 16) |
                  (uint64_t)session;

    auto it = pending_.find(k);
    if (it == pending_.end())
        return;   // 没有匹配的 REQUEST（启动前发出的，正常）

    // 计算时延
    uint64_t lat = recv_ts - it->second.send_ts;

    // 合理性检查：时延 > 60 秒视为异常（可能是时钟跳变或重复 session_id）
    if (lat > 60ULL * 1000 * 1000 * 1000) {
        pending_.erase(it);
        return;
    }

    // 收集时延样本（纳秒），定期输出时用于计算 p50/p99/max/avg
    latency_.push_back(lat);

    // 输出 [LATENCY] 事件
    if (log_writer_) {
        const char* type_str =
            msg_type == SOMEIP_MT_RESPONSE   ? "RESPONSE" :
            msg_type == SOMEIP_MT_ERROR      ? "ERROR"    :
            msg_type == SOMEIP_MT_NOTIFICATION ? "NOTIFICATION" : "UNKNOWN";

        char b[256];
        snprintf(b, sizeof(b),
            "{\"svc\":%u,\"method\":%u,\"client\":%u,\"session\":%u,"
            "\"type\":\"%s\",\"send_ts\":%" PRIu64 ",\"recv_ts\":%" PRIu64
            ",\"latency_us\":%.1f}",
            svc, method, client, session,
            type_str,
            it->second.send_ts, recv_ts,
            (double)lat / 1000.0);    // 纳秒 → 微秒
        log_writer_->write_latency(b);
    }

    // 已匹配，从 pending 表删除
    pending_.erase(it);
}

// ═══════════════════════════════════════════════════════════════════════
// flush_report — 定期输出统计摘要
//
// 由 CollectorManager 在事件循环中周期性调用（默认每 10 秒）。
// 输出三类信息：
//   1. 每个模块的收发量
//   2. 时延统计（p50 / p99 / max / avg），只包含本周期匹配到的样本
//   3. 每个 hook 的调用计数（total / succ / fail）
//
// 输出后所有计数器归零，进入下一个统计周期。
// ═══════════════════════════════════════════════════════════════════════
void StatsCollector::flush_report()
{
    // 获取当前时间（CLOCK_MONOTONIC = 不受系统时间调整影响）
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

    // 计算距离上次报告的时间间隔（秒）
    double elapse = last_report_ns_ ? (now - last_report_ns_) / 1e9 : 0.0;
    last_report_ns_ = now;

    if (!log_writer_)
        return;

    // ── 1. 每个模块的收发量 ─────────────────────────────────────────
    for (int m = 1; m <= MAX_MODULE_ID; m++) {
        if (!mod_send_[m] && !mod_recv_[m])
            continue;   // 本周期没有活动，跳过这个模块

        // 从 file_groups 表中查模块名称
        const char* nm = "?";
        for (int f = 0; f < NUM_FILE_GROUPS; f++)
            if (file_groups[f].module_id == m) {
                nm = file_groups[f].name;
                break;
            }

        char b[256];
        snprintf(b, sizeof(b),
            "{\"module\":\"%s\",\"elapsed\":%.1f,"
            "\"send\":%" PRIu64 ",\"recv\":%" PRIu64 "}",
            nm, elapse, mod_send_[m], mod_recv_[m]);
        log_writer_->write_stats(b);

        // 重置本模块的计数器
        mod_send_[m] = mod_recv_[m] = 0;
    }

    // ── 2. 时延统计 ─────────────────────────────────────────────────
    if (!latency_.empty()) {
        // 排序后计算百分位
        std::sort(latency_.begin(), latency_.end());

        size_t n = latency_.size();
        uint64_t sum = 0;
        for (auto v : latency_) sum += v;

        // 纳秒 → 微秒
        uint64_t avg_us = (sum / n) / 1000;
        uint64_t p50_us = latency_[n * 50 / 100] / 1000;
        uint64_t p99_us = latency_[n * 99 / 100] / 1000;
        uint64_t max_us = latency_[n - 1] / 1000;

        char b[256];
        snprintf(b, sizeof(b),
            "{\"type\":\"latency\",\"samples\":%zu,"
            "\"avg_us\":%" PRIu64 ",\"p50_us\":%" PRIu64 ","
            "\"p99_us\":%" PRIu64 ",\"max_us\":%" PRIu64 "}",
            n, avg_us, p50_us, p99_us, max_us);
        log_writer_->write_stats(b);

        latency_.clear();
    }

    // ── 3. 重置 hook 计数器 ─────────────────────────────────────────
    for (auto& p : hook_stats_)
        p.second = {};    // 归零
}

// ═══════════════════════════════════════════════════════════════════════
// evict_expired — 清理 pending 表中超时的条目
//
// pending 表会随着时间增长——每一个发送的 REQUEST 都会新增一条记录。
// 正常情况下对应的 RESPONSE 到达后会删除。
// 但有些 REQUEST 永远不会收到 RESPONSE（丢包、超时、服务端崩溃），
// 这些"孤儿"条目如果不清理，内存会无限增长。
//
// 这个函数遍历 pending 表，删除超过 30 秒仍未匹配的条目，
// 并为每个超时条目输出一条 [STATS] 日志。
// ═══════════════════════════════════════════════════════════════════════
void StatsCollector::evict_expired()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

    auto it = pending_.begin();
    while (it != pending_.end()) {
        uint64_t elapsed = now - it->second.send_ts;

        if (elapsed > TIMEOUT_NS) {
            // 输出超时事件
            if (log_writer_) {
                char b[128];
                snprintf(b, sizeof(b),
                    "{\"type\":\"timeout\",\"key\":\"0x%" PRIx64 "\","
                    "\"elapsed_ms\":%" PRIu64 "}",
                    it->first, elapsed / 1000000);    // 纳秒 → 毫秒
                log_writer_->write_stats(b);
            }
            it = pending_.erase(it);    // 删除并前进迭代器
        } else {
            ++it;   // 没超时，继续检查下一个
        }
    }
}
