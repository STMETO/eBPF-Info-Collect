// routing_handler.cpp — routing 模块的事件处理
//
// 两个回调：
//   1. format_payload  — writer 回调：格式化 routing 特有的 SOME/IP header 字段
//   2. on_latency      — stats 回调：时延匹配（record_pending / try_match）

#include "../../common/routing_event.h"
#include "../../common/vsomeip_types.h"
#include "../stats_collector.h"
#include "../output/log_writer.h"
#include <cstdio>
#include <cinttypes>

// ── payload 格式化回调 ────────────────────────────────────────────────

static void format_payload(const void* data, const char* /*hook*/,
                           char* buf, size_t size)
{
    auto* e = static_cast<const routing_event*>(data);
    snprintf(buf, size,
             "\"svc\":%u,\"method\":%u,\"client\":%u,\"session\":%u,"
             "\"msg_type\":\"%s\",\"ret_code\":%u,\"len\":%u,\"retval\":%" PRId64,
             e->service_id, e->method_id, e->client_id, e->session_id,
             e->message_type == SOMEIP_MT_REQUEST ? "REQUEST" :
             e->message_type == SOMEIP_MT_REQUEST_NO_RETURN ? "REQ_NORET" :
             e->message_type == SOMEIP_MT_NOTIFICATION ? "NOTIFICATION" :
             e->message_type == SOMEIP_MT_REQUEST_ACK ? "REQ_ACK" :
             e->message_type == SOMEIP_MT_RESPONSE ? "RESPONSE" :
             e->message_type == SOMEIP_MT_ERROR ? "ERROR" : "UNKNOWN",
             e->return_code, e->payload_length,
             e->retval);
}

// ── 时延匹配回调 ──────────────────────────────────────────────────────

static void on_latency(const void* data, const char* /*hook*/, StatsCollector* self)
{
    auto* e = static_cast<const routing_event*>(data);
    if (e->hdr.is_retprobe) return;

    if (e->hdr.direction == DIR_SEND &&
        (e->message_type == SOMEIP_MT_REQUEST ||
         e->message_type == SOMEIP_MT_REQUEST_NO_RETURN)) {
        self->record_pending(e->service_id, e->method_id,
                             e->client_id, e->session_id,
                             e->hdr.timestamp_ns);
    }

    if (e->hdr.direction == DIR_RECV &&
        (e->message_type == SOMEIP_MT_RESPONSE ||
         e->message_type == SOMEIP_MT_ERROR ||
         e->message_type == SOMEIP_MT_NOTIFICATION)) {
        self->try_match(e->service_id, e->method_id,
                        e->client_id, e->session_id,
                        e->hdr.timestamp_ns, e->message_type);
    }
}

// ── ★ 被 collector.cpp 调用的统一入口 ★ ───────────────────────────────

extern "C"
void routing_event_handler(const void *data, const char *hook,
                           StatsCollector *stats, ILogWriter *writer)
{
    auto *e = static_cast<const routing_event*>(data);

    // 通用处理（计数器）
    stats->process_event(&e->hdr, data, hook, e->retval, on_latency);

    // 通用输出（公共头 + payload 回调）
    writer->write_event(&e->hdr, data, hook, format_payload);
}
