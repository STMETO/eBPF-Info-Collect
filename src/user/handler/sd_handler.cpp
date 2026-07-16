// sd_handler.cpp — sd 模块的事件处理

#include "../../common/sd_event.h"
#include "../stats/stats_collector.h"
#include "../output/log_writer.h"
#include <cstdio>
#include <cinttypes>

static void format_payload(const void* data, const char* /*hook*/,
                           char* buf, size_t size)
{
    auto* e = static_cast<const sd_event*>(data);
    snprintf(buf, size,
             "\"svc\":%u,\"inst\":%u,\"evg\":%u,\"ttl\":%u",
             e->service_id, e->instance_id, e->eventgroup_id, e->ttl);
}

extern "C"
void sd_event_handler(const void *data, const char *hook,
                      StatsCollector *stats, ILogWriter *writer)
{
    auto *e = static_cast<const sd_event*>(data);
    stats->process_event(&e->hdr, data, hook, 0, nullptr);  // sd 不做时延匹配
    writer->write_event(&e->hdr, data, hook, format_payload);
}
