// app_handler.cpp — app 模块的事件处理

#include "../../common/app_event.h"
#include "../stats/stats_collector.h"
#include "../output/log_writer.h"
#include <cstdio>
#include <cinttypes>

static void format_payload(const void* data, const char* /*hook*/,
                           char* buf, size_t size)
{
    auto* e = static_cast<const app_event*>(data);
    snprintf(buf, size,
             "\"this\":\"0x%" PRIx64 "\",\"msg\":\"0x%" PRIx64 "\",\"retval\":%" PRId64,
             e->this_ptr, e->message_ptr, e->retval);
}

extern "C"
void app_event_handler(const void *data, const char *hook,
                       StatsCollector *stats, ILogWriter *writer)
{
    auto *e = static_cast<const app_event*>(data);
    stats->process_event(&e->hdr, data, hook, e->retval, nullptr);  // app 不做时延匹配
    writer->write_event(&e->hdr, data, hook, format_payload);
}
