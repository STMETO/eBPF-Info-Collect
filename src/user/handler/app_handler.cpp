// app_handler.cpp — app 模块的事件处理函数

#include "../../common/app_event.h"
#include "../stats_collector.h"
#include "../output/log_writer.h"

extern "C"
void app_event_handler(const void *data, const char *hook,
                       StatsCollector *stats, ILogWriter *writer)
{
    auto *e = static_cast<const app_event*>(data);
    stats->process_app(*e, hook);
    writer->write_app(*e, hook);
}
