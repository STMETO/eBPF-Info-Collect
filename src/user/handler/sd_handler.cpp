// sd_handler.cpp — sd 模块的事件处理函数

#include "../../common/sd_event.h"
#include "../stats_collector.h"
#include "../output/log_writer.h"

extern "C"
void sd_event_handler(const void *data, const char *hook,
                      StatsCollector *stats, ILogWriter *writer)
{
    auto *e = static_cast<const sd_event*>(data);
    stats->process_sd(*e, hook);
    writer->write_sd(*e, hook);
}
