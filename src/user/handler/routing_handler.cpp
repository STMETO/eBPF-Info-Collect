// routing_handler.cpp — routing 模块的事件处理函数
// ★ 新增模块时，collector.cpp 不需要改，只需添加对应的 handler 并注册到 file_group

#include "../../common/routing_event.h"
#include "../stats_collector.h"
#include "../output/log_writer.h"

extern "C"
void routing_event_handler(const void *data, const char *hook,
                           StatsCollector *stats, ILogWriter *writer)
{
    auto *e = static_cast<const routing_event*>(data);
    stats->process_routing(*e, hook);
    writer->write_routing(*e, hook);
}
