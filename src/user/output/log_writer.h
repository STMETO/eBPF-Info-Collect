// log_writer.h — 日志输出的抽象接口
//
// 支持多种输出目标：终端 (stdout)、文件、Android logcat。
// CollectorManager 持有一个 ILogWriter 指针，所有 collector
// 通过同一个 writer 输出事件，保证日志顺序一致。
//
// 扩展方式：
//   如果需要同时输出到终端和文件，可以实现一个 MultiWriter，
//   内部持有多个 ILogWriter，把 write() 广播到所有子 writer。

#pragma once

#include <string>
#include <cstdint>

struct vsomeip_event;       // 前向声明，定义在 common/vsomeip_event.h

class ILogWriter {
public:
    virtual ~ILogWriter() = default;

    /**
     * 写入一条事件
     *
     * @param event      BPF 发来的事件数据
     * @param hook_name  hook 名称（如 "rm_send_entry"），由 collector 提供
     */
    virtual void write(const vsomeip_event& event, const char* hook_name) = 0;

    /**
     * 写入一条统计摘要
     *
     * @param json_line  JSON 格式的统计行（stats_collector 生成）
     */
    virtual void write_stats(const char* json_line) = 0;

    /**
     * 写入一条延迟事件
     *
     * @param json_line  JSON 格式的延迟行
     */
    virtual void write_latency(const char* json_line) = 0;

    /**
     * 刷新缓冲区（文件 writer 需要，stdout writer 可空实现）
     */
    virtual void flush() = 0;

    /**
     * 获取 writer 名称（如 "stdout", "file:/tmp/vsomeip.log"）
     */
    virtual const char* name() const = 0;
};
