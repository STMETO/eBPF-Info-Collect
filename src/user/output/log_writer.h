// log_writer.h — 日志输出的抽象接口
//
// 每种事件类型有对应的 write_* 方法，由 collector 的 ringbuf 回调按模块 ID 分发。

#pragma once

#include <cstdint>

// 前向声明具体事件类型
struct routing_event;
struct app_event;
struct sd_event;

class ILogWriter {
public:
    virtual ~ILogWriter() = default;

    // ── 按类型写入事件 ────────────────────────────────────────────────
    virtual void write_routing(const routing_event& e, const char* hook) = 0;
    virtual void write_app(const app_event& e, const char* hook) = 0;
    virtual void write_sd(const sd_event& e, const char* hook) = 0;

    // ── 统计和时延 ────────────────────────────────────────────────────
    virtual void write_stats(const char* json_line) = 0;
    virtual void write_latency(const char* json_line) = 0;

    virtual void flush() = 0;
    virtual const char* name() const = 0;
};
