// log_writer.h — 日志输出接口（★ 解耦后只有通用方法，不含任何模块特定签名）

#pragma once

#include <cstddef>
#include <cstdint>

struct event_header;

class ILogWriter {
public:
    virtual ~ILogWriter() = default;

    /**
     * ★ 通用事件写入 ★
     *
     * 先写 event_header 的公共字段（ts/pid/tid/comm/module/hook/dir），
     * 然后调用 on_payload 回调写模块特定的 payload 字段，
     * 最后输出结尾（换行或 }）。
     *
     * @param hdr          公共头
     * @param payload      模块特定的 payload 数据（routing_event / app_event / sd_event 等）
     * @param hook         人类可读 hook 名
     * @param on_payload   模块提供的 payload 格式化回调（nullptr = 跳过 payload）
     * @param is_retprobe  是否为返回探测
     */
    virtual void write_event(const event_header* hdr, const void* payload,
                             const char* hook,
                             void (*on_payload)(const void* payload, const char* hook,
                                                char* buf, size_t size)) = 0;

    virtual void write_stats(const char* line) = 0;
    virtual void write_latency(const char* line) = 0;
    virtual void flush() = 0;
    virtual const char* name() const = 0;
};
