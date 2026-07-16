// stdout_writer.h — 终端输出

#pragma once

#include "log_writer.h"
#include <cstdio>

class StdoutWriter : public ILogWriter {
public:
    explicit StdoutWriter(bool use_json = false);
    void write_event(const event_header* hdr, const void* payload,
                     const char* hook,
                     void (*on_payload)(const void*, const char*, char*, size_t)) override;
    void write_stats(const char* line) override;
    void write_latency(const char* line) override;
    void flush() override;
    const char* name() const override { return "stdout"; }

private:
    bool use_json_;
};
