// file_writer.h — 文件日志输出

#pragma once

#include "log_writer.h"
#include <cstdio>
#include <string>

class FileWriter : public ILogWriter {
public:
    FileWriter(const char* path, bool json = true);
    ~FileWriter() override;
    void write_event(const event_header* hdr, const void* payload,
                     const char* hook,
                     format_callback_t format_payload) override;
    void write_stats(const char* line) override;
    void write_latency(const char* line) override;
    void flush() override;
    const char* name() const override { return path_.c_str(); }

private:
    bool ensure_open();
    std::string path_;
    FILE* file_ = nullptr;
    bool use_json_;
};
