// file_writer.h — 文件日志输出

#pragma once

#include "log_writer.h"
#include "../../common/event_header.h"
#include "../../common/routing_event.h"
#include "../../common/app_event.h"
#include "../../common/sd_event.h"
#include <cstdio>
#include <string>

class FileWriter : public ILogWriter {
public:
    FileWriter(const char* path, bool json = true);
    ~FileWriter() override;
    void write_routing(const routing_event& e, const char* hook) override;
    void write_app(const app_event& e, const char* hook) override;
    void write_sd(const sd_event& e, const char* hook) override;
    void write_stats(const char* line) override;
    void write_latency(const char* line) override;
    void flush() override;
    const char* name() const override { return path_.c_str(); }

private:
    bool ensure_open();
    void write_common_json(const event_header& h, const char* hook, FILE* f);

    std::string path_;
    FILE* file_ = nullptr;
    bool use_json_;
};
