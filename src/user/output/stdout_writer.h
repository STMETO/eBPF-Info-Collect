// stdout_writer.h — 终端输出日志

#pragma once

#include "log_writer.h"
#include "../../common/event_header.h"
#include "../../common/routing_event.h"
#include "../../common/app_event.h"
#include "../../common/sd_event.h"
#include <cstdio>

class StdoutWriter : public ILogWriter {
public:
    explicit StdoutWriter(bool use_json = false);
    void write_routing(const routing_event& e, const char* hook) override;
    void write_app(const app_event& e, const char* hook) override;
    void write_sd(const sd_event& e, const char* hook) override;
    void write_stats(const char* line) override;
    void write_latency(const char* line) override;
    void flush() override;
    const char* name() const override { return "stdout"; }

private:
    void write_common(const event_header& h, const char* hook, bool json);
    bool use_json_;
};

const char* message_type_str(uint8_t mt);
const char* module_name_str(uint8_t module_id);
