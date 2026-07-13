// file_writer.h — 文件日志输出
//
// 把事件写入文件，支持自动轮转（按小时或按大小）。
// 用于目标机器上没有终端时（嵌入式场景/后台运行）。

#pragma once

#include "log_writer.h"
#include <cstdio>
#include <string>

class FileWriter : public ILogWriter {
public:
    /**
     * @param file_path  日志文件路径（如 /tmp/vsomeip.log）
     * @param use_json   JSON 格式 vs 人类可读
     */
    FileWriter(const char* file_path, bool use_json = true);
    ~FileWriter() override;

    void write(const vsomeip_event& event, const char* hook_name) override;
    void write_stats(const char* json_line) override;
    void write_latency(const char* json_line) override;
    void flush() override;
    const char* name() const override { return file_path_.c_str(); }

    /**
     * 重新打开文件（用于日志轮转后）
     */
    void reopen();

private:
    std::string file_path_;
    FILE*       file_ = nullptr;
    bool        use_json_;

    /**
     * 确保文件已打开
     */
    bool ensure_open();
};
