// stdout_writer.h — 终端输出日志
//
// 把事件以人类可读格式打印到终端（stdout）。
// 支持两种模式：
//   普通模式（默认）：    带缩进和颜色标记的人类可读格式
//   JSON 模式（--json）： 每行一个 JSON 对象，方便管道给 jq / 日志系统

#pragma once

#include "log_writer.h"
#include <cstdio>

class StdoutWriter : public ILogWriter {
public:
    /**
     * @param use_json  true = JSON 格式输出，false = 人类可读格式
     */
    explicit StdoutWriter(bool use_json = false);

    void write(const vsomeip_event& event, const char* hook_name) override;
    void write_stats(const char* json_line) override;
    void write_latency(const char* json_line) override;
    void flush() override;
    const char* name() const override { return "stdout"; }

private:
    /**
     * 人类可读格式输出：把事件字段排版成易读的行
     *
     * 输出示例：
     *   [ROUTING] 12:34:56.789012  PID:1234 TID:5678  someipd
     *     hook: rm_send_entry  dir: SEND
     *     svc=0x1234 method=0x0001 client=0x5678 session=0x9ABC
     *     type=REQUEST(0x00) retcode=0x00 payload_len=64
     */
    void write_human(const vsomeip_event& event, const char* hook_name);

    /**
     * JSON 格式输出：一行一个 JSON 对象
     *
     * 输出示例：
     *   {"ts":1234567890123,"pid":1234,"tid":5678,"comm":"someipd",
     *    "module":"routing","hook":"rm_send_entry","dir":"SEND",
     *    "svc":4660,"method":1,"client":22136,"session":39612,
     *    "type":"REQUEST","rc":0,"payload_len":64}
     */
    void write_json(const vsomeip_event& event, const char* hook_name);

    bool use_json_;
};

/**
 * 辅助函数：把 message_type 数字转成人类可读字符串
 *
 * SOME/IP 协议规定的消息类型：
 *   0x00 = REQUEST        请求（期望响应）
 *   0x01 = REQUEST_NORET  请求（不期望响应）
 *   0x02 = NOTIFICATION   通知/事件
 *   0x40 = REQUEST_ACK    传输确认
 *   0x80 = RESPONSE       响应
 *   0x81 = ERROR          错误响应
 */
const char* message_type_str(uint8_t mt);

/**
 * 辅助函数：把模块 ID 转成字符串
 */
const char* module_name_str(uint8_t module_id);
