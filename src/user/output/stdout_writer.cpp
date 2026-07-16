// stdout_writer.cpp — 终端输出实现

#include "stdout_writer.h"
#include "../../common/event_header.h"
#include "../../common/vsomeip_types.h"
#include "../../gen/hook_ids.h"
#include <cstdio>
#include <cinttypes>
#include <ctime>

StdoutWriter::StdoutWriter(bool json) : use_json_(json) {
    setvbuf(stdout, nullptr, _IONBF, 0);
}

// ── 通用 write_event ─────────────────────────────────────────────────
// 公共部分永远不变；payload 部分通过 format_payload 回调让模块自己格式化

void StdoutWriter::write_event(const event_header* hdr, const void* payload,
                                const char* hook,
                                format_callback_t format_payload)
{
    const char* tag = hdr->module_id == MODULE_ROUTING ? "\033[31m[R]\033[0m" :
                      hdr->module_id == MODULE_APP     ? "\033[32m[A]\033[0m" :
                      hdr->module_id == MODULE_SD      ? "\033[34m[S]\033[0m" : "?";
    const char* dir = hdr->direction == DIR_SEND ? "SEND" : "RECV";
    const char* ret = hdr->is_retprobe ? " [RET]" : "";

    if (use_json_) {
        fprintf(stdout, "{\"ts\":%" PRIu64 ",\"pid\":%u,\"tid\":%u,\"comm\":\"%s\","
                "\"module\":\"%s\",\"hook\":\"%s\",\"dir\":\"%s\",\"is_ret\":%s",
                hdr->timestamp_ns, hdr->pid, hdr->tid, hdr->comm,
                hdr->module_id == 1 ? "routing" : hdr->module_id == 2 ? "app" : hdr->module_id == 3 ? "sd" : "?",
                hook, dir, hdr->is_retprobe ? "true" : "false");

        // 模块特定字段（JSON）
        if (format_payload) {
            char buf[512] = {};
            format_payload(payload, hook, buf, sizeof(buf));
            if (buf[0]) fprintf(stdout, ",%s", buf);
        }
        fprintf(stdout, "}\n");
    } else {
        time_t sec = hdr->timestamp_ns / 1000000000ULL;
        long ns = hdr->timestamp_ns % 1000000000ULL;
        struct tm tm; localtime_r(&sec, &tm);
        char tb[32]; strftime(tb, sizeof(tb), "%H:%M:%S", &tm);
        fprintf(stdout, "%s %s.%06ld PID:%-6u TID:%-6u %-16s %-20s%s %s\n",
                tag, tb, ns/1000L, hdr->pid, hdr->tid, hdr->comm, hook, ret, dir);

        // 模块特定字段（人类可读）
        if (format_payload) {
            char buf[256] = {};
            format_payload(payload, hook, buf, sizeof(buf));
            if (buf[0]) fprintf(stdout, "  %s\n", buf);
        }
    }
}

void StdoutWriter::write_stats(const char* l)   { fprintf(stdout, "[STATS] %s\n", l); }
void StdoutWriter::write_latency(const char* l) { fprintf(stdout, "[LATENCY] %s\n", l); }
void StdoutWriter::flush() { fflush(stdout); }
