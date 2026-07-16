// stdout_writer.cpp — 终端输出实现

#include "stdout_writer.h"
#include "../../common/vsomeip_types.h"
#include <cstdio>
#include <cinttypes>
#include <ctime>

StdoutWriter::StdoutWriter(bool json) : use_json_(json) { setvbuf(stdout, nullptr, _IONBF, 0); }

// ── 公共格式化 ────────────────────────────────────────────────────────

void StdoutWriter::write_common(const event_header& h, const char* hook, bool json)
{
    const char* tag = h.module_id == MODULE_ROUTING ? "\033[31m[R]\033[0m" :
                      h.module_id == MODULE_APP     ? "\033[32m[A]\033[0m" :
                      h.module_id == MODULE_SD      ? "\033[34m[S]\033[0m" : "?";
    const char* dir = h.direction == DIR_SEND ? "SEND" : "RECV";
    const char* ret = h.is_retprobe ? " [RET]" : "";

    if (json) {
        fprintf(stdout, "{\"ts\":%" PRIu64 ",\"pid\":%u,\"tid\":%u,\"comm\":\"%s\","
                "\"module\":\"%s\",\"hook\":\"%s\",\"dir\":\"%s\",\"is_ret\":%s",
                h.timestamp_ns, h.pid, h.tid, h.comm,
                module_name_str(h.module_id), hook, dir, h.is_retprobe ? "true" : "false");
    } else {
        time_t sec = h.timestamp_ns / 1000000000ULL;
        long ns = h.timestamp_ns % 1000000000ULL;
        struct tm tm; localtime_r(&sec, &tm);
        char tb[32]; strftime(tb, sizeof(tb), "%H:%M:%S", &tm);
        fprintf(stdout, "%s %s.%06ld PID:%-6u TID:%-6u %-16s %-20s%s %s\n",
                tag, tb, ns/1000L, h.pid, h.tid, h.comm, hook, ret, dir);
    }
}

// ── routing ────────────────────────────────────────────────────────────

void StdoutWriter::write_routing(const routing_event& e, const char* hook)
{
    write_common(e.hdr, hook, use_json_);
    if (use_json_) {
        fprintf(stdout, ",\"svc\":%u,\"method\":%u,\"client\":%u,\"session\":%u,"
                "\"msg_type\":\"%s\",\"ret_code\":%u,\"payload_len\":%u,"
                "\"retval\":%" PRId64 "}\n",
                e.service_id, e.method_id, e.client_id, e.session_id,
                message_type_str(e.message_type), e.return_code, e.payload_length, e.retval);
    } else {
        if (e.service_id || e.method_id)
            fprintf(stdout, "  svc=0x%04x method=0x%04x client=0x%04x session=0x%04x "
                    "type=%s(0x%02x) rc=0x%02x len=%u\n",
                    e.service_id, e.method_id, e.client_id, e.session_id,
                    message_type_str(e.message_type), e.message_type, e.return_code, e.payload_length);
        if (e.hdr.is_retprobe) fprintf(stdout, "  retval=%" PRId64 "\n", e.retval);
    }
}

// ── app ────────────────────────────────────────────────────────────────

void StdoutWriter::write_app(const app_event& e, const char* hook)
{
    write_common(e.hdr, hook, use_json_);
    if (use_json_)
        fprintf(stdout, ",\"this\":\"0x%" PRIx64 "\",\"msg\":\"0x%" PRIx64 "\",\"retval\":%" PRId64 "}\n",
                e.this_ptr, e.message_ptr, e.retval);
    else {
        if (e.hdr.is_retprobe) fprintf(stdout, "  retval=%" PRId64 "\n", e.retval);
        else fprintf(stdout, "  this=0x%" PRIx64 " msg=0x%" PRIx64 "\n", e.this_ptr, e.message_ptr);
    }
}

// ── sd ─────────────────────────────────────────────────────────────────

void StdoutWriter::write_sd(const sd_event& e, const char* hook)
{
    write_common(e.hdr, hook, use_json_);
    if (use_json_)
        fprintf(stdout, ",\"svc\":%u,\"inst\":%u,\"evg\":%u,\"ttl\":%u}\n",
                e.service_id, e.instance_id, e.eventgroup_id, e.ttl);
    else
        fprintf(stdout, "  svc=0x%04x inst=0x%04x evg=0x%04x ttl=%u\n",
                e.service_id, e.instance_id, e.eventgroup_id, e.ttl);
}

// ── 统计 / 时延 ────────────────────────────────────────────────────────

void StdoutWriter::write_stats(const char* l)   { fprintf(stdout, "[STATS] %s\n", l); }
void StdoutWriter::write_latency(const char* l) { fprintf(stdout, "[LATENCY] %s\n", l); }
void StdoutWriter::flush() { fflush(stdout); }

// ── 辅助 ───────────────────────────────────────────────────────────────

const char* message_type_str(uint8_t mt) {
    switch (mt) {
        case SOMEIP_MT_REQUEST:           return "REQUEST";
        case SOMEIP_MT_REQUEST_NO_RETURN: return "REQ_NORET";
        case SOMEIP_MT_NOTIFICATION:      return "NOTIFICATION";
        case SOMEIP_MT_REQUEST_ACK:       return "REQ_ACK";
        case SOMEIP_MT_RESPONSE:          return "RESPONSE";
        case SOMEIP_MT_ERROR:             return "ERROR";
        default:                          return "UNKNOWN";
    }
}
const char* module_name_str(uint8_t id) {
    switch (id) { case 1: return "routing"; case 2: return "app"; case 3: return "sd"; default: return "?"; }
}
