// stdout_writer.cpp — 终端输出实现

#include "stdout_writer.h"
#include "../../common/vsomeip_event.h"
#include "../../common/vsomeip_types.h"
#include <cstdio>
#include <cinttypes>
#include <ctime>

// ═══════════════════════════════════════════════════════════════════════
// 构造
// ═══════════════════════════════════════════════════════════════════════

StdoutWriter::StdoutWriter(bool use_json)
    : use_json_(use_json)
{
    // 终端输出默认不缓冲，确保实时看到日志
    setvbuf(stdout, nullptr, _IONBF, 0);
}

// ═══════════════════════════════════════════════════════════════════════
// 入口：根据模式分发
// ═══════════════════════════════════════════════════════════════════════

void StdoutWriter::write(const vsomeip_event& event, const char* hook_name)
{
    if (use_json_)
        write_json(event, hook_name);
    else
        write_human(event, hook_name);
}

void StdoutWriter::write_stats(const char* json_line)
{
    // 统计行：以 [STATS] 前缀突出显示
    fprintf(stdout, "[STATS] %s\n", json_line);
}

void StdoutWriter::write_latency(const char* json_line)
{
    // 时延事件：以 [LATENCY] 前缀
    fprintf(stdout, "[LATENCY] %s\n", json_line);
}

void StdoutWriter::flush()
{
    fflush(stdout);
}

// ═══════════════════════════════════════════════════════════════════════
// 人类可读格式
// ═══════════════════════════════════════════════════════════════════════

void StdoutWriter::write_human(const vsomeip_event& event, const char* hook_name)
{
    // 模块标签用不同颜色前缀区分
    // R=Routing(红)  A=App(绿)  S=SD(蓝)
    const char* mod_tag = "?";
    switch (event.module_id) {
        case MODULE_ROUTING: mod_tag = "\033[31m[R]\033[0m"; break;  // 红色
        case MODULE_APP:     mod_tag = "\033[32m[A]\033[0m"; break;  // 绿色
        case MODULE_SD:      mod_tag = "\033[34m[S]\033[0m"; break;  // 蓝色
    }

    // 方向标记
    const char* dir_str = (event.direction == DIR_SEND) ? "SEND" : "RECV";
    const char* ret_str = event.is_retprobe ? " [RET]" : "";

    // 时间戳转成可读时间
    time_t sec = event.timestamp_ns / 1000000000ULL;
    long   ns  = event.timestamp_ns % 1000000000ULL;
    struct tm tm_buf;
    localtime_r(&sec, &tm_buf);
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%H:%M:%S", &tm_buf);

    // 第一行：基本信息
    fprintf(stdout,
        "%s %s.%06ld  PID:%-6u TID:%-6u  %-16s  %-20s%s  %s\n",
        mod_tag, time_buf, ns / 1000L,
        event.pid, event.tid,
        event.comm,
        hook_name, ret_str,
        dir_str
    );

    // 第二行：SOME/IP 报文字段（只有 routing 模块能读到 header）
    if (event.service_id != 0 || event.method_id != 0) {
        fprintf(stdout,
            "  svc=0x%04x  method=0x%04x  client=0x%04x  session=0x%04x  "
            "type=%s(0x%02x)  rc=0x%02x  payload=%u\n",
            event.service_id, event.method_id,
            event.client_id, event.session_id,
            message_type_str(event.message_type), event.message_type,
            event.return_code, event.payload_length
        );
    }

    // 第三行：函数参数（UREtprobe 时显示返回值）
    if (event.is_retprobe) {
        fprintf(stdout, "  retval=%" PRId64 "\n", event.retval);
    } else if (event.arg0 != 0 || event.arg1 != 0) {
        fprintf(stdout, "  arg0=0x%" PRIx64 "  arg1=0x%" PRIx64 "  arg2=0x%" PRIx64 "\n",
                event.arg0, event.arg1, event.arg2);
    }
}

// ═══════════════════════════════════════════════════════════════════════
// JSON 格式
// ═══════════════════════════════════════════════════════════════════════

void StdoutWriter::write_json(const vsomeip_event& event, const char* hook_name)
{
    fprintf(stdout,
        "{"
        "\"ts\":%" PRIu64 ","
        "\"pid\":%u,"
        "\"tid\":%u,"
        "\"comm\":\"%s\","
        "\"module\":\"%s\","
        "\"hook\":\"%s\","
        "\"dir\":\"%s\","
        "\"is_ret\":%s,"
        "\"svc\":%u,"
        "\"method\":%u,"
        "\"client\":%u,"
        "\"session\":%u,"
        "\"proto_ver\":%u,"
        "\"iface_ver\":%u,"
        "\"msg_type\":\"%s\","
        "\"ret_code\":%u,"
        "\"payload_len\":%u,"
        "\"retval\":%" PRId64 ","
        "\"arg0\":\"0x%" PRIx64 "\","
        "\"arg1\":\"0x%" PRIx64 "\""
        "}\n",
        event.timestamp_ns,
        event.pid, event.tid,
        event.comm,
        module_name_str(event.module_id),
        hook_name,
        event.direction == DIR_SEND ? "SEND" : "RECV",
        event.is_retprobe ? "true" : "false",
        event.service_id, event.method_id,
        event.client_id, event.session_id,
        event.protocol_version, event.interface_version,
        message_type_str(event.message_type),
        event.return_code, event.payload_length,
        event.retval,
        event.arg0, event.arg1
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 辅助函数
// ═══════════════════════════════════════════════════════════════════════

const char* message_type_str(uint8_t mt)
{
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

const char* module_name_str(uint8_t module_id)
{
    switch (module_id) {
        case MODULE_ROUTING: return "routing";
        case MODULE_APP:     return "app";
        case MODULE_SD:      return "sd";
        default:             return "unknown";
    }
}
