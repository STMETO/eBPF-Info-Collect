// file_writer.cpp — 文件日志输出实现

#include "file_writer.h"
#include "../../common/vsomeip_event.h"
#include "../../common/vsomeip_types.h"
#include <cstdio>
#include <cinttypes>

FileWriter::FileWriter(const char* file_path, bool use_json)
    : file_path_(file_path), use_json_(use_json)
{
    ensure_open();
}

FileWriter::~FileWriter()
{
    if (file_) {
        fclose(file_);
        file_ = nullptr;
    }
}

bool FileWriter::ensure_open()
{
    if (file_)
        return true;

    // 以追加模式打开文件，行缓冲确保及时写入
    file_ = fopen(file_path_.c_str(), "a");
    if (file_) {
        setvbuf(file_, nullptr, _IOLBF, 0);  // 行缓冲
        fprintf(file_, "# vsomeip collector started\n");
        return true;
    }
    return false;
}

void FileWriter::reopen()
{
    if (file_)
        fclose(file_);
    file_ = nullptr;
    ensure_open();
}

// ═══════════════════════════════════════════════════════════════════════
// 写入：用 JSON 格式写事件（文件输出默认 JSON，方便后续分析）
// ═══════════════════════════════════════════════════════════════════════

void FileWriter::write(const vsomeip_event& event, const char* hook_name)
{
    if (!ensure_open())
        return;

    if (use_json_) {
        // JSON 格式：与 stdout_writer 的 JSON 输出一致
        fprintf(file_,
            "{"
            "\"ts\":%" PRIu64 ","
            "\"pid\":%u,\"tid\":%u,"
            "\"comm\":\"%s\","
            "\"module\":\"%s\","
            "\"hook\":\"%s\","
            "\"dir\":\"%s\","
            "\"is_ret\":%s,"
            "\"svc\":%u,\"method\":%u,"
            "\"client\":%u,\"session\":%u,"
            "\"msg_type\":\"%s\","
            "\"ret_code\":%u,"
            "\"payload_len\":%u,"
            "\"retval\":%" PRId64
            "}\n",
            event.timestamp_ns,
            event.pid, event.tid,
            event.comm,
            // module 名
            event.module_id == MODULE_ROUTING ? "routing" :
            event.module_id == MODULE_APP     ? "app"     :
            event.module_id == MODULE_SD      ? "sd"      : "unknown",
            hook_name,
            event.direction == DIR_SEND ? "SEND" : "RECV",
            event.is_retprobe ? "true" : "false",
            event.service_id, event.method_id,
            event.client_id, event.session_id,
            // message_type 转字符串
            event.message_type == SOMEIP_MT_REQUEST           ? "REQUEST" :
            event.message_type == SOMEIP_MT_REQUEST_NO_RETURN ? "REQ_NORET" :
            event.message_type == SOMEIP_MT_NOTIFICATION      ? "NOTIFICATION" :
            event.message_type == SOMEIP_MT_REQUEST_ACK       ? "REQ_ACK" :
            event.message_type == SOMEIP_MT_RESPONSE          ? "RESPONSE" :
            event.message_type == SOMEIP_MT_ERROR             ? "ERROR" : "UNKNOWN",
            event.return_code, event.payload_length,
            event.retval
        );
    }
}

void FileWriter::write_stats(const char* json_line)
{
    if (!ensure_open()) return;
    fprintf(file_, "[STATS] %s\n", json_line);
}

void FileWriter::write_latency(const char* json_line)
{
    if (!ensure_open()) return;
    fprintf(file_, "[LATENCY] %s\n", json_line);
}

void FileWriter::flush()
{
    if (file_)
        fflush(file_);
}
