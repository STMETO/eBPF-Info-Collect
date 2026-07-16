// file_writer.cpp — 文件日志输出实现

#include "file_writer.h"
#include "../../common/vsomeip_types.h"
#include <cinttypes>

FileWriter::FileWriter(const char* path, bool json) : path_(path), use_json_(json) { ensure_open(); }
FileWriter::~FileWriter() { if (file_) fclose(file_); }
bool FileWriter::ensure_open() { if (file_) return true; file_ = fopen(path_.c_str(), "a"); if (file_) setvbuf(file_, nullptr, _IOLBF, 0); return file_; }
void FileWriter::flush() { if (file_) fflush(file_); }

void FileWriter::write_common_json(const event_header& h, const char* hook, FILE* f) {
    fprintf(f, "{\"ts\":%" PRIu64 ",\"pid\":%u,\"tid\":%u,\"comm\":\"%s\",\"module\":\"%s\",\"hook\":\"%s\",\"dir\":\"%s\",\"is_ret\":%s",
            h.timestamp_ns, h.pid, h.tid, h.comm,
            h.module_id == 1 ? "routing" : h.module_id == 2 ? "app" : h.module_id == 3 ? "sd" : "?",
            hook, h.direction == DIR_SEND ? "SEND" : "RECV", h.is_retprobe ? "true" : "false");
}

void FileWriter::write_routing(const routing_event& e, const char* hook) {
    if (!ensure_open()) return;
    write_common_json(e.hdr, hook, file_);
    fprintf(file_, ",\"svc\":%u,\"method\":%u,\"client\":%u,\"session\":%u,\"msg_type\":%u,\"ret_code\":%u,\"len\":%u,\"retval\":%" PRId64 "}\n",
            e.service_id, e.method_id, e.client_id, e.session_id, e.message_type, e.return_code, e.payload_length, e.retval);
}

void FileWriter::write_app(const app_event& e, const char* hook) {
    if (!ensure_open()) return;
    write_common_json(e.hdr, hook, file_);
    fprintf(file_, ",\"this\":\"0x%" PRIx64 "\",\"msg\":\"0x%" PRIx64 "\",\"retval\":%" PRId64 "}\n", e.this_ptr, e.message_ptr, e.retval);
}

void FileWriter::write_sd(const sd_event& e, const char* hook) {
    if (!ensure_open()) return;
    write_common_json(e.hdr, hook, file_);
    fprintf(file_, ",\"svc\":%u,\"inst\":%u,\"evg\":%u,\"ttl\":%u}\n", e.service_id, e.instance_id, e.eventgroup_id, e.ttl);
}

void FileWriter::write_stats(const char* l)   { if (ensure_open()) fprintf(file_, "[STATS] %s\n", l); }
void FileWriter::write_latency(const char* l) { if (ensure_open()) fprintf(file_, "[LATENCY] %s\n", l); }
