// file_writer.cpp — 文件输出实现

#include "file_writer.h"
#include "../../common/event_header.h"
#include "../../common/vsomeip_types.h"
#include <cinttypes>

FileWriter::FileWriter(const char* p, bool j) : path_(p), use_json_(j) { ensure_open(); }
FileWriter::~FileWriter() { if (file_) fclose(file_); }
bool FileWriter::ensure_open() { if (file_) return true; file_ = fopen(path_.c_str(), "a"); if (file_) setvbuf(file_, nullptr, _IOLBF, 0); return file_; }
void FileWriter::flush() { if (file_) fflush(file_); }

void FileWriter::write_event(const event_header* hdr, const void* payload,
                              const char* hook,
                              format_callback_t format_payload)
{
    if (!ensure_open()) return;

    fprintf(file_, "{\"ts\":%" PRIu64 ",\"pid\":%u,\"tid\":%u,\"comm\":\"%s\","
            "\"module\":\"%s\",\"hook\":\"%s\",\"dir\":\"%s\",\"is_ret\":%s",
            hdr->timestamp_ns, hdr->pid, hdr->tid, hdr->comm,
            hdr->module_id == 1 ? "routing" : hdr->module_id == 2 ? "app" : hdr->module_id == 3 ? "sd" : "?",
            hook, hdr->direction == DIR_SEND ? "SEND" : "RECV", hdr->is_retprobe ? "true" : "false");

    if (format_payload) {
        char buf[512] = {};
        format_payload(payload, hook, buf, sizeof(buf));
        if (buf[0]) fprintf(file_, ",%s", buf);
    }
    fprintf(file_, "}\n");
}

void FileWriter::write_stats(const char* l)   { if (ensure_open()) fprintf(file_, "[STATS] %s\n", l); }
void FileWriter::write_latency(const char* l) { if (ensure_open()) fprintf(file_, "[LATENCY] %s\n", l); }
