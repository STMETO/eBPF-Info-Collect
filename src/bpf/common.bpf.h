// common.bpf.h — Shared BPF helpers for all vsomeip uprobe modules
// Each module .bpf.c includes this header.

#pragma once

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "../common/vsomeip_types.h"
#include "../common/vsomeip_event.h"

// ── Shared license ───────────────────────────────────────────────────
// Each module defines its own LICENSE; this is a reminder.
// char LICENSE[] SEC("license") = "GPL";

// ── fill_common — fill PID/TID/comm/timestamp fields ─────────────────
static __always_inline void fill_common(struct vsomeip_event *e,
                                         uint8_t module_id, uint8_t hook_id,
                                         uint8_t direction, bool is_retprobe,
                                         void *ctx)
{
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = pid_tgid >> 32;
    e->tid = (uint32_t)pid_tgid;
    e->module_id = module_id;
    e->hook_id = hook_id;
    e->direction = direction;
    e->is_retprobe = is_retprobe;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Zero SOME/IP fields (will be filled by caller if data ptr available)
    e->service_id = 0;
    e->method_id = 0;
    e->client_id = 0;
    e->session_id = 0;
    e->protocol_version = 0;
    e->interface_version = 0;
    e->message_type = 0;
    e->return_code = 0;
    e->payload_length = 0;
    e->arg0 = 0;
    e->arg1 = 0;
    e->arg2 = 0;
    e->retval = 0;
}

// ── read_someip_header — read 16-byte SOME/IP header from user-space buffer ──
// Returns 0 on success, -1 if bpf_probe_read_user fails.
static __always_inline int read_someip_header(struct vsomeip_event *e,
                                               const unsigned char *data,
                                               uint32_t data_len)
{
    if (!data || data_len < SOMEIP_HEADER_SIZE)
        return -1;

    // Read the 16-byte SOME/IP header in one bpf_probe_read_user call
    unsigned char hdr[SOMEIP_HEADER_SIZE];
    if (bpf_probe_read_user(hdr, sizeof(hdr), data) < 0)
        return -1;

    // Parse big-endian fields from the header
    e->service_id  = ((uint16_t)hdr[SOMEIP_OFF_SERVICE_ID  ] << 8) | hdr[SOMEIP_OFF_SERVICE_ID+1];
    e->method_id   = ((uint16_t)hdr[SOMEIP_OFF_METHOD_ID   ] << 8) | hdr[SOMEIP_OFF_METHOD_ID+1];
    e->payload_length = ((uint32_t)hdr[SOMEIP_OFF_LENGTH   ] << 24) |
                        ((uint32_t)hdr[SOMEIP_OFF_LENGTH+1 ] << 16) |
                        ((uint32_t)hdr[SOMEIP_OFF_LENGTH+2 ] << 8)  |
                         (uint32_t)hdr[SOMEIP_OFF_LENGTH+3];
    e->client_id   = ((uint16_t)hdr[SOMEIP_OFF_CLIENT_ID   ] << 8) | hdr[SOMEIP_OFF_CLIENT_ID+1];
    e->session_id  = ((uint16_t)hdr[SOMEIP_OFF_SESSION_ID  ] << 8) | hdr[SOMEIP_OFF_SESSION_ID+1];
    e->protocol_version  = hdr[SOMEIP_OFF_PROTOCOL_VER];
    e->interface_version = hdr[SOMEIP_OFF_INTERFACE_VER];
    e->message_type      = hdr[SOMEIP_OFF_MESSAGE_TYPE];
    e->return_code       = hdr[SOMEIP_OFF_RETURN_CODE];

    return 0;
}
