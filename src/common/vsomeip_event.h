// vsomeip_event.h — Event pushed from BPF ringbuf to userspace
// This struct is shared between BPF C code and userspace C++ code.

#pragma once

#include <stdint.h>
#include <stdbool.h>

#define TASK_COMM_LEN   16
#define EVENT_PADDING   24

// ── BPF → Userspace event ────────────────────────────────────────────
struct vsomeip_event {
    // ── Generic fields ───────────────────────────────────────────────
    uint64_t timestamp_ns;          // bpf_ktime_get_ns()
    uint32_t pid;                   // Process ID
    uint32_t tid;                   // Thread ID
    char     comm[TASK_COMM_LEN];   // Process/thread name

    uint8_t  module_id;             // MODULE_ROUTING / MODULE_APP / MODULE_SD
    uint8_t  hook_id;               // Hook index within the module
    uint8_t  direction;             // DIR_SEND or DIR_RECV
    bool     is_retprobe;           // true = uretprobe (return probe)

    // ── Function arguments ───────────────────────────────────────────
    uint64_t arg0;                  // First argument (usually "this" or data ptr)
    uint64_t arg1;                  // Second argument
    uint64_t arg2;                  // Third argument (e.g., size)
    int64_t  retval;                // Return value (meaningful for uretprobe)

    // ── SOME/IP header (read from byte buffer) ───────────────────────
    uint16_t service_id;            // SOME/IP Service ID
    uint16_t method_id;             // SOME/IP Method ID
    uint16_t client_id;             // SOME/IP Client ID
    uint16_t session_id;            // SOME/IP Session ID
    uint8_t  protocol_version;      // SOME/IP Protocol Version
    uint8_t  interface_version;     // SOME/IP Interface Version
    uint8_t  message_type;          // SOME/IP Message Type
    uint8_t  return_code;           // SOME/IP Return Code
    uint32_t payload_length;        // SOME/IP Payload Length (from header)

    // ── Reserved for future use ──────────────────────────────────────
    uint8_t  reserved[EVENT_PADDING];
};

// Ensure event fits in a single ringbuf page (4KB)
_Static_assert(sizeof(struct vsomeip_event) <= 256,
    "vsomeip_event too large for efficient ring buffer use");

// ── Hook ID definitions per module ───────────────────────────────────

// Module: ROUTING
#define HOOK_RM_SEND_ENTRY      0
#define HOOK_RM_SEND_RET        1
#define HOOK_RM_SEND_TO_ENTRY   2
#define HOOK_RM_SEND_TO_RET     3
#define HOOK_RM_ON_MESSAGE      4

// Module: APP
#define HOOK_APP_SEND_ENTRY     0
#define HOOK_APP_SEND_RET       1
#define HOOK_APP_ON_MESSAGE     2

// Module: SD
#define HOOK_SD_SEND            0
#define HOOK_SD_PROCESS_OFFER   1
#define HOOK_SD_SEND_SUB        2
#define HOOK_SD_HANDLE_SUB      3
