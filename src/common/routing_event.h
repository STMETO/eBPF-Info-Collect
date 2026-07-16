// routing_event.h — routing 模块的事件结构体
//
// 对应 bpf/routing.bpf.c，挂在 libvsomeip3.so 的 routing_manager_impl 函数上。
// ★ 只有 routing 模块能从 byte* 直接读到 SOME/IP header ★

#pragma once

#include "event_header.h"

struct routing_event {
    // ── 公共头（必须第一个字段） ──────────────────────────────────────
    struct event_header hdr;

    // ── SOME/IP 报文头（从 byte* 参数中解析）─────────────────────────
    uint16_t service_id;
    uint16_t method_id;
    uint16_t client_id;
    uint16_t session_id;
    uint8_t  protocol_version;
    uint8_t  interface_version;
    uint8_t  message_type;          // REQUEST / RESPONSE / NOTIFICATION ...
    uint8_t  return_code;
    uint32_t payload_length;

    // ── 原始参数 ─────────────────────────────────────────────────────
    int64_t retval;                 // 仅 uretprobe 有效
};

// routing 模块的 hook_id 定义
#define HOOK_RM_SEND_ENTRY      0
#define HOOK_RM_SEND_RET        1
#define HOOK_RM_SEND_TO_ENTRY   2
#define HOOK_RM_SEND_TO_RET     3
#define HOOK_RM_ON_MESSAGE      4
