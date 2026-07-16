// common.bpf.h — 所有 BPF 模块共享的辅助函数

#pragma once

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "../common/vsomeip_types.h"
#include "../common/event_header.h"
#include "../common/routing_event.h"

// ═══════════════════════════════════════════════════════════════════════
// fill_header — 填充事件的公共头
//
// 每个 hook handler 从 ringbuf 分配好事件后第一个调用的函数。
// 填好 PID / TID / 时间戳 / comm / 模块信息 —— 所有模块的事件都从这里开始。
//
// @param h         指向事件公共头的指针
// @param module_id MODULE_ROUTING / MODULE_APP / MODULE_SD
// @param hook_id   模块内 hook 编号
// @param direction DIR_SEND / DIR_RECV
// @param is_ret    true = uretprobe（返回探测）
// ═══════════════════════════════════════════════════════════════════════

static __always_inline void fill_header(struct event_header *h,
    uint8_t module_id, uint8_t hook_id, uint8_t direction, bool is_ret)
{
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    h->timestamp_ns = bpf_ktime_get_ns();
    h->pid       = pid_tgid >> 32;
    h->tid       = (uint32_t)pid_tgid;
    h->module_id = module_id;
    h->hook_id   = hook_id;
    h->direction = direction;
    h->is_retprobe = is_ret;
    bpf_get_current_comm(&h->comm, sizeof(h->comm));
}

// ═══════════════════════════════════════════════════════════════════════
// read_someip_header — 从用户态 byte* 安全读取 SOME/IP 16 字节报文头
//
// 只被 routing 模块调用（它的 hook 参数有 byte* data）。
// 用 bpf_probe_read_user() 安全读取用户态内存（BPF 不能直接解引用）。
//
// @param e     routing_event 指针
// @param data  用户态内存中 SOME/IP 报文的起始地址
// @param len   报文总长度（字节数）
// @return      0=成功，-1=失败
// ═══════════════════════════════════════════════════════════════════════

static __always_inline int read_someip_header(struct routing_event *e,
    const unsigned char *data, uint32_t len)
{
    if (!data || len < SOMEIP_HEADER_SIZE)
        return -1;

    unsigned char hdr[SOMEIP_HEADER_SIZE];
    if (bpf_probe_read_user(hdr, sizeof(hdr), data) < 0)
        return -1;

    e->service_id  = ((uint16_t)hdr[0] << 8) | hdr[1];
    e->method_id   = ((uint16_t)hdr[2] << 8) | hdr[3];
    e->payload_length = ((uint32_t)hdr[4] << 24) | ((uint32_t)hdr[5] << 16) |
                        ((uint32_t)hdr[6] << 8)  | hdr[7];
    e->client_id   = ((uint16_t)hdr[8] << 8) | hdr[9];
    e->session_id  = ((uint16_t)hdr[10] << 8) | hdr[11];
    e->protocol_version  = hdr[12];
    e->interface_version = hdr[13];
    e->message_type      = hdr[14];
    e->return_code       = hdr[15];

    return 0;
}
