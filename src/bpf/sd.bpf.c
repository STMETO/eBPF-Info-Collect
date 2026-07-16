// SPDX-License-Identifier: GPL-2.0
// sd.bpf.c — 服务发现 hook 模块（4 个 hook）
// ★ 私有事件结构体 sd_event（定义在 common/sd_event.h） ★

#include "common.bpf.h"
#include "../common/sd_event.h"
#include "../common/hook_ids.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 128 * 1024);
} sd_events SEC(".maps");

static __always_inline int submit_sd(void *ctx,
    uint8_t hook_id, uint8_t dir, uint16_t svc, uint16_t inst, uint16_t evg)
{
    struct sd_event *e;
    e = bpf_ringbuf_reserve(&sd_events, sizeof(*e), 0);
    if (!e) return 0;
    fill_header(&e->hdr, MODULE_SD, hook_id, dir, false);
    e->service_id = svc;
    e->instance_id = inst;
    e->eventgroup_id = evg;
    e->ttl = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/sd_send")
int hook_sd_send(struct pt_regs *ctx) {
    return submit_sd(ctx, HOOK_SD_SEND, DIR_SEND, 0, 0, (uint16_t)PT_REGS_PARM2(ctx));
}

SEC("uprobe/sd_process_offer")
int hook_sd_process_offer(struct pt_regs *ctx) {
    return submit_sd(ctx, HOOK_SD_PROCESS_OFFER, DIR_RECV,
        (uint16_t)PT_REGS_PARM2(ctx), (uint16_t)PT_REGS_PARM3(ctx), 0);
}

SEC("uprobe/sd_send_subscription")
int hook_sd_send_subscription(struct pt_regs *ctx) {
    return submit_sd(ctx, HOOK_SD_SEND_SUBSCRIPTION, DIR_SEND,
        (uint16_t)PT_REGS_PARM3(ctx), (uint16_t)PT_REGS_PARM4(ctx),
        (uint16_t)PT_REGS_PARM5(ctx));
}

SEC("uprobe/sd_handle_subscription")
int hook_sd_handle_subscription(struct pt_regs *ctx) {
    return submit_sd(ctx, HOOK_SD_HANDLE_SUBSCRIPTION, DIR_RECV,
        (uint16_t)PT_REGS_PARM2(ctx), (uint16_t)PT_REGS_PARM3(ctx),
        (uint16_t)PT_REGS_PARM4(ctx));
}
