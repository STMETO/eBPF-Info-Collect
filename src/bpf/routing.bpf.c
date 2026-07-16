// SPDX-License-Identifier: GPL-2.0
// routing.bpf.c — 路由管理器 hook 模块（5 个 hook）
//
// 私有事件结构体 routing_event（定义在 common/routing_event.h）
// 用户态通过 hdr.module_id == 1 识别后强转为 routing_event*。

#include "common.bpf.h"
#include "../common/routing_event.h"
#include "../common/hook_ids.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} routing_events SEC(".maps");

static __always_inline int submit_routing(void *ctx,
    uint8_t hook_id, uint8_t dir, bool is_ret,
    const unsigned char *data_ptr, uint32_t data_len, int64_t retval)
{
    struct routing_event *e;
    e = bpf_ringbuf_reserve(&routing_events, sizeof(*e), 0);
    if (!e) return 0;
    fill_header(&e->hdr, MODULE_ROUTING, hook_id, dir, is_ret);
    if (data_ptr && data_len >= SOMEIP_HEADER_SIZE)
        read_someip_header(e, data_ptr, data_len);
    e->retval = retval;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Hook 1: rm_send_entry — send() 入口, PARM3=data PARM4=size
SEC("uprobe/rm_send_entry")
int hook_rm_send_entry(struct pt_regs *ctx) {
    return submit_routing(ctx, HOOK_RM_SEND_ENTRY, DIR_SEND, false,
        (const unsigned char *)PT_REGS_PARM3(ctx), (uint32_t)PT_REGS_PARM4(ctx), 0);
}

// Hook 2: rm_send_ret — send() 返回
SEC("uretprobe/rm_send_ret")
int hook_rm_send_ret(struct pt_regs *ctx) {
    return submit_routing(ctx, HOOK_RM_SEND_RET, DIR_SEND, true,
        NULL, 0, (int64_t)PT_REGS_RC(ctx));
}

// Hook 3: rm_send_to_entry — send_to() 入口
SEC("uprobe/rm_send_to_entry")
int hook_rm_send_to_entry(struct pt_regs *ctx) {
    return submit_routing(ctx, HOOK_RM_SEND_TO_ENTRY, DIR_SEND, false,
        (const unsigned char *)PT_REGS_PARM3(ctx), (uint32_t)PT_REGS_PARM4(ctx), 0);
}

// Hook 4: rm_send_to_ret — send_to() 返回
SEC("uretprobe/rm_send_to_ret")
int hook_rm_send_to_ret(struct pt_regs *ctx) {
    return submit_routing(ctx, HOOK_RM_SEND_TO_RET, DIR_SEND, true,
        NULL, 0, (int64_t)PT_REGS_RC(ctx));
}

// Hook 5: rm_on_message — on_message() 入口, PARM2=data PARM3=size（接收方向）
SEC("uprobe/rm_on_message")
int hook_rm_on_message(struct pt_regs *ctx) {
    return submit_routing(ctx, HOOK_RM_ON_MESSAGE, DIR_RECV, false,
        (const unsigned char *)PT_REGS_PARM2(ctx), (uint32_t)PT_REGS_PARM3(ctx), 0);
}
