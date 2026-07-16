// SPDX-License-Identifier: GPL-2.0
// app.bpf.c — 应用层 hook 模块（3 个 hook）
//
// ★ 使用私有事件结构体 app_event（定义在 common/app_event.h） ★
// 参数是 C++ 对象（shared_ptr<message>），BPF 不能解引用，只记录指针。

#include "common.bpf.h"
#include "../common/app_event.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 128 * 1024);
} app_events SEC(".maps");

// ── 通用提交 ─────────────────────────────────────────────────────────
static __always_inline int submit_app(void *ctx,
    uint8_t hook_id, uint8_t dir, bool is_ret,
    uint64_t this_ptr, uint64_t msg_ptr, int64_t retval)
{
    struct app_event *e;

    e = bpf_ringbuf_reserve(&app_events, sizeof(*e), 0);
    if (!e) return 0;

    fill_header(&e->hdr, MODULE_APP, hook_id, dir, is_ret);
    e->this_ptr    = this_ptr;
    e->message_ptr = msg_ptr;
    e->retval      = retval;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
// Hook 1: app_send_entry — application_impl::send() 入口
// PARM1 = this, PARM2 = message 裸指针
// ═══════════════════════════════════════════════════════════════════════
SEC("uprobe/app_send_entry")
int hook_app_send_entry(struct pt_regs *ctx)
{
    return submit_app(ctx, HOOK_APP_SEND_ENTRY, DIR_SEND, false,
        PT_REGS_PARM1(ctx), PT_REGS_PARM2(ctx), 0);
}

// ═══════════════════════════════════════════════════════════════════════
// Hook 2: app_send_ret — send() 返回
// ═══════════════════════════════════════════════════════════════════════
SEC("uretprobe/app_send_ret")
int hook_app_send_ret(struct pt_regs *ctx)
{
    return submit_app(ctx, HOOK_APP_SEND_RET, DIR_SEND, true,
        0, 0, (int64_t)PT_REGS_RC(ctx));
}

// ═══════════════════════════════════════════════════════════════════════
// Hook 3: app_on_message — application_impl::on_message() 入口
// ═══════════════════════════════════════════════════════════════════════
SEC("uprobe/app_on_message")
int hook_app_on_message(struct pt_regs *ctx)
{
    return submit_app(ctx, HOOK_APP_ON_MESSAGE, DIR_RECV, false,
        PT_REGS_PARM1(ctx), PT_REGS_PARM2(ctx), 0);
}
