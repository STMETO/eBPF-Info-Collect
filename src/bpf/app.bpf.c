// SPDX-License-Identifier: GPL-2.0
/*
 * app.bpf.c — 应用层 hook 模块
 *
 * 挂载到 vsomeip 的 application_impl 方法。
 * 相比 routing 模块，这里的 hook 更接近业务代码：
 *   - app_send_entry/ret → 应用程序调用 send()
 *   - app_on_message    → 消息被投递到应用程序
 *
 * 注意：application_impl::send() 的参数是 shared_ptr<message>
 * （C++ 智能指针），不是原始 byte*。所以我们无法在 BPF 中直接
 * 读取 message 的字段（需要解引用智能指针 → 虚函数表，太复杂）。
 * 这里只记录调用事件、参数地址和返回值。
 *
 * Hook 清单（3 个）：
 *   app_send_entry  → uprobe    application_impl::send()
 *   app_send_ret    → uretprobe send() 返回
 *   app_on_message  → uprobe    application_impl::on_message()
 */

#include "common.bpf.h"

char LICENSE[] SEC("license") = "GPL";

// ── Ring buffer：应用层事件专用 ──────────────────────────────────────
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 128 * 1024);   // 128KB
} app_events SEC(".maps");

// ── 通用提交 ─────────────────────────────────────────────────────────
static __always_inline int submit_app_event(
    void *ctx, uint8_t hook_id, uint8_t direction, bool is_retprobe,
    uint64_t arg0, uint64_t arg1, uint64_t arg2, int64_t retval)
{
    struct vsomeip_event *e;

    e = bpf_ringbuf_reserve(&app_events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_common(e, MODULE_APP, hook_id, direction, is_retprobe, ctx);
    e->arg0 = arg0;     // this 指针 (application_impl*)
    e->arg1 = arg1;     // shared_ptr<message> 的内部指针
    e->arg2 = arg2;
    e->retval = retval;

    // app 层拿不到原始 byte buffer，SOME/IP header 字段保持为 0
    // 需要完整 header 信息的话，看 routing 模块的事件

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
// Hook 1: app_send_entry — 进入 application_impl::send()
//
// 函数签名：
//   application_impl::send(shared_ptr<message> _message)
//       PARM1 = this (application_impl*)
//       PARM2 = shared_ptr<message> 的内部裸指针
//
// 这是业务代码调用 send() 的入口。
// 注意：shared_ptr 在 x86-64 上通过寄存器传递（8 bytes），
// 其内部是一个指向 message_impl 对象的裸指针。
// ═══════════════════════════════════════════════════════════════════════
SEC("uprobe/hook_app_send_entry")
int hook_app_send_entry(struct pt_regs *ctx)
{
    return submit_app_event(
        ctx, HOOK_APP_SEND_ENTRY, DIR_SEND, false,
        PT_REGS_PARM1(ctx),     // arg0 = this (application_impl*)
        PT_REGS_PARM2(ctx),     // arg1 = message 裸指针
        0, 0);
}

// ═══════════════════════════════════════════════════════════════════════
// Hook 2: app_send_ret — application_impl::send() 返回
//
// 返回值：0 = 成功发送，非0 = 发送失败
// 用户态将 entry 和 ret 配对 → 应用层发送耗时 + 成功率
// ═══════════════════════════════════════════════════════════════════════
SEC("uretprobe/hook_app_send_ret")
int hook_app_send_ret(struct pt_regs *ctx)
{
    int64_t retval = (int64_t)PT_REGS_RC(ctx);

    return submit_app_event(
        ctx, HOOK_APP_SEND_RET, DIR_SEND, true,
        0, 0, 0, retval);
}

// ═══════════════════════════════════════════════════════════════════════
// Hook 3: app_on_message — 进入 application_impl::on_message()
//
// 函数签名：
//   application_impl::on_message(shared_ptr<message>&& _message)
//       PARM1 = this
//       PARM2 = message 右值引用的内部指针
//
// 当 routing_manager 把收到的消息投递给应用程序时调用。
// 这个 hook 的时间戳 = 消息到达应用层的时间点。
//
// 时延计算：
//   网络收到消息 (rm_on_message) → 路由处理 → 投递到应用 (app_on_message)
//   app_on_message.time - rm_on_message.time = 路由内部处理耗时
// ═══════════════════════════════════════════════════════════════════════
SEC("uprobe/hook_app_on_message")
int hook_app_on_message(struct pt_regs *ctx)
{
    return submit_app_event(
        ctx, HOOK_APP_ON_MESSAGE, DIR_RECV, false,
        PT_REGS_PARM1(ctx),     // arg0 = this
        PT_REGS_PARM2(ctx),     // arg1 = message 裸指针
        0, 0);
}
