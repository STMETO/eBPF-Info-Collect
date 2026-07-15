// SPDX-License-Identifier: GPL-2.0
/*
 * routing.bpf.c — 路由管理器 hook 模块
 *
 * 挂载到 vsomeip 的 routing_manager_impl 核心收发函数。
 * 这是最重要的模块：所有 SOME/IP 消息的发送和接收都经过这里。
 *
 * Hook 清单（5 个）：
 *   rm_send_entry      → uprobe   进入 routing_manager_impl::send()
 *   rm_send_ret        → uretprobe send() 返回（捕获成功/失败）
 *   rm_send_to_entry   → uprobe   进入 send_to()（端点定向发送）
 *   rm_send_to_ret     → uretprobe send_to() 返回
 *   rm_on_message      → uprobe   进入 on_message()（消息接收）
 *
 * 关键：send() 和 send_to() 的第一个参数是 byte* data，
 * 指向序列化后的 SOME/IP 报文。从 data[0..15] 可以直接读出
 * Service ID、Method ID、Message Type 等全部 header 字段，
 * 不需要解析 C++ 对象。
 */

#include "common.bpf.h"

char LICENSE[] SEC("license") = "GPL";

// ── Ring buffer：路由事件专用 ────────────────────────────────────────
// 用户态通过 skeleton 找到这个 map，创建 ring_buffer consumer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);   // 256KB，高吞吐场景可调大
} routing_events SEC(".maps");

// ── 通用提交函数：从 ringbuf 分配空间 → 填充公共字段 → 提交 ─────────
static __always_inline int submit_routing_event(
    void *ctx, uint8_t hook_id, uint8_t direction, bool is_retprobe,
    const unsigned char *data_ptr, uint32_t data_len,
    uint64_t arg0, uint64_t arg1, uint64_t arg2, int64_t retval)
{
    struct vsomeip_event *e;

    e = bpf_ringbuf_reserve(&routing_events, sizeof(*e), 0);
    if (!e)
        return 0;   // ringbuf 满了，丢弃本次事件（不阻塞）

    fill_common(e, MODULE_ROUTING, hook_id, direction, is_retprobe, ctx);

    // 尝试从 data 指针读取 SOME/IP 报文头
    if (data_ptr && data_len >= SOMEIP_HEADER_SIZE)
        read_someip_header(e, data_ptr, data_len);

    e->arg0 = arg0;
    e->arg1 = arg1;
    e->arg2 = arg2;     // data_len，即 payload 总长度
    e->retval = retval;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
// Hook 1: rm_send_entry — 进入 routing_manager_impl::send()
//
// 函数签名：
//   routing_manager_impl::send(
//       uint16_t      client,         // PARM2  (16-bit client ID)
//       const byte_t* data,           // PARM3  → 指向序列化 SOME/IP 报文
//       uint32_t      size,           // PARM4  → 报文长度
//       uint16_t      instance,       // PARM5
//       bool          is_reliable,    // PARM6  (栈上)
//       ...
//   )
//
// 这是最核心的 hook，所有消息发送都经过这里。
// 从 PARM3 (data 指针) + PARM4 (size) 读取完整的 SOME/IP header。
// ═══════════════════════════════════════════════════════════════════════
SEC("uprobe/rm_send_entry")
int hook_rm_send_entry(struct pt_regs *ctx)
{
    // ARM32: PT_REGS_PARM1 = r0, PARM2 = r1, PARM3 = r2, PARM4 = r3
    // ARM64: PT_REGS_PARM1 = x0, PARM2 = x1, ..., PARM8 = x7
    // x86:   PARM1 = rdi, PARM2 = rsi, PARM3 = rdx, PARM4 = rcx
    //
    // C++ 成员函数：PARM1 = this（隐式），PARM2 = 第一个显式参数，以此类推
    // send() 的参数：PARM1=this, PARM2=client, PARM3=data_ptr, PARM4=data_len

    const unsigned char *data_ptr = (const unsigned char *)PT_REGS_PARM3(ctx);
    uint32_t data_len = (uint32_t)PT_REGS_PARM4(ctx);

    return submit_routing_event(
        ctx, HOOK_RM_SEND_ENTRY, DIR_SEND, false,
        data_ptr, data_len,
        PT_REGS_PARM2(ctx),     // arg0 = client ID
        (uint64_t)(unsigned long)data_ptr,  // arg1 = data 指针地址
        data_len,               // arg2 = 数据长度
        0);                     // retval 无效（入口 probe）
}

// ═══════════════════════════════════════════════════════════════════════
// Hook 2: rm_send_ret — routing_manager_impl::send() 返回
//
// 返回值是 send 的结果（0=成功，非0=失败码）。
// 用户态把 send_entry 和 send_ret 配对后可以判断：
//   - 哪次发送成功了
//   - 哪次发送失败了（结合 retval 判断失败原因）
//   - 发送耗时 = send_ret.timestamp - send_entry.timestamp
// ═══════════════════════════════════════════════════════════════════════
SEC("uretprobe/rm_send_ret")
int hook_rm_send_ret(struct pt_regs *ctx)
{
    // PT_REGS_RC(ctx) 获取函数返回值（ARM: r0, ARM64: x0, x86: rax）
    int64_t retval = (int64_t)PT_REGS_RC(ctx);

    return submit_routing_event(
        ctx, HOOK_RM_SEND_RET, DIR_SEND, true,
        NULL, 0,               // retprobe 没有 data 指针
        0, 0, 0,               // arg0/arg1/arg2 无效
        retval);                // ★ 返回值：0=成功, !0=失败
}

// ═══════════════════════════════════════════════════════════════════════
// Hook 3: rm_send_to_entry — 进入 routing_manager_impl::send_to()
//
// 函数签名：
//   routing_manager_impl::send_to(
//       shared_ptr<endpoint_definition> target,  // PARM2
//       const byte_t* data,                      // PARM3 → SOME/IP 报文
//       uint32_t      size,                      // PARM4 → 报文长度
//       uint16_t      instance                   // PARM5
//   )
//
// 与 send() 的区别：send_to() 指定了目标端点。
// 当路由管理器决定把消息发给某个具体 endpoint（TCP/UDP/本地）时调用。
// ═══════════════════════════════════════════════════════════════════════
SEC("uprobe/rm_send_to_entry")
int hook_rm_send_to_entry(struct pt_regs *ctx)
{
    const unsigned char *data_ptr = (const unsigned char *)PT_REGS_PARM3(ctx);
    uint32_t data_len = (uint32_t)PT_REGS_PARM4(ctx);

    return submit_routing_event(
        ctx, HOOK_RM_SEND_TO_ENTRY, DIR_SEND, false,
        data_ptr, data_len,
        0,                      // arg0
        (uint64_t)(unsigned long)data_ptr,
        data_len,
        0);
}

// ═══════════════════════════════════════════════════════════════════════
// Hook 4: rm_send_to_ret — send_to() 返回
//
// 捕获端点发送的结果。用户态可以和 send_to_entry 配对计算发送耗时。
// ═══════════════════════════════════════════════════════════════════════
SEC("uretprobe/rm_send_to_ret")
int hook_rm_send_to_ret(struct pt_regs *ctx)
{
    int64_t retval = (int64_t)PT_REGS_RC(ctx);

    return submit_routing_event(
        ctx, HOOK_RM_SEND_TO_RET, DIR_SEND, true,
        NULL, 0, 0, 0, 0,
        retval);
}

// ═══════════════════════════════════════════════════════════════════════
// Hook 5: rm_on_message — 进入 routing_manager_impl::on_message()
//
// 函数签名：
//   routing_manager_impl::on_message(
//       const byte_t*          data,        // PARM2 → 接收到的 SOME/IP 报文
//       uint32_t               size,        // PARM3 → 报文长度
//       boardnet_endpoint*     endpoint,    // PARM4 → 来源端点
//       const address&         src_addr,    // PARM5 → 来源 IP 地址
//       uint16_t               src_port,    // PARM6 → 来源端口
//       bool                   is_reliable  // PARM7 → TCP/UDP
//   )
//
// 这是接收方向的唯一 hook 点。
// 所有从网络收到的 SOME/IP 消息都先到这里，
// 然后再分发给对应的 application_impl::on_message()。
//
// ★ 时延计算的关键：
//   1. 某条 REQUEST 消息经 rm_send_entry 发出 → 记录时间戳 Ts
//   2. 对应的 RESPONSE 经 rm_on_message 收到 → 记录时间戳 Tr
//   3. 往返时延 RTT = Tr - Ts
//
//   匹配逻辑在用户态完成（用 service_id + method_id + session_id 做 key）
// ═══════════════════════════════════════════════════════════════════════
SEC("uprobe/rm_on_message")
int hook_rm_on_message(struct pt_regs *ctx)
{
    const unsigned char *data_ptr = (const unsigned char *)PT_REGS_PARM2(ctx);
    uint32_t data_len = (uint32_t)PT_REGS_PARM3(ctx);

    return submit_routing_event(
        ctx, HOOK_RM_ON_MESSAGE, DIR_RECV, false,
        data_ptr, data_len,
        0,                      // arg0
        (uint64_t)(unsigned long)data_ptr,
        data_len,
        0);
}
