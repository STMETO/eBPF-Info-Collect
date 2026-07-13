// SPDX-License-Identifier: GPL-2.0
/*
 * sd.bpf.c — 服务发现 (Service Discovery) hook 模块
 *
 * 挂载到 libvsomeip3-sd.so 的 service_discovery_impl 方法。
 * SD 负责 SOME/IP 的服务注册与发现：
 *   - OfferService：  服务端广播自己提供了哪些服务
 *   - FindService：    客户端查找某个服务
 *   - SubscribeEventgroup：客户端订阅事件组
 *   - StopOfferService：服务端停止提供服务
 *
 * SD 函数的参数都是 C++ 对象（subscription、message_impl、serviceinfo），
 * 不是原始 byte*。所以 BPF 侧只记录：
 *   - 调用了哪个 SD 操作
 *   - 相关参数（service_id 等原始类型）
 *   - 时间戳
 * 详细的 SD 消息内容由用户态在 routing 模块的 byte buffer 中解析。
 *
 * Hook 清单（4 个）：
 *   sd_send                → uprobe  SD 消息刷新到网络
 *   sd_process_offer       → uprobe  收到 OfferService 条目
 *   sd_send_subscription   → uprobe  发送 SubscribeEventgroup
 *   sd_handle_subscription → uprobe  处理收到的订阅请求
 *
 * ★ 这 4 个 hook 可以追踪一次完整的 SD 交互：
 *   客户端：sd_send_subscription → 服务端：sd_handle_subscription
 *   服务端：sd_process_offer ← 客户端的 FindService 请求（由 SD 自动生成）
 */

#include "common.bpf.h"

char LICENSE[] SEC("license") = "GPL";

// ── Ring buffer：SD 事件专用 ─────────────────────────────────────────
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 128 * 1024);   // 128KB
} sd_events SEC(".maps");

// ── 通用提交 ─────────────────────────────────────────────────────────
static __always_inline int submit_sd_event(
    void *ctx, uint8_t hook_id, uint8_t direction, bool is_retprobe,
    uint64_t arg0, uint64_t arg1, uint64_t arg2, int64_t retval)
{
    struct vsomeip_event *e;

    e = bpf_ringbuf_reserve(&sd_events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_common(e, MODULE_SD, hook_id, direction, is_retprobe, ctx);
    e->arg0 = arg0;
    e->arg1 = arg1;
    e->arg2 = arg2;
    e->retval = retval;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
// Hook 1: sd_send — SD 消息刷新到网络
//
// 函数签名：
//   service_discovery_impl::send(bool _is_required)
//       PARM1 = this
//       PARM2 = _is_required (bool，是否必须立即发送)
//
// SD 模块把待发送的 SD 消息缓存在内部队列里，
// 调用 send(bool) 时一次性把所有待发送条目序列化并发送到网络。
// 这是 SD 消息真正的"出口"。
//
// ★ 注意区分：
//   - service_discovery_impl::send(bool)              ← PARM2 = bool
//   - service_discovery_impl::send(vector<message>)   ← PARM2 = vector（另一个重载）
//   两个重载的参数类型不同，内核通过符号表中的 mangled 名区分。
//   我们只 hook (bool) 版本，因为它是被定时器周期性调用的刷新函数。
// ═══════════════════════════════════════════════════════════════════════
SEC("uprobe/hook_sd_send")
int hook_sd_send(struct pt_regs *ctx)
{
    return submit_sd_event(
        ctx, HOOK_SD_SEND, DIR_SEND, false,
        PT_REGS_PARM1(ctx),     // arg0 = this (service_discovery_impl*)
        PT_REGS_PARM2(ctx),     // arg1 = _is_required (bool: 0 or 1)
        0, 0);
}

// ═══════════════════════════════════════════════════════════════════════
// Hook 2: sd_process_offer — 处理收到的 OfferService 条目
//
// 函数签名：
//   service_discovery_impl::process_offerservice_serviceentry(
//       uint16_t  service_id,        // PARM2 — 被 offer 的服务 ID
//       uint16_t  instance_id,       // PARM3 — 实例 ID
//       uint8_t   major_version,     // PARM4 — 主版本号
//       uint32_t  minor_version,     // PARM5 — 次版本号
//       uint32_t  ttl,               // PARM6 — 生存时间
//       const address&  src_addr,    // PARM7 — 来源 IP（复杂类型）
//       uint16_t  src_port,          // 栈上
//       ... 更多 IP/端口/标志位 ...
//   )
//
// 当 SD 模块收到一个 OfferService 条目时调用。
// 这表明网络上有服务端在广播某个服务的可用性。
//
// 我们抓取 service_id + instance_id + major/minor version，
// 这些足够在用户态统计"哪些服务被发现"。
// ═══════════════════════════════════════════════════════════════════════
SEC("uprobe/hook_sd_process_offer")
int hook_sd_process_offer(struct pt_regs *ctx)
{
    // PARM2 = service_id (uint16_t), PARM3 = instance_id (uint16_t)
    // PARM4 = major_version (uint8_t), PARM5 = minor_version (uint32_t)
    return submit_sd_event(
        ctx, HOOK_SD_PROCESS_OFFER, DIR_RECV, false,
        PT_REGS_PARM2(ctx),     // arg0 = service_id
        PT_REGS_PARM3(ctx),     // arg1 = instance_id
        0, 0);
}

// ═══════════════════════════════════════════════════════════════════════
// Hook 3: sd_send_subscription — 发送订阅请求
//
// 函数签名：
//   service_discovery_impl::send_subscription(
//       shared_ptr<subscription> sub,  // PARM2 — 订阅对象（智能指针）
//       uint16_t service_id,           // PARM3 — 要订阅的服务 ID
//       uint16_t instance_id,          // PARM4 — 实例 ID
//       uint16_t eventgroup_id,        // PARM5 — 事件组 ID
//       uint16_t client_id             // PARM6 — 客户端 ID
//   )
//
// 客户端通过这个函数向服务端发送 SubscribeEventgroup 消息。
// 抓取 service_id + instance_id + eventgroup_id 用于统计。
// ═══════════════════════════════════════════════════════════════════════
SEC("uprobe/hook_sd_send_subscription")
int hook_sd_send_subscription(struct pt_regs *ctx)
{
    return submit_sd_event(
        ctx, HOOK_SD_SEND_SUB, DIR_SEND, false,
        PT_REGS_PARM3(ctx),     // arg0 = service_id
        PT_REGS_PARM4(ctx),     // arg1 = instance_id
        PT_REGS_PARM5(ctx),     // arg2 = eventgroup_id
        0);
}

// ═══════════════════════════════════════════════════════════════════════
// Hook 4: sd_handle_subscription — 处理收到的订阅请求
//
// 函数签名（很长）：
//   service_discovery_impl::handle_eventgroup_subscription(
//       uint16_t  service_id,         // PARM2
//       uint16_t  instance_id,        // PARM3
//       uint16_t  eventgroup_id,      // PARM4
//       uint8_t   major_version,      // PARM5
//       uint32_t  ttl,                // PARM6
//       uint16_t  counter,            // PARM7
//       const address&  src_addr,     // ...
//       ... 还有很多参数 ...
//   )
//
// 服务端收到客户端的 SubscribeEventgroup 请求时调用。
// 与 sd_send_subscription 配对可以追踪订阅时延。
// ═══════════════════════════════════════════════════════════════════════
SEC("uprobe/hook_sd_handle_subscription")
int hook_sd_handle_subscription(struct pt_regs *ctx)
{
    return submit_sd_event(
        ctx, HOOK_SD_HANDLE_SUB, DIR_RECV, false,
        PT_REGS_PARM2(ctx),     // arg0 = service_id
        PT_REGS_PARM3(ctx),     // arg1 = instance_id
        PT_REGS_PARM4(ctx),     // arg2 = eventgroup_id
        0);
}
