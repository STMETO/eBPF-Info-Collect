// common.bpf.h — 所有 BPF 模块共享的辅助函数
//
// 这个文件被三个 .bpf.c（routing / app / sd）同时 #include。
// 提供了两个核心辅助函数，封装了重复的逻辑：
//
//   1. fill_common()        — 填充事件的通用字段（PID / TID / 时间戳 / 模块信息）
//   2. read_someip_header() — 从用户态的 byte* 指针安全读取 16 字节 SOME/IP header
//
// 为什么要把它们抽成公共头文件？
//   - 三个模块的 handler 都要做一模一样的"填 PID、填时间戳"操作
//   - 重复代码 = 维护噩梦，改一处漏一处
//   - __always_inline 确保编译时内联展开，没有函数调用开销（BPF 不允许函数调用）
//
// 约束：
//   - 所有函数必须标记 __always_inline（BPF verifier 要求单条执行路径）
//   - 不能使用标准库（没有 memcpy，没有 printf）
//   - 访问用户态内存必须用 bpf_probe_read_user()，直接解引用会导致 verifier 拒绝
//   - 所有变量必须初始化（verifier 会拒绝未初始化的变量）

#pragma once

// ── BPF 必需的头文件 ─────────────────────────────────────────────────
#include "vmlinux.h"                  // 内核类型定义（从 vmlinux BTF 生成，包含所有内核结构体）
#include <bpf/bpf_helpers.h>          // BPF 辅助宏和 helper 函数声明
#include <bpf/bpf_tracing.h>          // PT_REGS_PARMx / PT_REGS_RC — 读取函数参数和返回值
#include <bpf/bpf_core_read.h>        // bpf_probe_read_user — 安全读取用户态内存
#include <bpf/bpf_endian.h>           // bpf_ntohs / bpf_htons — 字节序转换

// ── 项目公共头文件 ──────────────────────────────────────────────────
#include "../common/vsomeip_types.h"   // SOME/IP 协议常量（header 偏移量、message_type 等）
#include "../common/vsomeip_event.h"   // 事件结构体（BPF → 用户态的数据格式）

// ═══════════════════════════════════════════════════════════════════════
// fill_common — 填充事件的通用字段
//
// 每个 hook handler 在拿到 vsomeip_event 后，第一个调用的就是这个函数。
// 它负责填好所有与"具体是哪个 hook"无关的公共信息：
//
//   - timestamp_ns   : 当前时间（bpf_ktime_get_ns()），纳秒精度
//   - pid / tid      : 通过 bpf_get_current_pid_tgid() 获取（高 32 位 = PID，低 32 位 = TID）
//   - comm           : 进程名（bpf_get_current_comm()），最多 16 字节
//   - module_id      : 哪个模块（routing / app / sd）
//   - hook_id        : 模块内的 hook 编号（0~4）
//   - direction      : SEND / RECV
//   - is_retprobe    : 是不是 uretprobe（返回探测）
//
// 同时把所有可能由 caller 填充的字段先置零，
// 避免 caller 忘记填导致用户态读到垃圾数据。
//
// 参数：
//   e          — 指向 ringbuf 中已分配的事件的指针
//   module_id  — MODULE_ROUTING / MODULE_APP / MODULE_SD
//   hook_id    — 模块内编号（见 vsomeip_event.h 末尾的 #define）
//   direction  — DIR_SEND / DIR_RECV
//   is_retprobe— true=uretprobe, false=uprobe
//   ctx        — BPF 程序的上下文（struct pt_regs *），这里没有用到，保留给未来扩展
// ═══════════════════════════════════════════════════════════════════════

static __always_inline void fill_common(struct vsomeip_event *e,
                                         uint8_t module_id, uint8_t hook_id,
                                         uint8_t direction, bool is_retprobe,
                                         void *ctx)
{
    // ── 时间和身份信息 ──────────────────────────────────────────────
    // bpf_ktime_get_ns() 返回内核单调时钟（CLOCK_MONOTONIC），单位纳秒。
    // 注意：这个时钟不受系统时间调整影响，适合用来计算时间间隔（时延）。
    // 但不能直接对应到人类可读的"墙钟时间"（需要用户态用 clock_gettime 校准）。
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = pid_tgid >> 32;            // 高 32 位是 PID（进程 ID）
    e->tid = (uint32_t)pid_tgid;       // 低 32 位是 TID（线程 ID）
    bpf_get_current_comm(&e->comm, sizeof(e->comm));  // 进程名

    // ── 事件分类 ────────────────────────────────────────────────────
    e->module_id  = module_id;
    e->hook_id    = hook_id;
    e->direction  = direction;
    e->is_retprobe = is_retprobe;

    // ── 清零可选字段 ────────────────────────────────────────────────
    // 为什么要清零？
    //   BPF verifier 不允许 ringbuf 中残留内核栈的旧数据泄漏给用户态。
    //   bpf_ringbuf_reserve() 返回的内存可能包含之前被 submit 并消费后的残留数据。
    //   虽然 verifier 会自动拒绝未初始化的访问，但显式置零是最安全的做法。
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

// ═══════════════════════════════════════════════════════════════════════
// read_someip_header — 从用户态 byte* 指针安全读取 SOME/IP 报文头
//
// 这是 routing 模块的核心函数。
// routing_manager_impl::send() 的参数 data 指向用户态内存中序列化好的
// SOME/IP 报文。BPF 不能直接解引用用户态指针（会触发 page fault 或
// 被 verifier 拒绝），必须通过 bpf_probe_read_user() 安全读取。
//
// 函数流程：
//   1. 安全检查：data 不为空 && data_len ≥ 16（至少要有完整的 header）
//   2. 用 bpf_probe_read_user() 一次读 16 字节到内核栈上的局部数组
//   3. 按大端序（网络字节序）逐字段解析
//   4. 填入 vsomeip_event 的对应字段
//
// 参数：
//   e        — 要填充的事件
//   data     — 用户态内存中 SOME/IP 报文的起始地址
//   data_len — 报文总长度（字节数）
//
// 返回值：
//   0  = 成功读取并解析
//   -1 = data 为空 / data_len 不够 / bpf_probe_read_user 失败
//
// ★ 注意：
//   app 和 sd 模块不调用这个函数，因为它们的 hook 参数是 C++ 对象
//   （shared_ptr<message> 等），不是原始 byte*。
//   只有 routing 模块能直接拿到序列化后的字节流。
// ═══════════════════════════════════════════════════════════════════════

static __always_inline int read_someip_header(struct vsomeip_event *e,
                                               const unsigned char *data,
                                               uint32_t data_len)
{
    // ── 安全检查 ────────────────────────────────────────────────────
    // data 为 NULL 或长度不够 16 字节 → 放弃解析（返回 -1）
    // caller 不需要检查返回值，因为 fill_common 已经把 header 字段清零了
    if (!data || data_len < SOMEIP_HEADER_SIZE)
        return -1;

    // ── 安全读取 16 字节 ────────────────────────────────────────────
    // bpf_probe_read_user(dst, size, src) 是 BPF 内核提供的 helper 函数。
    // 它会在读取前检查 src 指向的内存是否在用户态地址空间内、是否已映射。
    // 如果读取失败（例如 data 指向已释放的内存），返回负值。
    //
    // 为什么一次读 16 字节而不是逐字段读？
    //   - 减少 bpf_probe_read_user 调用次数（这个 helper 有固定开销）
    //   - 一次读完整 header，保证所有字段来自同一个"快照"
    //     （如果在两次逐字段读之间，用户态刚好修改了 buffer，
    //       可能出现 service_id 是旧值、method_id 是新值的错位问题）
    unsigned char hdr[SOMEIP_HEADER_SIZE];
    if (bpf_probe_read_user(hdr, sizeof(hdr), data) < 0)
        return -1;

    // ── 逐字段解析（全部大端序 → 主机字节序） ──────────────────────
    // SOME/IP 协议规定 wire 上全部用大端序（big-endian）。
    // x86 和 ARM 的默认字节序是小端，所以需要手动转换。

    // Service ID (offset 0, 2 bytes)
    //   例如：hdr[0]=0x12, hdr[1]=0x34 → service_id = 0x1234
    e->service_id  = ((uint16_t)hdr[SOMEIP_OFF_SERVICE_ID  ] << 8) |
                      (uint16_t)hdr[SOMEIP_OFF_SERVICE_ID+1];

    // Method ID (offset 2, 2 bytes)
    //   例如：hdr[2]=0x00, hdr[3]=0x01 → method_id = 0x0001
    e->method_id   = ((uint16_t)hdr[SOMEIP_OFF_METHOD_ID   ] << 8) |
                      (uint16_t)hdr[SOMEIP_OFF_METHOD_ID+1];

    // Length (offset 4, 4 bytes) — 注意这是 32 位字段，需要移位 24/16/8/0
    //   这个长度包含 header 自身的 16 字节 + payload 长度
    e->payload_length = ((uint32_t)hdr[SOMEIP_OFF_LENGTH   ] << 24) |
                        ((uint32_t)hdr[SOMEIP_OFF_LENGTH+1 ] << 16) |
                        ((uint32_t)hdr[SOMEIP_OFF_LENGTH+2 ] << 8)  |
                         (uint32_t)hdr[SOMEIP_OFF_LENGTH+3];

    // Client ID (offset 8, 2 bytes)
    e->client_id   = ((uint16_t)hdr[SOMEIP_OFF_CLIENT_ID   ] << 8) |
                      (uint16_t)hdr[SOMEIP_OFF_CLIENT_ID+1];

    // Session ID (offset 10, 2 bytes)
    // ★ 这个字段是时延匹配的关键：同一个 session 的 REQUEST 和 RESPONSE
    //   共享相同的 session_id，用户态据此配对。
    e->session_id  = ((uint16_t)hdr[SOMEIP_OFF_SESSION_ID  ] << 8) |
                      (uint16_t)hdr[SOMEIP_OFF_SESSION_ID+1];

    // Protocol Version (offset 12, 1 byte) — 单字节，无需字节序转换
    e->protocol_version  = hdr[SOMEIP_OFF_PROTOCOL_VER];

    // Interface Version (offset 13, 1 byte)
    e->interface_version = hdr[SOMEIP_OFF_INTERFACE_VER];

    // ★ Message Type (offset 14, 1 byte) — 最重要的字段
    //   决定用户态如何处理这个事件（统计分桶 / 时延匹配）
    e->message_type      = hdr[SOMEIP_OFF_MESSAGE_TYPE];

    // Return Code (offset 15, 1 byte)
    e->return_code       = hdr[SOMEIP_OFF_RETURN_CODE];

    return 0;
}
