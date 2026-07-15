// vsomeip_event.h — BPF 内核态 → 用户态 的统一事件结构体
//
// 这是整个项目的核心数据抽象
//
// 三个 BPF 模块（routing / app / sd）在各自的 uprobe handler 里，
// 把捕获到的信息填进 struct vsomeip_event，然后通过 ring buffer 推给用户态。
// 用户态的 collector 从 ring buffer 读出这个结构体，交给 stats_collector
// 和 log_writer 做统计和日志输出。
//
// 数据流：
//   someipd 进程调用某个函数
//     → BPF uprobe 触发
//     → handler 从 bpf_ringbuf_reserve() 分配一个 vsomeip_event
//     → fill_common() 填充 PID / TID / comm / 时间戳 / 模块ID
//     → 特定 handler 填充 hook_id / direction / arg0-arg2 / SOME/IP header
//     → bpf_ringbuf_submit() 推给用户态
//     → 用户态 ring_buffer__consume() 读到这个结构体
//     → stats_collector.process_event() 处理 → 计数器 / 时延匹配
//     → log_writer.write() 输出到终端或文件
//
// 设计原则：
//   1. 所有模块共用同一个结构体，简化用户态代码
//   2. 大小 ≤ 256 字节，保证 ring buffer 单页即可容纳
//   3. 每个字段都有明确的语义和来源（哪个 hook、哪个参数）
//   4. 不同模块用同一组字段表达不同的含义（约定优于配置）
//
// 重要约束：
//   - 此文件同时被 BPF C 代码和用户态 C++ 代码 #include
//   - 只能用 C 兼容的语法（不能有 extern "C"、class、template 等）
//   - BPF 代码运行在内核态，只能使用 __attribute__((packed)) 等内核兼容语法

#pragma once

// 此文件同时被 BPF C 和用户态 C++ 使用，两边类型来源不同
#ifdef __BPF__
    // BPF 环境：vmlinux.h（由 common.bpf.h 先引入）提供了 __u8/__u16 等
    // 用它们 typedef 出标准 C 类型名，保持 struct 定义一致
    typedef __u8  uint8_t;
    typedef __u16 uint16_t;
    typedef __u32 uint32_t;
    typedef __u64 uint64_t;
    typedef __s64 int64_t;
    // bool 类型由 bpf_helpers.h 提供，这里用 _Bool 替代
    #define bool _Bool
#else
    // 用户态环境：使用标准 C 头文件
    #include <stdint.h>
    #include <stdbool.h>
#endif

// ── 常量定义 ──────────────────────────────────────────────────────────
#define TASK_COMM_LEN   16    // 进程名最大长度（Linux 内核限制）
#define EVENT_PADDING   24    // 预留空间（未来扩展用，保持向后兼容）

// ═══════════════════════════════════════════════════════════════════════
// struct vsomeip_event — BPF → 用户态 的单个事件
// ═══════════════════════════════════════════════════════════════════════

struct vsomeip_event {

    // ── 第 1 组：所有模块都会填充的通用字段 ──────────────────────────
    //         这些字段由 common.bpf.h 中的 fill_common() 设置

    uint64_t timestamp_ns;          // 事件发生时间戳（纳秒，bpf_ktime_get_ns()）
                                    //   → 用户态用于计算时延、排序事件

    uint32_t pid;                   // 触发事件的进程 PID
                                    //   → 例如 someipd 的进程 ID

    uint32_t tid;                   // 触发事件的线程 TID
                                    //   → vsomeip 是多线程的，不同线程处理不同消息

    char     comm[TASK_COMM_LEN];   // 进程/线程名称（bpf_get_current_comm()）
                                    //   → 例如 "someipd"、"routingmana"（截断到 16 字节）

    // ── 第 2 组：事件分类字段 ────────────────────────────────────────
    //         用户态根据这几个字段决定如何处理事件

    uint8_t  module_id;             // 来自哪个 BPF 模块
                                    //   MODULE_ROUTING = 1  （路由层）
                                    //   MODULE_APP     = 2  （应用层）
                                    //   MODULE_SD      = 3  （服务发现）

    uint8_t  hook_id;               // 模块内部的具体 hook 编号
                                    //   每个模块有自己的一组编号，见文件末尾的 #define

    uint8_t  direction;             // 消息方向
                                    //   DIR_SEND = 0  （发送方向）
                                    //   DIR_RECV = 1  （接收方向）

    bool     is_retprobe;           // 是否为 uretprobe（函数返回探测）
                                    //   true  = 这是函数的返回点（可以读取返回值）
                                    //   false = 这是函数的入口点（可以读取参数）

    // ── 第 3 组：函数参数 ────────────────────────────────────────────
    //      不同 hook 用这几个字段表达不同的含义，约定如下：

    uint64_t arg0;                  // ★ 含义因 hook 而异：
                                    //   routing hook: 通常为 0（routing 直接读 byte*）
                                    //   app hook:     this 指针（application_impl*）
                                    //   sd hook:      service_id（uint16_t 扩展为 u64）

    uint64_t arg1;                  // ★ 含义因 hook 而异：
                                    //   routing hook: data 指针（byte* 起始地址）
                                    //   app hook:     message 裸指针
                                    //   sd hook:      instance_id / is_required

    uint64_t arg2;                  // ★ 含义因 hook 而异（不常用，预留）：
                                    //   routing hook: data_len（字节数）
                                    //   sd hook:      eventgroup_id

    int64_t  retval;                // ★ 仅 uretprobe（is_retprobe = true）时有效
                                    //   函数的返回值：
                                    //     0  = 成功
                                    //    <0  = 错误码（负值）
                                    //   >0  = 某些函数返回的正整数值（如 getter）

    // ── 第 4 组：SOME/IP 报文头 ──────────────────────────────────────
    //      ★ 只有 routing 模块能可靠填充这组字段 ★
    //      因为 routing 的 hook 直接拿到 byte* data 指针，
    //      通过 read_someip_header() 从字节流解析出来。
    //      app 和 sd 模块的 hook 参数是 C++ 对象，BPF 无法解引用，
    //      所以它们的这组字段全为 0。
    //
    //      SOME/IP header 在 wire 上的布局（16 字节，大端序）：
    //        [0:1]   Service ID       (uint16_t BE)
    //        [2:3]   Method ID        (uint16_t BE)
    //        [4:7]   Length           (uint32_t BE, 包含 header 自身 + payload)
    //        [8:9]   Client ID        (uint16_t BE)
    //        [10:11] Session ID       (uint16_t BE)
    //        [12]    Protocol Version (uint8_t)
    //        [13]    Interface Version(uint8_t)
    //        [14]    Message Type     (uint8_t, ★ 核心分类字段)
    //        [15]    Return Code      (uint8_t)

    uint16_t service_id;            // SOME/IP Service ID
                                    //   例如 0x1234 = 某个具体的服务

    uint16_t method_id;             // SOME/IP Method ID
                                    //   bit 15-0: 方法编号
                                    //   例如 0x0001 = 服务的第一个方法

    uint16_t client_id;             // SOME/IP Client ID
                                    //   发送方的标识，用于区分不同的客户端

    uint16_t session_id;            // SOME/IP Session ID
                                    //   单次会话标识，REQUEST 和对应的 RESPONSE 共享同一个 session_id
                                    //   ★ 时延匹配的关键字段之一

    uint8_t  protocol_version;      // SOME/IP Protocol Version（通常为 1）

    uint8_t  interface_version;     // SOME/IP Interface Version（服务接口的版本号）

    uint8_t  message_type;          // ★ SOME/IP Message Type（最重要的分类字段）
                                    //   见 vsomeip_types.h 中的定义：
                                    //     0x00 = REQUEST         请求（期望响应）
                                    //     0x01 = REQUEST_NORET  请求（不期望响应）
                                    //     0x02 = NOTIFICATION   事件通知
                                    //     0x40 = REQUEST_ACK    传输层确认
                                    //     0x80 = RESPONSE       响应
                                    //     0x81 = ERROR          错误响应
                                    //
                                    //   用户态根据这个字段决定：
                                    //   - 是否加入 pending 表等待匹配（REQUEST/REQ_NORET）
                                    //   - 是否尝试匹配时延（RESPONSE/ERROR/NOTIFICATION）
                                    //   - 按类型分桶统计

    uint8_t  return_code;           // SOME/IP Return Code
                                    //   0x00 = E_OK              成功
                                    //   0x01 = E_NOT_OK          一般错误
                                    //   0x02 = E_UNKNOWN_SERVICE 未知服务
                                    //   0x03 = E_UNKNOWN_METHOD  未知方法
                                    //   0x04 = E_NOT_READY       服务未就绪
                                    //   0x05 = E_NOT_REACHABLE   不可达
                                    //   0x06 = E_TIMEOUT         超时
                                    //   0x07 = E_WRONG_PROTOCOL  协议版本错误
                                    //   0x08 = E_WRONG_INTERFACE 接口版本错误
                                    //   0x09 = E_MALFORMED       报文格式错误
                                    //   0x0A = E_WRONG_MESSAGE   消息类型错误

    uint32_t payload_length;        // SOME/IP Payload Length
                                    //   注意：这是 header 中声明的长度字段（含 header 自身 16 字节）
                                    //   实际 payload = payload_length - 16

    // ── 第 5 组：预留扩展 ────────────────────────────────────────────
    uint8_t  reserved[EVENT_PADDING];  // 24 字节预留空间
                                       //   未来可能添加：CPU ID、调用栈深度、延迟计数器等
};

// ── 编译期大小检查 ───────────────────────────────────────────────────
// 确保结构体 ≤ 256 字节，保证能在 ring buffer 的单页（4KB）内高效传输。
#ifdef __cplusplus
    static_assert(sizeof(struct vsomeip_event) <= 256,
        "vsomeip_event 太大！请检查是否添加了过多字段。ring buffer 要求 ≤ 256 字节");
#else
    _Static_assert(sizeof(struct vsomeip_event) <= 256,
        "vsomeip_event 太大！请检查是否添加了过多字段。ring buffer 要求 ≤ 256 字节");
#endif

// ═══════════════════════════════════════════════════════════════════════
// Hook ID 编号定义（每个模块内部独立编号，从 0 开始）
//
// 这些编号用于区分同一个模块内不同 hook 产生的事件。
// 用户态按 (module_id, hook_id) 二元组唯一定位到一个 hook。
// ═══════════════════════════════════════════════════════════════════════

// ── routing 模块 hook（5 个）─────────────────────────────────────────
// 见 bpf/routing.bpf.c — 挂载到 routing_manager_impl 的核心收发函数
#define HOOK_RM_SEND_ENTRY      0    // rm_send_entry     发送入口（读 byte* → header）
#define HOOK_RM_SEND_RET        1    // rm_send_ret       发送返回（成功/失败）
#define HOOK_RM_SEND_TO_ENTRY   2    // rm_send_to_entry  端点定向发送入口
#define HOOK_RM_SEND_TO_RET     3    // rm_send_to_ret    端点定向发送返回
#define HOOK_RM_ON_MESSAGE      4    // rm_on_message     消息接收入口

// ── app 模块 hook（3 个）─────────────────────────────────────────────
// 见 bpf/app.bpf.c — 挂载到 application_impl 的应用层函数
#define HOOK_APP_SEND_ENTRY     0    // app_send_entry    应用层发送入口
#define HOOK_APP_SEND_RET       1    // app_send_ret      应用层发送返回
#define HOOK_APP_ON_MESSAGE     2    // app_on_message    消息投递到应用

// ── sd 模块 hook（4 个）──────────────────────────────────────────────
// 见 bpf/sd.bpf.c — 挂载到 service_discovery_impl 的 SD 函数
#define HOOK_SD_SEND            0    // sd_send               SD 消息刷新到网络
#define HOOK_SD_PROCESS_OFFER   1    // sd_process_offer      收到 OfferService
#define HOOK_SD_SEND_SUB        2    // sd_send_subscription  发送 SubscribeEventgroup
#define HOOK_SD_HANDLE_SUB      3    // sd_handle_subscription 处理订阅请求
