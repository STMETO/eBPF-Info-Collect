// vsomeip_types.h — SOME/IP 协议常量定义
//
// 这个文件定义了 SOME/IP 协议中所有用到的魔数、枚举值和常量。
// 同时被 BPF 内核态 C 代码和用户态 C++ 代码 #include，所以只能用 C 兼容语法。
//
// 内容分为以下几组：
//   1. Message Type（消息类型）     — header 第 14 字节，决定这条消息是什么
//   2. Return Code（返回码）        — header 第 15 字节，表示处理结果
//   3. Header Layout（报文头布局）  — 16 字节固定头，各字段的偏移量和大小
//   4. Direction（方向）            — 发送 vs 接收
//   5. Module ID（模块编号）        — routing / app / sd

#pragma once

// ═══════════════════════════════════════════════════════════════════════
// 第 1 组：SOME/IP Message Type — 消息类型
//
// 位置：SOME/IP header 的偏移 14（1 字节）
//
// 这是整个协议中最重要的分类字段。
// 每个 SOME/IP 消息必须属于以下 6 种类型之一。
// 用户态根据这个字段决定时延匹配的策略（见 stats_collector.cpp）。
//
// 类型语义速查：
//   REQUEST         客户端 → 服务端 的调用请求，服务端必须返回 RESPONSE 或 ERROR
//   REQUEST_NO_RET  客户端 → 服务端 的单向通知，服务端不回复（Fire & Forget）
//   NOTIFICATION    服务端 → 客户端 的事件推送（如值变化通知）
//   REQUEST_ACK     传输层确认（可靠传输模式下的 ACK，业务层不关心）
//   RESPONSE        服务端 → 客户端 的成功响应
//   ERROR           服务端 → 客户端 的错误响应（携带 return_code 说明原因）
// ═══════════════════════════════════════════════════════════════════════

#define SOMEIP_MT_REQUEST           0x00   // Request — 请求（期望得到 RESPONSE）
#define SOMEIP_MT_REQUEST_NO_RETURN 0x01   // Request No Return — 单向请求（不期待响应）
#define SOMEIP_MT_NOTIFICATION      0x02   // Notification — 事件通知（服务端主动推送）
#define SOMEIP_MT_REQUEST_ACK       0x40   // Request ACK — 传输层确认（底层可靠传输用）
#define SOMEIP_MT_RESPONSE          0x80   // Response — 成功响应
#define SOMEIP_MT_ERROR             0x81   // Error — 错误响应

// ═══════════════════════════════════════════════════════════════════════
// 第 2 组：SOME/IP Return Code — 返回码
//
// 位置：SOME/IP header 的偏移 15（1 字节）
//
// 当 message_type = RESPONSE 或 ERROR 时，这个字段表示处理结果。
// 当 message_type = REQUEST 时，这个字段通常为 0（发送方不填）。
//
// AUTOSAR 规范定义了 0x00~0x1F 为系统级错误，0x20~0x3F 为服务级错误，
// 0x40~0x5F 为方法级错误。这里列出最常见的 11 种。
// ═══════════════════════════════════════════════════════════════════════

#define SOMEIP_RC_OK                0x00   // E_OK — 成功，一切正常
#define SOMEIP_RC_E_NOT_OK          0x01   // E_NOT_OK — 一般性错误（未分类）
#define SOMEIP_RC_E_UNKNOWN_SERVICE 0x02   // E_UNKNOWN_SERVICE — 请求的 Service ID 不存在
#define SOMEIP_RC_E_UNKNOWN_METHOD  0x03   // E_UNKNOWN_METHOD — Service 存在但 Method ID 不认识
#define SOMEIP_RC_E_NOT_READY       0x04   // E_NOT_READY — 服务未就绪（尚未完成初始化）
#define SOMEIP_RC_E_NOT_REACHABLE   0x05   // E_NOT_REACHABLE — 目标不可达（网络不通）
#define SOMEIP_RC_E_TIMEOUT         0x06   // E_TIMEOUT — 调用超时
#define SOMEIP_RC_E_WRONG_PROTOCOL  0x07   // E_WRONG_PROTOCOL_VERSION — 协议版本不匹配
#define SOMEIP_RC_E_WRONG_INTERFACE 0x08   // E_WRONG_INTERFACE_VERSION — 接口版本不匹配
#define SOMEIP_RC_E_MALFORMED       0x09   // E_MALFORMED_MESSAGE — 报文反序列化失败（格式错误）
#define SOMEIP_RC_E_WRONG_MESSAGE   0x0A   // E_WRONG_MESSAGE_TYPE — 消息类型错误

// ═══════════════════════════════════════════════════════════════════════
// 第 3 组：SOME/IP Header 布局（Wire Format）
//
// 每个 SOME/IP 消息的开头都有一个 16 字节的固定头，网络字节序（大端）。
//
//   字节偏移    字段名             大小     说明
//   ──────────────────────────────────────────────────────────
//   [ 0: 1]    Service ID         2 字节   服务标识（如 0x1234）
//   [ 2: 3]    Method ID          2 字节   方法标识（bit 15 = 事件标志）
//   [ 4: 7]    Length             4 字节   总长度 = 16 (header) + payload 长度
//   [ 8: 9]    Client ID          2 字节   客户端标识（发送方的唯一 ID）
//   [10:11]    Session ID         2 字节   会话标识 ★ 时延匹配的核心 key 之一
//   [12]       Protocol Version   1 字节   协议主版本（通常为 1）
//   [13]       Interface Version  1 字节   服务接口版本
//   [14]       Message Type       1 字节   消息类型（见第 1 组定义）
//   [15]       Return Code        1 字节   返回码（见第 2 组定义）
//
// 这些偏移量在 BPF 代码中用于 read_someip_header() 函数
// 直接从 byte* 数据指针解析 header 字段：
//   service_id = (data[0] << 8) | data[1];
//   method_id  = (data[2] << 8) | data[3];
//   ...
// ═══════════════════════════════════════════════════════════════════════

#define SOMEIP_HEADER_SIZE          16     // SOME/IP header 固定大小（字节）

// 各字段在 header 中的字节偏移
#define SOMEIP_OFF_SERVICE_ID       0      // Service ID 偏移（uint16_t BE）
#define SOMEIP_OFF_METHOD_ID        2      // Method ID 偏移（uint16_t BE）
#define SOMEIP_OFF_LENGTH           4      // Length 偏移（uint32_t BE）
#define SOMEIP_OFF_CLIENT_ID        8      // Client ID 偏移（uint16_t BE）
#define SOMEIP_OFF_SESSION_ID       10     // Session ID 偏移（uint16_t BE）
#define SOMEIP_OFF_PROTOCOL_VER     12     // Protocol Version 偏移（uint8_t）
#define SOMEIP_OFF_INTERFACE_VER    13     // Interface Version 偏移（uint8_t）
#define SOMEIP_OFF_MESSAGE_TYPE     14     // ★ Message Type 偏移（uint8_t，最重要）
#define SOMEIP_OFF_RETURN_CODE      15     // Return Code 偏移（uint8_t）

// ═══════════════════════════════════════════════════════════════════════
// 第 4 组：消息方向
//
// 用于 vsomeip_event 的 direction 字段。
// SEND = 消息从本节点发出（发起方视角）
// RECV = 消息从网络收到（接收方视角）
// ═══════════════════════════════════════════════════════════════════════

#define DIR_SEND    0   // 发送方向（本节点是消息的发起方）
#define DIR_RECV    1   // 接收方向（本节点是消息的接收方）

// ═══════════════════════════════════════════════════════════════════════
// module_id 定义见 common/hook_ids.h（由 gen_hook_config.sh 自动生成）
// MODULE_ROUTING / MODULE_APP / MODULE_SD 等，权威来源是 hooks.json
// ═══════════════════════════════════════════════════════════════════════
