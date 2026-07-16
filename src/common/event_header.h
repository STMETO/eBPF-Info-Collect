// event_header.h — 所有 BPF 事件结构体的公共头
//
// ★ 设计：Common Header + 任意 Payload ★
//
// 每个模块定义自己的事件结构体，但必须以 event_header 作为第一个字段。
// 用户态 ringbuf 回调先用 event_header* 读公共头（知道 module_id + hook_id），
// 再强转到具体类型。
//
//    BPF 侧                     ringbuf                      用户态
//   ──────                     ───────                      ──────
//   routing_event {             [字节流]                    event_header*
//     hdr  ← 公共头                │                       → module_id=1
//     service_id                   │                       → (routing_event*)
//     method_id                    │
//     ...                          │
//   }                              │
//   sd_event {                     │                       event_header*
//     hdr  ← 公共头（完全一样）     │                       → module_id=3
//     service_id                   │                       → (sd_event*)
//     instance_id                  │
//     ...                          │
//   }                              ▼

#pragma once

#ifdef __BPF__
    // BPF 环境：类型由 vmlinux.h 提供
    typedef __u8  uint8_t;
    typedef __u16 uint16_t;
    typedef __u32 uint32_t;
    typedef __u64 uint64_t;
    typedef __s64 int64_t;
    #define bool _Bool
#else
    #include <stdint.h>
    #include <stdbool.h>
#endif

// ── 公共头（所有事件结构体的第一个字段必须是它）────────────────────────

struct event_header {
    uint64_t timestamp_ns;          // bpf_ktime_get_ns()
    uint32_t pid;                   // 进程 ID
    uint32_t tid;                   // 线程 ID
    char     comm[16];              // 进程名
    uint8_t  module_id;             // MODULE_ROUTING / MODULE_APP / MODULE_SD
    uint8_t  hook_id;               // 模块内 hook 编号（从 0 开始）
    uint8_t  direction;             // DIR_SEND / DIR_RECV
    bool     is_retprobe;           // true = uretprobe
};
