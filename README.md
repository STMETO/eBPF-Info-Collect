# eBPF-Info-collect — 基于 eBPF uprobe 的 SOME/IP 流量采集器

## 项目简介

使用 eBPF uprobe 在 **vsomeip** 进程内挂载探测点，采集所有 SOME/IP 消息的收发信息。

- **消息统计**：按消息类型（REQUEST / RESPONSE / NOTIFICATION / ERROR）分类计数
- **时延测量**：匹配 REQUEST → RESPONSE 对，计算往返时延（RTT），输出 p50/p99/max
- **成功/失败追踪**：通过 uretprobe 捕获函数返回值，统计发送成功率
- **多维度覆盖**：同时监控路由层、应用层、服务发现层

**适用场景**：车载 SOA 架构下 SOME/IP 通信质量监控与问题排查。

---

## 架构概览

```
                     ┌── BPF 内核态 ──────────────────────────┐
 someipd 进程        │                                        │
   │                 │  routing.bpf.c  (5 hooks)              │
   ├─ send() ───────▶│  app.bpf.c      (3 hooks)              │
   ├─ on_message() ─▶│  sd.bpf.c       (4 hooks)              │
   │                 │     ↓ ring buffer                      │
   └─────────────────┴────────────────────────────────────────┘
                               │ epoll
                               ▼
                     ┌── 用户态 C++ ───────────────────────────┐
                     │                                        │
                     │  CollectorManager (epoll 多路复用)       │
                     │    └─ Collector × N（每模块一个实例）     │
                     │                                        │
                     │  StatsCollector (计数器 + 时延匹配)      │
                     │    └─ process_event() 通用入口           │
                     │    └─ pending 哈希表 (REQUEST→RESPONSE)  │
                     │                                        │
                     │  LogWriter (日志输出)                    │
                     │    ├─ StdoutWriter (终端，人类可读/JSON) │
                     │    └─ FileWriter  (文件，JSON)          │
                     │                                        │
                     │  Handler (每模块一个 .cpp)               │
                     │    ├─ routing_handler.cpp               │
                     │    ├─ app_handler.cpp                   │
                     │    └─ sd_handler.cpp                   │
                     └────────────────────────────────────────┘
```

**核心设计理念**：Common Header + 任意 Payload。每个模块定义自己的事件结构体，第一个字段必须是 `event_header`。BPF 提交任意大小的事件，用户态 ringbuf 回调先读公共头（知道 module_id），再交给对应模块的 handler 处理。collector / stats / writer 三层都不需要知道具体模块的类型。

---

## 目录结构

```
eBPF-Info-collect/
│
├── README.md
├── Makefile                           # 构建系统（BPF 编译 → embed → 链接）
├── .gitignore
│
├── config/
│   └── hooks.json                     # ★ 配置文件（每个模块的文件名/hook/偏移来源）
│
├── scripts/
│   ├── export_symbol.sh               # 从 ELF 提取符号偏移（mangled + demangled）
│   ├── gen_hook_config.sh             # 读 hooks.json → 生成 src/gen/ 下所有头文件
│   └── embed_bpf.sh                   # xxd -i 把 .bpf.o 转成嵌入头文件
│
├── symbol/                            # 本地 .so 文件（提取偏移用）
├── symbol-offsets/                    # 偏移表（export_symbol.sh 输出）
│
├── vmlinux/                           # BTF 类型头文件
│   └── arm64/vmlinux_601.h            # ★ ARM64 Linux 6.1
│
├── lib/
│   ├── libbpf/                        # libbpf 静态库
│   ├── bpftool/                       # BPF 工具
│   └── vsomeip/                       # vsomeip 源码（git submodule）
│
└── src/
    ├── gen/                           # ★ 自动生成（git ignore）
    │   ├── hook_config.h              #   file_groups[] + handler 指针
    │   ├── hook_ids.h                 #   MODULE_* + HOOK_* 宏定义
    │   ├── embed_data.cpp             #   统一包含所有 embed 头文件
    │   └── embed/                     #   xxd -i 生成的 BPF 字节数组
    │
    ├── common/                        # ★ BPF ↔ 用户态 共享头文件
    │   ├── event_header.h             #   公共头（所有事件结构体的第一个字段）
    │   ├── vsomeip_types.h            #   SOME/IP 协议常量（message_type 等）
    │   ├── routing_event.h            #   routing 模块事件结构体
    │   ├── app_event.h                #   app 模块事件结构体
    │   └── sd_event.h                 #   sd 模块事件结构体
    │
    ├── bpf/                           # BPF 内核态代码（C，每个模块一个 .bpf.c）
    │   ├── common.bpf.h               #   公共辅助：fill_header() / read_someip_header()
    │   ├── routing.bpf.c              #   路由层（5 hooks）
    │   ├── app.bpf.c                  #   应用层（3 hooks）
    │   └── sd.bpf.c                   #   服务发现（4 hooks）
    │
    └── user/                          # 用户态加载器（C++）
        ├── main.cpp                   #   入口：CLI 参数解析 + 组装所有组件
        │
        ├── collector/
        │   ├── collector_base.h       #   抽象接口 + EventContext 结构体
        │   ├── collector.h            #   通用 Collector 实现（配置驱动）
        │   ├── collector.cpp
        │   ├── collector_manager.h    #   epoll 多路复用 + 生命周期管理
        │   └── collector_manager.cpp
        │
        ├── stats/
        │   ├── stats_collector.h      #   统计收集 + 时延匹配
        │   └── stats_collector.cpp
        │
        ├── output/
        │   ├── log_writer.h           #   日志输出接口 + format_callback_t 类型
        │   ├── stdout_writer.h        #   终端输出
        │   ├── stdout_writer.cpp
        │   ├── file_writer.h          #   文件输出
        │   └── file_writer.cpp
        │
        └── handler/                   # ★ 每个模块的事件处理器
            ├── routing_handler.cpp    #   format_payload + on_latency 回调
            ├── app_handler.cpp
            └── sd_handler.cpp
```

---

## Hook 清单（12 个，3 个模块）

| 模块 | Hook | 探头 | 挂载函数 |
|------|------|:---:|------|
| routing | `rm_send_entry` | uprobe | `routing_manager_impl::send(byte*, ...)` |
| routing | `rm_send_ret` | uretprobe | 同上 |
| routing | `rm_send_to_entry` | uprobe | `routing_manager_impl::send_to(byte*, ...)` |
| routing | `rm_send_to_ret` | uretprobe | 同上 |
| routing | `rm_on_message` | uprobe | `routing_manager_impl::on_message(byte*, ...)` |
| app | `app_send_entry` | uprobe | `application_impl::send(shared_ptr<message>)` |
| app | `app_send_ret` | uretprobe | 同上 |
| app | `app_on_message` | uprobe | `application_impl::on_message(...)` |
| sd | `sd_send` | uprobe | `service_discovery_impl::send(bool)` |
| sd | `sd_process_offer` | uprobe | `process_offerservice_serviceentry(...)` |
| sd | `sd_send_subscription` | uprobe | `send_subscription(...)` |
| sd | `sd_handle_subscription` | uprobe | `handle_eventgroup_subscription(...)` |

---

## 数据流

```
1. 启动
   main.cpp
     → 解析 CLI（-p PID / -o output / --json / --enable / -s stats_interval）
     → 创建 StdoutWriter / FileWriter
     → 创建 StatsCollector + EventContext{&stats, writer}
     → manager.set_event_context(&stats, writer)
     → 遍历 file_groups[]，创建 Collector(&file_groups[i])
     → manager.init_all()       // 从嵌入字节码加载所有 BPF
     → manager.attach_all(pid)  // 注入 EventContext → 偏移量挂载 uprobe → 创建 ringbuf

2. 运行时（每个 SOME/IP 消息触发一次）
   someipd 调用 routing_manager_impl::send(byte* data, ...)
     → BPF uprobe 触发
     → routing.bpf.c: hook_rm_send_entry()
         → bpf_ringbuf_reserve(&routing_events, sizeof(struct routing_event))
         → fill_header(&e->hdr, MODULE_ROUTING, HOOK_RM_SEND_ENTRY, ...)
         → read_someip_header(e, data, len)
         → bpf_ringbuf_submit(e)

     → epoll_wait 返回 ringbuf fd 可读
     → ring_buffer__consume()
     → collector.cpp: ringbuf_callback()
         → hdr = (event_header*)data
         → group_->handler(data, hook_name, stats, writer)  // ★ handler 指针

            ┌─ routing_handler.cpp: routing_event_handler()
            │   ├─ stats->process_event(&e->hdr, data, hook, e->retval, on_latency)
            │   │   ├─ 计数器累加（total / succ / fail）
            │   │   ├─ 模块收发量累加
            │   │   └─ on_latency(payload, hook, this)
            │   │       ├─ record_pending() // REQUEST → pending[key] = timestamp
            │   │       └─ try_match()      // RESPONSE → latency = now - pending[key]
            │   │
            │   └─ writer->write_event(&e->hdr, data, hook, format_payload)
            │       ├─ 公共头格式化（ts / pid / tid / comm / module / hook / dir）
            │       └─ format_payload() → 模块特有字段格式化
            │
            └─ 日志输出 → stdout / file

3. 定时（每 N 秒，默认 10s）
   CollectorManager 事件循环中调用：
     → stats.flush_report()
         ├─ 每个模块的收发量统计
         ├─ 时延统计（avg / p50 / p99 / max）
         └─ hook 调用计数
     → stats.evict_expired()
         └─ 清理 pending 表中超过 30 秒的条目

4. 停止
   Ctrl+C → SIGINT → g_running=0
     → stats.flush_report()     // 最后一次统计
     → stats.evict_expired()
     → manager.shutdown()       // detach + destroy
```

---

## 代码阅读顺序

按自底向上，从基础定义到入口：

| 层 | 顺序 | 文件 | 读什么 |
|---|:---:|------|------|
| 基础定义 | 1 | `src/common/vsomeip_types.h` | SOME/IP 协议常量：message_type、header 布局 |
| 基础定义 | 2 | `src/common/event_header.h` | ★ 公共头结构体，所有事件的前几个字节 |
| 基础定义 | 3 | `src/common/routing_event.h` | routing 模块的私有事件结构体 |
| 基础定义 | 4 | `src/common/app_event.h` | app 模块的私有事件结构体 |
| 基础定义 | 5 | `src/common/sd_event.h` | sd 模块的私有事件结构体 |
| 接口 | 6 | `src/user/collector/collector_base.h` | Collector 抽象接口 + EventContext |
| 接口 | 7 | `src/user/output/log_writer.h` | 日志输出接口 + format_callback_t |
| 接口 | 8 | `src/user/stats/stats_collector.h` | 统计接口 + stats_callback_t |
| 核心实现 | 9 | `src/user/collector/collector.cpp` | ★ BPF 加载 / uprobe 挂载 / ringbuf 消费 |
| 核心实现 | 10 | `src/user/collector/collector_manager.cpp` | epoll 多路复用 + 生命周期管理 |
| 核心实现 | 11 | `src/user/stats/stats_collector.cpp` | ★ 计数器 + 时延匹配算法 |
| 输出 | 12 | `src/user/output/stdout_writer.cpp` | 终端输出（人类可读 + JSON） |
| 输出 | 13 | `src/user/output/file_writer.cpp` | 文件输出 |
| handler | 14 | `src/user/handler/routing_handler.cpp` | ★ format_payload + on_latency 回调示例 |
| handler | 15 | `src/user/handler/app_handler.cpp` | 只做格式化，不做时延匹配 |
| handler | 16 | `src/user/handler/sd_handler.cpp` | 同上 |
| 入口 | 17 | `src/user/main.cpp` | CLI 入口：组装所有组件 |
| BPF | 18 | `src/bpf/common.bpf.h` | BPF 辅助函数：fill_header / read_someip_header |
| BPF | 19 | `src/bpf/routing.bpf.c` | ★ routing BPF handler |
| BPF | 20 | `src/bpf/app.bpf.c` | app BPF handler |
| BPF | 21 | `src/bpf/sd.bpf.c` | sd BPF handler |
| 配置 | 22 | `config/hooks.json` | 模块和 hook 配置 |
| 脚本 | 23 | `scripts/export_symbol.sh` | readelf → 计算文件偏移 |
| 脚本 | 24 | `scripts/gen_hook_config.sh` | hooks.json → 生成头文件 |
| 生成 | 25 | `src/gen/hook_config.h` | 自动生成的 file_groups[]（构建后查看） |
| 生成 | 26 | `src/gen/hook_ids.h` | 自动生成的 MODULE_*/HOOK_* 宏 |

---

## 构建

```bash
# 1. 提取符号偏移（每次更新 symbol/ 下的 .so 后执行）
./scripts/export_symbol.sh

# 2. 生成配置头文件
./scripts/gen_hook_config.sh

# 3. 编译
make

# 产物：build/vsomeip_collector（单文件，BPF 字节码嵌入其中）
```

---

## 使用

```bash
# 监控所有进程，终端人类可读输出
vsomeip_collector

# 只监控 PID 1234
vsomeip_collector -p 1234

# JSON 格式写入文件
vsomeip_collector --json -o file -f /tmp/vsomeip.log

# 只开启 routing 和 app 模块，每 5 秒输出统计
vsomeip_collector --enable routing,app -s 5

# 查看帮助
vsomeip_collector -h
```

**输出示例：**

```
[R] 14:32:01.234567  PID:1234   TID:5678   someipd   rm_send_entry       SEND
  svc=0x1234 method=0x0001 client=0x5678 session=0x9ABC type=REQUEST(0x00) rc=0x00 payload=64

[LATENCY] {"svc":4660,"method":1,"client":22136,"session":39612,"type":"RESPONSE","latency_us":334.2}

[STATS] {"module":"routing","elapsed":10.0,"send":5000,"recv":4800}
[STATS] {"type":"latency","samples":4800,"avg_us":234,"p50_us":150,"p99_us":850,"max_us":5000}
```

---

## 新增一个模块

以新增 `abc` 模块为例，需要 hook `xyz::hij_impl::ght(bool, bool)` 函数（挂在 `/usr/lib/xyz.so.3`）。

### 前提

- 目标 `.so` 文件已放到 `symbol/` 目录
- 已运行 `./scripts/export_symbol.sh` 提取偏移
- 在 `symbol-offsets/` 中可以查到 `xyz::hij_impl::ght(bool, bool)` 的 FILE_OFFSET

### 第 1 步：定义事件结构体 `src/common/abc_event.h`

```c
#pragma once
#include "event_header.h"

struct abc_event {
    // ★ 第一个字段必须是 event_header
    struct event_header hdr;

    // 自定义字段（想抓什么就定义什么）
    uint64_t param_bool1;       // bool 参数 1
    uint64_t param_bool2;       // bool 参数 2
    int64_t  retval;            // uretprobe 返回值
};
```

### 第 2 步：写 BPF 内核代码 `src/bpf/abc.bpf.c`

```c
#include "common.bpf.h"
#include "../common/abc_event.h"
#include "../gen/hook_ids.h"     // HOOK_* 宏

char LICENSE[] SEC("license") = "GPL";

// ringbuf map（名称和 hooks.json 中保持一致）
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 128 * 1024);
} abc_events SEC(".maps");

// 通用提交函数
static __always_inline int submit_abc(void *ctx, uint8_t hook_id,
    uint8_t dir, bool is_ret, int64_t retval)
{
    struct abc_event *e;
    e = bpf_ringbuf_reserve(&abc_events, sizeof(*e), 0);
    if (!e) return 0;

    fill_header(&e->hdr, MODULE_ABC, hook_id, dir, is_ret);
    e->retval = retval;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Hook: ght 函数入口
SEC("uprobe/ght")
int hook_ght(struct pt_regs *ctx)
{
    return submit_abc(ctx, HOOK_GHT, DIR_SEND, false, 0);
}
```

### 第 3 步：写 handler `src/user/handler/abc_handler.cpp`

```c
#include "../../common/abc_event.h"
#include "../stats/stats_collector.h"
#include "../output/log_writer.h"
#include <cstdio>
#include <cinttypes>

// ★ payload 格式化回调：决定 abc 事件的日志输出格式
static void format_abc(const void* data, const char* /*hook*/,
                       char* buf, size_t size)
{
    auto* e = static_cast<const abc_event*>(data);
    snprintf(buf, size,
             "\"param1\":%" PRIu64 ",\"param2\":%" PRIu64 ",\"retval\":%" PRId64,
             e->param_bool1, e->param_bool2, e->retval);
}

// ★ 可选：自定义统计回调
// static void abc_custom_stats(const void* data, const char* hook,
//                               StatsCollector* self)
// {
//     auto* e = static_cast<const abc_event*>(data);
//     // 自定义统计逻辑...
// }

// ★ 必须有的统一入口（函数名 = {name}_event_handler）
extern "C"
void abc_event_handler(const void *data, const char *hook,
                       StatsCollector *stats, ILogWriter *writer)
{
    auto *e = static_cast<const abc_event*>(data);

    // 通用统计，不需要时延匹配则 on_latency 传 nullptr
    stats->process_event(&e->hdr, data, hook, e->retval, nullptr);

    // 通用输出，传入自定义格式化回调
    writer->write_event(&e->hdr, data, hook, format_abc);
}
```

### 第 4 步：配置 `config/hooks.json`

在 `files[]` 数组中加一条：

```json
{
    "name": "abc",
    "ringbuf_map": "abc_events",
    "module_id": 4,
    "lib": "xyz.so.3",
    "target_path": "/usr/lib/xyz.so.3",
    "hooks": [
        {
            "name": "ght",
            "demangled": "xyz::hij_impl::ght(bool, bool)",
            "retprobe": false
        }
    ]
}
```

- `name`：模块名，用于生成 handler 函数名 `abc_event_handler` 和 embed 数组名 `abc_bpf_o`
- `ringbuf_map`：和 `.bpf.c` 中的 map 名称一致
- `module_id`：全局唯一，不重复即可
- `lib`：`symbol/` 下的 `.so` 文件名，用于查偏移表
- `target_path`：目标机器上的库路径
- `hooks[]`：要 hook 的函数列表，`name` 是 SEC 名

### 第 5 步：重新生成 + 编译

```bash
./scripts/export_symbol.sh         # 重新提取偏移
./scripts/gen_hook_config.sh       # 重新生成头文件
make                                # 编译
```

### 新增模块需要改动的文件汇总

| 文件 | 操作 | 说明 |
|------|:---:|------|
| `src/common/abc_event.h` | 新建 | 事件结构体 |
| `src/bpf/abc.bpf.c` | 新建 | BPF 内核代码 |
| `src/user/handler/abc_handler.cpp` | 新建 | 自定义处理逻辑 |
| `config/hooks.json` | 修改 | 加一条 `files[]` 条目 |
| `symbol/xyz.so.3` | 放入 | 本地 .so 文件 |

### 不需要改动的文件

| 文件 | 原因 |
|------|------|
| `collector.cpp` | handler 指针由配置驱动 |
| `collector_manager.cpp` | 遍历 `file_groups[]`，自动覆盖 |
| `stats_collector.cpp` | `process_event()` 通用入口，数组按 `MAX_MODULE_ID` 自动扩容 |
| `stdout_writer.cpp` | `write_event()` 通用入口，payload 格式化交给回调 |
| `file_writer.cpp` | 同上 |
| `main.cpp` | 遍历 `file_groups[]` 创建 Collector |

---

## 设计要点

- **偏移量挂载**：`bpf_program__attach_uprobe_opts(prog, pid, lib_path, file_offset, opts)` — 不依赖目标机器的符号表，通过 ELF section header 计算的文件偏移挂载
- **ARM64 目标**：`vmlinux/vmlinux.h` 指向 `arm64/vmlinux_601.h`（Linux 6.1）
- **BPF 字节码嵌入**：`xxd -i` 把 `.bpf.o` 转成 C 数组，编译时嵌入可执行文件，部署无需额外文件
- **Common Header**：所有事件结构体以 `event_header` 开头，用户态通过 module_id 分发到对应 handler
- **配置驱动**：`hooks.json` → `gen_hook_config.sh` → 自动生成 `file_groups[]`、`hook_ids.h`、`embed_data.cpp`
- **三层解耦**：collector（加载+挂载）、stats（计数+时延）、writer（日志）都不需要知道模块类型，所有类型相关的逻辑在 handler 的回调函数里
