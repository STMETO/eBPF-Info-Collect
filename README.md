# eBPF-Info-collect — 基于 eBPF uprobe 的 SOME/IP 流量采集器

## 项目简介

本项目使用 eBPF uprobe 技术，在 **vsomeip** 进程内挂载探测点（hook），
采集所有 SOME/IP 消息的收发信息。核心能力：

- **消息统计**：按消息类型（REQUEST / RESPONSE / NOTIFICATION / ERROR）分类计数
- **时延测量**：匹配 REQUEST → RESPONSE 对，计算往返时延（RTT），输出 p50/p99/max
- **成功/失败追踪**：通过 uretprobe 捕获函数返回值，统计发送成功率和失败率
- **多维度覆盖**：同时监控路由层、应用层、服务发现层

**适用场景**：车载 SOA 架构下的 SOME/IP 通信质量监控与问题排查。

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
                    │    ├─ RoutingCollector                  │
                    │    ├─ AppCollector                      │
                    │    └─ SdCollector                       │
                    │                                        │
                    │  StatsCollector (计数器 + 时延匹配)      │
                    │    └─ pending 哈希表 (REQUEST→RESPONSE)  │
                    │                                        │
                    │  LogWriter (日志输出)                    │
                    │    ├─ StdoutWriter (终端，人类可读/JSON) │
                    │    └─ FileWriter  (文件，JSON)          │
                    └────────────────────────────────────────┘
```

---

## 目录结构

```
eBPF-Info-collect/
│
├── README.md                          ← 你正在看的文件
├── Makefile                           ★ 构建系统（后续添加）
│
├── config/
│   └── hooks.json                     ★ hook 配置文件（人类可读签名 + 目标路径）
│
├── scripts/
│   ├── export_symbol.sh               ★ 从 ELF 提取符号偏移（mangled + demangled）
│   └── gen_hook_config.sh             ★ 查偏移 → 生成 src/hook_config.h
│
├── symbol/                            ★ 本地编译的 .so 文件（用于提取偏移）
│   ├── libvsomeip3.so.3.7.4
│   ├── libvsomeip3-sd.so.3.7.4
│   ├── libvsomeip3-cfg.so.3.7.4
│   └── libvsomeip3-e2e.so.3.7.4
│
├── symbol-offsets/                    ★ 自动生成的偏移表（export_symbol.sh 输出）
│   ├── *.offsets.tsv                  （mangled 名 + 偏移）
│   └── *.offsets.demangled.tsv        （demangled 人类可读名 + 偏移）
│
├── vmlinux/                           BTF 类型头文件
│   ├── arm64/vmlinux_601.h            ★ ARM64 Linux 6.1
│   ├── arm/vmlinux_62.h               ARM32 Linux 6.2
│   ├── x86/vmlinux_601.h              x86 Linux 6.1（本地开发用）
│   └── ... 其他架构 ...
│
├── lib/
│   ├── libbpf/                         libbpf 静态库
│   ├── bpftool/                        BPF 工具链
│   └── vsomeip/                        ★ vsomeip 源码（git submodule）
│
└── src/
    ├── common/                         ★ BPF ↔ 用户态 共享头文件
    │   ├── vsomeip_types.h             SOME/IP 协议常量
    │   └── vsomeip_event.h             事件结构体（数据格式定义）
    │
    ├── bpf/                            ★ BPF 内核态代码（C）
    │   ├── common.bpf.h                公共辅助函数
    │   ├── routing.bpf.c               路由层（5 hooks，最重要）
    │   ├── app.bpf.c                   应用层（3 hooks）
    │   └── sd.bpf.c                    服务发现（4 hooks）
    │
    ├── hook_config.h                   ★ 自动生成：12 个 hook 的偏移表
    │
    └── user/                           ★ 用户态加载器（C++）
        ├── main.cpp                    入口（CLI 参数解析 + 组装）
        │
        ├── collector/
        │   ├── collector_base.h        抽象接口（IUprobeCollector + EventContext）
        │   ├── collector_manager.h     epoll 多路复用管理器
        │   ├── collector_manager.cpp
        │   ├── routing_collector.h     路由层 collector
        │   ├── routing_collector.cpp
        │   ├── app_collector.h         应用层 collector
        │   ├── app_collector.cpp
        │   ├── sd_collector.h          服务发现 collector
        │   └── sd_collector.cpp
        │
        ├── output/
        │   ├── log_writer.h            日志输出接口
        │   ├── stdout_writer.h         终端输出
        │   ├── stdout_writer.cpp
        │   ├── file_writer.h           文件输出
        │   └── file_writer.cpp
        │
        └── stats_collector.h           统计 + 时延匹配
            └── stats_collector.cpp
```

---

## Hook 清单（12 个）

### Routing 模块（`routing.bpf.c`）— 挂在 `libvsomeip3.so`

| Hook | 探头 | 挂载函数 | 捕获内容 |
|------|:---:|------|------|
| `rm_send_entry` | uprobe | `routing_manager_impl::send(byte*, ...)` | ★ 所有发出消息的 SOME/IP header |
| `rm_send_ret` | uretprobe | 同上 | 发送成功/失败返回值 |
| `rm_send_to_entry` | uprobe | `routing_manager_impl::send_to(byte*, ...)` | 端点定向发送的 header |
| `rm_send_to_ret` | uretprobe | 同上 | 端点发送结果 |
| `rm_on_message` | uprobe | `routing_manager_impl::on_message(byte*, ...)` | ★ 所有收到消息的 SOME/IP header |

### App 模块（`app.bpf.c`）— 挂在 `libvsomeip3.so`

| Hook | 探头 | 挂载函数 | 捕获内容 |
|------|:---:|------|------|
| `app_send_entry` | uprobe | `application_impl::send(shared_ptr<message>)` | 应用调用 send() |
| `app_send_ret` | uretprobe | 同上 | 应用层发送结果 |
| `app_on_message` | uprobe | `application_impl::on_message(...)` | 消息投递到应用 |

### SD 模块（`sd.bpf.c`）— 挂在 `libvsomeip3-sd.so`

| Hook | 探头 | 挂载函数 | 捕获内容 |
|------|:---:|------|------|
| `sd_send` | uprobe | `service_discovery_impl::send(bool)` | SD 消息刷新到网络 |
| `sd_process_offer` | uprobe | `process_offerservice_serviceentry(...)` | 收到 OfferService |
| `sd_send_subscription` | uprobe | `send_subscription(...)` | 发送 SubscribeEventgroup |
| `sd_handle_subscription` | uprobe | `handle_eventgroup_subscription(...)` | 处理订阅请求 |

---

## 代码阅读顺序

按自底向上，从基础组件到入口，建议按以下顺序阅读：

### 第 1 层：基础定义（理解"有什么"）

| 顺序 | 文件 | 读什么 |
|:---:|------|------|
| 1 | `src/common/vsomeip_types.h` | SOME/IP 协议常量：message_type 枚举、header 16 字节布局、返回码 |
| 2 | `src/common/vsomeip_event.h` | ★ 核心数据结构：BPF→用户态的事件格式，所有模块共用 |
| 3 | `src/user/output/log_writer.h` | 日志输出接口（ILogWriter）：write / write_stats / write_latency |
| 4 | `src/user/collector/collector_base.h` | Collector 抽象接口 + EventContext（stats + writer 的桥接结构体） |
| 5 | `src/user/stats_collector.h` | 统计模块接口：计数器、pending 表、时延匹配 |

### 第 2 层：输出实现（理解"写到哪"）

| 顺序 | 文件 | 读什么 |
|:---:|------|------|
| 6 | `src/user/output/stdout_writer.h` | 终端输出（人类可读格式 + JSON 格式） |
| 7 | `src/user/output/stdout_writer.cpp` | 实现细节：颜色标记、时间格式化、JSON 构造 |
| 8 | `src/user/output/file_writer.h` | 文件输出（追加模式，行缓冲） |
| 9 | `src/user/output/file_writer.cpp` | 实现细节：ensure_open / reopen / JSON 格式 |

### 第 3 层：统计实现（理解"怎么算"）

| 顺序 | 文件 | 读什么 |
|:---:|------|------|
| 10 | `src/user/stats_collector.cpp` | ★ 核心算法：<br>• `process_event()` — 事件入口<br>• `make_key()` — 构造 (svc,method,client,session) 64位 key<br>• `record_pending()` — REQUEST 存入待匹配表<br>• `try_match_latency()` — RESPONSE 匹配计算时延<br>• `flush_report()` — p50/p99/max 统计摘要<br>• `evict_expired()` — 30 秒超时清理 |

### 第 4 层：Collector 实现（理解"怎么抓"）

| 顺序 | 文件 | 读什么 |
|:---:|------|------|
| 11 | `src/user/collector/routing_collector.h` | 最重要 collector 的接口（5 hooks） |
| 12 | `src/user/collector/routing_collector.cpp` | ★ 关键流程：<br>• `ringbuf_callback()` — 事件回调（stats + log）<br>• `init()` — open → load → filter_hooks<br>• `attach()` — 遍历 hooks → 偏移量挂载 → 创建 ringbuf consumer |
| 13 | `src/user/collector/app_collector.h` | 应用层 collector 接口 |
| 14 | `src/user/collector/app_collector.cpp` | 实现，和 routing 相同的模式 |
| 15 | `src/user/collector/sd_collector.h` | 服务发现 collector 接口 |
| 16 | `src/user/collector/sd_collector.cpp` | 实现，挂在 libvsomeip3-sd.so 上 |

### 第 5 层：管家（理解"怎么管"）

| 顺序 | 文件 | 读什么 |
|:---:|------|------|
| 17 | `src/user/collector/collector_manager.h` | Manager 接口：add_collector / init_all / attach_all / run_loop |
| 18 | `src/user/collector/collector_manager.cpp` | ★ 核心逻辑：<br>• `init_all()` — 加载所有 .bpf.o<br>• `attach_all()` — 注入 EventContext → attach<br>• `run_loop()` — epoll_wait 多路复用<br>• `set_event_context()` — 桥接 stats + writer |

### 第 6 层：入口（理解"怎么启动"）

| 顺序 | 文件 | 读什么 |
|:---:|------|------|
| 19 | `src/user/main.cpp` | CLI 入口：getopt_long 参数解析 → 创建组件 → 组装 → run_loop |

### BPF 内核态代码

| 顺序 | 文件 | 读什么 |
|:---:|------|------|
| 20 | `src/bpf/common.bpf.h` | 公共辅助：fill_common() / read_someip_header() |
| 21 | `src/bpf/routing.bpf.c` | ★ 路由层 hook：5 个 SEC handler，读 byte* 解析 header |
| 22 | `src/bpf/app.bpf.c` | 应用层 hook：3 个 SEC handler，读 shared_ptr 指针 |
| 23 | `src/bpf/sd.bpf.c` | 服务发现 hook：4 个 SEC handler，读 service_id 等参数 |

### 脚本和配置

| 顺序 | 文件 | 读什么 |
|:---:|------|------|
| 24 | `config/hooks.json` | Hook 配置：每个 hook 的 demangled 签名 + 库名 + retprobe |
| 25 | `scripts/export_symbol.sh` | ELF 解析：readelf → 计算 file_offset → 输出 tsv |
| 26 | `scripts/gen_hook_config.sh` | 查偏移脚本：读 hooks.json + offsets → 生成 hook_config.h |

---

## 数据流（完整版）

```
1. 启动
   main.cpp
     → 解析 CLI（-p PID / -d bpf_dir / -o output / --json / --enable）
     → 创建 StdoutWriter / FileWriter
     → 创建 StatsCollector + EventContext{&stats, writer}
     → manager.set_event_context(&stats, writer)
     → manager.add_collector(RoutingCollector / AppCollector / SdCollector)
     → manager.init_all(bpf_dir)     // 加载所有 .bpf.o
     → manager.attach_all(pid)       // 注入 EventContext → 挂载 uprobe → 创建 ringbuf

2. 运行时（每个 SOME/IP 消息触发一次）
   someipd 调用 routing_manager_impl::send(byte* data, ...)
     → BPF uprobe 触发
     → routing.bpf.c: hook_rm_send_entry()
         → bpf_ringbuf_reserve(&routing_events)
         → fill_common(event, ...)           // 填 PID/TID/时间戳
         → read_someip_header(event, data)   // 从 byte* 读 16 字节 header
         → bpf_ringbuf_submit(event)

     → epoll_wait 返回 routing_collector 的 ringbuf fd 可读
     → ring_buffer__consume()
     → ringbuf_callback()                     // ★ 静态 C 回调

           ┌─ stats->process_event(event, hook_name)
           │   ├─ update_counters()           // 累加：total/success/fail/by_type
           │   ├─ record_pending()            // REQUEST → pending[key] = timestamp
           │   └─ try_match_latency()         // RESPONSE → latency = now - pending[key]
           │       └─ writer->write_latency() // [LATENCY] svc=... latency_us=334
           │
           └─ writer->write(event, hook_name) // [routing] ts=... svc=... type=REQUEST

3. 定时（每 N 秒）
   CollectorManager 定时器
     → stats.flush_report()
         ├─ writer->write_stats("[STATS] routing: send=5000(succ=4950) recv=4800")
         ├─ writer->write_stats("[STATS] latency: p50=150us p99=850us max=5000us")
         └─ 重置计数器
     → stats.evict_expired()
         └─ 清理 pending 表中超过 30 秒的条目 → [TIMEOUT]

4. 停止
   Ctrl+C → SIGINT → g_running=0 → run_loop 退出
     → stats.flush_report()   // 最后一次统计
     → stats.evict_expired()
     → manager.shutdown()     // detach + destroy
```

---

## 构建（TODO）

```bash
# 1. 提取符号偏移
./scripts/export_symbol.sh

# 2. 生成 hook_config.h
./scripts/gen_hook_config.sh

# 3. 编译
make ARCH=arm64
```

---

## 使用

```bash
# 监控所有进程，终端人类可读输出（默认）
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
[R] 14:32:01.234567  PID:1234   TID:5678   someipd            rm_send_entry       SEND
  svc=0x1234  method=0x0001  client=0x5678  session=0x9ABC  type=REQUEST(0x00)  rc=0x00  payload=64

[R] 14:32:01.234789  PID:1234   TID:5678   someipd            rm_send_ret   [RET] SEND
  retval=0
  ...
[LATENCY] {"svc":4660,"method":1,"client":22136,"session":39612,"type":"RESPONSE","send_ts":...,"recv_ts":...,"latency_us":334.2}

[STATS] {"module":"routing","elapsed":10.0,"send_total":5000,"recv_total":4800}
[STATS] {"type":"latency","samples":4800,"avg_us":234,"p50_us":150,"p99_us":850,"max_us":5000}
```

---

## 添加新 Hook 的步骤

1. 在 `config/hooks.json` 中添加条目（复制 demangled 签名）
2. 运行 `./scripts/gen_hook_config.sh` 重新生成 `hook_config.h`
3. 在对应 `.bpf.c` 中添加新的 `SEC("uprobe/...")` handler
4. 在对应 collector 的 `ringbuf_callback()` 中添加 hook 名
5. 重新编译

---

## 目标机器部署

1. 编译得到 `vsomeip_collector` 可执行文件
2. 把 `routing.bpf.o`、`app.bpf.o`、`sd.bpf.o` 放到 `/usr/lib/ebpf/`
3. 目标机器只需要 `.dynsym`（动态符号表），不需要 `.symtab`
4. 挂载方式使用**文件偏移量**，不依赖符号表

---

## 技术要点

- **偏移量挂载**：`bpf_program__attach_uprobe_opts(prog, pid, lib_path, file_offset, opts)`
  — 不依赖目标机器的符号表，通过 ELF section header 计算的文件偏移挂载
- **ARM64 目标**：vmlinux.h 已切换为 `arm64/vmlinux_601.h`（Linux 6.1）
- **C++ mangled name**：通过 `export_symbol.sh` 的 demangled 输出来匹配人类可读的函数签名
- **Ring buffer**：每个模块独立 ringbuf，epoll 多路复用
