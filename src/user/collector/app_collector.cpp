// app_collector.cpp — 应用层模块的实现
//
// 加载 app.bpf.o，把 3 个 uprobe hook 挂载到 application_impl 的函数上，
// 然后通过 ring buffer 消费 BPF 事件，推给统计和日志模块。
//
// app 模块的 3 个 hook 分别对应：
//   1. app_send_entry   → application_impl::send() 入口
//                         应用程序调用 send() 的时刻
//   2. app_send_ret     → application_impl::send() 返回
//                         应用层发送成功/失败
//   3. app_on_message   → application_impl::on_message() 入口
//                         消息被投递到应用程序的时刻
//
// 时延分析示例（结合 routing 模块）：
//   rm_on_message 时间戳  = 网络收到消息的时间点
//   app_on_message 时间戳 = 消息投递到应用的时间点
//   路由内部处理耗时      = app_on_message - rm_on_message
//
// 注意：app 模块不能读取 SOME/IP header 字段
//   application_impl 的参数是 shared_ptr<message>（C++ 智能指针），
//   不是 byte*。BPF 不能安全地解引用 C++ 对象和虚函数表。
//   所以事件的 service_id / method_id / message_type 等字段全为 0。
//   需要 header 信息的话，看 routing 模块（它直接从 byte* data 解析）。

#include "app_collector.h"

// libbpf C API（extern "C" 确保 C++ 正确链接 C 函数）
extern "C" {
#include <bpf/libbpf.h>     // bpf_object__open, bpf_program__attach_uprobe_opts, ring_buffer__new
#include <bpf/bpf.h>        // bpf_map__fd
}

#include "../../common/vsomeip_event.h"   // struct vsomeip_event
#include "../../common/vsomeip_types.h"   // MODULE_APP 等常量
#include "../../hook_config.h"             // NUM_HOOKS, struct hook_cfg
#include "../stats_collector.h"            // StatsCollector::process_event()
#include "../output/log_writer.h"          // ILogWriter::write()

#include <cstdio>
#include <cstring>

// ═══════════════════════════════════════════════════════════════════════
// 构造 / 析构
// ═══════════════════════════════════════════════════════════════════════

AppCollector::AppCollector() = default;
AppCollector::~AppCollector() { destroy(); }

// ═══════════════════════════════════════════════════════════════════════
// ringbuf_callback — libbpf 每消费到一个事件就会调用这个函数
//
// 调用链：
//   epoll_wait() 返回 ringbuf fd 可读
//     → CollectorManager::handle_collector_event()
//     → collector->poll()                     // 虚函数调用
//     → ring_buffer__consume()                // libbpf 内部读 ringbuf
//     → ringbuf_callback()  ← 这里！          // 每个事件触发一次
//
// @param ctx    ring_buffer__new() 时传入的 this 指针（AppCollector*）
// @param data   指向 vsomeip_event 的用户态内存副本（libbpf 已从内核拷出）
// @param size   数据大小，应等于 sizeof(struct vsomeip_event)
// @return       0 = 继续消费下一个事件，非0 = 停止消费
// ═══════════════════════════════════════════════════════════════════════

int AppCollector::ringbuf_callback(void *ctx, void *data, size_t size)
{
    // ── 安全检查：数据必须至少包含完整的 vsomeip_event ──────────────
    if (size < sizeof(struct vsomeip_event))
        return 0;

    // ── 还原上下文 ──────────────────────────────────────────────────
    // ring_buffer__new 时把 this 指针作为 ctx 传入，这里转回来
    auto* self  = static_cast<AppCollector*>(ctx);
    auto* event = static_cast<const struct vsomeip_event*>(data);

    // EventContext 还没注入（应该在 attach 之前调用 set_event_context）
    if (!self->event_ctx_)
        return 0;

    // ── hook_id → 人类可读名称 ──────────────────────────────────────
    // app 模块有 3 个 hook，编号 0 / 1 / 2（见 vsomeip_event.h）
    static const char* hook_names[] = {
        "app_send_entry",   // HOOK_APP_SEND_ENTRY = 0
        "app_send_ret",     // HOOK_APP_SEND_RET   = 1
        "app_on_message",   // HOOK_APP_ON_MESSAGE = 2
    };
    const char* hook_name = (event->hook_id < 3)
        ? hook_names[event->hook_id] : "unknown";

    // ── 把事件推给统计和日志模块  ─────────────────────────────────
    // process_event: 累加计数器（app 模块不参与时延匹配，因为 header 为 0）
    self->event_ctx_->stats->process_event(*event, hook_name);
    // write: 格式化成人类可读或 JSON 输出
    self->event_ctx_->writer->write(*event, hook_name);

    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
// init — 打开并加载 BPF 对象
//
// 步骤：
//   1. bpf_object__open()  → 解析 ELF 文件（app.bpf.o）
//   2. bpf_object__load()  → 加载到内核（verifier 检查所有内存访问安全性）
//   3. filter_own_hooks()  → 从全局 hook_configs[] 筛选 app_ 前缀的条目
// ═══════════════════════════════════════════════════════════════════════

int AppCollector::init(const char* bpf_obj_path)
{
    // 步骤 1：打开 ELF 文件，解析 SEC 段和符号表
    obj_ = bpf_object__open(bpf_obj_path);
    if (!obj_) {
        fprintf(stderr, "[app] 打开 BPF 对象失败: %s\n"
                "  请检查 app.bpf.o 是否存在\n", bpf_obj_path);
        return -1;
    }

    // 步骤 2：加载到内核
    // BPF verifier 会逐条检查指令，确保：
    //   - 所有内存访问都经过 bpf_probe_read_user
    //   - 没有无限循环
    //   - 栈使用不超过 512 字节
    //   - 所有寄存器路径都能证明安全性
    if (bpf_object__load(obj_) != 0) {
        fprintf(stderr, "[app] 加载 BPF 对象失败（verifier 拒绝了程序）\n");
        bpf_object__close(obj_);
        obj_ = nullptr;
        return -1;
    }

    filter_own_hooks();

    fprintf(stdout, "[app] 初始化完成，%d 个 hook 待挂载\n", hook_count_);
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
// filter_own_hooks — 从全局 hook_configs[] 筛选 app 模块的 hook
//
// 筛选规则：hook 名以 "app_" 开头
// app 模块有 3 个 hook：app_send_entry, app_send_ret, app_on_message
// ═══════════════════════════════════════════════════════════════════════

void AppCollector::filter_own_hooks()
{
    own_hooks_.clear();
    for (int i = 0; i < NUM_HOOKS; i++) {
        if (strncmp(hook_configs[i].name, "app_", 4) == 0)
            own_hooks_.push_back(&hook_configs[i]);
    }
    hook_count_ = (int)own_hooks_.size();
}

// ═══════════════════════════════════════════════════════════════════════
// find_bpf_program — 根据 hook 名查找对应的 BPF 程序
//
// BPF 程序命名规则（在 app.bpf.c 的 SEC 宏中定义）：
//   SEC("uprobe/hook_<hook_name>") → 程序名为 "hook_<hook_name>"
// 例如：app_send_entry → 查找名为 "hook_app_send_entry" 的程序
// ═══════════════════════════════════════════════════════════════════════

struct bpf_program* AppCollector::find_bpf_program(const char* hook_name)
{
    char prog_name[64];
    snprintf(prog_name, sizeof(prog_name), "hook_%s", hook_name);
    return bpf_object__find_program_by_name(obj_, prog_name);
}

// ═══════════════════════════════════════════════════════════════════════
// attach — 挂载 hooks + 创建 ringbuf consumer
//
// 分两步：
//   1. 遍历 own_hooks_，用 bpf_program__attach_uprobe_opts()
//      按偏移量把每个 BPF 程序挂载到对应函数上
//   2. 创建 ring_buffer consumer，传入 ringbuf_callback 和 this 指针
//      每当 BPF 推事件到 ringbuf，libbpf 自动调用回调
//
// @param target_pid  -1=所有进程, 0=自身, >0=指定 PID
// @return            成功挂载的 hook 数量
// ═══════════════════════════════════════════════════════════════════════

int AppCollector::attach(int target_pid)
{
    if (!obj_) {
        fprintf(stderr, "[app] 未初始化\n");
        return -1;
    }
    if (attached_) detach();  // 先卸载旧挂载

    int attached_count = 0;

    // ── 第一步：逐个挂载 uprobe ──────────────────────────────────────
    for (const auto* cfg : own_hooks_) {
        struct bpf_program* prog = find_bpf_program(cfg->name);
        if (!prog) {
            fprintf(stderr, "[app] 找不到 BPF 程序: hook_%s\n", cfg->name);
            continue;
        }

        // retprobe = true → uretprobe（挂载到函数返回点，能读返回值）
        // retprobe = false → uprobe（挂载到函数入口，能读参数）
        DECLARE_LIBBPF_OPTS(bpf_uprobe_opts, opts,
            .retprobe = cfg->retprobe,
        );

        // 按偏移量挂载，不依赖目标机器的符号表
        struct bpf_link* link = bpf_program__attach_uprobe_opts(
            prog,
            target_pid,              // -1 = 所有进程
            cfg->target_path,        // 目标机器库路径，如 /usr/lib/libvsomeip3.so.3
            cfg->offset,             // 文件偏移（从本地 .so ELF 计算，见 export_symbol.sh）
            &opts
        );

        if (!link) {
            fprintf(stderr, "[app] 挂载失败: %s @ %s+0x%lx\n",
                    cfg->name, cfg->target_path, (unsigned long)cfg->offset);
            continue;
        }

        links_.push_back(link);
        attached_count++;
    }

    // ── 第二步：创建 ring buffer consumer ────────────────────────────
    struct bpf_map* rb_map = bpf_object__find_map_by_name(obj_, "app_events");
    if (!rb_map) {
        fprintf(stderr, "[app] 找不到 ringbuf map 'app_events'\n");
        return -1;
    }

    ringbuf_ = ring_buffer__new(
        bpf_map__fd(rb_map),
        ringbuf_callback,       // 每个事件的回调函数
        this,                   // 作为 ctx 传给回调
        nullptr                 // 使用默认选项
    );

    if (!ringbuf_) {
        fprintf(stderr, "[app] 创建 ring buffer consumer 失败\n");
        return -1;
    }

    // 获取 epoll fd，注册到 CollectorManager 的事件循环
    ringbuf_fd_ = ring_buffer__epoll_fd(ringbuf_);
    attached_ = true;

    fprintf(stdout, "[app] 挂载完成：%d/%d 个 hook 成功\n",
            attached_count, hook_count_);
    return attached_count;
}

// ═══════════════════════════════════════════════════════════════════════
// detach — 卸载所有 hook 和 ring buffer
//
// detach 后可以重新 attach（例如切换到不同的目标 PID）
// ═══════════════════════════════════════════════════════════════════════

int AppCollector::detach()
{
    // 销毁所有 uprobe link
    for (auto* link : links_) {
        bpf_link__destroy(link);
    }
    links_.clear();

    // 销毁 ring buffer consumer
    if (ringbuf_) {
        ring_buffer__free(ringbuf_);
        ringbuf_ = nullptr;
        ringbuf_fd_ = -1;
    }

    attached_ = false;
    fprintf(stdout, "[app] 已卸载所有 hook\n");
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
// 其余接口方法
// ═══════════════════════════════════════════════════════════════════════

// destroy — 完全释放资源
void AppCollector::destroy()
{
    detach();
    if (obj_) {
        bpf_object__close(obj_);    // 释放内核中加载的 BPF 程序和 map
        obj_ = nullptr;
    }
}

int AppCollector::ringbuf_fd() const { return ringbuf_fd_; }

// poll — 消费 ring buffer
// ring_buffer__consume() 内部逐个调用 ringbuf_callback()
int AppCollector::poll(int /*timeout_ms*/)
{
    if (!ringbuf_) return 0;
    return ring_buffer__consume(ringbuf_);
}
