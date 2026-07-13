// routing_collector.cpp — 路由管理器模块的实现

#include "routing_collector.h"

// libbpf C 头文件（extern "C" 包裹以兼容 C++）
extern "C" {
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
}

// 项目公共头文件
#include "../../common/vsomeip_event.h"
#include "../../common/vsomeip_types.h"
#include "../../hook_config.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>

// ═══════════════════════════════════════════════════════════════════════
// 构造 / 析构
// ═══════════════════════════════════════════════════════════════════════

RoutingCollector::RoutingCollector() = default;

RoutingCollector::~RoutingCollector()
{
    destroy();
}

// ═══════════════════════════════════════════════════════════════════════
// init — 加载 BPF 对象，筛选自己的 hook 列表
// ═══════════════════════════════════════════════════════════════════════

int RoutingCollector::init(const char* bpf_obj_path)
{
    // 步骤 1：打开 BPF 对象文件（routing.bpf.o）
    // bpf_object__open() 解析 ELF 文件，读取所有 SEC 段、map 定义、
    // 程序代码，但不加载到内核。
    obj_ = bpf_object__open(bpf_obj_path);
    if (!obj_) {
        fprintf(stderr, "[routing] 打开 BPF 对象失败: %s\n", bpf_obj_path);
        return -1;
    }

    // 步骤 2：将 BPF 对象加载到内核
    // 这一步验证 BPF 字节码、创建 map、加载程序。
    // verifier 会检查所有内存访问的安全性。
    if (bpf_object__load(obj_) != 0) {
        fprintf(stderr, "[routing] 加载 BPF 对象失败: %s\n", bpf_obj_path);
        bpf_object__close(obj_);
        obj_ = nullptr;
        return -1;
    }

    // 步骤 3：从全局 hook_configs[] 中筛选属于 routing 模块的条目
    // 筛选规则：hook 名以 "rm_" 开头
    filter_own_hooks();

    fprintf(stdout, "[routing] 初始化完成，%d 个 hook 待挂载\n", hook_count_);

    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
// filter_own_hooks — 从 hook_configs[] 筛选本模块的 hook
// ═══════════════════════════════════════════════════════════════════════

void RoutingCollector::filter_own_hooks()
{
    own_hooks_.clear();

    for (int i = 0; i < NUM_HOOKS; i++) {
        const struct hook_cfg* cfg = &hook_configs[i];

        // routing 模块的 hook 都以 "rm_" 开头
        if (strncmp(cfg->name, "rm_", 3) == 0) {
            own_hooks_.push_back(cfg);
        }
    }

    hook_count_ = (int)own_hooks_.size();
}

// ═══════════════════════════════════════════════════════════════════════
// find_bpf_program — 根据 hook 名找到 BPF 程序
//
// BPF 程序中 SEC 名的命名规则（见 routing.bpf.c）：
//   uprobe   → SEC("uprobe/hook_<hook_name>")     → 程序名 "hook_<hook_name>"
//   uretprobe→ SEC("uretprobe/hook_<hook_name>")  → 程序名 "hook_<hook_name>"
//
// 两者共用同一个程序名，libbpf 在 attach 时根据 opts.retprobe 区分
// 是挂载到入口还是出口。
// ═══════════════════════════════════════════════════════════════════════

struct bpf_program* RoutingCollector::find_bpf_program(const char* hook_name)
{
    // 构造 BPF 程序名： "hook_" + hook_name
    char prog_name[64];
    snprintf(prog_name, sizeof(prog_name), "hook_%s", hook_name);

    struct bpf_program* prog = bpf_object__find_program_by_name(obj_, prog_name);
    if (!prog) {
        fprintf(stderr, "[routing] 找不到 BPF 程序: %s\n", prog_name);
    }
    return prog;
}

// ═══════════════════════════════════════════════════════════════════════
// attach — 遍历本模块 hook，逐个用偏移量挂载 uprobe
//
// 挂载方式：偏移量（不需要目标机器有符号表！）
//   bpf_program__attach_uprobe_opts(prog, pid, lib_path, offset, opts)
//
// 其中：
//   lib_path    ← hook_cfg.target_path（目标机器上的 .so 路径）
//   offset      ← hook_cfg.offset（从本地 .so 的 ELF 文件计算出的偏移）
//   opts.retprobe ← hook_cfg.retprobe（入口 or 返回探测）
// ═══════════════════════════════════════════════════════════════════════

int RoutingCollector::attach(int target_pid)
{
    if (!obj_) {
        fprintf(stderr, "[routing] 未初始化，请先调用 init()\n");
        return -1;
    }

    if (attached_) {
        detach();   // 如果已挂载，先卸载旧的
    }

    int attached_count = 0;

    for (const auto* cfg : own_hooks_) {
        // 找到对应的 BPF 程序
        struct bpf_program* prog = find_bpf_program(cfg->name);
        if (!prog)
            continue;

        // 设置挂载参数
        DECLARE_LIBBPF_OPTS(bpf_uprobe_opts, opts,
            .retprobe = cfg->retprobe,   // true = 挂载到函数返回点
        );

        // 用偏移量挂载 uprobe
        // func_offset = cfg->offset（文件偏移，从 ELF section header 计算）
        // pid = target_pid（-1 = 所有进程）
        struct bpf_link* link = bpf_program__attach_uprobe_opts(
            prog,
            target_pid,                 // 目标进程 PID
            cfg->target_path,           // 目标机器上的库路径
            cfg->offset,                // ★ 偏移量，不依赖符号表！
            &opts
        );

        if (!link) {
            fprintf(stderr, "[routing] 挂载失败: %s @ %s+0x%lx\n",
                    cfg->name, cfg->target_path, (unsigned long)cfg->offset);
            continue;
        }

        links_.push_back(link);
        attached_count++;
    }

    // 步骤 4：创建 ring buffer consumer
    // routing_events 是在 routing.bpf.c 中定义的 map 名称
    struct bpf_map* rb_map = bpf_object__find_map_by_name(obj_, "routing_events");
    if (!rb_map) {
        fprintf(stderr, "[routing] 找不到 ringbuf map 'routing_events'\n");
        return -1;
    }

    // ring_buffer__new 创建一个 ring buffer consumer
    // 参数：map fd、回调函数、上下文指针、选项（NULL=默认）
    ringbuf_ = ring_buffer__new(bpf_map__fd(rb_map), nullptr, nullptr, nullptr);
    if (!ringbuf_) {
        fprintf(stderr, "[routing] 创建 ring buffer 失败\n");
        return -1;
    }

    // 获取 ringbuf 的 epoll fd（用于 CollectorManager 的事件循环）
    ringbuf_fd_ = ring_buffer__epoll_fd(ringbuf_);

    attached_ = true;
    fprintf(stdout, "[routing] 挂载完成：%d/%d 个 hook 成功\n",
            attached_count, hook_count_);

    return attached_count;
}

// ═══════════════════════════════════════════════════════════════════════
// detach — 销毁所有 bpf_link
// ═══════════════════════════════════════════════════════════════════════

int RoutingCollector::detach()
{
    for (auto* link : links_) {
        bpf_link__destroy(link);
    }
    links_.clear();

    if (ringbuf_) {
        ring_buffer__free(ringbuf_);
        ringbuf_ = nullptr;
        ringbuf_fd_ = -1;
    }

    attached_ = false;
    fprintf(stdout, "[routing] 已卸载所有 hook\n");

    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
// destroy — 完全释放资源
// ═══════════════════════════════════════════════════════════════════════

void RoutingCollector::destroy()
{
    detach();

    if (obj_) {
        bpf_object__close(obj_);
        obj_ = nullptr;
    }
}

// ═══════════════════════════════════════════════════════════════════════
// ringbuf_fd — 返回 epoll fd
// ═══════════════════════════════════════════════════════════════════════

int RoutingCollector::ringbuf_fd() const
{
    return ringbuf_fd_;
}

// ═══════════════════════════════════════════════════════════════════════
// poll — 消费 ringbuffer 中的事件
// ═══════════════════════════════════════════════════════════════════════

int RoutingCollector::poll(int timeout_ms)
{
    if (!ringbuf_)
        return 0;

    // ring_buffer__consume 非阻塞地消费所有就绪的事件
    // 注意：当前版本使用了空回调，实际事件处理逻辑由 CollectorManager
    // 通过单独的事件循环完成（此方法保留供 epoll 通知用）。
    //
    // TODO: 添加事件处理回调，把 vsomeip_event 推给 stats_collector
    //       和 log_writer。
    return ring_buffer__consume(ringbuf_);
}
