// collector.cpp — 通用的 uprobe 收集器
//
// 一个 Collector 实例 = 一个 .bpf.o 文件 + 一组 hook + 一个 ringbuf。
// 所有模块行为完全相同：加载嵌入的 BPF 字节码 → 偏移量挂载 hook → 消费 ringbuf。
//
// 和具体模块的关联只有一个地方：
//   ringbuf_callback 中把数据交给 group_->handler 函数指针。
//   这个指针在 gen_hook_config.sh 生成 hook_config.h 时写好，
//   指向对应模块的 handler（如 routing_event_handler）。
//
// 数据流：
//   BPF submit(routing_event) → ringbuf
//     → epoll 唤醒 → poll() → ring_buffer__consume()
//     → ringbuf_callback(data, size)
//       → hdr = (event_header*)data       // 读公共头
//       → hook_id 查 hook 名
//       → group_->handler(data, hook, stats, writer)  // 交给模块 handler

#include "collector.h"

extern "C" {
    #include <bpf/libbpf.h>     
    #include <bpf/bpf.h>      
}

#include "../../common/event_header.h"  
#include "../../gen/hook_config.h"     

#include <cstdio>
#include <cstring>

Collector::Collector(const struct file_group* group) : group_(group) {}
Collector::~Collector() { destroy(); }
const char* Collector::name() const { return group_->name; }

// ═══════════════════════════════════════════════════════════════════════
// ringbuf_callback — BPF 事件到达时 libbpf 自动调用
//
// 这个函数做三件事：
//   1. 把 data 转成 event_header*，读公共字段
//      （timestamp、pid、tid、comm、module_id、hook_id、direction）
//   2. 用 hook_id 从 file_group 的 hook_names[] 查出人类可读名称
//   3. 调用 file_group 注册的 handler，把数据交给模块处理
//      handler 内部做：stats.process_event() + writer.write_event()
//
// 这里不关心数据是 routing_event 还是 app_event 还是别的——
//   handler 指针是什么就调什么，新增模块不需要改这行代码。
//
// 参数：
//   ctx  — ring_buffer__new() 时传入的 this 指针（Collector*）
//   data — BPF 提交的事件数据（内核态的字节流拷贝到用户态）
//   size — 数据的实际大小
// ═══════════════════════════════════════════════════════════════════════

int Collector::ringbuf_callback(void *ctx, void *data, size_t size)
{
    // 安全校验：数据至少要能容纳一个公共头
    if (size < sizeof(struct event_header))
        return 0;

    // 从 ctx 恢复 Collector 实例
    auto *self = static_cast<Collector*>(ctx);

    // 公共头：所有模块事件的前 N 字节布局完全一样
    auto *hdr  = static_cast<const struct event_header*>(data);

    // EventContext（stats + writer 指针）由 CollectorManager 在 attach 前注入
    if (!self->event_ctx_)
        return 0;

    // hook_id → 人类可读名称（如 HOOK_RM_SEND_ENTRY → "rm_send_entry"）
    // hook_names[] 由 gen_hook_config.sh 生成
    const char *hook_name = "unknown";
    if (hdr->hook_id < self->group_->hook_count)
        hook_name = self->group_->hook_names[hdr->hook_id];

    // 调用模块注册的 handler，把 stats 和 writer 传进去
    // handler 内部负责：强转到具体类型 + 调 stats + 调 writer
    if (self->group_->handler)
        self->group_->handler(data, hook_name,
                              self->event_ctx_->stats,
                              self->event_ctx_->writer);

    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
// init — 从嵌入的字节码加载 BPF 程序到内核
//
// BPF 字节码在编译时通过 xxd -i 嵌入到可执行文件中，
// 运行时用 bpf_object__open_mem() 直接从内存加载，不需要读 .bpf.o 文件。
// ═══════════════════════════════════════════════════════════════════════
int Collector::init()
{
    fprintf(stdout, "[%s] 初始化 (%d hooks, %u bytes embedded)\n",
            group_->name, group_->hook_count, group_->embed_size);

    // 从内存中的字节数组打开 BPF 对象（和 bpf_object__open("文件路径") 语义相同）
    obj_ = bpf_object__open_mem(group_->embed_data, group_->embed_size, NULL);
    if (!obj_) {
        fprintf(stderr, "[%s] open_mem 失败\n", group_->name);
        return -1;
    }

    // 加载到内核：verifier 逐条检查 BPF 指令，通过后创建 map
    if (bpf_object__load(obj_) != 0) {
        fprintf(stderr, "[%s] load 失败（verifier 拒绝了程序）\n", group_->name);
        bpf_object__close(obj_);
        obj_ = nullptr;
        return -1;
    }

    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
// attach — 把本模块的所有 hook 用偏移量挂载到目标进程
//
// 遍历 file_group 中的 hooks[] 数组：
//   1. 按 hook 名查找 BPF 程序（SEC 名 = hook 名）
//   2. 用文件偏移量挂载 uprobe（不依赖目标机器的符号表）
//   3. 保存 bpf_link 句柄（detach 时批量销毁）
//
// 最后创建 ring_buffer consumer，把 ringbuf_callback 注册进去。
// 之后每当 BPF 推事件到 ringbuf，libbpf 自动调用回调。
// ═══════════════════════════════════════════════════════════════════════
int Collector::attach(int target_pid)
{
    if (!obj_)
        return -1;

    // 如果之前已挂载，先卸载
    if (attached_)
        detach();

    int ok = 0;

    // 遍历本模块的每个 hook
    for (int i = 0; i < group_->hook_count; i++) {
        const auto *cfg = &group_->hooks[i];

        // SEC 名 = hook 名（如 "rm_send_entry"），两者一致
        auto *prog = bpf_object__find_program_by_name(obj_, cfg->name);
        if (!prog) {
            fprintf(stderr, "[%s] BPF 程序未找到: %s\n",
                    group_->name, cfg->name);
            continue;
        }

        // retprobe:  true = uretprobe（挂载到函数返回点，能读返回值）
        //            false = uprobe（挂载到函数入口，能读参数）
        DECLARE_LIBBPF_OPTS(bpf_uprobe_opts, opts,
            .retprobe = cfg->retprobe,
        );

        // 用文件偏移量挂载（不需要目标机器有符号表）
        auto *link = bpf_program__attach_uprobe_opts(
            prog, target_pid, cfg->target_path, cfg->offset, &opts);

        if (!link) {
            fprintf(stderr, "[%s] 挂载失败: %s @ %s+0x%lx\n",
                    group_->name, cfg->name, cfg->target_path,
                    (unsigned long)cfg->offset);
            continue;
        }

        links_.push_back(link);
        ok++;
    }

    // 创建 ring buffer consumer
    auto *rb = bpf_object__find_map_by_name(obj_, group_->ringbuf_map);
    if (!rb) {
        fprintf(stderr, "[%s] 找不到 ringbuf map '%s'\n",
                group_->name, group_->ringbuf_map);
        return -1;
    }

    // ring_buffer__new 的参数:
    //   1. map fd — BPF map 的文件描述符
    //   2. ringbuf_callback — 每个事件的回调函数
    //   3. this — 作为 ctx 传给回调（回调里转回 Collector*）
    //   4. NULL — 使用默认选项
    ringbuf_ = ring_buffer__new(bpf_map__fd(rb),
                                ringbuf_callback, this, nullptr);
    if (!ringbuf_) {
        fprintf(stderr, "[%s] 创建 ring buffer consumer 失败\n",
                group_->name);
        return -1;
    }

    // epoll fd：注册到 CollectorManager 的事件循环中
    ringbuf_fd_ = ring_buffer__epoll_fd(ringbuf_);
    attached_ = true;

    fprintf(stdout, "[%s] 挂载完成: %d/%d\n",
            group_->name, ok, group_->hook_count);
    return ok;
}

// ═══════════════════════════════════════════════════════════════════════
// detach — 卸载所有 hook，释放 ringbuf consumer
// 可以再次 attach 到不同的目标进程
// ═══════════════════════════════════════════════════════════════════════
int Collector::detach()
{
    // 销毁所有 uprobe link
    for (auto *l : links_)
        bpf_link__destroy(l);
    links_.clear();

    // 销毁 ring buffer consumer
    if (ringbuf_) {
        ring_buffer__free(ringbuf_);
        ringbuf_ = nullptr;
        ringbuf_fd_ = -1;
    }

    attached_ = false;
    fprintf(stdout, "[%s] 已卸载\n", group_->name);
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
// destroy — 完全释放资源（detach + 关闭 BPF 对象）
// ═══════════════════════════════════════════════════════════════════════
void Collector::destroy()
{
    detach();

    if (obj_) {
        bpf_object__close(obj_);    // 释放内核中的 BPF 程序和 map
        obj_ = nullptr;
    }
}

int Collector::ringbuf_fd() const
{
    return ringbuf_fd_;
}

// poll — 消费 ringbuf 中的事件
// ring_buffer__consume 内部逐个调用 ringbuf_callback
int Collector::poll(int /*timeout_ms*/)
{
    return ringbuf_ ? ring_buffer__consume(ringbuf_) : 0;
}
