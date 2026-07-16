// collector.cpp — 通用的 uprobe 收集器实现
//
// ringbuf 回调中按 event_header.module_id 强转到具体事件类型

#include "collector.h"

extern "C" {
    #include <bpf/libbpf.h>
    #include <bpf/bpf.h>
}

#include "../../common/event_header.h"   // 仅用于 sizeof 检查
#include "../../gen/hook_config.h"            // file_group + handler 指针

#include <cstdio>
#include <cstring>

Collector::Collector(const struct file_group* group) : group_(group) {}
Collector::~Collector() { destroy(); }
const char* Collector::name() const { return group_->name; }

// ═══════════════════════════════════════════════════════════════════════
// ringbuf_callback — 先读公共头，再按 module_id 强转到具体类型
// 1. data → event_header*（所有事件的前几个字节都是公共头）
// 2. 读 hdr->module_id 知道是哪个模块
// 3. 强转到对应模块的私有结构体
// 4. 推给 stats + log（带类型安全）
// ═══════════════════════════════════════════════════════════════════════
int Collector::ringbuf_callback(void *ctx, void *data, size_t size)
{
    // 小于公共头文件直接返回
    if (size < sizeof(struct event_header)) return 0;

    auto *self = static_cast<Collector*>(ctx);
    auto *hdr  = static_cast<const struct event_header*>(data); // 强转为公共头
    if (!self->event_ctx_) return 0;

    const char *hook_name = "unknown";
    if (hdr->hook_id < self->group_->hook_count)
        hook_name = self->group_->hook_names[hdr->hook_id];

    // 数据驱动：调用 file_group 注册的 handler
    // 新增模块不需改这里的代码。
    if (self->group_->handler)
        self->group_->handler(data, hook_name,
            self->event_ctx_->stats, self->event_ctx_->writer);

    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
// init / attach / detach / destroy / poll
// ═══════════════════════════════════════════════════════════════════════
int Collector::init()
{
    fprintf(stdout, "[%s] 初始化 (%d hooks, %u bytes embedded)\n",
            group_->name, group_->hook_count, group_->embed_size);
    obj_ = bpf_object__open_mem(group_->embed_data, group_->embed_size, NULL);
    if (!obj_) { 
        fprintf(stderr, "[%s] open_mem 失败\n", group_->name); 
        return -1; 
    }
    if (bpf_object__load(obj_) != 0) { 
        fprintf(stderr, "[%s] load 失败\n", group_->name); 
        bpf_object__close(obj_); 
        obj_ = nullptr; 
        return -1; 
    }
    return 0;
}

int Collector::attach(int target_pid)
{
    if (!obj_) 
        return -1;
    if (attached_) 
        detach();

    int ok = 0;
    for (int i = 0; i < group_->hook_count; i++) {
        const auto *cfg = &group_->hooks[i];
        auto *prog = bpf_object__find_program_by_name(obj_, cfg->name);
        if (!prog) { 
            fprintf(stderr, "[%s] BPF 程序未找到: %s\n", group_->name, cfg->name); 
            continue; 
        }

        DECLARE_LIBBPF_OPTS(bpf_uprobe_opts, opts, .retprobe = cfg->retprobe);
        auto *link = bpf_program__attach_uprobe_opts(prog, target_pid, cfg->target_path, cfg->offset, &opts);
        if (!link) { 
            fprintf(stderr, "[%s] 挂载失败: %s\n", group_->name, cfg->name); continue; 
        }
        links_.push_back(link); ok++;
    }

    auto *rb = bpf_object__find_map_by_name(obj_, group_->ringbuf_map);
    if (!rb) 
        return -1;

    ringbuf_ = ring_buffer__new(bpf_map__fd(rb), ringbuf_callback, this, nullptr);
    if (!ringbuf_) 
        return -1;

    ringbuf_fd_ = ring_buffer__epoll_fd(ringbuf_);
    attached_ = true;
    fprintf(stdout, "[%s] 挂载完成: %d/%d\n", group_->name, ok, group_->hook_count);
    return ok;
}

int  Collector::detach() { 
    for (auto *l : links_) 
        bpf_link__destroy(l); 
    
        links_.clear(); 
        if (ringbuf_) { 
            ring_buffer__free(ringbuf_); 
            ringbuf_ = nullptr; ringbuf_fd_ = -1; 
        } 
        attached_ = false; 
        return 0; 
}

void Collector::destroy() { 
    detach(); 
    if (obj_) { 
        bpf_object__close(obj_); 
        obj_ = nullptr; 
    } 
}

int  Collector::ringbuf_fd() const { 
    return ringbuf_fd_; 
}

int  Collector::poll(int) { 
    return ringbuf_ ? ring_buffer__consume(ringbuf_) : 0; 
}
