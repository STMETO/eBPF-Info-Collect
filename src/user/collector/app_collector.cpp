// app_collector.cpp — 应用层模块的实现

#include "app_collector.h"

extern "C" {
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
}

#include "../../common/vsomeip_event.h"
#include "../../hook_config.h"

#include <cstdio>
#include <cstring>

AppCollector::AppCollector() = default;
AppCollector::~AppCollector() { destroy(); }

int AppCollector::init(const char* bpf_obj_path)
{
    // 打开 app.bpf.o
    obj_ = bpf_object__open(bpf_obj_path);
    if (!obj_) {
        fprintf(stderr, "[app] 打开 BPF 对象失败: %s\n", bpf_obj_path);
        return -1;
    }

    // 加载到内核（verifier 检查 + 创建 map）
    if (bpf_object__load(obj_) != 0) {
        fprintf(stderr, "[app] 加载 BPF 对象失败\n");
        bpf_object__close(obj_);
        obj_ = nullptr;
        return -1;
    }

    // 筛选 app 模块的 hook（hook 名以 "app_" 开头）
    filter_own_hooks();

    fprintf(stdout, "[app] 初始化完成，%d 个 hook 待挂载\n", hook_count_);
    return 0;
}

void AppCollector::filter_own_hooks()
{
    own_hooks_.clear();
    for (int i = 0; i < NUM_HOOKS; i++) {
        const struct hook_cfg* cfg = &hook_configs[i];
        // app 模块的 hook 前缀
        if (strncmp(cfg->name, "app_", 4) == 0) {
            own_hooks_.push_back(cfg);
        }
    }
    hook_count_ = (int)own_hooks_.size();
}

struct bpf_program* AppCollector::find_bpf_program(const char* hook_name)
{
    // BPF 程序名 = "hook_" + hook_name
    // 例如："app_send_entry" → "hook_app_send_entry"
    char prog_name[64];
    snprintf(prog_name, sizeof(prog_name), "hook_%s", hook_name);

    return bpf_object__find_program_by_name(obj_, prog_name);
}

int AppCollector::attach(int target_pid)
{
    if (!obj_) {
        fprintf(stderr, "[app] 未初始化\n");
        return -1;
    }

    if (attached_) detach();

    int attached_count = 0;

    for (const auto* cfg : own_hooks_) {
        struct bpf_program* prog = find_bpf_program(cfg->name);
        if (!prog) continue;

        // 用偏移量挂载 uprobe（不依赖目标机器的符号表）
        DECLARE_LIBBPF_OPTS(bpf_uprobe_opts, opts,
            .retprobe = cfg->retprobe,
        );

        struct bpf_link* link = bpf_program__attach_uprobe_opts(
            prog, target_pid, cfg->target_path, cfg->offset, &opts);

        if (!link) {
            fprintf(stderr, "[app] 挂载失败: %s @ %s+0x%lx\n",
                    cfg->name, cfg->target_path, (unsigned long)cfg->offset);
            continue;
        }

        links_.push_back(link);
        attached_count++;
    }

    // 创建 ring buffer consumer（map 名: app_events）
    struct bpf_map* rb_map = bpf_object__find_map_by_name(obj_, "app_events");
    if (!rb_map) {
        fprintf(stderr, "[app] 找不到 ringbuf map 'app_events'\n");
        return -1;
    }

    ringbuf_ = ring_buffer__new(bpf_map__fd(rb_map), nullptr, nullptr, nullptr);
    if (!ringbuf_) {
        fprintf(stderr, "[app] 创建 ring buffer 失败\n");
        return -1;
    }

    ringbuf_fd_ = ring_buffer__epoll_fd(ringbuf_);
    attached_ = true;

    fprintf(stdout, "[app] 挂载完成：%d/%d 个 hook 成功\n",
            attached_count, hook_count_);
    return attached_count;
}

int AppCollector::detach()
{
    for (auto* link : links_) bpf_link__destroy(link);
    links_.clear();

    if (ringbuf_) {
        ring_buffer__free(ringbuf_);
        ringbuf_ = nullptr;
        ringbuf_fd_ = -1;
    }

    attached_ = false;
    return 0;
}

void AppCollector::destroy() { detach(); if (obj_) { bpf_object__close(obj_); obj_ = nullptr; } }
int  AppCollector::ringbuf_fd() const { return ringbuf_fd_; }
int  AppCollector::poll(int timeout_ms) { return ringbuf_ ? ring_buffer__consume(ringbuf_) : 0; }
