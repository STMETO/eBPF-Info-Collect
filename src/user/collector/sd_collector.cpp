// sd_collector.cpp — 服务发现模块的实现

#include "sd_collector.h"

extern "C" {
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
}

#include "../../common/vsomeip_event.h"
#include "../../hook_config.h"

#include <cstdio>
#include <cstring>

SdCollector::SdCollector() = default;
SdCollector::~SdCollector() { destroy(); }

int SdCollector::init(const char* bpf_obj_path)
{
    obj_ = bpf_object__open(bpf_obj_path);
    if (!obj_) {
        fprintf(stderr, "[sd] 打开 BPF 对象失败: %s\n", bpf_obj_path);
        return -1;
    }

    if (bpf_object__load(obj_) != 0) {
        fprintf(stderr, "[sd] 加载 BPF 对象失败\n");
        bpf_object__close(obj_);
        obj_ = nullptr;
        return -1;
    }

    filter_own_hooks();

    fprintf(stdout, "[sd] 初始化完成，%d 个 hook 待挂载\n", hook_count_);
    return 0;
}

void SdCollector::filter_own_hooks()
{
    own_hooks_.clear();
    for (int i = 0; i < NUM_HOOKS; i++) {
        const struct hook_cfg* cfg = &hook_configs[i];
        // sd 模块的 hook 前缀
        if (strncmp(cfg->name, "sd_", 3) == 0) {
            own_hooks_.push_back(cfg);
        }
    }
    hook_count_ = (int)own_hooks_.size();
}

struct bpf_program* SdCollector::find_bpf_program(const char* hook_name)
{
    char prog_name[64];
    snprintf(prog_name, sizeof(prog_name), "hook_%s", hook_name);
    return bpf_object__find_program_by_name(obj_, prog_name);
}

int SdCollector::attach(int target_pid)
{
    if (!obj_) {
        fprintf(stderr, "[sd] 未初始化\n");
        return -1;
    }

    if (attached_) detach();

    int attached_count = 0;

    for (const auto* cfg : own_hooks_) {
        struct bpf_program* prog = find_bpf_program(cfg->name);
        if (!prog) continue;

        DECLARE_LIBBPF_OPTS(bpf_uprobe_opts, opts,
            .retprobe = cfg->retprobe,
        );

        struct bpf_link* link = bpf_program__attach_uprobe_opts(
            prog, target_pid, cfg->target_path, cfg->offset, &opts);

        if (!link) {
            fprintf(stderr, "[sd] 挂载失败: %s @ %s+0x%lx\n",
                    cfg->name, cfg->target_path, (unsigned long)cfg->offset);
            continue;
        }

        links_.push_back(link);
        attached_count++;
    }

    // ringbuf map 名: sd_events
    struct bpf_map* rb_map = bpf_object__find_map_by_name(obj_, "sd_events");
    if (!rb_map) {
        fprintf(stderr, "[sd] 找不到 ringbuf map 'sd_events'\n");
        return -1;
    }

    ringbuf_ = ring_buffer__new(bpf_map__fd(rb_map), nullptr, nullptr, nullptr);
    if (!ringbuf_) {
        fprintf(stderr, "[sd] 创建 ring buffer 失败\n");
        return -1;
    }

    ringbuf_fd_ = ring_buffer__epoll_fd(ringbuf_);
    attached_ = true;

    fprintf(stdout, "[sd] 挂载完成：%d/%d 个 hook 成功\n",
            attached_count, hook_count_);
    return attached_count;
}

int SdCollector::detach()
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

void SdCollector::destroy() { detach(); if (obj_) { bpf_object__close(obj_); obj_ = nullptr; } }
int  SdCollector::ringbuf_fd() const { return ringbuf_fd_; }
int  SdCollector::poll(int timeout_ms) { return ringbuf_ ? ring_buffer__consume(ringbuf_) : 0; }
