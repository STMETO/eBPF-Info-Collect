// sd_collector.cpp — 服务发现模块的实现
//
// 加载 sd.bpf.o，把 4 个 uprobe hook 挂载到 service_discovery_impl 的函数上，
// 然后通过 ring buffer 消费 BPF 事件，推给统计和日志模块。
//
// SD 模块的 4 个 hook 分别对应：
//   1. sd_send                 → service_discovery_impl::send(bool)
//                                 SD 消息缓冲队列刷新到网络
//   2. sd_process_offer        → process_offerservice_serviceentry(...)
//                                 收到并处理 OfferService 条目
//   3. sd_send_subscription    → send_subscription(...)
//                                 客户端发送 SubscribeEventgroup
//   4. sd_handle_subscription  → handle_eventgroup_subscription(...)
//                                 服务端处理收到的订阅请求
//
// SD 模块的特点：
//   - 所有 hook 都挂在 libvsomeip3-sd.so（不是 libvsomeip3.so）
//   - 函数参数是 C++ 对象（subscription、message_impl），BPF 不能解引用
//   - 所以事件的 SOME/IP header 全为 0，统计信息通过 arg0/arg1/arg2 传递
//   - arg0 = service_id, arg1 = instance_id, arg2 = eventgroup_id

#include "sd_collector.h"

// libbpf C API
extern "C" {
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
}

#include "../../common/vsomeip_event.h"   // struct vsomeip_event
#include "../../common/vsomeip_types.h"   // MODULE_SD 等常量
#include "../../hook_config.h"             // NUM_HOOKS, struct hook_cfg
#include "../stats_collector.h"            // StatsCollector::process_event()
#include "../output/log_writer.h"          // ILogWriter::write()

#include <cstdio>
#include <cstring>

// ═══════════════════════════════════════════════════════════════════════
// 构造 / 析构
// ═══════════════════════════════════════════════════════════════════════

SdCollector::SdCollector() = default;
SdCollector::~SdCollector() { destroy(); }

// ═══════════════════════════════════════════════════════════════════════
// ringbuf_callback — libbpf 每消费到一个事件就会调用这个函数
//
// 功能：把 BPF 内核态发来的事件转交给统计和日志模块处理。
//
// @param ctx    ring_buffer__new() 时传入的 this 指针
// @param data   vsomeip_event 的用户态副本
// @param size   数据大小
// @return       0 = 继续消费
// ═══════════════════════════════════════════════════════════════════════

int SdCollector::ringbuf_callback(void *ctx, void *data, size_t size)
{
    if (size < sizeof(struct vsomeip_event))
        return 0;

    auto* self  = static_cast<SdCollector*>(ctx);
    auto* event = static_cast<const struct vsomeip_event*>(data);

    if (!self->event_ctx_)
        return 0;

    // hook_id → 人类可读名称（4 个 hook）
    static const char* hook_names[] = {
        "sd_send",                 // HOOK_SD_SEND          = 0
        "sd_process_offer",        // HOOK_SD_PROCESS_OFFER = 1
        "sd_send_subscription",   // HOOK_SD_SEND_SUB      = 2
        "sd_handle_subscription", // HOOK_SD_HANDLE_SUB    = 3
    };
    const char* hook_name = (event->hook_id < 4)
        ? hook_names[event->hook_id] : "unknown";

    // 推给统计模块（计数器累加，SD 不参与时延匹配因为 header 为 0）
    self->event_ctx_->stats->process_event(*event, hook_name);
    // 推给日志模块（格式化输出）
    self->event_ctx_->writer->write(*event, hook_name);

    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
// init — 打开并加载 BPF 对象
// ═══════════════════════════════════════════════════════════════════════

int SdCollector::init(const char* bpf_obj_path)
{
    obj_ = bpf_object__open(bpf_obj_path);
    if (!obj_) {
        fprintf(stderr, "[sd] 打开 BPF 对象失败: %s\n"
                "  请检查 sd.bpf.o 是否存在\n", bpf_obj_path);
        return -1;
    }

    if (bpf_object__load(obj_) != 0) {
        fprintf(stderr, "[sd] 加载 BPF 对象失败（verifier 拒绝了程序）\n");
        bpf_object__close(obj_);
        obj_ = nullptr;
        return -1;
    }

    filter_own_hooks();

    fprintf(stdout, "[sd] 初始化完成，%d 个 hook 待挂载\n", hook_count_);
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
// filter_own_hooks — 筛选 sd_ 前缀的 hook
// ═══════════════════════════════════════════════════════════════════════

void SdCollector::filter_own_hooks()
{
    own_hooks_.clear();
    for (int i = 0; i < NUM_HOOKS; i++) {
        if (strncmp(hook_configs[i].name, "sd_", 3) == 0)
            own_hooks_.push_back(&hook_configs[i]);
    }
    hook_count_ = (int)own_hooks_.size();
}

// ═══════════════════════════════════════════════════════════════════════
// find_bpf_program — hook 名 → BPF 程序
// ═══════════════════════════════════════════════════════════════════════

struct bpf_program* SdCollector::find_bpf_program(const char* hook_name)
{
    char prog_name[64];
    snprintf(prog_name, sizeof(prog_name), "hook_%s", hook_name);
    return bpf_object__find_program_by_name(obj_, prog_name);
}

// ═══════════════════════════════════════════════════════════════════════
// attach — 挂载 hooks + 创建 ringbuf consumer
//
// SD 模块挂在 libvsomeip3-sd.so 上（不是 libvsomeip3.so），
// target_path 在 hooks.json 中单独配置。
// ═══════════════════════════════════════════════════════════════════════

int SdCollector::attach(int target_pid)
{
    if (!obj_) {
        fprintf(stderr, "[sd] 未初始化\n");
        return -1;
    }
    if (attached_) detach();

    int attached_count = 0;

    // ── 第一步：逐个挂载 uprobe ──────────────────────────────────────
    for (const auto* cfg : own_hooks_) {
        struct bpf_program* prog = find_bpf_program(cfg->name);
        if (!prog) {
            fprintf(stderr, "[sd] 找不到 BPF 程序: hook_%s\n", cfg->name);
            continue;
        }

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

    // ── 第二步：创建 ring buffer consumer ────────────────────────────
    struct bpf_map* rb_map = bpf_object__find_map_by_name(obj_, "sd_events");
    if (!rb_map) {
        fprintf(stderr, "[sd] 找不到 ringbuf map 'sd_events'\n");
        return -1;
    }

    ringbuf_ = ring_buffer__new(
        bpf_map__fd(rb_map),
        ringbuf_callback,       // 事件回调
        this,                   // 回调上下文
        nullptr
    );

    if (!ringbuf_) {
        fprintf(stderr, "[sd] 创建 ring buffer consumer 失败\n");
        return -1;
    }

    ringbuf_fd_ = ring_buffer__epoll_fd(ringbuf_);
    attached_ = true;

    fprintf(stdout, "[sd] 挂载完成：%d/%d 个 hook 成功\n",
            attached_count, hook_count_);
    return attached_count;
}

// ═══════════════════════════════════════════════════════════════════════
// detach — 卸载所有 hook 和 ring buffer
// ═══════════════════════════════════════════════════════════════════════

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
    fprintf(stdout, "[sd] 已卸载所有 hook\n");
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
// 其余接口方法
// ═══════════════════════════════════════════════════════════════════════
void SdCollector::destroy()
{
    detach();
    if (obj_) {
        bpf_object__close(obj_);
        obj_ = nullptr;
    }
}

int SdCollector::ringbuf_fd() const { return ringbuf_fd_; }

// poll — 消费 ring buffer，内部调用 ringbuf_callback
int SdCollector::poll(int /*timeout_ms*/)
{
    if (!ringbuf_) return 0;
    return ring_buffer__consume(ringbuf_);
}
