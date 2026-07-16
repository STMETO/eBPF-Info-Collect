// main.cpp — vsomeip 信息收集器入口
//
// 用法：
//   vsomeip_collector [选项]
//
// 选项：
//   -p, --pid <PID>       只监控指定 PID 的进程
//                           -1 = 所有进程（默认）
//   -d, --bpf-dir <DIR>    BPF 对象文件目录（默认: /usr/lib/ebpf）
//   -o, --output <TYPE>    输出类型: stdout | file | both（默认: stdout）
//   -f, --log-file <PATH>  日志文件路径（配合 -o file 或 -o both）
//   --json                 JSON 格式输出（默认: 人类可读）
//   -s, --stats <SEC>      统计摘要间隔（秒，默认: 10，0=关闭）
//   --enable <模块列表>     只启用指定模块（逗号分隔: routing,app,sd）
//   --disable <模块列表>    禁用指定模块
//   -v, --verbose          详细输出
//   -h, --help             显示帮助信息
//
// 示例：
//   # 监控 PID 1234，终端人类可读输出
//   vsomeip_collector -p 1234
//
//   # 监控所有进程，JSON 格式写入文件
//   vsomeip_collector -o file -f /tmp/vsomeip.log --json
//
//   # 只启用 routing 模块，每 5 秒输出统计
//   vsomeip_collector --enable routing -s 5

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <getopt.h>
#include <unistd.h>

#include "collector/collector_base.h"
#include "collector/collector_manager.h"
#include "collector/collector.h"
#include "output/stdout_writer.h"
#include "output/file_writer.h"
#include "stats/stats_collector.h"
#include "../gen/hook_config.h"

// ── 默认配置 ──────────────────────────────────────────────────────────

// ── 帮助信息 ──────────────────────────────────────────────────────────
static void print_help(const char* prog)
{
    fprintf(stdout,
        "vsomeip_collector — eBPF-based SOME/IP traffic monitor\n"
        "\n"
        "用法: %s [选项]\n"
        "\n"
        "选项:\n"
        "  -p, --pid <PID>        只监控指定 PID（默认: -1 = 所有进程）\n"
        "  -o, --output <TYPE>    输出类型: stdout | file | both（默认: stdout）\n"
        "  -f, --log-file <PATH>  日志文件路径\n"
        "  --json                 JSON 格式输出（默认: 人类可读）\n"
        "  -s, --stats <SEC>      统计摘要间隔（秒，默认: 10）\n"
        "  --enable <list>        只启用指定模块: routing,app,sd\n"
        "  --disable <list>       禁用指定模块\n"
        "  -v, --verbose          详细输出\n"
        "  -h, --help             显示本帮助\n"
        "\n"
        "示例:\n"
        "  %s -p 1234                          # 监控 PID 1234\n"
        "  %s -o file -f /tmp/vsomeip.log      # 日志写入文件\n"
        "  %s --enable routing -s 5 --json     # 只开 routing，JSON 统计\n"
        "\n",
        prog, prog, prog, prog
    );
}

// ── 主函数 ────────────────────────────────────────────────────────────
int main(int argc, char** argv)
{
    // ── 解析命令行参数 ───────────────────────────────────────────────

    // getopt_long 的长选项定义
    static struct option long_opts[] = {
        {"pid",      required_argument, nullptr, 'p'},
        {"output",   required_argument, nullptr, 'o'},
        {"log-file", required_argument, nullptr, 'f'},
        {"json",     no_argument,       nullptr, 'j'},
        {"stats",    required_argument, nullptr, 's'},
        {"enable",   required_argument, nullptr, 'e'},
        {"disable",  required_argument, nullptr, 'x'},
        {"verbose",  no_argument,       nullptr, 'v'},
        {"help",     no_argument,       nullptr, 'h'},
        {nullptr,    0,                 nullptr, 0}
    };

    std::string output    = "stdout";
    std::string log_file;
    std::string enable_list;
    std::string disable_list;
    int    target_pid     = -1;           // -1 = 所有进程
    int    stats_interval = 10;           // 默认每 10 秒输出统计
    bool   use_json       = false;
    bool   verbose        = false;

    int opt;
    while ((opt = getopt_long(argc, argv, "p:o:f:s:vh", long_opts, nullptr)) != -1) {
        switch (opt) {
            case 'p':
                target_pid = atoi(optarg);
                break;
            case 'o':
                output = optarg;
                break;
            case 'f':
                log_file = optarg;
                break;
            case 'j':
                use_json = true;
                break;
            case 's':
                stats_interval = atoi(optarg);
                break;
            case 'e':
                enable_list = optarg;
                break;
            case 'x':
                disable_list = optarg;
                break;
            case 'v':
                verbose = true;
                break;
            case 'h':
                print_help(argv[0]);
                return 0;
            default:
                print_help(argv[0]);
                return 1;
        }
    }

    // ── 打印启动信息 ─────────────────────────────────────────────────
    fprintf(stdout, "╔══════════════════════════════════════════════╗\n");
    fprintf(stdout, "║  vsomeip collector — eBPF uprobe monitor    ║\n");
    fprintf(stdout, "╠══════════════════════════════════════════════╣\n");
    fprintf(stdout, "║  BPF     : 嵌入编译（无需外部文件）        ║\n");
    fprintf(stdout, "║  Target  : %s%-32s ║\n",
            target_pid < 0 ? "所有进程" : "PID ",
            target_pid < 0 ? "" : std::to_string(target_pid).c_str());
    fprintf(stdout, "║  Output  : %-32s ║\n", output.c_str());
    fprintf(stdout, "║  Stats   : every %d sec%-22s ║\n", stats_interval, "");
    fprintf(stdout, "╚══════════════════════════════════════════════╝\n");

    // ── 创建日志输出 ─────────────────────────────────────────────────
    ILogWriter* writer = nullptr;
    StdoutWriter stdout_writer(use_json);
    FileWriter   file_writer(log_file.c_str(), true);

    if (output == "file") {
        writer = &file_writer;
        fprintf(stdout, "日志输出: 文件 (%s)\n", log_file.c_str());
    } else if (output == "both") {
        // "both" 模式：后续可扩展为 MultiWriter，同时输出到终端和文件
        writer = &stdout_writer;
        fprintf(stdout, "日志输出: 终端 + 文件 (%s)\n", log_file.c_str());
    } else {
        writer = &stdout_writer;
        fprintf(stdout, "日志输出: 终端\n");
    }

    // ── 创建收集器管理器 ─────────────────────────────────────────────
    CollectorManager manager;
    manager.set_stats_interval(stats_interval);

    // ── 创建统计收集器 ───────────────────────────────────────────────
    // 统计数据在 ringbuf 回调中实时更新，不是定时采集。
    // flush_report() 只是定时把累计值输出成 [STATS] 日志行。
    StatsCollector stats;
    stats.set_log_writer(writer);
    stats.set_report_interval(stats_interval);

    // ── 核心接线：把 stats + writer 注入 CollectorManager ──────────
    // CollectorManager 在 attach_all() 时会把 EventContext 传给每个 collector，
    // collector 创建 ringbuf 时把回调函数注册进去。
    // 之后每次 BPF 事件到达，回调函数自动调用：
    //   stats.process_event()  → 计数器 + 时延匹配
    //   writer.write()         → 日志输出
    manager.set_event_context(&stats, writer);

    // ── 注册收集器（配置驱动）─────────────────────────────────────────
    // 遍历 file_groups[]，每个分组创建一个 Collector 实例。
    // 模块名用 file_group 的逻辑名称来标识（如 "routing"）。
    // --enable / --disable 通过文件名的前缀匹配来过滤。

    std::string enabled_names;
    for (int i = 0; i < NUM_FILE_GROUPS; i++) {
        const char* mod_name = file_groups[i].name;  // 如 "routing"

        bool enabled = true;
        if (!enable_list.empty()) {
            enabled = (enable_list.find(mod_name) != std::string::npos);
        }
        if (!disable_list.empty()) {
            if (disable_list.find(mod_name) != std::string::npos)
                enabled = false;
        }

        if (enabled) {
            manager.add_collector(new Collector(&file_groups[i]));
            if (!enabled_names.empty()) enabled_names += " ";
            enabled_names += mod_name;
        }
    }

    fprintf(stdout, "启用模块: %s\n", enabled_names.c_str());

    // ── 初始化所有 collector（BPF 字节码已嵌入，无需外部文件）────────
    int ok = manager.init_all();
    if (ok == 0) {
        fprintf(stderr, "错误：没有 collector 初始化成功\n");
        return 1;
    }

    // ── 挂载到目标进程 ───────────────────────────────────────────────
    manager.attach_all(target_pid);

    // ── 进入主事件循环 ───────────────────────────────────────────────
    // 这个循环会一直运行，直到收到 SIGINT (Ctrl+C) 或 SIGTERM
    fprintf(stdout, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    fprintf(stdout, "开始监控... (Ctrl+C 停止)\n\n");

    manager.run_loop();

    // ── 清理 ─────────────────────────────────────────────────────────
    fprintf(stdout, "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    // 输出最后一次统计摘要
    stats.flush_report();
    stats.evict_expired();

    manager.shutdown();

    fprintf(stdout, "已退出。\n");
    return 0;
}
