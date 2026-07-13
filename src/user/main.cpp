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

#include "collector/collector_manager.h"
#include "collector/routing_collector.h"
#include "collector/app_collector.h"
#include "collector/sd_collector.h"
#include "output/stdout_writer.h"
#include "output/file_writer.h"
#include "stats_collector.h"

// ── 默认配置 ──────────────────────────────────────────────────────────
static const char* DEFAULT_BPF_DIR = "/usr/lib/ebpf";

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
        "  -d, --bpf-dir <DIR>    BPF 对象文件目录（默认: %s）\n"
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
        prog, DEFAULT_BPF_DIR, prog, prog, prog
    );
}

// ── 主函数 ────────────────────────────────────────────────────────────
int main(int argc, char** argv)
{
    // ── 解析命令行参数 ───────────────────────────────────────────────

    // getopt_long 的长选项定义
    static struct option long_opts[] = {
        {"pid",      required_argument, nullptr, 'p'},
        {"bpf-dir",  required_argument, nullptr, 'd'},
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

    std::string bpf_dir   = DEFAULT_BPF_DIR;
    std::string output    = "stdout";
    std::string log_file;
    std::string enable_list;
    std::string disable_list;
    int    target_pid     = -1;           // -1 = 所有进程
    int    stats_interval = 10;           // 默认每 10 秒输出统计
    bool   use_json       = false;
    bool   verbose        = false;

    int opt;
    while ((opt = getopt_long(argc, argv, "p:d:o:f:s:vh", long_opts, nullptr)) != -1) {
        switch (opt) {
            case 'p':
                target_pid = atoi(optarg);
                break;
            case 'd':
                bpf_dir = optarg;
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
    fprintf(stdout, "║  BPF dir : %-32s ║\n", bpf_dir.c_str());
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
    manager.set_log_writer(writer);
    manager.set_stats_interval(stats_interval);

    // ── 注册收集器 ───────────────────────────────────────────────────
    // 三个模块的 collector，可以通过 --enable/--disable 控制

    bool en_routing = true, en_app = true, en_sd = true;

    // 解析 --enable（白名单模式）
    if (!enable_list.empty()) {
        en_routing = en_app = en_sd = false;  // 默认全关
        if (enable_list.find("routing") != std::string::npos) en_routing = true;
        if (enable_list.find("app")     != std::string::npos) en_app = true;
        if (enable_list.find("sd")      != std::string::npos) en_sd = true;
    }

    // 解析 --disable（黑名单模式）
    if (!disable_list.empty()) {
        if (disable_list.find("routing") != std::string::npos) en_routing = false;
        if (disable_list.find("app")     != std::string::npos) en_app = false;
        if (disable_list.find("sd")      != std::string::npos) en_sd = false;
    }

    if (en_routing) manager.add_collector(new RoutingCollector());
    if (en_app)     manager.add_collector(new AppCollector());
    if (en_sd)      manager.add_collector(new SdCollector());

    fprintf(stdout, "启用模块: %s%s%s\n",
            en_routing ? "routing " : "",
            en_app     ? "app "     : "",
            en_sd      ? "sd"       : "");

    // ── 创建统计收集器 ───────────────────────────────────────────────
    StatsCollector stats;
    stats.set_log_writer(writer);
    stats.set_report_interval(stats_interval);

    // ── 初始化所有 collector ─────────────────────────────────────────
    int ok = manager.init_all(bpf_dir.c_str());
    if (ok == 0) {
        fprintf(stderr, "错误：没有 collector 初始化成功，检查 BPF 文件是否在 %s/\n",
                bpf_dir.c_str());
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
