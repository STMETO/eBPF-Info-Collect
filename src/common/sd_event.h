// sd_event.h — SD (Service Discovery) 模块的事件结构体
//
// 对应 bpf/sd.bpf.c，挂在 libvsomeip3-sd.so 的 service_discovery_impl 函数上。

#pragma once

#include "event_header.h"

struct sd_event {
    struct event_header hdr;

    uint16_t service_id;
    uint16_t instance_id;
    uint16_t eventgroup_id;
    uint32_t ttl;                   // 生存时间
};

#define HOOK_SD_SEND            0
#define HOOK_SD_PROCESS_OFFER   1
#define HOOK_SD_SEND_SUB        2
#define HOOK_SD_HANDLE_SUB      3
