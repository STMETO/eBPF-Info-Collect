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

// hook_id 见 common/hook_ids.h（由 gen_hook_config.sh 自动生成）
