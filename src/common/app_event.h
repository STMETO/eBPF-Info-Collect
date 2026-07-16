// app_event.h — app 模块的事件结构体
//
// 对应 bpf/app.bpf.c，挂在 application_impl 函数上。
// 参数是 C++ 对象（shared_ptr<message>），BPF 不能解引用，
// 所以只记录指针地址。SOME/IP header 信息在 routing 模块获取。

#pragma once

#include "event_header.h"

struct app_event {
    struct event_header hdr;

    uint64_t this_ptr;              // application_impl* (this)
    uint64_t message_ptr;           // message_impl* 裸指针
    int64_t  retval;                // 仅 uretprobe 有效
};

#define HOOK_APP_SEND_ENTRY     0
#define HOOK_APP_SEND_RET       1
#define HOOK_APP_ON_MESSAGE     2
