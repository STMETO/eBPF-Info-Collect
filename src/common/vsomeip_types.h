// vsomeip_types.h — SOME/IP protocol constants shared between BPF and userspace
// These must be C-compatible for BPF inclusion.

#pragma once

// ── SOME/IP Message Types (offset 14 in header) ──────────────────────
#define SOMEIP_MT_REQUEST           0x00  // Request (expects response)
#define SOMEIP_MT_REQUEST_NO_RETURN 0x01  // Fire & Forget (no response)
#define SOMEIP_MT_NOTIFICATION      0x02  // Event / Notification
#define SOMEIP_MT_REQUEST_ACK       0x40  // Transport-layer ACK (reliable)
#define SOMEIP_MT_RESPONSE          0x80  // Response
#define SOMEIP_MT_ERROR             0x81  // Error response

// ── SOME/IP Return Codes (offset 15 in header) ───────────────────────
#define SOMEIP_RC_OK                0x00
#define SOMEIP_RC_E_NOT_OK          0x01
#define SOMEIP_RC_E_UNKNOWN_SERVICE 0x02
#define SOMEIP_RC_E_UNKNOWN_METHOD  0x03
#define SOMEIP_RC_E_NOT_READY       0x04
#define SOMEIP_RC_E_NOT_REACHABLE   0x05
#define SOMEIP_RC_E_TIMEOUT         0x06
#define SOMEIP_RC_E_WRONG_PROTOCOL  0x07
#define SOMEIP_RC_E_WRONG_INTERFACE 0x08
#define SOMEIP_RC_E_MALFORMED       0x09
#define SOMEIP_RC_E_WRONG_MESSAGE   0x0A

// ── SOME/IP Header Layout (wire format, big-endian) ──────────────────
#define SOMEIP_HEADER_SIZE          16
#define SOMEIP_OFF_SERVICE_ID       0
#define SOMEIP_OFF_METHOD_ID        2
#define SOMEIP_OFF_LENGTH           4
#define SOMEIP_OFF_CLIENT_ID        8
#define SOMEIP_OFF_SESSION_ID       10
#define SOMEIP_OFF_PROTOCOL_VER     12
#define SOMEIP_OFF_INTERFACE_VER    13
#define SOMEIP_OFF_MESSAGE_TYPE     14
#define SOMEIP_OFF_RETURN_CODE      15

// ── Direction ────────────────────────────────────────────────────────
#define DIR_SEND    0
#define DIR_RECV    1

// ── Module IDs ───────────────────────────────────────────────────────
#define MODULE_ROUTING   1
#define MODULE_APP       2
#define MODULE_SD        3
