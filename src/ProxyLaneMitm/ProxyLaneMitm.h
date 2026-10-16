#pragma once
#include <stddef.h>
#include <stdint.h>

// Dynamically loaded; all sessions belong to the caller's PRC event thread.
// side 0 = application, side 1 = original destination (after proxy negotiation).
// Caller must preserve unsent output: peek, Send, consume only Send's byte count.
#define PLM_ABI_VERSION 3u
#define PLM_FEED 0u
#define PLM_PEEK 1u
#define PLM_CONSUME 2u
#define PLM_EOF 3u
#define PLM_STATUS 4u
#define PLM_CAN_READ 1
#define PLM_SHUTDOWN_CLIENT 2
#define PLM_SHUTDOWN_SERVER 4
#define PLM_CLIENT_EOF 8
#define PLM_SERVER_EOF 16
#define PLM_READY 32
typedef uint32_t (__cdecl *PLM_VERSION_FN)();
typedef int (__cdecl *PLM_CREATE_FN)(const char*, const char*, void**, char*, size_t);
typedef int (__cdecl *PLM_IO_FN)(void*, uint32_t, uint32_t, uint8_t*, size_t);
typedef void (__cdecl *PLM_ERROR_FN)(void*, char*, size_t);
typedef void (__cdecl *PLM_FREE_FN)(void*);
typedef int (__cdecl *PLM_CA_FN)(uint32_t, char*, size_t);
// Observer: 0 = a single UTF-8 error (no handshake JSON), 1/2 = decrypted
// application/upstream bytes, 3/4 = classified non-TLS application/upstream bytes.
typedef void (__cdecl *PLM_OBSERVER)(uintptr_t, uint32_t, const uint8_t*, size_t);
typedef void (__cdecl *PLM_OBSERVE_FN)(void*, PLM_OBSERVER, uintptr_t);
