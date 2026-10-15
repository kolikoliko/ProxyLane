#include "DetourHooks.h"
#include "HookCallGate.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>

namespace {
void Check(bool ok, const char* message)
{
    if (!ok) { std::fprintf(stderr, "Detours: %s (error %lu)\n", message, GetLastError()); std::abort(); }
}
typedef ULONG_PTR (WINAPI *Function)();
Function original;
ULONG_PTR WINAPI Replacement()
{
    HookCallScope scope(g_HookCalls);
    return original() + (scope.Enabled() ? 1 : 0);
}
ULONG_PTR WINAPI WrongReplacement() { return 0; }
struct Code {
    BYTE* bytes;
    Code() : bytes(static_cast<BYTE*>(VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)))
    { Check(bytes != NULL, "allocate code"); }
    ~Code() { VirtualFree(bytes, 0, MEM_RELEASE); }
    void Seal() {
        DWORD old;
        Check(VirtualProtect(bytes, 4096, PAGE_EXECUTE_READ, &old) != FALSE, "protect code");
        FlushInstructionCache(GetCurrentProcess(), bytes, 4096);
    }
};
void Exercise(const BYTE* instructions, size_t size, bool addressResult)
{
    Code code;
    std::memcpy(code.bytes, instructions, size);
    const BYTE destination[] = { 0xb8, 42, 0, 0, 0, 0xc3 };
    std::memcpy(code.bytes + 128, destination, sizeof(destination));
    code.Seal();
    Function entry = reinterpret_cast<Function>(code.bytes);
    original = entry;
    ULONG_PTR expected = addressResult ? reinterpret_cast<ULONG_PTR>(code.bytes + 128) : 42;
    Check(entry() == expected, "original code result");
    DetourHookBinding binding = { reinterpret_cast<PVOID*>(&original), Replacement };
    for (int cycle = 0; cycle < 8; ++cycle) {
        Check(g_HookCalls.Close(1000), "close for attach");
        Check(ApplyDetourHooks(&binding, 1, true) == NO_ERROR, "attach relocated code");
        g_HookCalls.Open(true);
        Check(entry() == expected + 1 && original() == expected, "hook and trampoline results");
        Check(g_HookCalls.Close(1000), "close for detach");
        DetourHookBinding wrong = { reinterpret_cast<PVOID*>(&original), WrongReplacement };
        Check(ApplyDetourHooks(&wrong, 1, false) != NO_ERROR, "reject mismatched detach");
        Check(ApplyDetourHooks(&binding, 1, false) == NO_ERROR, "detach after rejected transaction");
        g_HookCalls.Open(false);
        Check(original == entry && entry() == expected, "restore original pointer and behavior");
        Check(std::memcmp(code.bytes, instructions, size) == 0, "restore original bytes");
        MEMORY_BASIC_INFORMATION info = {};
        VirtualQuery(code.bytes, &info, sizeof(info));
        Check(info.Protect == PAGE_EXECUTE_READ, "restore page protection");
    }
}
struct WorkerState { Function entry; volatile LONG stop; volatile LONG failures; volatile LONG calls; };
DWORD WINAPI CallWorker(void* parameter)
{
    WorkerState* state = static_cast<WorkerState*>(parameter);
    while (!InterlockedCompareExchange(&state->stop, 0, 0)) {
        ULONG_PTR result = state->entry();
        if (result != 42 && result != 43) InterlockedIncrement(&state->failures);
        InterlockedIncrement(&state->calls);
        SwitchToThread();
    }
    return 0;
}
void ConcurrentCycles()
{
    Code code;
    const BYTE constant[] = { 0xb8, 42, 0, 0, 0, 0xc3 };
    std::memcpy(code.bytes, constant, sizeof(constant)); code.Seal();
    original = reinterpret_cast<Function>(code.bytes);
    WorkerState state = { original, 0, 0, 0 };
    HANDLE workers[4];
    for (int i = 0; i < 4; ++i) { workers[i] = CreateThread(NULL, 0, CallWorker, &state, 0, NULL); Check(workers[i] != NULL, "start worker"); }
    DetourHookBinding binding = { reinterpret_cast<PVOID*>(&original), Replacement };
    for (int i = 0; i < 50; ++i) {
        Check(g_HookCalls.Close(5000), "drain for concurrent attach");
        Check(ApplyDetourHooks(&binding, 1, true) == NO_ERROR, "concurrent attach");
        g_HookCalls.Open(true);
        SwitchToThread();
        Check(g_HookCalls.Close(5000), "drain for concurrent detach");
        Check(ApplyDetourHooks(&binding, 1, false) == NO_ERROR, "concurrent detach");
        g_HookCalls.Open(false);
    }
    InterlockedExchange(&state.stop, 1);
    Check(WaitForMultipleObjects(4, workers, TRUE, 5000) == WAIT_OBJECT_0, "join callers");
    for (int i = 0; i < 4; ++i) CloseHandle(workers[i]);
    Check(state.calls > 0 && state.failures == 0, "concurrent results");
}
struct HeldCall { HANDLE entered; HANDLE release; };
DWORD WINAPI HoldCall(void* parameter)
{
    HeldCall* call = static_cast<HeldCall*>(parameter);
    HookCallScope outer(g_HookCalls);
    Check(outer.Enabled(), "enabled admission");
    SetEvent(call->entered);
    WaitForSingleObject(call->release, INFINITE);
    HookCallScope nested(g_HookCalls);
    Check(nested.Enabled(), "nested admission");
    return 0;
}
void GateTimeout()
{
    g_HookCalls.Open(true);
    HeldCall held = { CreateEventW(NULL, TRUE, FALSE, NULL), CreateEventW(NULL, TRUE, FALSE, NULL) };
    HANDLE worker = CreateThread(NULL, 0, HoldCall, &held, 0, NULL);
    Check(WaitForSingleObject(held.entered, 5000) == WAIT_OBJECT_0, "held callback started");
    Check(!g_HookCalls.Close(10) && GetLastError() == ERROR_TIMEOUT, "busy stop times out without detach");
    SetEvent(held.release);
    Check(WaitForSingleObject(worker, 5000) == WAIT_OBJECT_0, "drain nested callback");
    CloseHandle(worker); CloseHandle(held.entered); CloseHandle(held.release);
    Check(g_HookCalls.Close(1000), "close after callback returns"); g_HookCalls.Open(false);
    SetLastError(12345);
    { HookCallScope call(g_HookCalls); Check(!call.Enabled() && GetLastError() == 12345, "disabled admission preserves error"); }
    Check(GetLastError() == 12345, "callback exit preserves error");
    { HookCallScope call(g_HookCalls); Check(!g_HookCalls.Close(10) && GetLastError() == ERROR_BUSY, "reject lifecycle changes inside callback"); }
}
void Rollback()
{
    Code code;
    const BYTE constant[] = { 0xb8, 42, 0, 0, 0, 0xc3 };
    std::memcpy(code.bytes, constant, sizeof(constant));
    code.bytes[128] = 0xc3; // Too short, followed by non-padding bytes.
    code.Seal();
    original = reinterpret_cast<Function>(code.bytes);
    Function tooShort = reinterpret_cast<Function>(code.bytes + 128);
    DetourHookBinding bindings[] = { { reinterpret_cast<PVOID*>(&original), Replacement }, { reinterpret_cast<PVOID*>(&tooShort), WrongReplacement } };
    Check(ApplyDetourHooks(bindings, 2, true) != NO_ERROR, "reject unrelocatable batch");
    Check(original == reinterpret_cast<Function>(code.bytes) && original() == 42, "abort rolls back prepared hook");
    Check(std::memcmp(code.bytes, constant, sizeof(constant)) == 0, "abort leaves code unchanged");
}
}
int DetourHooksTestsMain()
{
    const BYTE call[] = { 0xe8, 123, 0, 0, 0, 0xc3 };
    const BYTE shortBranch[] = { 0x31, 0xc0, 0x74, 124, 0x90, 0xc3 };
    const BYTE nearBranch[] = { 0x31, 0xc0, 0x0f, 0x84, 120, 0, 0, 0, 0xc3 };
    Exercise(call, sizeof(call), false);
    Exercise(shortBranch, sizeof(shortBranch), false);
    Exercise(nearBranch, sizeof(nearBranch), false);
#ifdef _WIN64
    const BYTE lea[] = { 0x48, 0x8d, 0x05, 121, 0, 0, 0, 0xc3 };
    Exercise(lea, sizeof(lea), true);
    const BYTE mov[] = { 0x8b, 0x05, 123, 0, 0, 0, 0xc3 };
    Exercise(mov, sizeof(mov), false);
#endif
    Rollback(); GateTimeout(); ConcurrentCycles();
    std::puts("Detours relocation, rollback, lifecycle and concurrent callers passed");
    return 0;
}
