#include "DetourHooks.h"
#include <tlhelp32.h>
#include <vector>
#include <detours.h>

namespace
{
    struct TransactionLock
    {
        CRITICAL_SECTION value;
        TransactionLock() { InitializeCriticalSection(&value); }
        ~TransactionLock() { DeleteCriticalSection(&value); }
    } transactionLock;

    struct ScopedLock
    {
        ScopedLock() { EnterCriticalSection(&transactionLock.value); }
        ~ScopedLock() { LeaveCriticalSection(&transactionLock.value); }
    };

    struct ThreadHandles
    {
        std::vector<HANDLE> handles;
        ~ThreadHandles()
        {
            for (size_t i = 0; i < handles.size(); ++i) CloseHandle(handles[i]);
        }
        LONG Collect()
        {
            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (snapshot == INVALID_HANDLE_VALUE) return GetLastError();
            THREADENTRY32 entry = { sizeof(entry) };
            BOOL found = Thread32First(snapshot, &entry);
            LONG error = NO_ERROR;
            while (found)
            {
                if (entry.th32OwnerProcessID == GetCurrentProcessId() &&
                    entry.th32ThreadID != GetCurrentThreadId())
                {
                    HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME |
                        THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
                        FALSE, entry.th32ThreadID);
                    if (thread) handles.push_back(thread);
                    else if (GetLastError() != ERROR_INVALID_PARAMETER)
                    {
                        error = GetLastError();
                        break;
                    }
                }
                entry.dwSize = sizeof(entry);
                found = Thread32Next(snapshot, &entry);
            }
            if (!found && GetLastError() != ERROR_NO_MORE_FILES) error = GetLastError();
            CloseHandle(snapshot);
            return error;
        }
    };
}

LONG ApplyDetourHooks(const DetourHookBinding* bindings, size_t count, bool attach)
{
    if (!bindings && count) return ERROR_INVALID_PARAMETER;
    if (!count) return NO_ERROR;
    ScopedLock lock;
    for (size_t i = 0; i < count; ++i)
    {
        if (!bindings[i].original || !*bindings[i].original || !bindings[i].replacement)
            return ERROR_INVALID_PARAMETER;
        for (size_t j = 0; j < i; ++j)
            if (bindings[i].original == bindings[j].original ||
                *bindings[i].original == *bindings[j].original)
                return ERROR_INVALID_PARAMETER;
    }
    ThreadHandles threads;
    LONG error = threads.Collect();
    if (error != NO_ERROR) return error;
    error = DetourTransactionBegin();
    if (error != NO_ERROR) return error;
    // Prepare allocations and relocations before suspending peer threads.
    for (size_t i = 0; i < count && error == NO_ERROR; ++i)
        error = attach ? DetourAttach(bindings[i].original, bindings[i].replacement)
                       : DetourDetach(bindings[i].original, bindings[i].replacement);
    for (size_t i = 0; i < threads.handles.size() && error == NO_ERROR; ++i)
    {
        DWORD exitCode = 0;
        if (!GetExitCodeThread(threads.handles[i], &exitCode)) error = GetLastError();
        else if (exitCode == STILL_ACTIVE) error = DetourUpdateThread(threads.handles[i]);
    }
    if (error != NO_ERROR)
    {
        DetourTransactionAbort();
        return error;
    }
    return DetourTransactionCommit();
}
