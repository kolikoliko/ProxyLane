#pragma once
#include <windows.h>
#include <stddef.h>

struct DetourHookBinding
{
    PVOID* original;
    PVOID replacement;
};

// Prepare all bindings in one transaction, aborting on preparation failure.
// No host thread is suspended: entry patches/pointer updates are not atomic
// to concurrent callers. Initialize callback state before installation and
// retain targets, pointer slots, callbacks and their state until process exit.
LONG InstallDetourHooks(const DetourHookBinding* bindings, size_t count);
