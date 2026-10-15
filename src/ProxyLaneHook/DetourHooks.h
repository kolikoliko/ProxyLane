#pragma once
#include <windows.h>
#include <stddef.h>

struct DetourHookBinding
{
    PVOID* original;
    PVOID replacement;
};

// All bindings commit together. On failure their pointers and installed state
// remain unchanged. Callers must keep the bindings/pointer slots alive and
// quiesce their callbacks before detaching or destroying callback state.
LONG ApplyDetourHooks(const DetourHookBinding* bindings, size_t count, bool attach);
