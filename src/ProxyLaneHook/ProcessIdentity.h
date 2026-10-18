#pragma once
#include <windows.h>

#pragma pack(push, 1)
typedef struct _HookProcessIdentityInfo
{
	DWORD dwProcessId;
	ULONGLONG processCreateTime;
	WCHAR szAppPath[MAX_PATH];
	DWORD hookState;
	DWORD hookError;
} HookProcessIdentityInfo, *LPHookProcessIdentityInfo;
#pragma pack(pop)

#define PROCESS_HOOK_STATE_PENDING 0
#define PROCESS_HOOK_STATE_SUCCEEDED 1
#define PROCESS_HOOK_STATE_FAILED 2

// Borrowed from the Hook module loaded by the GUI. Survives service recreation.
// All methods are thread-safe; no STL objects cross the DLL boundary.
class IProxyProcessRegistry
{
public:
	virtual BOOL Register(const HookProcessIdentityInfo* identity) = 0;
	virtual BOOL Update(DWORD pid, ULONGLONG creationTime, DWORD error) = 0;
	// creationTime == 0 queries the latest registered lifetime for path lookup.
	virtual BOOL Get(DWORD pid, ULONGLONG creationTime, HookProcessIdentityInfo* identity) = 0;
	virtual void PruneExited() = 0;
protected:
	virtual ~IProxyProcessRegistry() {}
};
