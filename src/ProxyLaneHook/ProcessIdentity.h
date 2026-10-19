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

namespace ProxyProcessIdentity
{
	// Only positive evidence removes a registered lifetime. Access denial or
	// a failed query must not hide a possibly running hooked application.
	inline BOOL HasExited(const HookProcessIdentityInfo& identity)
	{
		HANDLE process = OpenProcess(SYNCHRONIZE | 0x1000 /* QUERY_LIMITED_INFORMATION */,
			FALSE, identity.dwProcessId);
		if (!process)
			process = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION, FALSE, identity.dwProcessId);
		if (!process)
			return GetLastError() == ERROR_INVALID_PARAMETER;
		BOOL exited = WaitForSingleObject(process, 0) == WAIT_OBJECT_0;
		FILETIME created, ended, kernel, user;
		if (!exited && GetProcessTimes(process, &created, &ended, &kernel, &user))
			exited = (((ULONGLONG)created.dwHighDateTime << 32) | created.dwLowDateTime)
				!= identity.processCreateTime;
		CloseHandle(process);
		return exited;
	}
}

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
	// Copy a consistent snapshot of successful hooks into caller-owned memory.
	// Returns the required entry count; if capacity is too small, writes nothing.
	// Appended to preserve existing virtual method slots across the DLL boundary.
	virtual DWORD SnapshotHooked(HookProcessIdentityInfo* identities, DWORD capacity) = 0;
protected:
	virtual ~IProxyProcessRegistry() {}
};
