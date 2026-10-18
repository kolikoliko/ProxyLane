#pragma once
#include <windows.h>
#include <set>
#include <utility>

// GUI-lifetime history: stopping/restarting the PRC does not remove remote hooks.
// No parent PID is stored; a successful hook belongs to one process lifetime.
class CHookedProcessRegistry
{
public:
	typedef std::pair<DWORD, ULONGLONG> Identity;
	typedef std::set<Identity> Identities;

	CHookedProcessRegistry() { InitializeCriticalSection(&m_lock); }
	~CHookedProcessRegistry() { DeleteCriticalSection(&m_lock); }

	void Record(DWORD pid, ULONGLONG creationTime, DWORD error)
	{
		if (!pid || !creationTime || error != 0) return;
		EnterCriticalSection(&m_lock);
		m_identities.insert(Identity(pid, creationTime));
		LeaveCriticalSection(&m_lock);
	}

	Identities Snapshot()
	{
		EnterCriticalSection(&m_lock);
		Identities result = m_identities;
		LeaveCriticalSection(&m_lock);
		return result;
	}

private:
	CHookedProcessRegistry(const CHookedProcessRegistry&);
	CHookedProcessRegistry& operator=(const CHookedProcessRegistry&);
	CRITICAL_SECTION m_lock;
	Identities m_identities;
};
