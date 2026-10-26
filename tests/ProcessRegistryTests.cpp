#include "ProcessRegistry.h"
#include <iostream>
#include <thread>

static int RegistryFailure(int line)
{
	std::cerr << "ProcessRegistry test failed at line " << line << std::endl;
	return 1;
}

static ULONGLONG CreationTime(HANDLE process)
{
	FILETIME created, exited, kernel, user;
	if (!GetProcessTimes(process, &created, &exited, &kernel, &user)) return 0;
	return ((ULONGLONG)created.dwHighDateTime << 32) | created.dwLowDateTime;
}

int ProcessRegistryTestsMain()
{
	CProcessRegistry registry;
	HookProcessIdentityInfo identity = { 0 }, result = { 0 };
	if (registry.Register(&identity) || registry.Update(0, 100, 0) ||
		registry.Update(41, 0, 0)) return RegistryFailure(__LINE__);
	identity.dwProcessId = 41;
	identity.processCreateTime = 100;
	wcscpy_s(identity.szAppPath, L"C:\\test.exe");
	if (!registry.Register(&identity) || !registry.Get(41, 100, &result) ||
		result.hookState != PROCESS_HOOK_STATE_PENDING) return RegistryFailure(__LINE__);
	registry.Update(41, 100, ERROR_ACCESS_DENIED);
	if (!registry.Get(41, 100, &result) || result.hookState != PROCESS_HOOK_STATE_FAILED ||
		result.hookError != ERROR_ACCESS_DENIED) return RegistryFailure(__LINE__);
	// Concurrent pipe callbacks and late path reports converge on one record.
	std::thread first([&]() {
		for (int i = 0; i < 1000; ++i) registry.Update(41, 100, 0);
	});
	std::thread second([&]() {
		for (int i = 0; i < 1000; ++i) registry.Register(&identity);
	});
	first.join(); second.join();
	registry.Update(41, 100, ERROR_ACCESS_DENIED);
	if (!registry.Get(41, 100, &result) || result.hookState != PROCESS_HOOK_STATE_SUCCEEDED ||
		result.hookError || wcscmp(result.szAppPath, identity.szAppPath)) return RegistryFailure(__LINE__);
	// The success notification can precede a valid path registration.
	registry.Update(42, 200, 0);
	identity.dwProcessId = 42; identity.processCreateTime = 200;
	registry.Register(&identity);
	if (!registry.Get(42, 200, &result) || result.hookState != PROCESS_HOOK_STATE_SUCCEEDED ||
		!result.szAppPath[0]) return RegistryFailure(__LINE__);
	// PID reuse resets state/path, and an old delayed report cannot undo it.
	registry.Update(42, 300, ERROR_ACCESS_DENIED);
	if (registry.Register(&identity) || registry.Update(42, 200, 0) ||
		registry.Get(42, 200, &result)) return RegistryFailure(__LINE__);
	if (!registry.Get(42, 300, &result) || result.szAppPath[0] ||
		result.hookState != PROCESS_HOOK_STATE_FAILED) return RegistryFailure(__LINE__);
	// Failed/pending entries are excluded; each call includes newly registered
	// successes. An undersized buffer must not return a usable partial snapshot.
	HookProcessIdentityInfo snapshot[2] = {};
	if (registry.SnapshotHooked(NULL, 0) != 1 || registry.SnapshotHooked(snapshot, 2) != 1 ||
		snapshot[0].dwProcessId != 41 || snapshot[0].processCreateTime != 100) return RegistryFailure(__LINE__);
	registry.Update(43, 400, 0);
	snapshot[0].dwProcessId = 12345;
	if (registry.SnapshotHooked(snapshot, 1) != 2 || snapshot[0].dwProcessId != 12345 ||
		registry.SnapshotHooked(snapshot, 2) != 2 || snapshot[1].dwProcessId != 43 ||
		snapshot[1].processCreateTime != 400) return RegistryFailure(__LINE__);
	registry.Update(43, 500, ERROR_ACCESS_DENIED);
	if (registry.SnapshotHooked(snapshot, 2) != 1) return RegistryFailure(__LINE__);
	std::thread registration([&]() {
		for (DWORD i = 1000; i < 2000; ++i) registry.Update(i, i, 0);
	});
	for (int i = 0; i < 100; ++i)
	{
		HookProcessIdentityInfo concurrent[1001] = {};
		const DWORD count = registry.SnapshotHooked(concurrent, 1001);
		if (count < 1 || count > 1001) { registration.join(); return RegistryFailure(__LINE__); }
		for (DWORD j = 0; j < count; ++j)
			if (concurrent[j].hookState != PROCESS_HOOK_STATE_SUCCEEDED)
			{ registration.join(); return RegistryFailure(__LINE__); }
	}
	registration.join();
	if (registry.SnapshotHooked(NULL, 0) != 1001) return RegistryFailure(__LINE__);

	CProcessRegistry live;
	const DWORD pid = GetCurrentProcessId();
	const ULONGLONG created = CreationTime(GetCurrentProcess());
	live.Update(pid, created, 0);
	if (live.SnapshotHooked(snapshot, 2) != 1 || ProxyProcessIdentity::HasExited(snapshot[0])) return RegistryFailure(__LINE__);
	live.PruneExited();
	if (!live.Get(pid, created, &result)) return RegistryFailure(__LINE__);
	// An existing PID with a different creation time is also safely removed.
	CProcessRegistry reused;
	reused.Update(pid, created - 1, 0);
	if (reused.SnapshotHooked(snapshot, 2) != 1 || !ProxyProcessIdentity::HasExited(snapshot[0])) return RegistryFailure(__LINE__);
	reused.PruneExited();
	if (reused.Get(pid, created - 1, &result)) return RegistryFailure(__LINE__);

	WCHAR executable[MAX_PATH] = { 0 };
	GetSystemDirectoryW(executable, MAX_PATH);
	wcscat_s(executable, L"\\cmd.exe");
	WCHAR command[] = L"cmd.exe /d /c exit 0";
	STARTUPINFOW startup = { sizeof(startup) };
	PROCESS_INFORMATION child = { 0 };
	if (!CreateProcessW(executable, command, NULL, NULL, FALSE,
		CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &startup, &child)) return RegistryFailure(__LINE__);
	const ULONGLONG childTime = CreationTime(child.hProcess);
	live.Update(child.dwProcessId, childTime, 0);
	live.PruneExited();
	bool passed = live.Get(child.dwProcessId, childTime, &result) != FALSE;
	ResumeThread(child.hThread);
	if (WaitForSingleObject(child.hProcess, 10000) != WAIT_OBJECT_0)
	{
		TerminateProcess(child.hProcess, 1);
		passed = false;
	}
	live.PruneExited();
	passed = passed && !live.Get(child.dwProcessId, childTime, &result) &&
		live.Get(pid, created, &result);
	CloseHandle(child.hThread); CloseHandle(child.hProcess);
	if (!passed) return RegistryFailure(__LINE__);
	// A real process with an empty DACL cannot be reopened for queries. Keep
	// its registered identity rather than interpreting access denial as exit.
	ACL acl;
	SECURITY_DESCRIPTOR descriptor;
	if (!InitializeAcl(&acl, sizeof(acl), ACL_REVISION) ||
		!InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) ||
		!SetSecurityDescriptorDacl(&descriptor, TRUE, &acl, FALSE)) return RegistryFailure(__LINE__);
	SECURITY_ATTRIBUTES attributes = { sizeof(attributes), &descriptor, FALSE };
	WCHAR protectedCommand[] = L"cmd.exe /d /c exit 0";
	if (!CreateProcessW(executable, protectedCommand, &attributes, NULL, FALSE,
		CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &startup, &child)) return RegistryFailure(__LINE__);
	const ULONGLONG protectedTime = CreationTime(child.hProcess);
	CProcessRegistry protectedRegistry;
	protectedRegistry.Update(child.dwProcessId, protectedTime, 0);
	HANDLE denied = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION, FALSE, child.dwProcessId);
	const DWORD openError = GetLastError();
	passed = !denied && openError == ERROR_ACCESS_DENIED;
	if (!passed) std::cerr << "Expected query access denial, handle=" << denied << ", error=" << openError << std::endl;
	if (denied) CloseHandle(denied);
	passed = passed && protectedRegistry.SnapshotHooked(snapshot, 2) == 1 &&
		!ProxyProcessIdentity::HasExited(snapshot[0]);
	protectedRegistry.PruneExited();
	passed = passed && protectedRegistry.Get(child.dwProcessId, protectedTime, &result);
	if (!passed) std::cerr << "Protected live identity was not retained" << std::endl;
	ResumeThread(child.hThread);
	if (WaitForSingleObject(child.hProcess, 10000) != WAIT_OBJECT_0)
	{
		TerminateProcess(child.hProcess, 1);
		WaitForSingleObject(child.hProcess, 10000);
		passed = false;
	}
	// Keep the exited object alive through its original handles. Query access
	// is still denied, but it must no longer block ProxyLane's exit warning.
	protectedRegistry.PruneExited();
	if (protectedRegistry.Get(child.dwProcessId, protectedTime, &result))
	{ std::cerr << "Exited protected identity with retained handles was not pruned" << std::endl; passed = false; }
	CloseHandle(child.hThread); CloseHandle(child.hProcess);
	// Removal remains stable after the retained handles are closed.
	for (int i = 0; i < 100 && protectedRegistry.Get(child.dwProcessId, protectedTime, &result); ++i)
	{
		protectedRegistry.PruneExited();
		Sleep(10);
	}
	if (protectedRegistry.Get(child.dwProcessId, protectedTime, &result))
	{ std::cerr << "Exited protected identity was not pruned" << std::endl; passed = false; }
	if (!passed) return RegistryFailure(__LINE__);
	std::cout << "ProcessRegistry tests passed" << std::endl;
	return 0;
}
