#include "ProcessRegistry.h"
#include <iostream>
#include <thread>

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
		registry.Update(41, 0, 0)) return 1;
	identity.dwProcessId = 41;
	identity.processCreateTime = 100;
	wcscpy_s(identity.szAppPath, L"C:\\test.exe");
	if (!registry.Register(&identity) || !registry.Get(41, 100, &result) ||
		result.hookState != PROCESS_HOOK_STATE_PENDING) return 1;
	registry.Update(41, 100, ERROR_ACCESS_DENIED);
	if (!registry.Get(41, 100, &result) || result.hookState != PROCESS_HOOK_STATE_FAILED ||
		result.hookError != ERROR_ACCESS_DENIED) return 1;
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
		result.hookError || wcscmp(result.szAppPath, identity.szAppPath)) return 1;
	// The success notification can precede a valid path registration.
	registry.Update(42, 200, 0);
	identity.dwProcessId = 42; identity.processCreateTime = 200;
	registry.Register(&identity);
	if (!registry.Get(42, 200, &result) || result.hookState != PROCESS_HOOK_STATE_SUCCEEDED ||
		!result.szAppPath[0]) return 1;
	// PID reuse resets state/path, and an old delayed report cannot undo it.
	registry.Update(42, 300, ERROR_ACCESS_DENIED);
	if (registry.Register(&identity) || registry.Update(42, 200, 0) ||
		registry.Get(42, 200, &result)) return 1;
	if (!registry.Get(42, 300, &result) || result.szAppPath[0] ||
		result.hookState != PROCESS_HOOK_STATE_FAILED) return 1;

	CProcessRegistry live;
	const DWORD pid = GetCurrentProcessId();
	const ULONGLONG created = CreationTime(GetCurrentProcess());
	live.Update(pid, created, 0);
	live.PruneExited();
	if (!live.Get(pid, created, &result)) return 1;
	// An existing PID with a different creation time is also safely removed.
	CProcessRegistry reused;
	reused.Update(pid, created - 1, 0);
	reused.PruneExited();
	if (reused.Get(pid, created - 1, &result)) return 1;

	WCHAR executable[MAX_PATH] = { 0 };
	GetSystemDirectoryW(executable, MAX_PATH);
	wcscat_s(executable, L"\\cmd.exe");
	WCHAR command[] = L"cmd.exe /d /c exit 0";
	STARTUPINFOW startup = { sizeof(startup) };
	PROCESS_INFORMATION child = { 0 };
	if (!CreateProcessW(executable, command, NULL, NULL, FALSE,
		CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &startup, &child)) return 1;
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
	if (!passed) return 1;
	std::cout << "ProcessRegistry tests passed" << std::endl;
	return 0;
}
