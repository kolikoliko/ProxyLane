// Test-only PRC host. Injects one child; never modifies application profiles.
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include "../../src/ProxyLaneHook/ProxyModule.h"

class Settings : public IProxySettings {
public:
    int port;
    const wchar_t* type;
    BOOL GetProxySettings(LPProxySettingsInfo s) {
        ZeroMemory(s, sizeof(*s)); s->bHookTCP = TRUE; return TRUE;
    }
    BOOL GetProxyInfo(const LPPRCClient, LPProxyInfo p) {
        ZeroMemory(p, sizeof(*p)); p->strProxyType = type;
        p->strProxyHost = L"127.0.0.1"; p->nProxyPort = port; return TRUE;
    }
};
class Log : public IProxyLog {
public:
    void LogText(LPCWSTR text) { fwprintf(stderr, L"%s", text); }
    void LogNewProxyTask(const LPPRCClient c) { fprintf(stderr, "CONNECTION pid=%lu generation=%I64u\n", c->dwPid, c->socketGeneration); }
    BOOL ShouldInjectNewProcess(LPHookNewProcessInfo) { return FALSE; }
    void OnHookWsock(LPHookWSockResult r) { fprintf(stderr, "HOOK pid=%lu error=%lu\n", r->dwProcessId, r->err); }
    void OnHookLogtext(LPHookLogtext r) { fwprintf(stderr, L"HOOKLOG %s\n", r->str); }
    void OnChildInjectionResult(LPHookNewProcessInfo, BOOL) {}
    void OnConnectionEvent(ConnectionEvent event, const LPPRCClient c, LPCWSTR) { fprintf(stderr, "ROUTE pid=%lu event=%d\n", c->dwPid, event); }
    void OnConnectionFailure(const LPPRCClient c, LPCWSTR, ConnectionStage stage, DWORD error) { fprintf(stderr, "FAIL pid=%lu stage=%d error=%lu\n", c->dwPid, stage, error); }
};
int wmain(int argc, wchar_t** argv) {
    IGlobalProxy* proxy = GetGlobalProxyInstance();
    IProxyTlsControl* tls = proxy->GetTlsControl();
    IProxyMonitor* monitor = proxy->GetMonitorInstance();
    if (argc == 2 && wcscmp(argv[1], L"monitor-queue") == 0) {
        gp_UnhookWinsock();
        if (!proxy->EnableProxy()) return 25;
        auto data = proxy->GetPRCInstance()->GetPDHInstance();
        PRCClient client = {}; client.dwPid = 42; client.socketGeneration = 7;
        auto record = [&](DWORD value) {
            ProxyPacketInfo packet = {};
            packet.lpC = &client; packet.pData = (const char*)&value; packet.datalen = sizeof(value);
            data->OnEachPacket(&packet);
        };
        monitor->SetEnabled(TRUE);
        for (DWORD i = 0; i < 10000; ++i) record(i);
        if (monitor->TakeDroppedCount() != 10000 - 512) return 20;
        ProxyMonitorEvent event; DWORD expected = 10000 - 512;
        while (monitor->Poll(&event)) {
            DWORD value = 0; memcpy(&value, event.data, sizeof(value));
            if (value != expected++ || event.client.dwPid != 42 || event.kind != 3) return 21;
        }
        if (expected != 10000 || monitor->TakeDroppedCount()) return 22;
        record(expected);
        monitor->Clear(); if (monitor->Poll(&event)) return 23;
        monitor->SetEnabled(FALSE);
        record(expected);
        if (monitor->Poll(&event)) return 24;
        proxy->DisableProxy();
        ReleaseGlobalProxyInstance();
        // Services survive destruction/recreation of the reference-counted owner.
        proxy = GetGlobalProxyInstance();
        if (proxy->GetMonitorInstance() != monitor || proxy->GetTlsControl() != tls) return 26;
        if (!proxy->EnableProxy()) return 27;
        data = proxy->GetPRCInstance()->GetPDHInstance();
        monitor->SetEnabled(TRUE); record(123);
        if (!monitor->Poll(&event) || event.kind != 3) return 28;
        monitor->SetEnabled(FALSE); proxy->DisableProxy(); ReleaseGlobalProxyInstance();
        puts("Monitor interfaces, core capture, overflow, clear, pause and restart passed"); return 0;
    }
    if (argc == 2 && wcsncmp(argv[1], L"ca-", 3) == 0) {
        char details[4096] = {};
        int flags = tls->ManageCA(static_cast<IProxyTlsControl::CaAction>(_wtoi(argv[1] + 3)), details, sizeof(details));
        printf("FLAGS=%d\n%s\n", flags, details); ReleaseGlobalProxyInstance(); return flags < 0 ? 1 : 0;
    }
    if (argc != 4) { fputs("mitm_host port proxy-type \"child command line\"\n", stderr); return 2; }
    // This test host may inherit a developer's running ProxyLane hook. No sockets
    // or worker threads exist here yet; remove ONLY this host's inherited hooks.
    gp_UnhookWinsock();
    char error[4096] = {};
    if (tls->IsEnabled()) return 9; // Test GUI API without the legacy env switch.
    if (!tls->SetEnabled(TRUE, error, sizeof(error))) { fprintf(stderr, "%s\n", error); return 10; }
    if (!tls->IsEnabled()) return 11;
    monitor->SetEnabled(TRUE);
    char disabled[8] = {};
    bool disableBeforeConnect = GetEnvironmentVariableA("PROXYLANE_MITM_TEST_DISABLED", disabled, sizeof(disabled)) != 0;
    if (disableBeforeConnect) tls->SetEnabled(FALSE, NULL, 0);
    WSADATA data; if (WSAStartup(MAKEWORD(2,2), &data)) return 3;
    Settings settings; settings.port = _wtoi(argv[1]); settings.type = argv[2];
    Log log;
    proxy->GetSettingsInstance()->AddInstance(&settings);
    proxy->GetLogInstance()->AddInstance(&log);
    if (!proxy->EnableProxy()) return 4;
    char pipe[MAX_PATH] = {0};
    if (!proxy->GetPRCInstance()->GetPRCPipeName(pipe, sizeof(pipe))) return 5;
    STARTUPINFOW startup = {sizeof(startup)};
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    PROCESS_INFORMATION child = {0};
    std::wstring command(argv[3]);
    if (!CreateProcessW(NULL, &command[0], NULL, NULL, TRUE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &startup, &child)) return 6;
    bool injected = proxy->GetPRCInstance()->AuthorizeProcessPipeAccess(child.hProcess) && AttachToI(child.dwProcessId, child.dwThreadId, pipe) == 0xFF01;
    if (!injected) { TerminateProcess(child.hProcess, 7); return 7; }
    fprintf(stderr, "CHILD pid=%lu\n", child.dwProcessId);
    ResumeThread(child.hThread);
    DWORD started = GetTickCount(); bool toggled = false;
    auto drain = [&]() {
        ProxyMonitorEvent e;
        while (monitor->Poll(&e)) {
            if (e.client.dwPid != child.dwProcessId || !e.client.processCreateTime) ExitProcess(12);
            if (e.kind == 5) {
                fprintf(stderr, "CONNECTION_EVENT pid=%lu bytes=%lu\n", e.client.dwPid, e.length);
                continue;
            }
            if (e.kind >= 3) {
                fprintf(stderr, "RAW_EVENT pid=%lu kind=%lu bytes=%lu\n", e.client.dwPid, e.kind, e.length);
                continue;
            }
            if (disableBeforeConnect) ExitProcess(14);
            if (!e.connection) ExitProcess(12);
            std::string bytes((const char*)e.data, e.length);
            if (e.kind == 0) fprintf(stderr, "TLS_ERROR %s\n", bytes.c_str());
            fprintf(stderr, "GUI_EVENT pid=%lu birth=%I64u connection=%I64u kind=%lu bytes=%lu get=%d response=%d\n",
                e.client.dwPid, e.client.processCreateTime, e.connection, e.kind, e.length,
                bytes.find("GET /probe") != std::string::npos, bytes.find("HTTP/1.1 200") != std::string::npos);
            // Switching off must not interrupt an already established TLS stream.
            if (!toggled && e.kind == 1) { tls->SetEnabled(FALSE, NULL, 0); toggled = true; }
        }
    };
    while (WaitForSingleObject(child.hProcess, 10) != WAIT_OBJECT_0) {
        drain();
        if (GetTickCount() - started > 45000) { TerminateProcess(child.hProcess, 8); break; }
    }
    // Allow the PRC to finish both TLS shutdown directions before tearing it down.
    DWORD closing = GetTickCount();
    for (;;) {
        drain();
        DWORD count = 0;
        proxy->GetPRCInstance()->GetPTMInstance(0)->GetTaskCount(&count);
        if (!count || GetTickCount() - closing >= 2000) break;
        Sleep(10);
    }
    drain();
    DWORD code = 8; GetExitCodeProcess(child.hProcess, &code);
    CloseHandle(child.hThread); CloseHandle(child.hProcess);
    proxy->DisableProxy(); settings.Detach(); log.Detach(); ReleaseGlobalProxyInstance(); WSACleanup();
    if (monitor->TakeDroppedCount()) return 13;
    monitor->SetEnabled(FALSE);
    return (int)code;
}
