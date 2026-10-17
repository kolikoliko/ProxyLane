#include "stdafx.h"
#include "MitmBridge.h"
#include "TcpProxyTask.h"
#include "PRCTcpPeer.h"
#include "ProxyTaskMgr.h"
#include "ProxyReceptionCentre.h"
#include "ProxyLog.h"
#include "ProxyDataHandle.h"
#include "MitmControl.h"
#include "ProxyMonitor.h"
#include "PlatformSupport.h"
#include <atomic>
#include <mutex>
#include <algorithm>

namespace {
    std::mutex moduleLock;
    std::atomic<int> enabledMode(-1);
    std::atomic<bool> streamMonitoring(false);
    std::atomic<ULONGLONG> connectionSequence(0);
    std::atomic<PLM_PROTOCOL_FN> protocolQuery(NULL);
    // Kept loaded for process lifetime: the Rust context owns the CRL listener.
    HMODULE LoadMitm()
    {
        if (!ProxySupportsOptionalModules()) { SetLastError(ERROR_NOT_SUPPORTED); return NULL; }
        std::lock_guard<std::mutex> guard(moduleLock);
        static HMODULE module = NULL;
        if (module) return module;
        TCHAR path[MAX_PATH] = {0};
        DWORD n = GetModuleFileName(NULL, path, _countof(path));
        if (!n || n >= _countof(path)) return NULL;
        TCHAR* slash = _tcsrchr(path, _T('\\'));
        if (!slash) return NULL;
        _tcscpy_s(slash + 1, _countof(path) - (slash + 1 - path), _T("ProxyLaneMitm64.dll"));
        module = LoadLibrary(path);
        if (module) {
            PLM_VERSION_FN version = (PLM_VERSION_FN)GetProcAddress(module, "plm_abi_version");
            if (version && version() == PLM_ABI_VERSION)
                protocolQuery.store((PLM_PROTOCOL_FN)GetProcAddress(module, "plm_protocol"));
        }
        return module;
    }
    CStringA Address(const _SockAddr& address)
    {
        char buffer[64] = {0};
        if (address.IsIPv6())
            ProxyInetNtopA(AF_INET6, address.GetAddr6(), buffer, sizeof(buffer));
        else {
            IN_ADDR v4; v4.s_addr = address.GetdwIP();
            ProxyInetNtopA(AF_INET, &v4, buffer, sizeof(buffer));
        }
        return CStringA(buffer);
    }
}

CMitmControl& CMitmControl::Instance()
{
    static CMitmControl instance;
    return instance;
}

BOOL CMitmControl::IsEnabled()
{
    if (!ProxySupportsOptionalModules()) return FALSE;
    int mode = enabledMode.load();
    if (mode >= 0) return mode != 0;
    TCHAR value[8] = {0};
    return GetEnvironmentVariable(_T("PROXYLANE_MITM"), value, _countof(value)) == 1 && value[0] == _T('1');
}
int CMitmControl::ManageCA(CaAction action, char* output, size_t capacity)
{
    if (!ProxySupportsOptionalModules()) {
        if (output && capacity) _snprintf_s(output, capacity, _TRUNCATE, "MITM requires a supported Windows version and the 64-bit ProxyLane host.");
        return -1;
    }
    HMODULE module = LoadMitm();
    PLM_VERSION_FN version = module ? (PLM_VERSION_FN)GetProcAddress(module, "plm_abi_version") : NULL;
    PLM_CA_FN ca = module ? (PLM_CA_FN)GetProcAddress(module, "plm_ca") : NULL;
    if (!version || version() != PLM_ABI_VERSION || !ca) {
        if (output && capacity) _snprintf_s(output, capacity, _TRUNCATE,
            "Cannot load compatible ProxyLaneMitm DLL (Windows error %lu). Rebuild/copy the optional TLS module next to ProxyLane.exe.", GetLastError());
        return -1;
    }
    if (action == 3) enabledMode.store(0);
    return ca(action, output, capacity);
}
BOOL CMitmControl::SetEnabled(BOOL enabled, char* error, size_t capacity)
{
    if (enabled && ManageCA(PrepareCA, error, capacity) < 0) return FALSE;
    enabledMode.store(enabled ? 1 : 0);
    return TRUE;
}
int CMitmControl::QueryProtocol(const char* request, char* output, size_t capacity)
{
    if (!ProxySupportsOptionalModules()) {
        if (output && capacity) _snprintf_s(output, capacity, _TRUNCATE, "MITM and protocol monitoring require a supported Windows version and the 64-bit ProxyLane host.");
        return -1;
    }
    if (request && (strcmp(request, "{\"type\":\"monitor_start\"}") == 0 ||
        strcmp(request, "{\"type\":\"monitor_stop\"}") == 0)) {
        const bool enabled = strstr(request, "monitor_start") != NULL;
        if (enabled) {
            LoadMitm();
            if (!protocolQuery.load()) {
                if (output && capacity) _snprintf_s(output, capacity, _TRUNCATE, "Cannot load compatible protocol module.");
                return -1;
            }
        }
        if (enabled && !streamMonitoring.load()) {
            char response[256] = {};
            if (protocolQuery.load()("{\"type\":\"analysis_start\"}", response, sizeof(response)) < 0) {
                if (output && capacity) _snprintf_s(output, capacity, _TRUNCATE, "%s", response);
                return -1;
            }
        }
        streamMonitoring.store(enabled);
        const char reply[] = "{\"type\":\"monitor\"}";
        if (output && capacity >= sizeof(reply)) memcpy(output, reply, sizeof(reply));
        return sizeof(reply);
    }
    if (request && strstr(request, "mitm_options")) LoadMitm();
    PLM_PROTOCOL_FN query = protocolQuery.load();
    if (query) return query(request, output, capacity);
    const char inactive[] = "{\"type\":\"inactive\"}";
    if (output && capacity >= sizeof(inactive)) memcpy(output, inactive, sizeof(inactive));
    return sizeof(inactive);
}
void CMitmControl::ShutdownProtocol()
{
    PLM_PROTOCOL_FN query = protocolQuery.load();
    if (!query) return; // Do not load Rust merely to shut down an unused service.
    char error[1024] = {};
    if (query("{\"type\":\"shutdown\"}", error, sizeof(error)) < 0)
        PrintText(_T("Protocol cache cleanup failed: %hs\r\n"), error);
}
void __cdecl CMitmBridge::Observe(uintptr_t user, uint32_t kind, const uint8_t* data, size_t length)
{
    CMitmBridge* bridge = reinterpret_cast<CMitmBridge*>(user);
    CProxyMonitor::Instance().Record(bridge->m_connection, bridge->m_task->m_PRCClient, kind, data, length);
}

CMitmBridge::CMitmBridge(CTcpProxyTask* task)
    : m_connection(++connectionSequence), m_task(task), m_session(NULL), m_io(NULL), m_error(NULL), m_free(NULL), m_failed(false), m_paused(false) {}
CMitmBridge::~CMitmBridge() { if (m_session && m_free) m_free(m_session); }

bool CMitmBridge::Enabled()
{
    return CMitmControl::Instance().IsEnabled() != FALSE;
}

bool CMitmBridge::Initialize()
{
    HMODULE module = LoadMitm();
    if (!module) {
        PrintText(_T("MITM: cannot load optional TLS module (error %lu).\r\n"), GetLastError());
        return false;
    }
    PLM_VERSION_FN version = (PLM_VERSION_FN)GetProcAddress(module, "plm_abi_version");
    PLM_CREATE_FN create = (PLM_CREATE_FN)GetProcAddress(module, "plm_create");
    m_io = (PLM_IO_FN)GetProcAddress(module, "plm_io");
    m_error = (PLM_ERROR_FN)GetProcAddress(module, "plm_error");
    m_free = (PLM_FREE_FN)GetProcAddress(module, "plm_free");
    PLM_OBSERVE_FN observe = (PLM_OBSERVE_FN)GetProcAddress(module, "plm_observe");
    if (!version || version() != PLM_ABI_VERSION || !create || !m_io || !m_error || !m_free || !observe) {
        PrintText(_T("MITM: incompatible TLS module.\r\n"));
        return false;
    }
    const PRCClient& c = m_task->m_PRCClient;
    CStringA target = Address(c.dstAddr), source = Address(c.srcAddr), effective = Address(c.GetProxyDestination());
    CStringA host = c.szDomainName[0] ? CStringA(c.szDomainName) : target;
    CStringA metadata;
    // Only numeric/address fields go into this JSON; host is a separate UTF-8 argument.
    metadata.Format("{\"connection_id\":%I64u,\"pid\":%lu,\"process_create_time\":%I64u,\"socket_generation\":%I64u,\"socket\":%I64u,\"destination\":\"%s\",\"port\":%d,\"source\":\"%s\",\"source_port\":%d,\"effective_destination\":\"%s\"}",
        m_connection, c.dwPid, c.processCreateTime, c.socketGeneration, c.s, (LPCSTR)target,
        c.dstAddr.GetPort(), (LPCSTR)source, c.srcAddr.GetPort(), (LPCSTR)effective);
    char error[1024] = {0};
    if (create(host, metadata, &m_session, error, sizeof(error)) != 0) {
        Observe(reinterpret_cast<uintptr_t>(this), 0, reinterpret_cast<const uint8_t*>(error), strlen(error));
        PrintText(_T("MITM initialization failed: %hs\r\n"), error);
        return false;
    }
    observe(m_session, Observe, reinterpret_cast<uintptr_t>(this));
    return true;
}

void CMitmBridge::Connected(int error)
{
    if (m_session) m_io(m_session, PLM_CONNECTED, 0, NULL, error);
}
void CProtocolTap::Connected(int error)
{
    if (m_handle) m_io(m_handle, 4, 0, NULL, error);
}
void CMitmBridge::Fail(int error)
{
    if (m_failed) return;
    m_failed = true;
    char text[1024] = {0};
    if (m_session) m_error(m_session, text, sizeof(text));
    PrintText(_T("MITM pid=%lu socket=%I64u failed: %hs (socket error %d).\r\n"),
        m_task->m_PRCClient.dwPid, m_task->m_PRCClient.s, text, error);
    m_task->m_pServer->OnClose(error ? error : WSAECONNABORTED);
}

bool CMitmBridge::Pump()
{
    CPRCTcpPeer* peers[2] = {m_task->m_pClient, m_task->m_pServer};
    if (m_failed) return false;
    if (!peers[1]->m_bForwardingReady) return true;
    BYTE buffer[16384];
    for (unsigned side = 0; side != 2; ++side) {
        int budget = 64 * 1024;
        while (budget > 0 && !peers[side]->m_bWriteShutdown) {
            int n = m_io(m_session, PLM_PEEK, side, buffer, sizeof(buffer));
            if (n < 0) { Fail(); return false; }
            if (!n) break;
            int sent = peers[side]->Send(buffer, n);
            if (sent == SOCKET_ERROR) {
                int error = WSAGetLastError();
                if (error == WSAEWOULDBLOCK) break;
                Fail(error); return false;
            }
            if (!sent) break;
            if (m_io(m_session, PLM_CONSUME, side, NULL, sent) < 0) { Fail(); return false; }
            peers[1-side]->m_DataLenSent += sent;
            m_task->m_pTaskmgr->m_pPRC->RecordTraffic(m_task->m_ProxyInfo, side == 0, sent);
            budget -= sent;
        }
        if (budget <= 0) peers[side]->TriggerEvent(FD_WRITE);
    }
    int status = m_io(m_session, PLM_STATUS, 0, NULL, 0);
    if (status < 0) { Fail(); return false; }
    bool paused = !(status & PLM_CAN_READ);
    for (unsigned side = 0; side != 2; ++side) {
        if (status & (side ? PLM_SERVER_EOF : PLM_CLIENT_EOF)) peers[side]->m_bReadClosed = TRUE;
        if ((status & (side ? PLM_SHUTDOWN_SERVER : PLM_SHUTDOWN_CLIENT)) && !peers[side]->m_bWriteShutdown) {
            peers[side]->ShutDown(SD_SEND);
            peers[side]->m_bWriteShutdown = TRUE;
        }
        peers[side]->AsyncSelect(FD_WRITE | FD_CLOSE | ((!paused && !peers[side]->m_bReadClosed) ? FD_READ : 0));
        if (m_paused && !paused && !peers[side]->m_bReadClosed) peers[side]->TriggerEvent(FD_READ);
    }
    m_paused = paused;
    if (peers[0]->m_bReadClosed && peers[1]->m_bReadClosed && peers[0]->m_bWriteShutdown && peers[1]->m_bWriteShutdown) {
        peers[0]->AsyncSelect(0); peers[1]->AsyncSelect(0);
        peers[0]->Close(); peers[1]->Close();
        m_task->OnPeerClosed(peers[0]);
    }
    return true;
}

void CMitmBridge::OnRead(CPRCTcpPeer* peer, int error)
{
    if (error) { Fail(error); return; }
    if (m_failed || !m_task->m_pServer->m_bForwardingReady || peer->m_bReadClosed) return;
    unsigned side = peer == m_task->m_pClient ? 0 : 1;
    BYTE buffer[4096];
    int budget = 64 * 1024;
    while (budget > 0) {
        int status = m_io(m_session, PLM_STATUS, 0, NULL, 0);
        if (status < 0) { Fail(); return; }
        if (!(status & PLM_CAN_READ)) break;
        int n = peer->Receive(buffer, sizeof(buffer));
        if (n == SOCKET_ERROR) {
            int code = WSAGetLastError();
            if (code != WSAEWOULDBLOCK) { Fail(code); return; }
            break;
        }
        int result = m_io(m_session, n ? PLM_FEED : PLM_EOF, side, buffer, n);
        if (result < 0) { Fail(); return; }
        if (n)
        {
            peer->m_ppi.errcode = 0;
            peer->m_ppi.datafrom = side;
            peer->m_ppi.pData = reinterpret_cast<const char*>(buffer);
            peer->m_ppi.datalen = n;
            peer->m_pProxyDataHandle->DispatchPacket(&peer->m_ppi, false);
        }
        peer->m_DataLenRecvd += n;
        budget -= n;
        if (!n) peer->m_bReadClosed = TRUE;
        if (!Pump() || peer->m_bReadClosed || peer->GetSocketHandle() == INVALID_SOCKET) return;
    }
    if (!Pump()) return;
    if (budget <= 0 && !m_paused && !peer->m_bReadClosed) peer->TriggerEvent(FD_READ);
}

void CMitmBridge::OnWritable() { Pump(); }

bool CProtocolTap::Enabled() { return streamMonitoring.load(); }
CProtocolTap::CProtocolTap(CTcpProxyTask* task) : CProtocolTap(task->m_PRCClient, false) {}
CProtocolTap::CProtocolTap(const PRCClient& c, bool udp) : m_handle(NULL), m_io(NULL), m_udp(udp) {
    HMODULE module = LoadMitm();
    if (!module || !protocolQuery.load()) return;
    auto open = (PLM_STREAM_OPEN_FN)GetProcAddress(module, "plm_stream_open");
    m_io = (PLM_STREAM_IO_FN)GetProcAddress(module, "plm_stream_io");
    if (!open || !m_io) return;
    CStringA target = Address(c.dstAddr);
    CStringA host = c.szDomainName[0] ? CStringA(c.szDomainName) : target;
    CStringA metadata;
    metadata.Format("{\"connection_id\":%I64u,\"pid\":%lu,\"process_create_time\":%I64u,\"socket_generation\":%I64u,\"socket\":%I64u,\"destination\":\"%s\",\"port\":%d}",
        ++connectionSequence, c.dwPid, c.processCreateTime, c.socketGeneration, c.s, (LPCSTR)target, c.dstAddr.GetPort());
    if (udp) { metadata.Delete(metadata.GetLength() - 1); metadata += ",\"transport\":\"udp\"}"; }
    m_handle = open(host, metadata);
    m_active.store(m_handle != NULL);
}
CProtocolTap::~CProtocolTap() { if (m_handle) {
    if (m_udp) { Eof(0); Eof(1); }
    m_io(m_handle, 2, 0, NULL, 0);
} }
void CProtocolTap::Data(unsigned side, const void* bytes, size_t length) {
    if (!Enabled()) { if (m_handle) m_io(m_handle, 2, 0, NULL, 0); m_handle = NULL; m_active.store(false); }
    if (m_handle) m_io(m_handle, m_udp ? 3 : 0, side, (const uint8_t*)bytes, length);
}
void CProtocolTap::Eof(unsigned side) { if (m_handle) m_io(m_handle, 1, side, NULL, 0); }
