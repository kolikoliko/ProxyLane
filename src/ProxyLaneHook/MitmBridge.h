#pragma once
#include "../ProxyLaneMitm/ProxyLaneMitm.h"

class CTcpProxyTask;
class CPRCTcpPeer;

class CMitmBridge
{
public:
    explicit CMitmBridge(CTcpProxyTask* task);
    ~CMitmBridge();
    static bool Enabled();
    bool Initialize();
    void OnRead(CPRCTcpPeer* peer, int error);
    void OnWritable();
private:
    static void __cdecl Observe(uintptr_t user, uint32_t kind, const uint8_t* data, size_t length);
    ULONGLONG m_connection;
    bool Pump();
    void Fail(int error = WSAECONNABORTED);
    CTcpProxyTask* m_task;
    void* m_session;
    PLM_IO_FN m_io;
    PLM_ERROR_FN m_error;
    PLM_FREE_FN m_free;
    bool m_failed;
    bool m_paused;
};
