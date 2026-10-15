#include "HookCallGate.h"

HookCallGate g_HookCalls;

HookCallGate::HookCallGate() : m_open(NULL), m_idle(NULL), m_tls(TLS_OUT_OF_INDEXES),
    m_active(0), m_closed(false), m_enabled(false)
{
    InitializeCriticalSection(&m_lock);
    m_open = CreateEventW(NULL, TRUE, TRUE, NULL);
    m_idle = CreateEventW(NULL, TRUE, TRUE, NULL);
    m_tls = TlsAlloc();
}
HookCallGate::~HookCallGate()
{
    if (m_tls != TLS_OUT_OF_INDEXES) TlsFree(m_tls);
    if (m_open) CloseHandle(m_open);
    if (m_idle) CloseHandle(m_idle);
    DeleteCriticalSection(&m_lock);
}
bool HookCallGate::Ready() const { return m_open && m_idle && m_tls != TLS_OUT_OF_INDEXES; }
bool HookCallGate::InCall() const
{
    DWORD error = GetLastError();
    bool result = Ready() && TlsGetValue(m_tls) != NULL;
    SetLastError(error);
    return result;
}
bool HookCallGate::Enter()
{
    DWORD error = GetLastError();
    ULONG_PTR state = reinterpret_cast<ULONG_PTR>(TlsGetValue(m_tls));
    if (state)
    {
        TlsSetValue(m_tls, reinterpret_cast<PVOID>(state + 2));
        SetLastError(error);
        return (state & 1) != 0;
    }
    for (;;)
    {
        EnterCriticalSection(&m_lock);
        if (!m_closed)
        {
            if (++m_active == 1) ResetEvent(m_idle);
            bool enabled = m_enabled;
            TlsSetValue(m_tls, reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(2 | (enabled ? 1 : 0))));
            LeaveCriticalSection(&m_lock);
            SetLastError(error);
            return enabled;
        }
        LeaveCriticalSection(&m_lock);
        WaitForSingleObject(m_open, INFINITE);
    }
}
void HookCallGate::Leave()
{
    DWORD error = GetLastError();
    ULONG_PTR state = reinterpret_cast<ULONG_PTR>(TlsGetValue(m_tls));
    if (state >= 4) TlsSetValue(m_tls, reinterpret_cast<PVOID>(state - 2));
    else
    {
        TlsSetValue(m_tls, NULL);
        EnterCriticalSection(&m_lock);
        if (--m_active == 0) SetEvent(m_idle);
        LeaveCriticalSection(&m_lock);
    }
    SetLastError(error);
}
bool HookCallGate::Close(DWORD timeout)
{
    if (!Ready() || InCall()) { SetLastError(ERROR_BUSY); return false; }
    EnterCriticalSection(&m_lock);
    m_closed = true;
    ResetEvent(m_open);
    LeaveCriticalSection(&m_lock);
    DWORD result = WaitForSingleObject(m_idle, timeout);
    if (result == WAIT_OBJECT_0) return true;
    Open(m_enabled);
    SetLastError(result == WAIT_TIMEOUT ? ERROR_TIMEOUT : ERROR_GEN_FAILURE);
    return false;
}
void HookCallGate::Open(bool enabled)
{
    EnterCriticalSection(&m_lock);
    m_enabled = enabled;
    m_closed = false;
    SetEvent(m_open);
    LeaveCriticalSection(&m_lock);
}
