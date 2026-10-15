#pragma once
#include <windows.h>

// A lifecycle change closes admission, drains callbacks, then changes the
// patches. Nested callbacks on an admitted thread must keep running to drain.
class HookCallGate
{
public:
    HookCallGate();
    ~HookCallGate();
    bool Ready() const;
    bool InCall() const;
    bool Enter();
    void Leave();
    bool Close(DWORD timeout);
    void Open(bool enabled);
private:
    HookCallGate(const HookCallGate&);
    HookCallGate& operator=(const HookCallGate&);
    CRITICAL_SECTION m_lock;
    HANDLE m_open;
    HANDLE m_idle;
    DWORD m_tls;
    LONG m_active;
    bool m_closed;
    bool m_enabled;
};

class HookCallScope
{
public:
    explicit HookCallScope(HookCallGate& gate) : m_gate(gate), m_enabled(gate.Enter()) {}
    ~HookCallScope() { m_gate.Leave(); }
    bool Enabled() const { return m_enabled; }
private:
    HookCallScope(const HookCallScope&);
    HookCallScope& operator=(const HookCallScope&);
    HookCallGate& m_gate;
    bool m_enabled;
};

extern HookCallGate g_HookCalls;
