#pragma once
#include "ProxyModule.h"

// Internal implementation; clients use IGlobalProxy::GetTlsControl().
class CMitmControl : public IProxyTlsControl
{
public:
    static CMitmControl& Instance();
    int ManageCA(CaAction action, char* output, size_t capacity) override;
    BOOL SetEnabled(BOOL enabled, char* error, size_t capacity) override;
    BOOL IsEnabled() override;
private:
    CMitmControl() = default;
};
