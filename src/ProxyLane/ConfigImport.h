#pragma once
#include <afxwin.h>
#include <vector>

#define WM_CONFIG_IMPORT_RESTART (WM_APP + 313)

namespace ConfigImport
{
// Owns only its uniquely named staging file and its prepared restart process.
// The source and backup are never deleted or modified by this object.
class Pending
{
public:
    Pending() = default;
    ~Pending();
    bool Prepare(const CString& source, CString& error);
    bool ArmRestart(CString& error);
    void FinishAfterShutdown();
    CString source, destination, backup;
    UINT profiles = 0;
private:
    Pending(const Pending&) = delete;
    Pending& operator=(const Pending&) = delete;
    CString staged, token, executable, readyName;
    std::vector<BYTE> contents, previous;
    bool hadPrevious = false;
    PROCESS_INFORMATION child = {};
    HANDLE ready = NULL;
    bool Restore();
    bool Launch(bool suspended);
};
CString ErrorText(DWORD error);
}
