#pragma once
#include "../ProxyLaneHook/ProxyModule.h"
#include "ModernUI.h"
#include "MonitorLogFormat.h"
#include <deque>
#include <memory>
#include <vector>

struct MitmJob;
class CPage4 : public CModernDialog
{
    DECLARE_DYNAMIC(CPage4)
public:
    CPage4(CWnd* parent = NULL);
    virtual ~CPage4();
    enum { IDD = IDD_Page4 };
    void UpdateMonitorStatus();
protected:
    virtual void DoDataExchange(CDataExchange* dx);
    virtual BOOL OnInitDialog();
    afx_msg void OnSize(UINT type, int cx, int cy);
    afx_msg void OnTimer(UINT_PTR id);
    afx_msg void OnMonitor();
    afx_msg void OnView();
    afx_msg void OnClear();
    afx_msg void OnCA();
    afx_msg void OnDecrypt();
    DECLARE_MESSAGE_MAP()
private:
    void LayoutControls(int cx, int cy);
    struct Record {
        CString header;
        DWORD kind, length;
        std::vector<BYTE> preview;
    };
    Record MakeRecord(const ProxyMonitorEvent& event);
    CString FormatRecord(const Record& record) const;
    void AppendText(const CString& text);
    void BeginReplay();
    void SetDecryptStatus();
    void OpenCA(bool enableAfterClose);
    void StartDecryption();
    CEdit m_edit;
    CButton m_monitor, m_hex, m_decrypt;
    CModernButton m_clear, m_ca;
    CFont m_font;
    IProxyTlsControl* m_tls;
    IProxyMonitor* m_dataMonitor;
    bool m_recording;
    std::deque<Record> m_history;
    ULONGLONG m_dropped, m_truncated, m_evicted;
    bool m_needsReplay, m_replaying;
    size_t m_replayIndex;
    std::shared_ptr<MitmJob> m_job;
};
