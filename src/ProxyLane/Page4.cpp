#include "stdafx.h"
#include "ProxyLane.h"
#include "Page4.h"
#include "Localization.h"
#include <thread>
#include <atomic>
#include <algorithm>

// Workers own their result, never a window pointer. Closing a dialog cannot
// leave a callback targeting a destroyed HWND. Release/acquire publishes text.
struct MitmJob {
    std::atomic<bool> done;
    int result;
    bool needsCA;
    char text[4096];
    MitmJob() : done(false), result(-1), needsCA(false) { text[0] = 0; }
};
static std::shared_ptr<MitmJob> StartMitmJob(IProxyTlsControl* tls, unsigned action, bool enable = false)
{
    auto job = std::make_shared<MitmJob>();
    try {
        std::thread([job, tls, action, enable]() {
            if (enable) {
                // Missing/untrusted CA is an onboarding state, not an error.
                // Query structured flags; never classify failures by their text.
                job->result = tls->ManageCA(IProxyTlsControl::QueryCA, job->text, sizeof(job->text));
                if (job->result >= 0) {
                    job->needsCA = (job->result & 2) == 0;
                    if (!job->needsCA)
                        job->result = tls->SetEnabled(TRUE, job->text, sizeof(job->text)) ? 3 : -1;
                }
            } else {
                job->result = tls->ManageCA(static_cast<IProxyTlsControl::CaAction>(action), job->text, sizeof(job->text));
            }
            job->done.store(true);
        }).detach();
    } catch (...) {
        strcpy_s(job->text, "Unable to start CA worker."); job->done.store(true);
    }
    return job;
}
static CString Utf8(const BYTE* bytes, size_t length)
{
    CString result;
    if (!length) return result;
    int count = MultiByteToWideChar(CP_UTF8, 0, (LPCCH)bytes, (int)length, NULL, 0);
    LPWSTR out = result.GetBuffer(count);
    MultiByteToWideChar(CP_UTF8, 0, (LPCCH)bytes, (int)length, out, count);
    // The edit control cannot show embedded NULs. Keep payload length explicit.
    for (int i = 0; i < count; ++i)
        if (out[i] < 32 && out[i] != '\r' && out[i] != '\n' && out[i] != '\t') out[i] = L'\x00b7';
    result.ReleaseBuffer(count);
    return result;
}
static CString Utf8(const char* text) { return Utf8((const BYTE*)text, strlen(text)); }
static CString Endpoint(const PRCClient& c)
{
    CString address;
    if (c.szDomainName[0]) address = Utf8((const BYTE*)c.szDomainName, strnlen(c.szDomainName, sizeof(c.szDomainName)));
    else {
        TCHAR text[64] = {};
        if (c.dstAddr.IsIPv6()) {
            ProxyInetNtopW(AF_INET6, (PVOID)c.dstAddr.GetAddr6(), text, _countof(text));
            address.Format(_T("[%s]"), text);
        } else {
            IN_ADDR ip; ip.s_addr = c.dstAddr.GetdwIP();
            ProxyInetNtopW(AF_INET, &ip, text, _countof(text)); address = text;
        }
    }
    CString out; out.Format(_T("%s:%d"), (LPCTSTR)address, c.dstAddr.GetPort()); return out;
}
class CMitmCaDialog : public CModernDialog {
    std::shared_ptr<MitmJob> m_job;
    CModernButton m_buttons[4];
    IProxyTlsControl* m_tls;
    int m_flags;
public:
    CMitmCaDialog(CWnd* parent, IProxyTlsControl* tls) : CModernDialog(IDD_MITM_CA, parent), m_tls(tls), m_flags(-1) {}
    bool IsTrusted() const { return m_flags >= 0 && (m_flags & 2) != 0; }
    void Start(unsigned action) {
        for (auto& button : m_buttons) button.EnableWindow(FALSE);
        SetDlgItemText(IDC_MITM_STATUS, Localization::Get(_T("mitm.busy")));
        m_job = StartMitmJob(m_tls, action);
    }
    BOOL OnInitDialog() override {
        CModernDialog::OnInitDialog();
        SetWindowText(Localization::Get(_T("mitm.ca")));
        const int ids[] = {IDC_CA_INSTALL, IDC_CA_REMOVE, IDC_CA_REFRESH, IDOK};
        const LPCTSTR keys[] = {_T("mitm.install"), _T("mitm.remove"), _T("mitm.refresh"), _T("mitm.close")};
        for (int i = 0; i < _countof(ids); ++i) {
            SetDlgItemText(ids[i], Localization::Get(keys[i]));
            m_buttons[i].SubclassDlgItem(ids[i], this);
        }
        ((CEdit*)GetDlgItem(IDC_CA_DETAILS))->SetLimitText(8192);
        SetTimer(1, 150, NULL); Start(0); return TRUE;
    }
    BOOL OnCommand(WPARAM wParam, LPARAM lParam) override {
        UINT id = LOWORD(wParam);
        if (id == IDC_CA_INSTALL || id == IDC_CA_REMOVE || id == IDC_CA_REFRESH) {
            if (!m_job) Start(id == IDC_CA_INSTALL ? IProxyTlsControl::TrustCA :
                id == IDC_CA_REMOVE ? IProxyTlsControl::RemoveCATrust : IProxyTlsControl::QueryCA);
            return TRUE;
        }
        return CModernDialog::OnCommand(wParam, lParam);
    }
    // Do not allow a trust operation to finish invisibly after dismissing it.
    void OnOK() override { if (!m_job) CModernDialog::OnOK(); }
    void OnCancel() override { if (!m_job) CModernDialog::OnCancel(); }
    afx_msg void OnTimer(UINT_PTR id) {
        if (m_job && m_job->done.load()) {
            int flags = m_job->result;
            m_flags = flags;
            SetDlgItemText(IDC_CA_DETAILS, Utf8(m_job->text));
            SetDlgItemText(IDC_MITM_STATUS, Localization::Get(flags < 0 ? _T("mitm.failed") :
                flags & 2 ? _T("mitm.trusted") : flags & 1 ? _T("mitm.untrusted") : _T("mitm.uninitialized")));
            m_job.reset();
            for (auto& button : m_buttons) button.EnableWindow(TRUE);
            GetDlgItem(IDC_CA_REMOVE)->EnableWindow((flags & 2) && flags >= 0);
        }
        CModernDialog::OnTimer(id);
    }
    DECLARE_MESSAGE_MAP()
};
BEGIN_MESSAGE_MAP(CMitmCaDialog, CModernDialog)
    ON_WM_TIMER()
END_MESSAGE_MAP()

IMPLEMENT_DYNAMIC(CPage4, CModernDialog)
CPage4::CPage4(CWnd* parent) : CModernDialog(IDD, parent), m_tls(nullptr), m_dataMonitor(nullptr),
    m_recording(false), m_dropped(0), m_truncated(0), m_evicted(0),
    m_needsReplay(false), m_replaying(false), m_replayIndex(0) {}
CPage4::~CPage4() { if (m_dataMonitor) m_dataMonitor->SetEnabled(FALSE); }
void CPage4::DoDataExchange(CDataExchange* dx)
{
    CModernDialog::DoDataExchange(dx);
    DDX_Control(dx, IDC_EDIT1, m_edit); DDX_Control(dx, IDC_CHECK1, m_monitor);
    DDX_Control(dx, IDC_CHECK_HEX, m_hex); DDX_Control(dx, IDC_BTN_CLEAR, m_clear);
    DDX_Control(dx, IDC_MITM_ENABLE, m_decrypt); DDX_Control(dx, IDC_MITM_CA, m_ca);
}
BOOL CPage4::OnInitDialog()
{
    CModernDialog::OnInitDialog();
    IGlobalProxy* proxy = GetGlobalProxyInstance();
    m_tls = proxy->GetTlsControl();
    m_dataMonitor = proxy->GetMonitorInstance();
    ReleaseGlobalProxyInstance(); // Borrowed services outlive this proxy reference.
    SetDlgItemText(IDC_MITM_CA, Localization::Get(_T("mitm.ca")));
    UiTheme::CreateUiFont(m_font, m_hWnd, 9, FW_NORMAL, _T("Consolas"));
    m_edit.SetFont(&m_font); m_edit.SetLimitText(MonitorLog::TextLimit);
    SetDecryptStatus(); SetTimer(1, 100, NULL);
    CRect rect; GetClientRect(rect); LayoutControls(rect.Width(), rect.Height()); return TRUE;
}
BEGIN_MESSAGE_MAP(CPage4, CModernDialog)
    ON_WM_SIZE()
    ON_WM_TIMER()
    ON_BN_CLICKED(IDC_CHECK1, &CPage4::OnMonitor)
    ON_BN_CLICKED(IDC_CHECK_HEX, &CPage4::OnView)
    ON_BN_CLICKED(IDC_BTN_CLEAR, &CPage4::OnClear)
    ON_BN_CLICKED(IDC_MITM_ENABLE, &CPage4::OnDecrypt)
    ON_BN_CLICKED(IDC_MITM_CA, &CPage4::OnCA)
END_MESSAGE_MAP()
void CPage4::OnSize(UINT type, int cx, int cy)
{
    CModernDialog::OnSize(type, cx, cy);
    CRect client; GetClientRect(client);
    LayoutControls(client.Width(), client.Height());
}
void CPage4::LayoutControls(int cx, int cy)
{
    // Shared layout helper: never call an MFC message handler from initialization.
    if (!m_edit.GetSafeHwnd()) return;
    auto s = [this](int v) { return UiTheme::ScaleForWindow(m_hWnd, v); };
    int width = max(0, cx - s(16)), top = s(44), h = s(28);
    // Size the single toolbar row to its localized labels, keeping actions right-aligned.
    auto labelWidth = [&](CWnd& control, int padding) {
        CClientDC dc(&control);
        CFont* old = dc.SelectObject(control.GetFont());
        CString text; control.GetWindowText(text);
        int result = dc.GetTextExtent(text).cx + s(padding);
        dc.SelectObject(old);
        return result;
    };
    int decryptWidth = labelWidth(m_decrypt, 20), monitorWidth = labelWidth(m_monitor, 20);
    int hexWidth = labelWidth(m_hex, 20), caWidth = labelWidth(m_ca, 16);
    int clearWidth = max(s(48), labelWidth(m_clear, 16));
    if (decryptWidth + monitorWidth + hexWidth + caWidth + clearWidth + s(8) > width) {
        decryptWidth = labelWidth(m_decrypt, 16);
        monitorWidth = labelWidth(m_monitor, 16);
        hexWidth = labelWidth(m_hex, 16);
        caWidth = labelWidth(m_ca, 8);
        clearWidth = max(s(40), labelWidth(m_clear, 8));
    }
    int gap = max(1, min(s(12), (width - decryptWidth - monitorWidth - hexWidth - caWidth - clearWidth) / 4));
    m_decrypt.MoveWindow(s(8), top, decryptWidth, h);
    m_monitor.MoveWindow(s(8) + decryptWidth + gap, top, monitorWidth, h);
    m_hex.MoveWindow(s(8) + decryptWidth + monitorWidth + gap * 2, top, hexWidth, h);
    m_clear.MoveWindow(cx - s(8) - clearWidth, top, clearWidth, h);
    m_ca.MoveWindow(cx - s(8) - clearWidth - gap - caWidth, top, caWidth, h);
    top += s(36);
    GetDlgItem(IDC_STATIC_TASKCOUNT)->MoveWindow(s(8), top, width, s(20));
    top += s(24);
    m_edit.MoveWindow(s(8), top, width, max(0, cy - top - s(8)));
}
void CPage4::SetDecryptStatus()
{
    m_decrypt.SetCheck(m_tls->IsEnabled() ? BST_CHECKED : BST_UNCHECKED);
    m_decrypt.SetWindowText(Localization::Get(_T("mitm.enable")));
}
void CPage4::OnCA()
{
    OpenCA(false);
}
void CPage4::OpenCA(bool enableAfterClose)
{
    CMitmCaDialog dialog(this, m_tls);
    dialog.DoModal();
    SetDecryptStatus();
    // Closing without installing cancels this attempt. A successful install
    // resumes the original checkbox action, including when closed with X/Esc.
    if (enableAfterClose && dialog.IsTrusted()) StartDecryption();
}
void CPage4::OnDecrypt()
{
    if (m_decrypt.GetCheck() != BST_CHECKED) {
        m_tls->SetEnabled(FALSE, NULL, 0); SetDecryptStatus(); return;
    }
    StartDecryption();
}
void CPage4::StartDecryption()
{
    m_decrypt.EnableWindow(FALSE); m_ca.EnableWindow(FALSE);
    m_decrypt.SetWindowText(Localization::Get(_T("monitor.preparing")));
    m_job = StartMitmJob(m_tls, IProxyTlsControl::PrepareCA, true);
}
void CPage4::UpdateMonitorStatus()
{
    if (!m_monitor.GetSafeHwnd()) return;
    bool recording = m_monitor.GetCheck() == BST_CHECKED;
    m_recording = recording;
    m_dataMonitor->SetEnabled(recording);
}
void CPage4::OnMonitor() { UpdateMonitorStatus(); }

CPage4::Record CPage4::MakeRecord(const ProxyMonitorEvent& e)
{
    Record record; record.kind = e.kind; record.length = e.length;
    const size_t preview = (std::min)(size_t(e.length), MonitorLog::PreviewBytes);
    record.preview.assign(e.data, e.data + preview);
    // Log text stays in English independently of the UI language.
    LPCTSTR label = e.kind == 1 || e.kind == 2 ? _T("Decrypted") :
        e.kind == 3 || e.kind == 4 ? _T("Raw") : e.kind == 0 ? _T("TLS error") : _T("Connection status");
    LPCTSTR direction = e.kind == 1 || e.kind == 3 ? _T("Application → server") :
        e.kind == 2 || e.kind == 4 ? _T("Server → application") : _T("Connection status");
    // Use the same PID/socket generation for raw and decrypted data.
    record.header.Format(_T("[%s] PID %lu · %s · %s · %s · socket %I64u/%I64u\r\n"),
        label, e.client.dwPid,
        e.client.sType == SOCK_DGRAM ? _T("UDP") : _T("TCP"), (LPCTSTR)Endpoint(e.client),
        direction, e.client.s, e.client.socketGeneration);
    return record;
}
CString CPage4::FormatRecord(const Record& record) const
{
    CString output = record.header;
    if (m_hex.GetCheck() == BST_CHECKED && record.kind != 0 && record.kind != 5)
        output += MonitorLog::Hex(record.preview.data(), record.preview.size()).c_str();
    else output += Utf8(record.preview.data(), record.preview.size());
    if (record.preview.size() < record.length) {
        CString preview;
        preview.Format(_T("\r\n[Preview %u / %lu bytes; remainder omitted]"),
            (unsigned)record.preview.size(), record.length);
        output += preview;
    }
    output += _T("\r\n\r\n");
    return output;
}
void CPage4::BeginReplay()
{
    m_edit.SetWindowText(_T("")); m_edit.EmptyUndoBuffer();
    m_replayIndex = 0; m_replaying = true; m_needsReplay = false;
}
void CPage4::OnView()
{
    // Reformat retained previews over subsequent timer ticks, never all at once.
    if (m_edit.IsWindowVisible()) BeginReplay(); else m_needsReplay = true;
}
void CPage4::OnClear()
{
    m_dataMonitor->Clear(); m_history.clear(); m_dropped = m_truncated = m_evicted = 0;
    m_replaying = m_needsReplay = false; m_replayIndex = 0;
    m_edit.SetWindowText(_T("")); m_edit.EmptyUndoBuffer();
}
void CPage4::AppendText(const CString& text)
{
    if (text.IsEmpty()) return;
    int length = m_edit.GetWindowTextLength();
    int start, end; m_edit.GetSel(start, end);
    int firstLine = m_edit.GetFirstVisibleLine();
    SCROLLINFO scroll = { sizeof(scroll), SIF_ALL };
    m_edit.GetScrollInfo(SB_VERT, &scroll);
    bool follow = start == end && (length == 0 || scroll.nPos + (int)scroll.nPage >= scroll.nMax);
    m_edit.SetRedraw(FALSE);
    if (length + text.GetLength() > MonitorLog::TextLimit) {
        int trim = length - MonitorLog::TextKeep;
        int line = m_edit.LineFromChar(max(0, trim));
        int boundary = m_edit.LineIndex(line + 1);
        trim = boundary >= trim && boundary <= length ? boundary : max(0, trim);
        int removedLines = m_edit.LineFromChar(trim);
        m_edit.SetSel(0, trim); m_edit.ReplaceSel(_T(""), FALSE);
        length -= trim; start = max(0, start - trim); end = max(0, end - trim);
        firstLine = max(0, firstLine - removedLines);
        ++m_evicted;
    }
    m_edit.SetSel(length, length); m_edit.ReplaceSel(text, FALSE);
    m_edit.EmptyUndoBuffer();
    // Re-enable redraw before scrolling: EDIT may defer its scrollbar range
    // update while redraw is disabled, leaving SB_BOTTOM at the previous end.
    m_edit.SetRedraw(TRUE);
    if (follow) {
        int endOfText = m_edit.GetWindowTextLength();
        m_edit.SetSel(endOfText, endOfText);
        m_edit.SendMessage(WM_VSCROLL, SB_BOTTOM);
        m_edit.SendMessage(WM_HSCROLL, SB_LEFT);
    } else {
        m_edit.SetSel(start, end, TRUE);
        m_edit.LineScroll(firstLine - m_edit.GetFirstVisibleLine());
    }
    m_edit.Invalidate(FALSE);
}
void CPage4::OnTimer(UINT_PTR id)
{
    if (m_job && m_job->done.load()) {
        int result = m_job->result; bool needsCA = m_job->needsCA;
        CString error = Utf8(m_job->text); m_job.reset();
        m_decrypt.EnableWindow(TRUE); m_ca.EnableWindow(TRUE); SetDecryptStatus();
        if (needsCA) OpenCA(true);
        else if (result < 0) MessageBox(Localization::Get(_T("mitm.enable_failed")) + _T("\r\n\r\n") + error,
            Localization::Get(_T("mitm.ca")), MB_ICONERROR);
        else { m_monitor.SetCheck(BST_CHECKED); UpdateMonitorStatus(); }
    }
    const bool visible = m_edit.IsWindowVisible() != FALSE;
    if (visible && m_needsReplay) BeginReplay();
    if (!visible && m_replaying) { m_replaying = false; m_needsReplay = true; }
    CString pending;
    const DWORD started = GetTickCount();
    for (unsigned count = 0; count < MonitorLog::BatchRecords; ++count) {
        if (pending.GetLength() >= MonitorLog::BatchCharacters || GetTickCount() - started >= MonitorLog::BatchMilliseconds) break;
        if (visible && m_replaying) {
            if (m_replayIndex < m_history.size()) {
                pending += FormatRecord(m_history[m_replayIndex++]); continue;
            }
            m_replaying = false;
        }
        if (!m_recording) break;
        ProxyMonitorEvent event;
        if (!m_dataMonitor->Poll(&event)) break;
        Record record = MakeRecord(event);
        if (record.preview.size() < record.length) ++m_truncated;
        if (m_history.size() >= MonitorLog::HistoryRecords) { m_history.pop_front(); ++m_evicted; }
        m_history.push_back(std::move(record));
        if (visible) pending += FormatRecord(m_history.back()); else m_needsReplay = true;
    }
    if (visible) AppendText(pending);
    m_dropped += m_dataMonitor->TakeDroppedCount();
    DWORD tcp = 0, udp = 0;
    if (g_GlobalProxy) {
        auto prc = g_GlobalProxy->GetPRCInstance();
        if (prc->GetPTMInstance(0)) prc->GetPTMInstance(0)->GetTaskCount(&tcp);
        if (prc->GetPTMInstance(1)) prc->GetPTMInstance(1)->GetTaskCount(&udp);
    }
    CString status = Localization::Format(_T("page4.connections"), tcp, udp);
    if (m_dropped || m_truncated || m_evicted)
        status += Localization::Format(_T("monitor.limits"), m_dropped, m_truncated, m_evicted);
    CString current; GetDlgItemText(IDC_STATIC_TASKCOUNT, current);
    if (status != current) SetDlgItemText(IDC_STATIC_TASKCOUNT, status);
    CModernDialog::OnTimer(id);
}
