#include "stdafx.h"
#include "ProxyLane.h"
#include "Page4.h"
#include "Localization.h"
#include "MitmSettings.h"
#include "../../third_party/nlohmann/json.hpp"
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
static std::shared_ptr<MitmJob> StartMitmJob(IProxyTlsControl* tls, unsigned action)
{
    auto job = std::make_shared<MitmJob>();
    try {
        std::thread([job, tls, action]() {
            job->result = tls->ManageCA(static_cast<IProxyTlsControl::CaAction>(action), job->text, sizeof(job->text));
            job->done.store(true);
        }).detach();
    } catch (...) { strcpy_s(job->text, "Unable to start CA worker."); job->done.store(true); }
    return job;
}
static std::shared_ptr<MitmJob> StartMonitorJob(IProxyTlsControl* tls, bool decrypt)
{
    auto job = std::make_shared<MitmJob>();
    const auto settings=MitmSettings::Load();
    const bool skip=GetPrivateProfileInt(L"options",L"MitmSkipUpstreamVerify",0,Localization::SettingsPath())==1;
    try {
        std::thread([job,tls,decrypt,settings,skip]() {
            try {
                if(decrypt) {
                    job->result=tls->ManageCA(IProxyTlsControl::QueryCA,job->text,sizeof(job->text));
                    if(job->result>=0) job->needsCA=(job->result&2)==0;
                    if(job->result<0 || job->needsCA) {job->done.store(true);return;}
                }
                auto options=nlohmann::json{{"type","mitm_options"},{"settings",MitmSettings::Json(settings)},{"skip_upstream_verify",skip}}.dump();
                job->result=tls->QueryProtocol(options.c_str(),job->text,sizeof(job->text));
                if(job->result>=0) {
                    const char* request=decrypt ? "{\"type\":\"monitor_start\",\"decrypt\":true}" : "{\"type\":\"monitor_start\",\"decrypt\":false}";
                    job->result=tls->QueryProtocol(request,job->text,sizeof(job->text));
                }
            } catch (...) { job->result=-1;strcpy_s(job->text,"Unable to prepare monitoring."); }
            job->done.store(true);
        }).detach();
    } catch (...) {strcpy_s(job->text,"Unable to start monitor worker.");job->done.store(true);}
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
// Section headers provide a visible boundary without adding group-box padding.
class CMitmSectionHeader : public CStatic {
    void DrawItem(LPDRAWITEMSTRUCT item) override {
        CDC dc;dc.Attach(item->hDC);CRect rect=item->rcItem;
        dc.FillSolidRect(rect,RGB(239,244,250));
        dc.FillSolidRect(rect.left,rect.top,UiTheme::ScaleForWindow(m_hWnd,3),rect.Height(),RGB(106,140,181));
        dc.FillSolidRect(rect.left,rect.bottom-1,rect.Width(),1,RGB(205,216,230));
        CFont* old=dc.SelectObject(GetFont());dc.SetBkMode(TRANSPARENT);dc.SetTextColor(UiTheme::TextPrimary());
        rect.DeflateRect(UiTheme::ScaleForWindow(m_hWnd,9),0);
        CString caption;GetWindowText(caption);dc.DrawText(caption,rect,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);
        dc.SelectObject(old);dc.Detach();
    }
};
class CMitmCaDialog : public CModernDialog {
    std::shared_ptr<MitmJob> m_job;
    CModernButton m_buttons[4], m_advanced, m_save, m_defaults;
    CStatic m_labels[9],m_effective,m_enableHint;
    CMitmSectionHeader m_caTitle,m_settingsTitle;
    CFont m_sectionFont;
    CEdit m_values[9];
    bool m_expanded=false, m_defaultsPending=false, m_savedSkip=false;
    bool m_savedDecrypt=false, m_enablePending=false, m_saveAfterTrust=false, m_monitoring=false;
    bool m_enableHintRequested=false;
    MitmSettings::Values m_saved;
    enum { AdvancedId=1300,SaveId=1301,DefaultsId=1302,EditBase=1310 };
    void Place(CWnd& control,int x,int y,int w,int h) {
        CRect r(x,y,x+w,y+h);MapDialogRect(r);control.MoveWindow(r);
    }
    void LayoutOptions() {
        auto scale=[&](int value){return UiTheme::ScaleForWindow(m_hWnd,value);};
        CClientDC dc(this);auto old=dc.SelectObject(&m_uiFont);
        TEXTMETRIC metrics={};dc.GetTextMetrics(&metrics);
        const int line=metrics.tmHeight, margin=scale(12), gap=scale(6);
        CRect client;GetClientRect(client);
        const int width=client.Width()-2*margin;
        const int editHeight=line+scale(4), buttonHeight=line+scale(8), rowHeight=editHeight+gap;
        auto measureText=[&](CString text) {
            CRect bounds(0,0,width,0);
            dc.DrawText(text,bounds,DT_CALCRECT|DT_WORDBREAK|DT_NOPREFIX);return bounds.Height();
        };
        auto textHeight=[&](LPCTSTR key){return measureText(Localization::Get(key));};
        auto buttonWidth=[&](CWnd& button) {
            CString text;button.GetWindowText(text);return dc.GetTextExtent(text).cx+scale(20);
        };
        int y=margin;
        GetDlgItem(IDC_MITM_ENABLE)->MoveWindow(margin,y,scale(150),line);
        m_enableHint.MoveWindow(margin+scale(160),y,max(0,width-scale(160)),line);
        y+=line+gap;
        const int headingHeight=line+scale(8);
        m_caTitle.MoveWindow(margin,y,width,headingHeight);y+=headingHeight+gap;
        CString status;GetDlgItemText(IDC_MITM_STATUS,status);
        const int statusHeight=max(line,measureText(status));
        GetDlgItem(IDC_MITM_STATUS)->MoveWindow(margin,y,width,statusHeight);y+=statusHeight+gap;
        int x=margin;
        for(int i=0;i<3;++i) {
            int w=buttonWidth(m_buttons[i]);m_buttons[i].MoveWindow(x,y,w,buttonHeight);x+=w+gap;
        }
        y+=buttonHeight+scale(8);
        GetDlgItem(IDC_MITM_SKIP_VERIFY)->MoveWindow(margin,y,width,line);y+=line+gap;
        const int hintHeight=textHeight(L"mitm.skip_hint");
        GetDlgItem(IDC_MITM_SKIP_HINT)->MoveWindow(margin,y,width,hintHeight);y+=hintHeight+scale(8);
        m_settingsTitle.MoveWindow(margin,y,width,headingHeight);y+=headingHeight+gap;
        const int columnGap=scale(20),column=(width-columnGap)/2,editWidth=scale(60);
        auto field=[&](int i,int n,int top) {
            int left=margin+(n%2)*(column+columnGap),row=top+(n/2)*rowHeight;
            m_labels[i].MoveWindow(left,row+(editHeight-line)/2,column-editWidth-gap,line);
            m_values[i].MoveWindow(left+column-editWidth,row,editWidth,editHeight);
            m_labels[i].ShowWindow(i<4||m_expanded ? SW_SHOW:SW_HIDE);
            m_values[i].ShowWindow(i<4||m_expanded ? SW_SHOW:SW_HIDE);
        };
        for(int i=0;i<4;++i) field(i,i,y);
        y+=2*rowHeight;
        m_advanced.SetWindowText(Localization::Get(m_expanded ? L"mitm.advanced_hide":L"mitm.advanced"));
        m_advanced.MoveWindow(margin,y,buttonWidth(m_advanced),buttonHeight);y+=buttonHeight+gap;
        for(int i=4;i<9;++i) field(i,i-4,y);
        if(m_expanded) y+=3*rowHeight;
        int effectiveHeight=line;
        for(auto key:{L"mitm.settings_effective",L"mitm.settings_saved",L"mitm.defaults_pending"})
            effectiveHeight=max(effectiveHeight,textHeight(key));
        m_effective.MoveWindow(margin,y,width,effectiveHeight);y+=effectiveHeight+scale(10);
        m_defaults.MoveWindow(margin,y,buttonWidth(m_defaults),buttonHeight);
        int closeWidth=buttonWidth(m_buttons[3]),saveWidth=buttonWidth(m_save);
        m_buttons[3].MoveWindow(margin+width-closeWidth,y,closeWidth,buttonHeight);
        m_save.MoveWindow(margin+width-closeWidth-gap-saveWidth,y,saveWidth,buttonHeight);
        dc.SelectObject(old);
        CRect window;GetWindowRect(window);
        const int height=window.Height()-client.Height()+y+buttonHeight+margin;
        MONITORINFO monitor={sizeof(monitor)};int top=window.top;
        if(GetMonitorInfo(MonitorFromWindow(m_hWnd,MONITOR_DEFAULTTONEAREST),&monitor))
            top=max(monitor.rcWork.top,min(top,monitor.rcWork.bottom-height));
        SetWindowPos(nullptr,window.left,top,window.Width(),height,SWP_NOZORDER);
        RedrawWindow(nullptr,nullptr,RDW_INVALIDATE|RDW_ALLCHILDREN|RDW_UPDATENOW);
    }
    void RestoreDefaults() {
        const auto values=MitmSettings::Defaults();
        for(int i=0;i<9;++i) SetDlgItemInt(EditBase+i,values[i]);
        CheckDlgButton(IDC_MITM_SKIP_VERIFY,BST_UNCHECKED);
        CheckDlgButton(IDC_MITM_ENABLE,BST_UNCHECKED);
        m_defaultsPending=true;
        m_effective.SetWindowText(Localization::Get(L"mitm.defaults_pending"));
    }
    void UpdateEnableHint() {
        // Opening options is not a mode change. Only a new unchecked->checked
        // choice during plaintext monitoring needs a restart; active MITM does not.
        const bool show=m_monitoring && m_enableHintRequested &&
            IsDlgButtonChecked(IDC_MITM_ENABLE)==BST_CHECKED && !m_tls->IsEnabled();
        m_enableHint.ShowWindow(show ? SW_SHOW : SW_HIDE);
    }
    void SaveOptions() {
        if(m_job) return;
        const bool decrypt=IsDlgButtonChecked(IDC_MITM_ENABLE)==BST_CHECKED;
        if(decrypt && !IsTrusted()) {m_enablePending=true;m_saveAfterTrust=true;Start(IProxyTlsControl::TrustCA);return;}
        auto values=m_saved;
        for(int i=0;i<9;++i) {
            CString text;m_values[i].GetWindowText(text);
            const auto& f=MitmSettings::Fields()[i];
            wchar_t* end=nullptr;unsigned long value=wcstoul(text,&end,10);
            if(text.IsEmpty() || text.SpanIncluding(L"0123456789")!=text || !end || *end || value<f.minimum || value>f.maximum) {
                if(i>=4 && !m_expanded){m_expanded=true;LayoutOptions();}
                MessageBox(Localization::Format(L"mitm.range",(LPCWSTR)Localization::Get(f.label),f.minimum,f.maximum),Localization::Get(L"mitm.ca"),MB_ICONWARNING);
                m_values[i].SetFocus();m_values[i].SetSel(0,-1);return;
            }
            values[i]=value;
        }
        if(values[0]>values[1]) {MessageBox(Localization::Get(L"mitm.quota_error"),Localization::Get(L"mitm.ca"),MB_ICONWARNING);return;}
        char response[4096]={};
        nlohmann::json request={{"type","mitm_options"},{"settings",MitmSettings::Json(values)},{"validate_only",true}};
        const bool skip=IsDlgButtonChecked(IDC_MITM_SKIP_VERIFY)==BST_CHECKED;
        request["skip_upstream_verify"]=skip;
        if(m_tls->QueryProtocol(request.dump().c_str(),response,sizeof(response))<0) {MessageBox(Utf8(response),Localization::Get(L"mitm.ca"),MB_ICONERROR);return;}
        if(!MitmSettings::Save(values)) {MessageBox(Localization::Get(L"mitm.save_failed"),Localization::Get(L"mitm.ca"),MB_ICONERROR);return;}
        if(!WritePrivateProfileString(L"options",L"MitmSkipUpstreamVerify",skip ? L"1":L"0",Localization::SettingsPath())) {
            MitmSettings::Save(m_saved);
            MessageBox(Localization::Get(L"mitm.save_failed"),Localization::Get(L"mitm.ca"),MB_ICONERROR);return;
        }
        if(!MitmSettings::SaveDecryptHTTPS(decrypt)) {
            MitmSettings::Save(m_saved);
            WritePrivateProfileString(L"options",L"MitmSkipUpstreamVerify",m_savedSkip ? L"1":L"0",Localization::SettingsPath());
            MessageBox(Localization::Get(L"mitm.save_failed"),Localization::Get(L"mitm.ca"),MB_ICONERROR);return;
        }
        request["validate_only"]=false;
        if(m_tls->QueryProtocol(request.dump().c_str(),response,sizeof(response))<0) {
            bool restored=MitmSettings::Save(m_saved);
            restored=MitmSettings::SaveDecryptHTTPS(m_savedDecrypt) && restored;
            restored=WritePrivateProfileString(L"options",L"MitmSkipUpstreamVerify",m_savedSkip ? L"1":L"0",Localization::SettingsPath()) && restored;
            CString error=Utf8(response);if(!restored) error+=L"\r\n"+Localization::Get(L"mitm.save_failed");
            MessageBox(error,Localization::Get(L"mitm.ca"),MB_ICONERROR);return;
        }
        m_savedSkip=skip;
        m_defaultsPending=false;m_savedDecrypt=decrypt;
        m_saved=values;m_effective.SetWindowText(Localization::Get(L"mitm.settings_saved"));
        if(GetParent()) GetParent()->SendMessage(WM_APP+41);
        EndDialog(IDOK);
    }
    IProxyTlsControl* m_tls;
    int m_flags;
    unsigned m_action=IProxyTlsControl::QueryCA;
    CString m_details;
public:
    CMitmCaDialog(CWnd* parent, IProxyTlsControl* tls, bool monitoring=false) : CModernDialog(IDD_MITM_CA, parent), m_tls(tls), m_flags(-1), m_monitoring(monitoring) {}
    bool IsTrusted() const { return m_flags >= 0 && (m_flags & 2) != 0; }
    void Start(unsigned action) {
        m_action=action;
        for (auto& button : m_buttons) button.EnableWindow(FALSE);
        GetDlgItem(IDC_MITM_ENABLE)->EnableWindow(FALSE);m_save.EnableWindow(FALSE);m_defaults.EnableWindow(FALSE);
        SetDlgItemText(IDC_MITM_STATUS, Localization::Get(_T("mitm.busy")));
        m_job = StartMitmJob(m_tls, action);
        LayoutOptions();
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
        SetDlgItemText(IDC_MITM_SKIP_VERIFY, Localization::Get(L"mitm.skip_verify"));
        SetDlgItemText(IDC_MITM_SKIP_HINT, Localization::Get(L"mitm.skip_hint"));
        m_saved=MitmSettings::Load();
        const DWORD child=WS_CHILD|WS_VISIBLE;
        m_savedDecrypt=MitmSettings::DecryptHTTPS();
        SetDlgItemText(IDC_MITM_ENABLE,Localization::Get(L"mitm.enable"));
        CheckDlgButton(IDC_MITM_ENABLE,m_savedDecrypt ? BST_CHECKED:BST_UNCHECKED);
        m_enableHint.Create(Localization::Get(L"mitm.next_monitor"),child|SS_LEFTNOWORDWRAP,CRect(),this);
        m_enableHint.SetFont(&m_uiFont);
        m_enableHintRequested=false;
        m_enableHint.ShowWindow(SW_HIDE);
        UiTheme::CreateUiFont(m_sectionFont,m_hWnd,9,FW_SEMIBOLD);
        m_caTitle.SubclassDlgItem(IDC_CA_HINT,this);
        m_caTitle.ModifyStyle(SS_TYPEMASK,SS_OWNERDRAW);m_caTitle.SetWindowText(L"ProxyLane CA / TLS");
        m_caTitle.SetFont(&m_sectionFont);
        m_settingsTitle.Create(Localization::Get(L"mitm.cache_display"),child|SS_OWNERDRAW,CRect(),this);
        m_settingsTitle.SetFont(&m_sectionFont);
        for(int i=0;i<9;++i) {
            m_labels[i].Create(Localization::Get(MitmSettings::Fields()[i].label),child,CRect(),this);
            m_values[i].CreateEx(WS_EX_CLIENTEDGE,L"EDIT",L"",child|WS_TABSTOP|ES_NUMBER|ES_AUTOHSCROLL,CRect(),this,EditBase+i);
            m_labels[i].SetFont(&m_uiFont);m_values[i].SetFont(&m_uiFont);m_values[i].SetLimitText(5);
            CString value;value.Format(L"%u",m_saved[i]);m_values[i].SetWindowText(value);
        }
        m_advanced.Create(L"",child|WS_TABSTOP|BS_PUSHBUTTON,CRect(),this,AdvancedId);Place(m_advanced,12,155,100,16);
        m_save.Create(Localization::Get(L"mitm.save"),child|WS_TABSTOP|BS_PUSHBUTTON,CRect(),this,SaveId);
        m_defaults.Create(Localization::Get(L"mitm.defaults"),child|WS_TABSTOP|BS_PUSHBUTTON,CRect(),this,DefaultsId);
        m_defaults.SetFont(&m_uiFont);
        m_effective.Create(Localization::Get(L"mitm.settings_effective"),child,CRect(),this);
        m_advanced.SetFont(&m_uiFont);m_save.SetFont(&m_uiFont);m_effective.SetFont(&m_uiFont);
        SendMessage(DM_SETDEFID,SaveId);LayoutOptions();
        char options[4096] = {};
        if (m_tls->QueryProtocol("{\"type\":\"mitm_options\"}", options, sizeof(options)) > 0) {
            auto value = nlohmann::json::parse(options, nullptr, false);
            if (value.is_object()) {m_savedSkip=value.value("skip_upstream_verify", false);CheckDlgButton(IDC_MITM_SKIP_VERIFY,m_savedSkip ? BST_CHECKED : BST_UNCHECKED);}
        }
        SetTimer(1, 150, NULL); Start(0); return TRUE;
    }
    BOOL OnCommand(WPARAM wParam, LPARAM lParam) override {
        UINT id = LOWORD(wParam);
        if(id==AdvancedId) {m_expanded=!m_expanded;LayoutOptions();return TRUE;}
        if(id==SaveId) {SaveOptions();return TRUE;}
        if(id==DefaultsId) {if(!m_job) {RestoreDefaults();m_enableHintRequested=false;UpdateEnableHint();}return TRUE;}
        if(id==IDC_MITM_ENABLE) {
            if(m_job) return TRUE;
            m_enableHintRequested=IsDlgButtonChecked(id)==BST_CHECKED;
            UpdateEnableHint();
            if(IsDlgButtonChecked(id)==BST_CHECKED) {
                m_enablePending=true;m_saveAfterTrust=false;
                Start(IProxyTlsControl::QueryCA);
            }
            return TRUE;
        }
        if (id == IDC_MITM_SKIP_VERIFY) return TRUE; // Draft until Save.
        if (id == IDC_CA_REFRESH) {
            if (!m_job) MessageBox(m_details, Localization::Get(L"mitm.ca"), MB_OK);
            return TRUE;
        }
        if (id == IDC_CA_INSTALL || id == IDC_CA_REMOVE) {
            if(id==IDC_CA_REMOVE && m_monitoring) return TRUE;
            if (!m_job) Start(id == IDC_CA_INSTALL ? IProxyTlsControl::TrustCA :
                id == IDC_CA_REMOVE ? IProxyTlsControl::RemoveCATrust : IProxyTlsControl::QueryCA);
            return TRUE;
        }
        return CModernDialog::OnCommand(wParam, lParam);
    }
    // Do not allow a trust operation to finish invisibly after dismissing it.
    void OnOK() override { OnCancel(); } // The resource button is the Cancel action.
    void OnCancel() override { if (!m_job) CModernDialog::OnCancel(); }
    afx_msg HBRUSH OnCtlColor(CDC* dc, CWnd* wnd, UINT color) {
        HBRUSH brush=CModernDialog::OnCtlColor(dc,wnd,color);
        if(color==CTLCOLOR_STATIC && wnd && wnd->GetDlgCtrlID()==IDC_MITM_STATUS &&
            !m_job && m_flags>=0 && !IsTrusted())
            dc->SetTextColor(RGB(184,135,0)); // Dark yellow remains readable on white.
        return brush;
    }
    afx_msg void OnTimer(UINT_PTR id) {
        if (m_job && m_job->done.load()) {
            // Consume before entering MessageBox's nested message loop: timer
            // messages must never display this completed failure repeatedly.
            auto job = std::move(m_job);
            int flags = job->result;
            m_flags = flags;
            m_details = Utf8(job->text);
            SetDlgItemText(IDC_MITM_STATUS, Localization::Get(flags < 0 ? _T("mitm.failed") :
                flags & 2 ? _T("mitm.trusted") : flags & 1 ? _T("mitm.untrusted") : _T("mitm.uninitialized")));
            for (auto& button : m_buttons) button.EnableWindow(TRUE);
            GetDlgItem(IDC_CA_INSTALL)->EnableWindow(!IsTrusted());
            SetDlgItemText(IDC_CA_REMOVE,Localization::Get(IsTrusted() && m_monitoring ?
                L"mitm.remove_stop_first" : L"mitm.remove"));
            GetDlgItem(IDC_CA_REMOVE)->EnableWindow((flags & 2) && flags >= 0 && !m_monitoring);
            GetDlgItem(IDC_MITM_ENABLE)->EnableWindow(TRUE);m_save.EnableWindow(TRUE);m_defaults.EnableWindow(TRUE);
            LayoutOptions();
            if(m_enablePending && m_action==IProxyTlsControl::QueryCA && flags>=0 && !IsTrusted()) {Start(IProxyTlsControl::TrustCA);return;}
            const bool save=m_saveAfterTrust && IsTrusted();
            if(m_enablePending && !IsTrusted()) CheckDlgButton(IDC_MITM_ENABLE,BST_UNCHECKED);
            UpdateEnableHint();
            m_enablePending=m_saveAfterTrust=false;
            if (flags < 0) MessageBox(m_details, Localization::Get(L"mitm.ca"), MB_ICONERROR);
            else if(save) SaveOptions();
        }
        CModernDialog::OnTimer(id);
    }
    DECLARE_MESSAGE_MAP()
};
BEGIN_MESSAGE_MAP(CMitmCaDialog, CModernDialog)
    ON_WM_TIMER()
    ON_WM_CTLCOLOR()
END_MESSAGE_MAP()

IMPLEMENT_DYNAMIC(CPage4, CModernDialog)
CPage4::CPage4(CWnd* parent) : CModernDialog(IDD, parent), m_tls(nullptr), m_recording(false) {}
CPage4::~CPage4() { CompleteReconnect(false); }
void CPage4::DoDataExchange(CDataExchange* dx)
{
    CModernDialog::DoDataExchange(dx);
    DDX_Control(dx, IDC_CHECK1, m_monitor);
    DDX_Control(dx, IDC_BTN_CLEAR, m_clear);
    DDX_Control(dx, IDC_MITM_CA, m_ca);
}
BOOL CPage4::OnInitDialog()
{
    CModernDialog::OnInitDialog();
    IGlobalProxy* proxy = GetGlobalProxyInstance();
    m_tls = proxy->GetTlsControl();
    ReleaseGlobalProxyInstance(); // Borrowed services outlive this proxy reference.
    // Pages initialize before auto-start/launch; restore once, not when reopening the options dialog.
    const auto settings=MitmSettings::Load();
    bool custom=false;for(size_t i=0;i<settings.size();++i) custom|=settings[i]!=MitmSettings::Fields()[i].initial;
    const bool skip=GetPrivateProfileInt(L"options",L"MitmSkipUpstreamVerify",0,Localization::SettingsPath())==1;
    if(m_mitmSupported && (custom||skip)) {
        char error[4096]={};
        auto request=nlohmann::json{{"type","mitm_options"},{"settings",MitmSettings::Json(settings)},{"skip_upstream_verify",skip}}.dump();
        if(m_tls->QueryProtocol(request.c_str(),error,sizeof(error))<0) MessageBox(Utf8(error),Localization::Get(L"mitm.ca"),MB_ICONERROR);
    }
    SetDlgItemText(IDC_MITM_CA, Localization::Get(_T("mitm.ca")));
    UiTheme::CreateUiFont(m_font, m_hWnd, 9, FW_NORMAL, _T("Consolas"));
    InitProtocolView(); ApplyMonitorSettings();
    m_tls->SetEnabled(FALSE,nullptr,0); // A saved preference never enables interception before monitoring.
    SetMonitorControls(false); SetTimer(1, 100, NULL);
    CRect rect; GetClientRect(rect); LayoutControls(rect.Width(), rect.Height()); return TRUE;
}
BEGIN_MESSAGE_MAP(CPage4, CModernDialog)
    ON_MESSAGE(WM_APP+41, &CPage4::OnMonitorSettings)
    ON_WM_SIZE()
    ON_WM_SHOWWINDOW()
    ON_WM_TIMER()
    ON_BN_CLICKED(IDC_CHECK1, &CPage4::OnMonitor)
    ON_NOTIFY(TCN_SELCHANGE, IDC_PROTOCOL_VIEW_TABS, &CPage4::OnView)
    ON_EN_CHANGE(IDC_PROTOCOL_FILTER, &CPage4::OnFilter)
    ON_BN_CLICKED(IDC_PROTOCOL_FOLLOW, &CPage4::OnFollowLatest)
    ON_NOTIFY(LVN_ENDSCROLL, IDC_PROTOCOL_REQUESTS, &CPage4::OnListScrolled)
    ON_CBN_SELCHANGE(IDC_PROTOCOL_KIND, &CPage4::OnFilter)
    ON_NOTIFY(NM_CLICK, IDC_PROTOCOL_HEX, &CPage4::OnHexSelection)
    ON_NOTIFY(EN_SELCHANGE, IDC_PROTOCOL_DETAIL, &CPage4::OnRawSelection)
    ON_WM_LBUTTONDOWN()
    ON_WM_LBUTTONUP()
    ON_WM_MOUSEMOVE()
    ON_WM_SETCURSOR()
    ON_WM_CAPTURECHANGED()
    ON_BN_CLICKED(IDC_BTN_CLEAR, &CPage4::OnClear)
    ON_BN_CLICKED(IDC_MITM_CA, &CPage4::OnCA)
    ON_NOTIFY(LVN_ITEMCHANGED, IDC_PROTOCOL_REQUESTS, &CPage4::OnRequestSelected)
    ON_NOTIFY(LVN_GETINFOTIP, IDC_PROTOCOL_REQUESTS, &CPage4::OnRequestInfoTip)
    ON_NOTIFY(TCN_SELCHANGE, IDC_PROTOCOL_DETAIL_TABS, &CPage4::OnDetailTab)
END_MESSAGE_MAP()
void CPage4::OnSize(UINT type, int cx, int cy)
{
    CModernDialog::OnSize(type, cx, cy);
    CRect client; GetClientRect(client);
    LayoutControls(client.Width(), client.Height());
}
void CPage4::OnShowWindow(BOOL show, UINT status)
{
    CModernDialog::OnShowWindow(show, status);
    if (show) { InitProtocolColumns(); SetMonitorControls(m_job || m_stopJob); }
}
void CPage4::LayoutControls(int cx, int cy)
{
    // Shared layout helper: never call an MFC message handler from initialization.
    if (!m_monitor.GetSafeHwnd()) return;
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
    int monitorWidth = labelWidth(m_monitor, 20);
    int caWidth = labelWidth(m_ca, 16);
    int clearWidth = max(s(48), labelWidth(m_clear, 16));
    if (monitorWidth + caWidth + clearWidth + s(8) > width) {
        monitorWidth = labelWidth(m_monitor, 16);
        caWidth = labelWidth(m_ca, 8);
        clearWidth = max(s(40), labelWidth(m_clear, 8));
    }
    int gap = max(1, min(s(12), (width - monitorWidth - caWidth - clearWidth) / 2));
    m_monitor.MoveWindow(s(8), top, monitorWidth, h);
    m_clear.MoveWindow(cx - s(8) - clearWidth, top, clearWidth, h);
    m_ca.MoveWindow(cx - s(8) - clearWidth - gap - caWidth, top, caWidth, h);
    GetDlgItem(IDC_STATIC_TASKCOUNT)->MoveWindow(max(s(160), cx - s(220)), s(10), min(s(212), max(0, cx - s(168))), s(20));
    top += s(36);
    LayoutProtocolView(s(8), top, width, max(0, cy - top - s(8)));
}
void CPage4::SetMonitorControls(bool busy)
{
    m_ca.EnableWindow(m_mitmSupported && !busy);m_monitor.EnableWindow(m_mitmSupported && !busy);
    // While running, describe this run; edited preferences apply to the next start.
    const bool decrypt=m_recording ? m_tls->IsEnabled()!=FALSE : MitmSettings::DecryptHTTPS();
    m_monitor.SetWindowText(Localization::Get(busy && m_job ? L"monitor.preparing" :
        decrypt ? L"page4.monitor_decrypt" : L"page4.monitor"));
    CRect client;GetClientRect(client);LayoutControls(client.Width(),client.Height());
}
void CPage4::OnCA() { OpenCA(false); }
void CPage4::OpenCA(bool resumeStart)
{
    if (!m_mitmSupported || m_stopJob) return;
    CMitmCaDialog dialog(this, m_tls, m_recording);
    const INT_PTR result=dialog.DoModal();
    ApplyMonitorSettings();
    SetMonitorControls(false);
    // This attempt requested decryption: changing the preference to off must
    // cancel it, never silently turn it into a plaintext-only monitoring start.
    if (resumeStart && result==IDOK && dialog.IsTrusted() && MitmSettings::DecryptHTTPS()) StartMonitoring();
    else if (resumeStart) {m_monitor.SetCheck(BST_UNCHECKED);CompleteReconnect(false);}
}
bool CPage4::PrepareReconnect(bool decrypt)
{
    CompleteReconnect(false);
    if (!decrypt) return true;
    auto manager = g_GlobalProxy ? g_GlobalProxy->GetPRCInstance()->GetPTMInstance(0) : nullptr;
    if (!manager) return true;
    DWORD count = manager->PrepareReconnect(decrypt ? TRUE : FALSE);
    m_reconnectPrepared = true;
    if (!count) return true;
    CString title = Localization::Get(L"page4.monitor");
    CString message = Localization::Format(L"mitm.reconnect", count);
    const int result = MessageBox(message, title, MB_YESNOCANCEL | MB_ICONQUESTION | MB_DEFBUTTON2);
    m_reconnectAccepted = result == IDYES;
    if (result != IDYES && result != IDNO) { CompleteReconnect(false); return false; }
    return true;
}
void CPage4::CompleteReconnect(bool commit)
{
    if (m_reconnectPrepared && g_GlobalProxy) {
        auto manager = g_GlobalProxy->GetPRCInstance()->GetPTMInstance(0);
        if (manager) manager->CompleteReconnect(commit && m_reconnectAccepted);
    }
    m_reconnectPrepared = m_reconnectAccepted = false;
}
void CPage4::StartMonitoring()
{
    if (!m_mitmSupported || m_job || m_stopJob) return;
    m_job = StartMonitorJob(m_tls,MitmSettings::DecryptHTTPS());
    SetMonitorControls(true);
}
void CPage4::UpdateMonitorStatus()
{
    if (!m_monitor.GetSafeHwnd()) return;
    if (!m_mitmSupported) {m_monitor.SetCheck(BST_UNCHECKED);return;}
    if (m_stopJob || m_job) return;
    if(m_monitor.GetCheck()==BST_CHECKED) { if(!m_recording) StartMonitoring();return; }
    auto job = std::make_shared<MitmJob>();
    try {
        auto tls = m_tls;
        std::thread([job, tls]() {
            job->result=tls->QueryProtocol("{\"type\":\"monitor_stop\"}",job->text,sizeof(job->text));
            job->done.store(true);
        }).detach();
    } catch (...) {
        m_monitor.SetCheck(m_recording ? BST_CHECKED:BST_UNCHECKED);
        MessageBox(L"Unable to start monitor stop worker.",Localization::Get(L"mitm.ca"),MB_ICONERROR);return;
    }
    m_stopJob=job;m_recording=false;SetMonitorControls(true);
    if(GetParent()) GetParent()->Invalidate(FALSE);
}
void CPage4::OnMonitor()
{
    if (!m_mitmSupported) {m_monitor.SetCheck(BST_UNCHECKED);return;}
    if(m_job || m_stopJob) return;
    if(!m_recording && m_monitor.GetCheck()==BST_CHECKED && !PrepareReconnect(MitmSettings::DecryptHTTPS())) {
        m_monitor.SetCheck(BST_UNCHECKED);return;
    }
    UpdateMonitorStatus();
}

void CPage4::OnClear() { ClearProtocolView(); }
void CPage4::OnTimer(UINT_PTR id)
{
    TickProtocolView();
    if (m_stopJob && m_stopJob->done.load()) {
        auto job = m_stopJob; m_stopJob.reset();
        SetMonitorControls(false);
        if (job->result < 0) MessageBox(Utf8(job->text), Localization::Get(L"mitm.ca"), MB_ICONERROR);
    }
    if (m_job && m_job->done.load()) {
        auto job=std::move(m_job);SetMonitorControls(false);
        if(job->needsCA) {m_monitor.SetCheck(BST_UNCHECKED);OpenCA(true);}
        else if(job->result<0) {
            m_monitor.SetCheck(BST_UNCHECKED);m_recording=false;CompleteReconnect(false);
            MessageBox(Localization::Get(L"monitor.start_failed")+L"\r\n\r\n"+Utf8(job->text),Localization::Get(L"mitm.ca"),MB_ICONERROR);
        } else {
            m_recording=true;m_monitor.SetCheck(BST_CHECKED);CompleteReconnect(true);
            SetMonitorControls(false);
            if(GetParent()) GetParent()->Invalidate(FALSE);
        }
    }
    DWORD tcp = 0, udp = 0;
    if (g_GlobalProxy) {
        auto prc = g_GlobalProxy->GetPRCInstance();
        if (prc->GetPTMInstance(0)) prc->GetPTMInstance(0)->GetTaskCount(&tcp);
        if (prc->GetPTMInstance(1)) prc->GetPTMInstance(1)->GetTaskCount(&udp);
    }
    CString status = Localization::Format(_T("page4.connections"), tcp, udp);
    CString current; GetDlgItemText(IDC_STATIC_TASKCOUNT, current);
    if (status != current) SetDlgItemText(IDC_STATIC_TASKCOUNT, status);
    CModernDialog::OnTimer(id);
}
