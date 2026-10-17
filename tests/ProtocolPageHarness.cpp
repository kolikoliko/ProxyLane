// Tests the actual page/controls in an owned test window. Uses a fake query
// service only; never installs a CA, starts a proxy or touches another app.
#include "../src/ProxyLane/stdafx.h"
#include "../src/ProxyLane/ProxyLane.h"
#include "../src/ProxyLane/Page4.cpp"
#include "../src/ProxyLane/Page4Protocol.cpp"
#include <atlimage.h>
#include <mutex>
#include <fstream>
#include <iostream>

IGlobalProxy* g_GlobalProxy = nullptr;
class FakeTls : public IProxyTlsControl {
public:
    std::atomic<bool> evicted{false};
    bool caOk=false, skipVerify=false;
    nlohmann::json settings;
    std::atomic<unsigned> count{2};
    std::atomic<unsigned> delay{0};
    std::atomic<bool> packetPayload{false};
    std::atomic<unsigned> queries{0};
    int ManageCA(CaAction, char* output, size_t capacity) override {
        if(caOk) {if(output&&capacity) strcpy_s(output,capacity,"Test CA trusted");return 3;}
        if (output && capacity) strcpy_s(output,capacity,"Test CA load failure");
        return -1;
    }
    BOOL SetEnabled(BOOL, char*, size_t) override { return FALSE; }
    BOOL IsEnabled() override { return FALSE; }
    int QueryProtocol(const char* request, char* output, size_t capacity) override {
        ++queries;
        using J = ProtocolView::Json;
        if (delay.load()) Sleep(delay.load());
        auto command = J::parse(request); J reply;
        std::string type = command.at("type");
        if (type == "mitm_options") {
            if(command.contains("settings") && !command.value("validate_only",false)) settings=command["settings"];
            if(command.contains("skip_upstream_verify") && !command.value("validate_only",false)) skipVerify=command["skip_upstream_verify"].get<bool>();
            reply={{"settings",settings},{"skip_upstream_verify",skipVerify}};
        } else if (type == "poll") {
            J records = J::array(); uint64_t next = command.value("after", uint64_t(0));
            for (uint64_t id = next + 1; id <= count && records.size() < 32; ++id) {
                J request = {{"method", "GET"}, {"target", "/ip"}, {"status", nullptr},
                    {"headers", J::array({J::array({"host", "ifconfig.test"})})}, {"trailers", J::array()},
                    {"body_bytes", 0}, {"complete", true}, {"text", nullptr}, {"body_base64", ""}};
                J response = request; response["method"] = nullptr; response["target"] = nullptr; response["status"] = 200;
                response["body_bytes"] = 5;
                response["headers"] = J::array({J::array({"content-type", "application/json"}), J::array({"content-encoding", "gzip"})});
                records.push_back({{"type", "exchange"}, {"sequence", id}, {"protocol", id % 2 ? "http1" : "h2"},
                    {"connection", {{"id", std::to_string(id)}, {"pid", id % 2 ? 1234 : 5678}, {"process_start", id % 2 + 1},
                        {"socket", id + 99}, {"generation", 1}, {"destination", "ifconfig.test [127.255.0.1]:443"},
                        {"process_name", "curl.exe"}, {"server_name", "ifconfig.test"}, {"server_port", 443}}},
                    {"exchange", {{"id", id}, {"cache", {{"id", id}}}, {"problem", nullptr}, {"request", request},
                        {"response", response}, {"informational", J::array()}}}});
                next = id;
            }
            reply = {{"type", "records"}, {"run_id", "test"}, {"records", records}, {"next", next}, {"lost_before", 0}};
        } else if (type == "stats") reply = {{"type", "stats"}, {"run_id", "test"}, {"last_sequence", count.load()}};
        else if (type == "cache_status") reply = {{"cache", {{"id", command["cache_id"]}, {"finished", true},
            {"evicted", evicted.load()}, {"pending_chunks", 0}, {"reason", nullptr}}}};
        else if (type == "cache_read" && packetPayload) reply = {{"payload",{{"data_base64",command.value("offset",0u)!=0 ? "AwQF" : command.value("length",0u)>3 ? "AAECAwQF" : "AAEC"}}}};
        else if (type == "dns_read") reply = {{"payload",{{"data_base64","AAEBAAABAAAAAAAAAWEAAAEAAQ=="}}},{"text","ID: 0x0001\r\n[Question]\r\na. IN A"}};
        else reply = {{"payload", {{"data_base64", "eyJpcCI6IjIwMy4wLjExMy4xMCJ9"}}}};
        auto text = reply.dump();
        if (capacity > text.size()) memcpy(output, text.c_str(), text.size() + 1);
        return (int)text.size() + 1;
    }
};
static void Require(bool good, const char* message) { if (!good) throw std::runtime_error(message); }
class ProtocolPageHarness {
public:
    static void DragThumb(CByteHexView& hex, int bar) {
        SCROLLBARINFO info = {}; info.cbSize=sizeof(info);
        Require(::GetScrollBarInfo(hex.m_hWnd,bar==SB_VERT ? OBJID_VSCROLL : OBJID_HSCROLL,&info)!=FALSE,"native scrollbar geometry");
        const bool vertical=bar==SB_VERT;
        CPoint start = vertical ? CPoint((info.rcScrollBar.left+info.rcScrollBar.right)/2,info.rcScrollBar.top+(info.xyThumbTop+info.xyThumbBottom)/2) :
            CPoint(info.rcScrollBar.left+(info.xyThumbTop+info.xyThumbBottom)/2,(info.rcScrollBar.top+info.rcScrollBar.bottom)/2);
        CPoint end = vertical ? CPoint(start.x,info.rcScrollBar.bottom-info.dxyLineButton-12) : CPoint(info.rcScrollBar.right-info.dxyLineButton-12,start.y);
        HWND owner=::GetAncestor(hex.m_hWnd,GA_ROOT);
        ::SetForegroundWindow(owner); ::UpdateWindow(owner);
        POINT previousCursor;::GetCursorPos(&previousCursor);
        std::atomic<bool> injected{false};
        // A real non-client scrollbar loop requires the mouse-button state;
        // posting WM_MOUSEMOVE alone causes Windows to cancel tracking.
        std::thread input([=,&injected] {
            Sleep(250); if(::GetForegroundWindow()!=owner || (GetAsyncKeyState(VK_LBUTTON)&0x8000)) return;
            INPUT event={};event.type=INPUT_MOUSE;
            ::SetCursorPos(start.x,start.y);event.mi.dwFlags=MOUSEEVENTF_LEFTDOWN;::SendInput(1,&event,sizeof(event));
            Sleep(100);::SetCursorPos(end.x,end.y);Sleep(150);
            event.mi.dwFlags=MOUSEEVENTF_LEFTUP;::SendInput(1,&event,sizeof(event));
            injected=true;
        });
        DWORD started=GetTickCount();
        while(GetTickCount()-started<800) {
            MSG msg;while(PeekMessage(&msg,nullptr,0,0,PM_REMOVE)){TranslateMessage(&msg);DispatchMessage(&msg);}Sleep(10);
        }
        input.join();
        if(::GetForegroundWindow()==owner) ::SetCursorPos(previousCursor.x,previousCursor.y);
        Require(injected,"owned thumb test requires foreground window and released mouse");
        Require(hex.GetScrollPos(bar)>0,vertical ? "native vertical thumb drag" : "native horizontal thumb drag");
        Require(::GetCapture()!=hex.m_hWnd,"thumb releases capture");
    }
    static void Pump(CPage4& page, const std::function<bool()>& done, DWORD timeout = 10000) {
        DWORD start = GetTickCount();
        do {
            MSG message;
            while (PeekMessage(&message, nullptr, 0, 0, PM_REMOVE)) {
                TranslateMessage(&message); DispatchMessage(&message);
            }
            page.OnTimer(1);
            if (done()) return;
            Sleep(10);
        } while (GetTickCount() - start < timeout);
        throw std::runtime_error("page worker timeout");
    }
    static void Run(bool nativeScroll) {
        FakeTls fake;
        CWnd parent;
        Require(parent.CreateEx(0, AfxRegisterWndClass(0), L"Protocol page regression", WS_OVERLAPPEDWINDOW,
            CRect(0, 0, 980, 720), nullptr, 0) != FALSE, "create parent");
        CPage4 page(&parent);
        Require(page.Create(IDD_Page4, &parent) != FALSE, "create page");
#ifndef _WIN64
        Require(!page.m_mitmSupported && !page.m_decrypt.IsWindowEnabled() && !page.m_monitor.IsWindowEnabled() && !page.m_ca.IsWindowEnabled(),"32-bit host disables MITM and monitoring controls");
        char unsupported[512]={};
        Require(page.m_tls->QueryProtocol("{\"type\":\"mitm_options\",\"skip_upstream_verify\":true}",unsupported,sizeof(unsupported))<0,"32-bit backend rejects persisted options");
        SetEnvironmentVariable(L"PROXYLANE_MITM",L"1");
        Require(!page.m_tls->IsEnabled(),"32-bit host ignores MITM environment setting");
        Require(!page.m_tls->SetEnabled(TRUE,unsupported,sizeof(unsupported)),"32-bit backend refuses enabling MITM");
        SetEnvironmentVariable(L"PROXYLANE_MITM",nullptr);
        page.OnCA();page.OnDecrypt();page.OnMonitor();page.OnTimer(1);
        Require(!GetModuleHandle(L"ProxyLaneMitm32.dll") && !GetModuleHandle(L"ProxyLaneMitm64.dll"),"32-bit host never loads MITM DLL");
        // Remaining view tests use an in-memory fake service, not a 32-bit Rust module.
        page.m_mitmSupported=true;
#endif
        page.m_tls = &fake;
        page.MoveWindow(0, 0, 960, 660); page.ShowWindow(SW_SHOW);
        parent.ShowWindow(SW_SHOWNOACTIVATE);
        page.m_recording = true;
        Pump(page, [&] { return page.m_requests.GetItemCount() == 2; });
        Require(page.m_follow.GetCheck() == BST_CHECKED, "follow latest enabled initially");
        Require(page.m_requests.GetGroupCount() == 0, "process groups");
        Require(page.m_requests.GetItemText(0, 1).Find(L"curl.exe") >= 0, "saved process name");
        Require(page.m_requests.GetItemText(0, 5) == L"ifconfig.test:443 /ip", "domain without mapped IP");
        Require(!page.GetDlgItem(IDC_PROTOCOL_TABS) && !page.GetDlgItem(IDC_EDIT1), "raw log controls removed");
        Require(!page.m_viewTabs.IsWindowEnabled(), "HEX disabled without selection");
        Require(page.m_requests.GetItemText(0, 3) == L"HTTP/1.1" && page.m_requests.GetItemText(1, 3) == L"HTTP/2", "protocol follows PID");
        Require(page.m_requests.GetItemText(0,4)==L"GET" && page.m_requests.GetItemText(0,6)==L"200", "method and status columns");
        Require(page.m_requests.GetColumnWidth(0) == UiTheme::ScaleForWindow(page.m_hWnd,38), "initial column sizing");
        const int customWidths[] = {45,170,70,55,310,88,115,130};
        for (int col=0; col<8; ++col) page.m_requests.SetColumnWidth(col,customWidths[col]);
        auto checkWidths = [&] {
            for (int col=0; col<8; ++col)
                Require(page.m_requests.GetColumnWidth(col)==customWidths[col], "manual column widths preserved");
        };
        page.m_requests.SetItemState(0, LVIS_SELECTED, LVIS_SELECTED);
        Require(page.m_follow.GetCheck() == BST_UNCHECKED, "selection pauses follow latest");
        Pump(page, [&] { return page.m_protocol->haveDetail; });
        checkWidths();
        CString text; page.m_detail.GetWindowText(text);
        Require(text.Find(L"GET /ip HTTP/1.1") >= 0 && text.Find(L"host: ifconfig.test") >= 0, "request headers");
        Require(page.m_viewTabs.IsWindowEnabled(), "headers available with empty request body");
        Require(!page.m_hexView.Bytes().empty() && page.m_hexView.Bytes()[0] == 'G', "HEX contains request headers");
        LRESULT ignored;
        page.m_detailTabs.SetCurSel(1); page.OnDetailTab(nullptr, &ignored);
        page.m_detail.GetWindowText(text);
        Require(text.Find(L"content-encoding: gzip") >= 0 && text.Find(L"203.0.113.10") >= 0, "decoded response body");
        page.m_viewTabs.SetCurSel(1); page.OnView(nullptr, &ignored); page.m_detail.GetWindowText(text);
        Require(page.m_hexView.IsWindowVisible() && !page.m_hexView.Bytes().empty(), "native HEX control");
        Require(page.m_hexView.SendMessage(WM_GETFONT) == (LRESULT)page.m_font.GetSafeHandle(), "HEX uses the configured monospaced font");
        // A slow result for B must not replace A after changing selection back.
        fake.delay = 120;
        page.m_requests.SetItemState(1, LVIS_SELECTED, LVIS_SELECTED);
        Require(page.m_viewTabs.GetCurSel() == 0, "HEX does not affect another request");
        Pump(page, [&] { return page.m_protocol->job && page.m_protocol->job->detail; });
        page.m_requests.SetItemState(0, LVIS_SELECTED, LVIS_SELECTED);
        Pump(page, [&] { return page.m_protocol->haveDetail; });
        Require(page.m_protocol->detail.context.find("Request/stream 1") != std::string::npos, "stale selection result");
        Require(page.m_viewTabs.GetCurSel() == 1, "request remembers its HEX preference");
        page.m_viewTabs.SetCurSel(0); page.OnView(nullptr, &ignored);
        fake.delay = 0;
        // Save the real page's rendering, not a mockup.
        CImage image; image.Create(960, 660, 32);
        HDC dc = image.GetDC(); page.PrintWindow(CDC::FromHandle(dc), 0); image.ReleaseDC();
        Require(SUCCEEDED(image.Save(L"build\\qa\\protocol-page.png")), "save page image");
        fake.evicted = true;
        Pump(page, [&] { return page.m_protocol->detail.state == ProtocolView::Detail::Evicted; }, 6000);
        page.m_detail.GetWindowText(text);
        Require(text.Find(L"203.0.113.10") < 0 && text.Find(L"evicted") < 0, "eviction removes displayed body");
        for (int width : {600, 960, 1200}) {
            page.MoveWindow(0, 0, width, 660);
            CRect list, detail; page.m_requests.GetWindowRect(list); page.m_detail.GetWindowRect(detail);
            Require(list.bottom < detail.top && detail.Height() > 100, "layout bounds");
            checkWidths();
        }
        // Filtering keeps the selection tied to record identity, not visible index.
        page.m_filter.SetWindowText(L"5678");
        Require(page.m_requests.GetItemCount() == 1 && page.m_requests.GetItemText(0,2) == L"5678", "exact PID filter");
        page.m_filter.SetWindowText(L"CURL"); Require(page.m_requests.GetItemCount() == 2, "case insensitive process filter");
        page.m_filter.SetWindowText(L"absent"); Require(page.m_requests.GetItemCount() == 0, "filter empty result");
        page.m_filter.SetWindowText(L"");
        CRect before; page.m_requests.GetWindowRect(before);
        CPoint split = page.m_splitRect.CenterPoint(); page.OnLButtonDown(0,split);
        page.OnMouseMove(MK_LBUTTON,CPoint(split.x,split.y+70)); page.OnLButtonUp(0,split);
        CRect after; page.m_requests.GetWindowRect(after); Require(after.Height() > before.Height(), "draggable splitter");
        page.m_follow.SetCheck(BST_CHECKED); page.OnFollowLatest();
        Require(page.m_protocol->selected.empty() && page.m_detail.GetWindowTextLength()==0, "resume clears inspected session");
        fake.count = 700;
        Pump(page, [&] { return page.m_protocol->next == 700; }, 20000);
        Require(page.m_requests.GetItemCount() == 512 && page.m_protocol->history.discarded == 188, "bounded visible history");
        Require(page.CanFollowLatest() && page.m_requests.GetTopIndex()>450, "follow stays at latest through history eviction");
        page.m_requests.SendMessage(WM_VSCROLL, SB_PAGEUP);
        page.TickProtocolView();
        Require(page.m_follow.GetCheck()==BST_UNCHECKED, "scrolling up pauses follow");
        const auto anchor = page.m_protocol->shownKeys[page.m_requests.GetTopIndex()];
        fake.count = 701;
        Pump(page, [&] { return page.m_protocol->next==701; });
        Require(page.m_protocol->shownKeys[page.m_requests.GetTopIndex()]==anchor, "new records preserve scrolled anchor");
        page.m_requests.SetItemState(page.m_requests.GetTopIndex()+1, LVIS_SELECTED, LVIS_SELECTED);
        const auto inspected = page.m_protocol->selected;
        fake.count = 702;
        Pump(page, [&] { return page.m_protocol->next==702; });
        Require(page.m_protocol->selected==inspected && page.m_follow.GetCheck()==BST_UNCHECKED, "new records preserve inspected session");
        page.m_follow.SetCheck(BST_CHECKED); page.OnFollowLatest();
        Require(page.CanFollowLatest() && page.m_requests.GetNextItem(-1,LVNI_SELECTED)==-1, "explicit resume jumps to latest");
        fake.delay = 120;
        page.m_requests.SetItemState(1, LVIS_SELECTED, LVIS_SELECTED);
        Pump(page, [&] { return page.m_protocol->job && page.m_protocol->job->detail; });
        page.OnClear(); // Clear while a detail query is in flight.
        Pump(page, [&] { return !page.m_protocol->baseline && !page.m_protocol->job; });
        Require(page.m_requests.GetItemCount() == 0 && page.m_detail.GetWindowTextLength() == 0, "clear suppresses backend history");
        Require(!page.m_viewTabs.IsWindowEnabled() && page.m_viewTabs.GetCurSel() == 0, "clear resets HEX");
        Require(page.m_follow.GetCheck()==BST_CHECKED, "clear restores follow latest");
        // Progress updates replace the same connection row and keep its selection/HEX preference.
        ProtocolView::Row flow; flow.run = "test"; flow.key = "test:stream:99"; flow.sequence = 701;
        flow.stream = true; flow.protocol = "TCP"; flow.pid = 1234; flow.cacheId = 99; flow.bytes = 512;
        flow.record = {{"type", "stream"}, {"connection", {{"id", "99"},{"upstream_verification_skipped",true},{"decrypted",false}}},
            {"stream", {{"sent_bytes", 10}, {"received_bytes", 20}, {"finished", false}}}};
        page.m_protocol->history.Add(flow); page.RebuildRequests();
        page.m_requests.SetItemState(0, LVIS_SELECTED, LVIS_SELECTED);
        fake.evicted = false; fake.delay = 0;
        Pump(page, [&] { return page.m_protocol->haveDetail; });
        page.m_viewTabs.SetCurSel(1); page.OnView(nullptr, &ignored);
        page.m_detailStatus.GetWindowText(text);
        Require(text.Find(L"certificate verification skipped")==-1,"plain TCP must not show target TLS verification warning");
        flow.sequence = 702; flow.responseBytes = 100; page.m_protocol->history.Add(flow); page.RebuildRequests();
        Require(page.m_requests.GetItemCount() == 1 && page.m_requests.GetItemText(0,7) == L"0 / 100", "stream updates same row");
        Require(page.m_protocol->selected == flow.key && page.m_protocol->history.rows.front().hex, "stream selection/HEX preserved");
        page.m_detail.GetWindowText(text);
        Require(page.m_hexView.Bytes().size() > 2 && page.m_hexView.Bytes()[0] == 0x7b && text.Find(L"Connection") < 0, "stream HEX detail");
        page.m_hexView.SetBytes(std::vector<unsigned char>(65536,0xab));
        CRect hexRect;page.m_hexView.GetWindowRect(hexRect);page.ScreenToClient(hexRect);
        page.m_hexView.MoveWindow(hexRect.left,hexRect.top,300,220);
        page.m_hexView.SetCapture();
        page.m_hexView.StopDrag();
        Require(::GetCapture()==page.m_hexView.m_hWnd,"selection cleanup preserves native scrollbar capture");
        ::ReleaseCapture();
        if (nativeScroll) {
            DragThumb(page.m_hexView,SB_VERT); DragThumb(page.m_hexView,SB_HORZ);
        }
        page.m_hexView.SendMessage(WM_HSCROLL,SB_TOP);
        page.m_hexView.MoveWindow(hexRect);
        page.m_hexView.SendMessage(WM_KEYDOWN,VK_END);
        Require(page.m_hexView.GetScrollPos(SB_VERT) > 0, "native byte view keyboard scroll");
        page.m_hexView.SendMessage(WM_KEYDOWN,VK_HOME);
        Require(page.m_hexView.GetScrollPos(SB_VERT) == 0, "native byte view home");
        // Dragging within one byte produces no paint; crossing a byte updates
        // only affected visible rows. Repeated buffered paints release GDI objects.
        {
            CClientDC dc(&page.m_hexView); CFont* old=dc.SelectObject(page.m_hexView.GetFont());
            TEXTMETRIC tm;dc.GetTextMetrics(&tm);dc.SelectObject(old);
            const int cw=tm.tmAveCharWidth,ch=tm.tmHeight+2;
            page.m_hexView.UpdateWindow();
            page.m_hexView.SendMessage(WM_LBUTTONDOWN,MK_LBUTTON,MAKELPARAM(10*cw+1,1));
            page.m_hexView.UpdateWindow();
            page.m_hexView.SendMessage(WM_MOUSEMOVE,MK_LBUTTON,MAKELPARAM(11*cw,1));
            Require(!page.m_hexView.GetUpdateRect(nullptr,FALSE),"same-byte drag must not repaint");
            page.m_hexView.SendMessage(WM_MOUSEMOVE,MK_LBUTTON,MAKELPARAM(13*cw+1,1));
            CRect dirty;Require(page.m_hexView.GetUpdateRect(dirty,FALSE) && dirty.top==0 && dirty.bottom<=ch,"single-row selection damage");
            page.m_hexView.UpdateWindow();
            const DWORD objects=GetGuiResources(GetCurrentProcess(),GR_GDIOBJECTS);
            for (int i=0;i<250;++i) {
                page.m_hexView.SendMessage(WM_MOUSEMOVE,MK_LBUTTON,MAKELPARAM((13+i%10*3)*cw+1,(i%3)*ch+1));
                page.m_hexView.UpdateWindow();
            }
            Require(GetGuiResources(GetCurrentProcess(),GR_GDIOBJECTS)<=objects+2,"buffered selection painting leaks GDI objects");
            page.m_hexView.SendMessage(WM_LBUTTONUP,0,0);
            // Holding a captured drag at/beyond the edge keeps scrolling even
            // without more mouse moves, while keeping the selection anchor.
            auto& hex = page.m_hexView;
            CRect client; hex.GetClientRect(client);
            hex.SendMessage(WM_LBUTTONDOWN,MK_LBUTTON,MAKELPARAM(10*cw+1,ch+1));
            const size_t anchor = hex.m_first;
            hex.SendMessage(WM_MOUSEMOVE,MK_LBUTTON,MAKELPARAM(13*cw+1,client.bottom+20));
            const size_t before = hex.m_last;
            for (int i=0;i<10;++i) hex.SendMessage(WM_TIMER,CByteHexView::DragTimer);
            Require(hex.GetScrollPos(SB_VERT)>0 && hex.m_last>before && hex.m_first==anchor,"drag scroll down extends selection with fixed anchor");
            const int down = hex.GetScrollPos(SB_VERT);
            hex.SendMessage(WM_MOUSEMOVE,MK_LBUTTON,MAKELPARAM(13*cw+1,-20));
            for (int i=0;i<3;++i) hex.SendMessage(WM_TIMER,CByteHexView::DragTimer);
            Require(hex.GetScrollPos(SB_VERT)<down && hex.m_first==anchor,"drag scroll up");
            hex.SendMessage(WM_MOUSEMOVE,MK_LBUTTON,MAKELPARAM(13*cw+1,client.Height()/2));
            const int middle = hex.GetScrollPos(SB_VERT);
            hex.UpdateWindow(); hex.SendMessage(WM_TIMER,CByteHexView::DragTimer);
            Require(hex.GetScrollPos(SB_VERT)==middle && !hex.GetUpdateRect(nullptr,FALSE),"inside drag does not scroll or repaint");
            hex.SendMessage(WM_MOUSEMOVE,MK_LBUTTON,MAKELPARAM(13*cw+1,client.bottom+20));
            hex.SendMessage(WM_LBUTTONUP,0,MAKELPARAM(13*cw+1,client.bottom+20));
            hex.SendMessage(WM_TIMER,CByteHexView::DragTimer);
            Require(!hex.m_drag && hex.GetScrollPos(SB_VERT)==middle,"release stops drag scrolling");
            hex.SendMessage(WM_LBUTTONDOWN,MK_LBUTTON,MAKELPARAM(13*cw+1,client.bottom+20));
            parent.SetCapture(); hex.SendMessage(WM_TIMER,CByteHexView::DragTimer);
            Require(!hex.m_drag && hex.GetScrollPos(SB_VERT)==middle,"capture loss stops drag scrolling");
            ReleaseCapture();
            hex.SendMessage(WM_VSCROLL,SB_BOTTOM);
            hex.SendMessage(WM_LBUTTONDOWN,MK_LBUTTON,MAKELPARAM(13*cw+1,client.bottom+20));
            hex.SendMessage(WM_TIMER,CByteHexView::DragTimer);
            Require(hex.m_last<hex.Bytes().size(),"drag at end remains within bytes");
            hex.SetBytes(std::vector<unsigned char>{1,2,3});
            Require(!hex.m_drag,"replacing payload stops drag scrolling");
        }
        // Packet rows preserve wire boundaries, independently of byte alignment.
        {
            auto& hex=page.m_hexView;
            std::vector<std::vector<unsigned char>> packets={{0,1,2},std::vector<unsigned char>(18,0xab),{}, {0xff}};
            hex.SetPackets(packets,false);
            Require(hex.Rows()==5 && hex.Bytes().size()==22,"packet padding and empty rows add no bytes");
            Require(hex.m_lines[1].offset==0 && hex.m_lines[2].offset==16 && hex.m_lines[4].offset==0,"offset restarts at each packet");
            Require(hex.Hit(CPoint(10*hex.m_cw+1,hex.m_ch+1))==3 && hex.Hit(CPoint(60*hex.m_cw+1,2*hex.m_ch+1))==19,"hex and text hit mapping across unaligned packets");
            hex.SendMessage(WM_LBUTTONDOWN,MK_LBUTTON,MAKELPARAM(10*hex.m_cw+1,3*hex.m_ch+1));
            Require(hex.SelectedPacket()==2 && !hex.m_hasSelection && hex.SelectionText().IsEmpty(),"empty packet is clickable without synthetic bytes");
            hex.SendMessage(WM_KEYDOWN,VK_RIGHT);
            Require(hex.SelectedPacket()==3 && hex.SelectedOffset()==0 && hex.m_last==21,"keyboard exits empty packet at next payload start");
            hex.m_first=1;hex.m_last=4;hex.m_hasSelection=true;
            Require(hex.SelectionText()==L"01 02 AB AB","cross-packet copy excludes row padding and labels");
            std::vector<std::vector<unsigned char>> many(120,std::vector<unsigned char>(17,0x42));
            hex.SetPackets(many,false);hex.m_first=35;hex.m_last=49;hex.m_selectedRow=hex.RowOfByte(49);hex.m_top=30;hex.UpdateScroll();
            const int top=hex.m_top,left=hex.m_left;
            many.push_back({3,4,5});hex.SetPackets(many,true);
            Require(hex.m_top==top && hex.m_left==left && hex.m_first==35 && hex.m_last==49,"packet append retains selection and scroll");
            hex.SetPackets(many,false);
            Require(hex.m_top==0 && hex.m_first==0 && hex.m_last==0,"different session resets view even with identical payload");
        }
        // QUIC uses the same cumulative UDP HexView while Raw retains its summary.
        Pump(page,[&]{return !page.m_protocol->job;});
        fake.packetPayload=true; ++flow.sequence; flow.udp=true; flow.quic=true; flow.protocol="QUIC v1";
        flow.record["quic"]={{"sni","example.test"}};
        flow.record["stream"]["datagrams"]=ProtocolView::Json::array({
            ProtocolView::Json::array({ProtocolView::Json::array({0,3}),ProtocolView::Json::array({3,3})}),
            ProtocolView::Json::array({ProtocolView::Json::array({0,3})})});
        page.m_protocol->history.Add(flow); page.RebuildRequests();
        page.m_protocol->haveDetail=false; page.m_protocol->displayed.clear();
        page.m_detailTabs.SetCurSel(0); page.m_viewTabs.SetCurSel(0); page.OnView(nullptr,&ignored);
        Pump(page,[&]{return page.m_protocol->haveDetail;});
        Require(!page.GetDlgItem(1106) && !page.GetDlgItem(1110),"packet navigation controls removed");
        page.m_viewTabs.SetCurSel(1);page.OnView(nullptr,&ignored);
        Require(page.m_hexView.Bytes()==std::vector<unsigned char>({0,1,2,3,4,5}) && page.m_hexView.Rows()==2,"all UDP packets appear together");
        page.m_hexView.SendMessage(WM_LBUTTONDOWN,MK_LBUTTON,MAKELPARAM(10*page.m_hexView.m_cw+1,page.m_hexView.m_ch+1));
        page.m_hexView.SendMessage(WM_LBUTTONUP,0,MAKELPARAM(10*page.m_hexView.m_cw+1,page.m_hexView.m_ch+1));
        page.ShowProtocolDetail();page.m_detailStatus.GetWindowText(text);
        Require(text.Find(L"#2")>=0 && text.Find(L"Offset 0x0")>=0,"Hex click reports packet and local offset");
        page.m_viewTabs.SetCurSel(0);page.OnView(nullptr,&ignored);page.m_detail.GetWindowText(text);
        Require(text.Find(L"Protocol: QUIC v1")>=0,"Raw summary remains available");
        // Plain UDP accumulates all packets, independent of the Hex selection.
        ++flow.sequence;flow.quic=false;flow.protocol="UDP";
        page.m_protocol->history.Add(flow);
        page.m_protocol->detail=ProtocolView::ReadDetail(QueryFor(&fake),flow);
        page.ShowProtocolDetail();page.m_detail.GetWindowText(text);
        Require(text==L"......","UDP Raw has only payload characters");
        auto& rawSide=page.m_protocol->detail.request;
        auto packetBytes=[](const std::string& text){return std::vector<unsigned char>(text.begin(),text.end());};
        rawSide.packets={packetBytes("\xe4\xb8\xad\r\n"),packetBytes("\xf0\x9f\x99\x82"),{},packetBytes("\xffX")};
        rawSide.datagrams={{0,5},{5,4},{9,0},{9,2},{11,10}};
        page.ShowProtocolDetail();
        auto spans=page.m_detail.Ranges();
        Require(spans.size()==4 && spans[0].first==0 && spans[0].last==2 && spans[1].first==2 && spans[1].last==4 && spans[2].first==4 && spans[2].last==4 && spans[3].last==6,"Unicode, CRLF, empty and invalid UTF-8 character mapping");
        auto colorAt=[&](int pos){
            page.m_protocol->rebuilding=true;page.m_detail.SetSel(pos,pos+1,TRUE);
            CHARFORMAT2 format={};format.cbSize=sizeof(format);
            page.m_detail.SendMessage(EM_GETCHARFORMAT,SCF_SELECTION,(LPARAM)&format);
            page.m_protocol->rebuilding=false;return format.crBackColor;
        };
        Require(colorAt(0)==UiTheme::PageBackground() && colorAt(2)==RGB(218,232,248) && colorAt(4)==UiTheme::PageBackground(),"alternating packet background colors");
        page.m_detail.SetSel(2,2,TRUE);
        int first,last;page.m_detail.GetSel(first,last);
        CString notice;page.m_detailStatus.GetWindowText(notice);
        Require(first==2 && last==2 && notice.Find(L"#2")>=0 && page.m_viewTabs.GetCurSel()==0,"Raw click identifies packet without changing view");
        page.m_detail.SetSel(4,5,TRUE);page.m_detailStatus.GetWindowText(notice);
        Require(notice.Find(L"#4")>=0,"Raw selection identifies containing datagram after empty packet");
        page.m_viewTabs.SetCurSel(1);page.OnView(nullptr,&ignored);
        Require(page.m_hexView.SelectedPacket()==3 && page.m_hexView.SelectedOffset()==0,"Raw Unicode packet selection transfers to Hex byte position");
        page.m_hexView.SendMessage(WM_KEYDOWN,VK_UP); // Empty third datagram.
        page.m_viewTabs.SetCurSel(0);page.OnView(nullptr,&ignored);
        page.m_detail.GetSel(first,last);page.m_detailStatus.GetWindowText(notice);
        Require(first==4 && last==4 && notice.Find(L"#3")>=0,"empty Hex packet transfers to Raw insertion point");
        page.m_viewTabs.SetCurSel(1);page.OnView(nullptr,&ignored);
        Require(page.m_hexView.SelectedPacket()==2 && !page.m_hexView.m_hasSelection,"empty packet survives a round trip");
        page.m_viewTabs.SetCurSel(0);page.OnView(nullptr,&ignored);
        std::string block;for(int i=0;i<50;++i) block+="packet text line\r\n";
        rawSide.packets.assign(8,packetBytes(block));rawSide.datagrams.clear();
        for(size_t i=0;i<8;++i) rawSide.datagrams.push_back({i*block.size(),block.size()});
        page.ShowProtocolDetail();
        const int fifth=page.m_detail.Ranges()[4].first;
        page.m_detail.SetSel(fifth+3,fifth+3);
        page.m_viewTabs.SetCurSel(1);page.OnView(nullptr,&ignored);
        Require(page.m_hexView.SelectedPacket()==4 && page.m_hexView.SelectedOffset()==0 && page.m_hexView.m_top>0,"view switch reveals fifth packet beyond first screen");
        page.m_hexView.m_first+=2;page.m_hexView.m_last+=4;page.m_hexView.m_top+=2;page.m_hexView.UpdateScroll();
        const auto hexFirst=page.m_hexView.m_first,hexLast=page.m_hexView.m_last;const auto hexTop=page.m_hexView.m_top;
        rawSide.packets.push_back(packetBytes("later"));page.ShowProtocolDetail();
        Require(page.m_hexView.m_first==hexFirst && page.m_hexView.m_last==hexLast && page.m_hexView.m_top==hexTop,"refresh after synchronization does not relocate or replace selection");
        page.m_viewTabs.SetCurSel(0);page.OnView(nullptr,&ignored);page.m_detail.GetSel(first,last);
        Require(first==fifth && last==fifth && page.m_detail.GetFirstVisibleLine()>0,"Hex to Raw reveals same packet start");
        GUITHREADINFO caretInfo={sizeof(caretInfo)};
        Require(GetGUIThreadInfo(GetCurrentThreadId(),&caretInfo) && caretInfo.hwndFocus==page.m_detail.m_hWnd && caretInfo.hwndCaret==page.m_detail.m_hWnd,"Raw synchronization transfers actual focus and creates caret");
        CRect caretClient;page.m_detail.GetClientRect(caretClient);
        Require(caretInfo.rcCaret.top>=0 && caretInfo.rcCaret.bottom<=caretClient.bottom && caretInfo.rcCaret.left>=0 && caretInfo.rcCaret.right<=caretClient.right,"Raw caret is inside the viewport");
        rawSide.packets.assign(8,packetBytes(std::string(3000,'x')));page.ShowProtocolDetail();
        page.m_viewTabs.SetCurSel(1);page.OnView(nullptr,&ignored);
        page.m_viewTabs.SetCurSel(0);page.OnView(nullptr,&ignored);page.m_detail.GetSel(first,last);
        POINT location={};page.m_detail.SendMessage(EM_POSFROMCHAR,(WPARAM)&location,first);
        CRect rawClient;page.m_detail.GetClientRect(rawClient);
        Require(first==12000 && location.x>=0 && location.x<rawClient.right,"single-line packet synchronization scrolls horizontally into view");
        page.m_viewTabs.SetCurSel(1);page.OnView(nullptr,&ignored);
        page.m_viewTabs.SetCurSel(0);page.OnView(nullptr,&ignored);page.m_detail.GetSel(first,last);
        page.m_detail.SendMessage(EM_POSFROMCHAR,(WPARAM)&location,first);
        Require(first==12000 && location.x>=0 && location.x<rawClient.right,"long horizontal position survives repeated view switching");
        rawSide.packets.resize(2);page.ShowProtocolDetail();
        page.m_viewTabs.SetCurSel(1);page.OnView(nullptr,&ignored);page.m_detailStatus.GetWindowText(notice);
        Require(notice.Find(L"outside the preview")>=0,"unavailable synchronized packet is reported instead of silently selecting another");
        page.m_viewTabs.SetCurSel(0);page.OnView(nullptr,&ignored);
        std::string lines;for(int i=0;i<120;++i) lines+="packet line\r\n";
        rawSide.packets={packetBytes(lines)};rawSide.datagrams={{0,lines.size()}};
        page.ShowProtocolDetail();page.m_detail.LineScroll(-page.m_detail.GetFirstVisibleLine());page.m_detail.SetSel(100,120,TRUE);page.m_detail.LineScroll(25);
        const int top=page.m_detail.GetFirstVisibleLine();
        rawSide.packets.push_back(packetBytes("next packet\r\n"));page.ShowProtocolDetail();
        page.m_detail.GetSel(first,last);
        Require(first==100 && last==120 && page.m_detail.GetFirstVisibleLine()==top,"Raw refresh preserves selection and scroll");
        page.m_detail.SetCapture();rawSide.packets.push_back(packetBytes("deferred packet\r\n"));page.ShowProtocolDetail();
        page.m_detail.GetWindowText(text);
        Require(text.Find(L"deferred packet")==-1 && page.m_protocol->pendingDisplay,"Raw drag defers replacement");
        ReleaseCapture();page.TickProtocolView();page.m_detail.GetWindowText(text);
        Require(text.Find(L"deferred packet")>=0 && !page.m_protocol->pendingDisplay,"Raw refresh resumes after drag");
        page.m_viewTabs.SetCurSel(1);page.OnView(nullptr,&ignored);
        auto priorHex=page.m_hexView.Bytes();page.m_hexView.SetCapture();
        rawSide.packets.push_back(packetBytes("hex deferred"));page.ShowProtocolDetail();
        Require(page.m_hexView.Bytes()==priorHex && page.m_protocol->pendingDisplay,"Hex drag defers refresh");
        ReleaseCapture();page.TickProtocolView();
        Require(page.m_hexView.Bytes().size()>priorHex.size(),"Hex refresh resumes after capture release");
        Require((page.m_detail.GetStyle()&WS_VISIBLE)==0 && page.m_hexView.IsWindowVisible(),"background Raw refresh must not uncover Raw over HexView");
        CRect afterRefresh;page.m_hexView.GetWindowRect(afterRefresh);page.ScreenToClient(afterRefresh);
        page.m_hexView.MoveWindow(afterRefresh.left,afterRefresh.top,300,220);
        if(nativeScroll) {
            DragThumb(page.m_hexView,SB_VERT);DragThumb(page.m_hexView,SB_HORZ);
        }
        for(int refresh=0;refresh<3;++refresh) {
            rawSide.packets.push_back(packetBytes("more UDP payload"));page.ShowProtocolDetail();
            Require((page.m_detail.GetStyle()&WS_VISIBLE)==0 && page.m_hexView.IsWindowVisible(),"repeated UDP updates keep Raw hidden");
        }
        page.m_hexView.MoveWindow(afterRefresh);

        page.m_viewTabs.SetCurSel(0);page.OnView(nullptr,&ignored);
        ++flow.sequence;flow.quic=true;flow.protocol="QUIC v1";
        page.m_protocol->history.Add(flow);
        fake.packetPayload=false;
        ProtocolView::Row dns;dns.key="test:dns:100:1";dns.run="test";dns.dns=true;dns.udp=true;dns.protocol="DNS/UDP";
        dns.cacheId=100;dns.requestBytes=19;dns.bytes=512;dns.sequence=703;
        dns.record={{"type","dns"},{"exchange",{{"id",1},{"cache",{{"id",100}}}}}};
        page.m_protocol->history.Add(dns);page.RebuildRequests();page.m_requests.SetItemState(1,LVIS_SELECTED,LVIS_SELECTED);
        page.m_detailTabs.SetCurSel(0);page.OnDetailTab(nullptr,&ignored);
        Pump(page,[&]{return page.m_protocol->haveDetail;});page.m_detail.GetWindowText(text);
        Require(text.Find(L"[Question]")>=0 && !page.GetDlgItem(1106),"DNS Raw fields without packet selector");
        page.m_viewTabs.SetCurSel(1);page.OnView(nullptr,&ignored);
        Require(page.m_hexView.Bytes().size()==19 && page.m_hexView.Bytes()[0]==0,"DNS HexView original wire bytes");
        page.m_protocolFilter.SetCurSel(5);page.OnFilter();Require(page.m_requests.GetItemCount()==1,"DNS filter");
        page.m_protocolFilter.SetCurSel(6);page.OnFilter();Require(page.m_requests.GetItemCount()==1 && page.m_requests.GetItemText(0,3)==L"QUIC v1","QUIC filter excludes DNS");
        Pump(page,[&]{return !page.m_protocol->job;});
        Require(!page.m_protocol->job, "worker completed before harness destruction");
        page.ShowWindow(SW_HIDE); page.ShowWindow(SW_SHOW);
        checkWidths(); // Also covers selection, refresh, filtering, splitter drag and clear above.
        page.KillTimer(1); page.ShowWindow(SW_HIDE);
        {
            CPage4 legacy(&parent); legacy.m_mitmSupported=false;
            Require(legacy.Create(IDD_Page4,&parent)!=FALSE,"create legacy page");
            legacy.m_tls=&fake; legacy.ShowWindow(SW_SHOW);
            Require(!legacy.m_monitor.IsWindowEnabled() && !legacy.m_decrypt.IsWindowEnabled() && !legacy.m_ca.IsWindowEnabled(),"legacy entry points disabled");
            const unsigned queries=fake.queries;
            legacy.OnCA(); legacy.m_decrypt.SetCheck(BST_CHECKED); legacy.OnDecrypt();
            legacy.m_monitor.SetCheck(BST_CHECKED); legacy.OnMonitor(); legacy.UpdateMonitorStatus();
            for (int i=0;i<5;++i) legacy.OnTimer(1);
            Require(fake.queries==queries && !legacy.m_protocol->job && !legacy.m_job,"legacy actions and background timer never query module");
            Require(legacy.m_monitor.GetCheck()==BST_UNCHECKED && legacy.m_decrypt.GetCheck()==BST_UNCHECKED,"legacy forced commands remain disabled");
            legacy.m_detailStatus.GetWindowText(text);
            Require(text==Localization::Get(ProxyIsLegacyWindows() ? L"mitm.legacy_unavailable" : L"mitm.x64_required"),"unsupported host explanation");
            legacy.KillTimer(1); legacy.DestroyWindow();
        }
        {
            // Leave a failing CA MessageBox open across several dialog timer
            // ticks. The completed job must be consumed before its modal loop.
            CMitmCaDialog ca(&parent,&fake);
            Require(ca.Create(IDD_MITM_CA,&parent)!=FALSE,"create failing CA dialog");
            ca.ShowWindow(SW_SHOW);
            std::atomic<bool> stop{false}; std::atomic<unsigned> prompts{0};
            const DWORD uiThread=GetCurrentThreadId();
            std::thread dismiss([&] {
                struct State { std::vector<HWND> seen; DWORD first=0; } state;
                while (!stop.load()) {
                    EnumThreadWindows(uiThread,[](HWND h,LPARAM value)->BOOL {
                        if (!::IsWindowVisible(h)) return TRUE;
                        wchar_t body[256]={};DWORD_PTR result=0;
                        HWND label=::GetDlgItem(h,0xffff);
                        if(!label || !::SendMessageTimeout(label,WM_GETTEXT,_countof(body),(LPARAM)body,SMTO_ABORTIFHUNG|SMTO_BLOCK,100,&result)) return TRUE;
                        if (wcscmp(body,L"Test CA load failure")!=0) return TRUE;
                        auto& state=*reinterpret_cast<State*>(value);
                        if (std::find(state.seen.begin(),state.seen.end(),h)==state.seen.end()) state.seen.push_back(h);
                        if (!state.first) state.first=GetTickCount();
                        if (GetTickCount()-state.first>500) ::PostMessage(h,WM_CLOSE,0,0);
                        return TRUE;
                    },reinterpret_cast<LPARAM>(&state));
                    prompts.store((unsigned)state.seen.size()); Sleep(10);
                }
            });
            const DWORD start=GetTickCount();
            while (GetTickCount()-start<1000) {
                MSG msg;while(PeekMessage(&msg,nullptr,0,0,PM_REMOVE)){TranslateMessage(&msg);DispatchMessage(&msg);}
                Sleep(10);
            }
            stop=true; dismiss.join();
            Require(prompts==1,"CA failure reported once across nested timer messages");
            ca.KillTimer(1);ca.DestroyWindow();
        }
        {
            const CString path=Localization::SettingsPath();
            const auto original=MitmSettings::Load();
            wchar_t originalSkip[32]={};GetPrivateProfileString(L"options",L"MitmSkipUpstreamVerify",L"",originalSkip,32,path);
            const bool hadIni=GetFileAttributes(path)!=INVALID_FILE_ATTRIBUTES;
            fake.caOk=true;
            CMitmCaDialog options(&parent,&fake);
            Require(options.Create(IDD_MITM_CA,&parent)!=FALSE,"create options dialog");options.ShowWindow(SW_SHOW);
            for(int n=0;n<40;++n){Sleep(10);options.OnTimer(1);}
            Require(!options.GetDlgItem(1314)->IsWindowVisible(),"advanced settings initially collapsed");
            CRect collapsed;options.GetWindowRect(collapsed);
            options.SendMessage(WM_COMMAND,MAKEWPARAM(1300,BN_CLICKED));
            CRect expanded;options.GetWindowRect(expanded);
            Require(expanded.Height()>collapsed.Height() && options.GetDlgItem(1318)->IsWindowVisible(),"advanced settings expand");
            const MitmSettings::Values changed={{48,768,1024,128,8,64,16,512,30}};
            for(int i=0;i<9;++i) options.SetDlgItemInt(1310+i,changed[i]);
            options.SendMessage(WM_COMMAND,MAKEWPARAM(1301,BN_CLICKED));
            Require(MitmSettings::Load()==changed,"all nine settings persisted to ini");
            Require(fake.settings==MitmSettings::Json(changed),"all nine settings applied to service");
            options.CheckDlgButton(IDC_MITM_SKIP_VERIFY,BST_CHECKED);
            options.SendMessage(WM_COMMAND,MAKEWPARAM(IDC_MITM_SKIP_VERIFY,BN_CLICKED));
            const unsigned beforeReset=fake.queries.load();
            options.SendMessage(WM_COMMAND,MAKEWPARAM(1302,BN_CLICKED));
            const auto defaults=MitmSettings::Defaults();
            for(int i=0;i<9;++i) Require(options.GetDlgItemInt(1310+i)==defaults[i],"restore drafts all nine defaults");
            Require(options.IsDlgButtonChecked(IDC_MITM_SKIP_VERIFY)==BST_UNCHECKED,"restore drafts strict verification");
            Require(fake.queries==beforeReset && fake.skipVerify && fake.settings==MitmSettings::Json(changed),"restore makes no service call");
            Require(MitmSettings::Load()==changed && GetPrivateProfileInt(L"options",L"MitmSkipUpstreamVerify",0,path)==1,"restore makes no ini changes");
            page.ApplyMonitorSettings();
            Require(page.m_protocol->history.rowLimit==1024 && page.m_protocol->history.metadataLimit==16*1024*1024 && page.m_protocol->previewLimit==128*1024,"display limits applied immediately");
            options.KillTimer(1);options.DestroyWindow();
            CMitmCaDialog reopened(&parent,&fake);Require(reopened.Create(IDD_MITM_CA,&parent),"reopen saved options");
            for(int i=0;i<9;++i) Require(reopened.GetDlgItemInt(1310+i)==changed[i],"restore saved option values");
            Require(reopened.IsDlgButtonChecked(IDC_MITM_SKIP_VERIFY)==BST_CHECKED,"discard draft verification change on close");
            reopened.SetDlgItemInt(1310,99);reopened.KillTimer(1);reopened.DestroyWindow();
            Require(MitmSettings::Load()==changed,"closing without save preserves settings");
            CMitmCaDialog reset(&parent,&fake);Require(reset.Create(IDD_MITM_CA,&parent),"open options for saved reset");
            reset.SendMessage(WM_COMMAND,MAKEWPARAM(1302,BN_CLICKED));
            reset.SendMessage(WM_COMMAND,MAKEWPARAM(1301,BN_CLICKED));
            Require(MitmSettings::Load()==defaults && fake.settings==MitmSettings::Json(defaults),"save applies and persists defaults");
            Require(!fake.skipVerify && GetPrivateProfileInt(L"options",L"MitmSkipUpstreamVerify",1,path)==0,"save applies and persists strict verification");
            reset.KillTimer(1);reset.DestroyWindow();
            Require(MitmSettings::Save(original),"restore harness ini values");
            WritePrivateProfileString(L"options",L"MitmSkipUpstreamVerify",originalSkip[0] ? originalSkip : nullptr,path);
            if(!hadIni) Require(DeleteFile(path)!=FALSE,"remove owned harness ini");
            page.ApplyMonitorSettings();fake.caOk=false;
        }
        page.DestroyWindow();parent.DestroyWindow();
        std::cout << "PASS actual page controls: saved process names, clean address, no raw log, per-request HEX, selection races, headers, decoded body, eviction, resize, bounds, clear\n";
    }
};
CWinApp testApplication;
int main(int argc, char** argv) {
    try {
        Require(AfxWinInit(GetModuleHandle(nullptr), nullptr, GetCommandLine(), 0) != FALSE, "MFC init");
        INITCOMMONCONTROLSEX controls = {sizeof(controls), ICC_WIN95_CLASSES}; InitCommonControlsEx(&controls);
        Require(Localization::Initialize() != FALSE, "locale init");
        // Opt in only on an idle desktop: this check moves the real cursor.
        const bool nativeScroll=argc>1 && std::string(argv[1])=="--native-scroll";
        ProtocolPageHarness::Run(nativeScroll); return 0;
    } catch (const std::exception& e) { std::cerr << "FAIL " << e.what() << "\n"; return 1; }
}
