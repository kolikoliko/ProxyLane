"""Regression for monitor activation/zero-size layout messages in an owned GUI.

Copies release files and a sample profile to build/qa. No proxy is started and
no CA trust is changed. Requires an unlocked Windows desktop and Python/Pillow.
"""
import argparse
import ctypes as c
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import time
import uuid

u, k, g = c.windll.user32, c.windll.kernel32, c.windll.gdi32
CALLBACK = c.WINFUNCTYPE(w.BOOL, w.HWND, w.LPARAM)
u.EnumWindows.argtypes = [CALLBACK, w.LPARAM]
u.EnumChildWindows.argtypes = [w.HWND, CALLBACK, w.LPARAM]
u.GetWindowThreadProcessId.argtypes = [w.HWND, c.POINTER(w.DWORD)]
u.GetDlgItem.argtypes = [w.HWND, c.c_int]; u.GetDlgItem.restype = w.HWND
u.GetClientRect.argtypes = [w.HWND, c.POINTER(w.RECT)]
u.GetWindowRect.argtypes = [w.HWND, c.POINTER(w.RECT)]
u.MapWindowPoints.argtypes = [w.HWND, w.HWND, c.c_void_p, w.UINT]
u.IsWindowVisible.argtypes = [w.HWND]
u.IsWindow.argtypes = [w.HWND]
u.IsWindowEnabled.argtypes = [w.HWND]
u.GetWindowTextW.argtypes = [w.HWND, w.LPWSTR, c.c_int]
u.SendMessageTimeoutW.argtypes = [w.HWND, w.UINT, w.WPARAM, w.LPARAM, w.UINT, w.UINT, c.POINTER(c.c_size_t)]
u.PostMessageW.argtypes = [w.HWND, w.UINT, w.WPARAM, w.LPARAM]
u.SetWindowPos.argtypes = [w.HWND, w.HWND, c.c_int, c.c_int, c.c_int, c.c_int, w.UINT]
u.GetDpiForWindow.argtypes = [w.HWND]
u.GetDC.argtypes = [w.HWND]; u.GetDC.restype = w.HDC
u.ReleaseDC.argtypes = [w.HWND, w.HDC]
u.PrintWindow.argtypes = [w.HWND, w.HDC, w.UINT]
g.CreateCompatibleDC.argtypes = [w.HDC]; g.CreateCompatibleDC.restype = w.HDC
g.CreateCompatibleBitmap.argtypes = [w.HDC, c.c_int, c.c_int]; g.CreateCompatibleBitmap.restype = w.HBITMAP
g.SelectObject.argtypes = [w.HDC, w.HANDLE]; g.SelectObject.restype = w.HANDLE
g.GetDIBits.argtypes = [w.HDC, w.HBITMAP, w.UINT, w.UINT, c.c_void_p, c.c_void_p, w.UINT]
g.DeleteObject.argtypes = [w.HANDLE]; g.DeleteDC.argtypes = [w.HDC]

def send(hwnd, message, wp=0, lp=0):
    result = c.c_size_t()
    assert u.SendMessageTimeoutW(hwnd, message, wp, lp, 2, 3000, c.byref(result)), 'Unresponsive window'
    return result.value

def rect(hwnd, parent=None):
    r = w.RECT(); u.GetWindowRect(hwnd, c.byref(r))
    if parent: u.MapWindowPoints(None, parent, c.byref(r), 2)
    return [r.left, r.top, r.right, r.bottom]

def screenshot(hwnd, path):
    from PIL import Image
    r = rect(hwnd); width, height = r[2]-r[0], r[3]-r[1]
    dc = u.GetDC(hwnd); memory = g.CreateCompatibleDC(dc)
    bitmap = g.CreateCompatibleBitmap(dc, width, height); old = g.SelectObject(memory, bitmap)
    try:
        assert u.PrintWindow(hwnd, memory, 2), 'PrintWindow failed'
        g.SelectObject(memory, old)
        # BITMAPINFOHEADER, followed by unused color entries for 32-bit RGB.
        info = (c.c_uint32 * 11)(); info[0] = 40; info[1] = width; info[2] = c.c_uint32(-height).value
        info[3] = 1 | (32 << 16)
        pixels = c.create_string_buffer(width*height*4)
        assert g.GetDIBits(memory, bitmap, 0, height, pixels, c.byref(info), 0) == height
        Image.frombytes('RGB', (width,height), pixels.raw, 'raw', 'BGRX').save(path)
    finally:
        g.SelectObject(memory, old); g.DeleteObject(bitmap); g.DeleteDC(memory); u.ReleaseDC(hwnd, dc)

def ca_guidance(process, page, main_window, work, verify_read_error=False):
    """Exercise real GUI onboarding using only this test's unique CA."""
    def wait(predicate, message):
        for _ in range(150):
            value = predicate()
            if value: return value
            assert process.poll() is None, ('GUI exited', process.returncode, str(work))
            time.sleep(.1)
        raise AssertionError((message, str(work)))
    def read(hwnd):
        buf = c.create_unicode_buffer(8192)
        send(hwnd, 0xD, len(buf), c.addressof(buf)); return buf.value
    def dialogs(ca):
        found = []
        @CALLBACK
        def collect(hwnd, _):
            pid = w.DWORD(); u.GetWindowThreadProcessId(hwnd, c.byref(pid))
            if pid.value == process.pid and hwnd != main_window and u.IsWindowVisible(hwnd):
                is_ca = bool(u.GetDlgItem(hwnd, 1091))
                if is_ca == ca and u.GetDlgItem(hwnd, 1): found.append(hwnd)
            return True
        u.EnumWindows(collect, 0)
        return found[0] if found else None
    decrypt = u.GetDlgItem(page, 1085)
    def toggle(enabled):
        send(decrypt, 0xF1, int(enabled))
        send(page, 0x111, 1085, decrypt)  # Finish reading the checkbox before toggling it again.
    def ready(dialog):
        return u.IsWindowEnabled(u.GetDlgItem(dialog, 1))
    def open_guide():
        toggle(True)
        def detect():
            assert not dialogs(False), 'Missing CA incorrectly opened an error message'
            return dialogs(True)
        dialog = wait(detect, 'CA guidance did not open')
        wait(lambda: ready(dialog), 'CA query did not finish')
        assert not u.GetDlgItem(dialog, 1096), 'Old introductory text remains'
        assert not u.GetDlgItem(dialog, 1092), 'Removed initialization button remains'
        instruction = read(u.GetDlgItem(dialog, 1087))
        assert 'HTTPS' in instruction and ('当前系统用户' in instruction or 'current Windows user' in instruction), instruction
        return dialog
    def close(dialog, message=0x10, wp=0):
        assert u.PostMessageW(dialog, message, wp, 0)
        wait(lambda: not u.IsWindow(dialog), 'CA dialog did not close')

    dialog = open_guide()
    close(dialog, 0x111, 2)  # Cancel before installing: remain off, no repeated guide.
    assert send(decrypt, 0xF0) == 0
    time.sleep(.3); assert not dialogs(True) and not dialogs(False)
    dialog = open_guide()
    assert not (work/'pki/ca.json').exists(), 'Guidance should not create the CA before installation'
    screenshot(dialog, work/'ca-install-guidance.png')
    assert u.PostMessageW(dialog, 0x111, 1093, u.GetDlgItem(dialog, 1093))
    try:
        wait(lambda: 'CurrentUser ROOT: true' in read(u.GetDlgItem(dialog, 1091)) and ready(dialog), 'CA installation failed')
    except AssertionError:
        screenshot(dialog, work/'ca-install-failure.png')
        print('CA details:', read(u.GetDlgItem(dialog, 1091)), 'status:', read(u.GetDlgItem(dialog, 1087)), flush=True)
        raise
    close(dialog)  # X must resume the original checkbox action too.
    wait(lambda: send(decrypt, 0xF0) == 1 and u.IsWindowEnabled(decrypt), 'Decryption did not resume after installation')
    assert send(u.GetDlgItem(page, 1011), 0xF0) == 1, 'Monitoring did not start'
    assert not dialogs(False)
    screenshot(main_window, work/'ca-guidance-enabled.png')
    toggle(False); wait(lambda: send(decrypt, 0xF0) == 0, 'Disable failed')
    if not verify_read_error: return
    # Corruption is a real failure: it must still show an error rather than
    # disguising it as a missing certificate. Restore for exact-CA cleanup.
    path = work/'pki/ca.json'; original = path.read_bytes()
    try:
        path.write_text('{invalid')
        toggle(True)
        error = wait(lambda: dialogs(False), 'Real CA error was not reported')
        assert not dialogs(True)
        assert u.PostMessageW(error, 0x111, 1, 0)
        wait(lambda: not u.IsWindow(error), 'Error did not close')
        assert send(decrypt, 0xF0) == 0
    finally:
        path.write_bytes(original)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary-directory', default='bin')
    parser.add_argument('--language', choices=['zh-CN','en-US'], default='zh-CN')
    parser.add_argument('--ca-guidance', action='store_true', help='Install and finally remove a unique temporary CA to verify onboarding')
    parser.add_argument('--ca-read-error', action='store_true', help='With --ca-guidance, deliberately display a CA read error dialog')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    source = (root / args.binary_directory).resolve()
    work = root / 'build/qa' / ('monitor-layout-' + uuid.uuid4().hex[:10]); work.mkdir()
    k.GetModuleHandleW.argtypes = [w.LPCWSTR]; k.GetModuleHandleW.restype = w.HMODULE
    module = k.GetModuleHandleW('ProxyLaneHook64.dll')
    if module: assert c.WinDLL('ProxyLaneHook64.dll', handle=module).gp_UnhookWinsock()
    u.SetProcessDPIAware()
    for name in ['ProxyLane64.exe','ProxyLaneHook64.dll','ProxyLaneHook32.dll','ProxyLaneMitm64.dll','ProxyLaneMitm64.exe','ProxyLaneSecureTransport64.dll']:
        shutil.copy2(source/name, work/name)
    config = (root/'examples/ProxyLane.ini').read_text().replace('[options]', '[options]\nlanguage=' + args.language)
    (work/'ProxyLane.ini').write_text(config)
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1',0)); port = reservation.getsockname()[1]
    env = dict(os.environ,PROXYLANE_MITM='0',PROXYLANE_MITM_HOME=str(work/'pki'),PROXYLANE_MITM_CRL_PORT=str(port))
    process = subprocess.Popen([str(work/'ProxyLane64.exe')], cwd=work, env=env)
    try:
        main_window = None
        for _ in range(100):
            assert process.poll() is None, ('GUI exited during initialization',process.returncode,str(work))
            windows = []
            @CALLBACK
            def collect(hwnd, _):
                pid=w.DWORD(); u.GetWindowThreadProcessId(hwnd,c.byref(pid))
                if pid.value == process.pid and u.IsWindowVisible(hwnd):
                    title=c.create_unicode_buffer(256);u.GetWindowTextW(hwnd,title,256)
                    if title.value.startswith('ProxyLane '): windows.append(hwnd)
                return True
            u.EnumWindows(collect,0)
            if len(windows)==1: main_window=windows[0];break
            time.sleep(.1)
        assert main_window, 'Main window did not appear'
        nav=u.GetDlgItem(main_window,0x1006); assert nav
        pages=[]
        @CALLBACK
        def find_page(hwnd,_):
            if u.GetDlgItem(hwnd,1085): pages.append(hwnd)
            return True
        u.EnumChildWindows(nav,find_page,0); assert len(pages)==1
        page=pages[0]; scale=u.GetDpiForWindow(nav)/96
        records=[]
        def activate(index):
            x,y=round(50*scale),round((78+index*44+20)*scale)
            send(nav,0x201,1,(y<<16)|x); send(nav,0x202,0,(y<<16)|x)
            time.sleep(.2)
        def validate(label):
            assert u.IsWindowVisible(page), 'Monitor page not activated'
            client=w.RECT();u.GetClientRect(page,c.byref(client))
            controls={}
            for ident in (1042,1087,1088,1089,1090):
                assert not u.GetDlgItem(page,ident), ('Removed control still exists',ident)
            for name, ident in [('decrypt',1085),('ca',1086),('monitor',1011),('hex',1012),('clear',1021),('plaintext',1000)]:
                h=u.GetDlgItem(page,ident); assert h and u.IsWindowVisible(h), name
                r=rect(h,page); controls[name]=r
                assert 0<=r[0]<r[2]<=client.right and 0<=r[1]<r[3]<=client.bottom, (label,name,r,[client.right,client.bottom])
                assert r[2]-r[0]>=40 and r[3]-r[1]>=14, (label,name,'collapsed',r)
            assert controls['plaintext'][3]-controls['plaintext'][1]>=100
            assert rect(u.GetDlgItem(page,1041),page)[3] <= controls['decrypt'][1], 'Title overlaps controls'
            toolbar = [controls[name] for name in ('decrypt','monitor','hex','ca','clear')]
            assert len({r[1] for r in toolbar}) == 1, 'Toolbar must occupy one row'
            assert all(left[2] <= right[0] for left,right in zip(toolbar,toolbar[1:])), ('Toolbar overlaps',controls)
            records.append({'case':label,'controls':controls})
        activate(3); validate('activation')
        screenshot(main_window,work/'monitor.png')
        send(page,5,0,0); validate('parameterless WM_SIZE')
        for width,height in [(800,610),(1200,900)]:
            assert u.SetWindowPos(main_window,None,0,0,width,height,0x16)
            time.sleep(.15); validate(f'resize {width}x{height}')
            activate(0); activate(3); validate(f'reactivate {width}x{height}')
        # Open only the test-owned CA dialog. Status is read from a fresh data
        # directory; no install/remove trust buttons are ever invoked.
        assert u.PostMessageW(page,0x111,1086,u.GetDlgItem(page,1086))  # BN_CLICKED
        ca_dialog=None
        for _ in range(50):
            dialogs=[]
            @CALLBACK
            def find_ca(hwnd,_):
                pid=w.DWORD();u.GetWindowThreadProcessId(hwnd,c.byref(pid))
                if pid.value==process.pid and u.GetDlgItem(hwnd,1091): dialogs.append(hwnd)
                return True
            u.EnumWindows(find_ca,0)
            if len(dialogs)==1:
                details=c.create_unicode_buffer(4096)
                send(u.GetDlgItem(dialogs[0],1091),0xD,4096,c.addressof(details))
                if 'CA not initialized' in details.value: ca_dialog=dialogs[0];break
            time.sleep(.1)
        assert ca_dialog, ('CA status dialog did not initialize', dialogs, details.value if dialogs else '')
        assert not u.GetDlgItem(ca_dialog,1096), 'Removed CA description still exists'
        assert not u.GetDlgItem(ca_dialog,1092), 'Removed CA initialization button still exists'
        bounds=w.RECT();u.GetClientRect(ca_dialog,c.byref(bounds))
        for ident in (1091,1093,1094,1095,1):
            control=u.GetDlgItem(ca_dialog,ident); r=rect(control,ca_dialog)
            assert u.IsWindowVisible(control) and 0<=r[0]<r[2]<=bounds.right and 0<=r[1]<r[3]<=bounds.bottom, (ident,r)
        screenshot(ca_dialog,work/'ca-management.png')
        assert u.PostMessageW(ca_dialog,0x111,1,0)  # Close via IDOK
        records.append({'case':'CA management status and controls'})
        if args.ca_guidance:
            for _ in range(50):
                if not u.IsWindow(ca_dialog): break
                time.sleep(.1)
            ca_guidance(process,page,main_window,work,args.ca_read_error)
            records.append({'case':'CA guidance, cancel, direct install and resume', 'read_error':args.ca_read_error})
        (work/'results.json').write_text(json.dumps(records,indent=2))
        print('PASS',args.language,work,flush=True)
    finally:
        if process.poll() is None: process.terminate(); process.wait(5)
        if args.ca_guidance and (work/'pki/ca.json').exists():
            subprocess.run([str(work/'ProxyLaneMitm64.exe'),'remove'],env=env,check=True,stdout=subprocess.PIPE,timeout=10)
            print('Temporary CA removed',flush=True)

if __name__=='__main__': main()
