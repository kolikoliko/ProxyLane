"""Owned GUI: cold close/reopen, warm catalog, shared recents and profile isolation."""
import base64
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid

from ExitWarningE2ETests import USER, CALLBACK, windows, settings_page, text, wait_for, dismiss
from HookRebindE2ETests import owned_pipe

KERNEL = ctypes.WinDLL('kernel32', use_last_error=True)
KERNEL.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
KERNEL.CreateMutexW.restype = wintypes.HANDLE
KERNEL.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
KERNEL.ReleaseMutex.argtypes = [wintypes.HANDLE]
KERNEL.CloseHandle.argtypes = [wintypes.HANDLE]


def page_with(main, control):
    found = []
    @CALLBACK
    def visit(window, _):
        if USER.GetDlgItem(window, control):
            found.append(window)
        return True
    USER.EnumChildWindows(main, visit, 0)
    return found[0] if found else None


def open_picker(owner, process_page):
    USER.PostMessageW(process_page, 0x111, 1072, 0)
    return wait_for(lambda: next((w for w in windows(owner.pid) if USER.GetDlgItem(w, 1074)), None), 'picker')


def count(picker):
    return USER.SendMessageW(USER.GetDlgItem(picker, 1074), 0x1004, 0, 0)


def search(picker, value):
    buffer = ctypes.create_unicode_buffer(value)
    USER.SendMessageW(USER.GetDlgItem(picker, 1073), 0x000c, 0, ctypes.addressof(buffer))
    return count(picker)


def idle(picker):
    status = text(USER.GetDlgItem(picker, 1075))
    return 'Loading' not in status and 'Updating' not in status


def history_gate(path):
    key = str(path.resolve()).replace('/', '\\').lower()
    hashed = 14695981039346656037
    for character in key:
        hashed = ((hashed ^ ord(character)) * 1099511628211) & ((1 << 64) - 1)
    handle = KERNEL.CreateMutexW(None, False, 'Global\\ProxyLane.RecentIni.%016x' % hashed)
    assert handle and KERNEL.WaitForSingleObject(handle, 1000) == 0
    return handle


def fixture_ini():
    result = '[options]\nlastselected=A\nlanguage=en-US\n'
    for profile, digit in [('A', 'a'), ('B', 'b')]:
        identity = digit * 32
        result += f'''[proxy_{profile}]
RecentAppsId={identity}
HookChildProcess=1
HookTCP=1
HookUDP=0
BlockUDP=0
dnsOpt=0
ChildFilter=
ChildFilterMode=1
TargetFilter=
TargetFilterMode=1
Type=SOCKS5
Host=127.0.0.1
Port=1080
Transport=PLAIN
[recent_app_{identity}_{digit * 31}1]
Version=1
ProfileId={identity}
Pinned=0
Elevated=0
LastUsed=100
'''
        for field, value in [('Name', 'Warm ' + profile), ('Path', sys.executable),
                             ('Aumid', ''), ('Arguments', '--preload-fixture-' + profile),
                             ('WorkingDirectory', ''), ('Shortcut', '')]:
            result += field + 'Utf8Base64=' + base64.b64encode(value.encode()).decode() + '\n'
    return result


def main():
    directory = Path('build/qa/application-preload-' + uuid.uuid4().hex[:8]).resolve()
    directory.mkdir(parents=True)
    for name in ('ProxyLane64.exe', 'ProxyLaneHook64.dll', 'ProxyLaneHook32.dll'):
        shutil.copy2(Path('bin') / name, directory / name)
    ini = directory / 'ProxyLane.ini'
    ini.write_text(fixture_ini(), encoding='utf-8')
    owner = subprocess.Popen([str(directory / 'ProxyLane64.exe')], cwd=directory,
                             creationflags=subprocess.CREATE_NO_WINDOW)
    gate = None
    try:
        main_window = wait_for(lambda: next((w for w in windows(owner.pid) if not USER.GetParent(w)), None), 'main')
        page = wait_for(lambda: settings_page(main_window), 'settings')
        process_page = wait_for(lambda: page_with(main_window, 1072), 'process page')
        first = open_picker(owner, process_page)
        cold_status = text(USER.GetDlgItem(first, 1075))
        dismiss(first, 2)
        # No picker exists while the process-wide catalog continues warming.
        time.sleep(5)
        started = time.monotonic()
        picker = open_picker(owner, process_page)
        warm_open = time.monotonic() - started
        assert count(picker) > 0 and idle(picker), (count(picker), text(USER.GetDlgItem(picker, 1075)))
        dismiss(picker, 2)
        USER.PostMessageW(page, 0x111, 1, 0)
        wait_for(lambda: owned_pipe(owner.pid), 'service A')
        picker = open_picker(owner, process_page)
        wait_for(lambda: idle(picker), 'A ready')
        assert search(picker, 'Warm A') == 1
        assert search(picker, 'Warm B') == 0
        search(picker, '')
        before = count(picker)
        # Hold validation pending, then close/reopen a refresh with old data.
        gate = history_gate(ini)
        USER.SendMessageW(picker, 0x111, 1079, 0)
        assert count(picker) >= before and not idle(picker)
        dismiss(picker, 2)
        picker = open_picker(owner, process_page)
        assert count(picker) > 0 and not idle(picker), 'refresh retains cached rows and pending state'
        KERNEL.ReleaseMutex(gate); KERNEL.CloseHandle(gate); gate = None
        wait_for(lambda: idle(picker), 'refresh finishes after reopening')
        assert search(picker, 'Warm A') == 1
        dismiss(picker, 2)
        # Selecting B while A is running must not display B's history.
        combo = USER.GetDlgItem(page, 1022)
        value = ctypes.create_unicode_buffer('B')
        index = USER.SendMessageW(combo, 0x158, -1, ctypes.addressof(value))
        assert index >= 0
        USER.SendMessageW(combo, 0x14e, index, 0)
        USER.SendMessageW(page, 0x111, (1 << 16) | 1022, combo)
        picker = open_picker(owner, process_page)
        wait_for(lambda: idle(picker), 'A still active')
        assert search(picker, 'Warm A') == 1 and search(picker, 'Warm B') == 0
        dismiss(picker, 2)
        USER.PostMessageW(page, 0x111, 2, 0)
        wait_for(lambda: not owned_pipe(owner.pid), 'stop A')
        time.sleep(.5)  # Selected B's preload is debounced independently.
        USER.PostMessageW(page, 0x111, 1, 0)
        wait_for(lambda: owned_pipe(owner.pid), 'service B')
        picker = open_picker(owner, process_page)
        wait_for(lambda: idle(picker), 'B ready')
        assert search(picker, 'Warm B') == 1 and search(picker, 'Warm A') == 0
        dismiss(picker, 2)
        USER.PostMessageW(main_window, 0x10, 0, 0)
        owner.wait(timeout=10)
        print('PASS', {'cold_status': cold_status, 'warm_open_seconds': round(warm_open, 3),
                       'catalog_rows': before, 'close_during_refresh': True, 'profile_isolation': True,
                       'fixture': str(directory)}, flush=True)
    finally:
        if gate:
            KERNEL.ReleaseMutex(gate); KERNEL.CloseHandle(gate)
        if owner.poll() is None:
            owner.terminate(); owner.wait(timeout=10)


if __name__ == '__main__':
    main()
