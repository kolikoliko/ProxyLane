"""Check process-list metadata and refresh in a disposable x64 GUI.

Only test-owned processes are opened for UI inspection or terminated.
Requires 64-bit Python and the existing exit-warning test dependencies.
"""
import ctypes as C
from ctypes import wintypes as W
from datetime import datetime
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

import psutil
from ExitWarningE2ETests import USER, CALLBACK, wait_for, windows


class Item(C.Structure):
    _fields_ = [('mask', W.UINT), ('row', C.c_int), ('column', C.c_int),
                ('state', W.UINT), ('stateMask', W.UINT), ('text', C.c_void_p),
                ('capacity', C.c_int), ('image', C.c_int), ('data', C.c_ssize_t)]


kernel = C.WinDLL('kernel32', use_last_error=True)


def api(name, result, *args):
    fn = getattr(kernel, name)
    fn.restype, fn.argtypes = result, args
    return fn


open_process = api('OpenProcess', W.HANDLE, W.DWORD, W.BOOL, W.DWORD)
allocate = api('VirtualAllocEx', C.c_void_p, W.HANDLE, C.c_void_p, C.c_size_t, W.DWORD, W.DWORD)
release = api('VirtualFreeEx', W.BOOL, W.HANDLE, C.c_void_p, C.c_size_t, W.DWORD)
write = api('WriteProcessMemory', W.BOOL, W.HANDLE, C.c_void_p, C.c_void_p, C.c_size_t, C.c_void_p)
read = api('ReadProcessMemory', W.BOOL, W.HANDLE, C.c_void_p, C.c_void_p, C.c_size_t, C.c_void_p)
close = api('CloseHandle', W.BOOL, W.HANDLE)


def deny_child_queries(process):
    """Apply an empty DACL to our child; keep Popen's original cleanup handle."""
    security = C.WinDLL('advapi32', use_last_error=True)
    for name, args in (
        ('InitializeAcl', (C.c_void_p, W.DWORD, W.DWORD)),
        ('InitializeSecurityDescriptor', (C.c_void_p, W.DWORD)),
        ('SetSecurityDescriptorDacl', (C.c_void_p, W.BOOL, C.c_void_p, W.BOOL)),
        ('SetKernelObjectSecurity', (W.HANDLE, W.DWORD, C.c_void_p)),
    ):
        fn = getattr(security, name)
        fn.restype, fn.argtypes = W.BOOL, args
    acl, descriptor = C.create_string_buffer(8), C.create_string_buffer(64)
    assert security.InitializeAcl(acl, C.sizeof(acl), 2), C.get_last_error()
    assert security.InitializeSecurityDescriptor(descriptor, 1), C.get_last_error()
    assert security.SetSecurityDescriptorDacl(descriptor, True, acl, False), C.get_last_error()
    assert security.SetKernelObjectSecurity(int(process._handle), 4, descriptor), C.get_last_error()
    denied = open_process(0x1000, False, process.pid)
    error = C.get_last_error()
    if denied:
        close(denied)
    assert not denied and error == 5, (denied, error)


def run():
    assert C.sizeof(C.c_void_p) == 8
    directory = Path('build/qa/process-list-' + uuid.uuid4().hex[:8]).resolve()
    directory.mkdir(parents=True)
    for name in ('ProxyLane64.exe', 'ProxyLaneHook64.dll', 'ProxyLaneHook32.dll'):
        shutil.copy2(Path('bin') / name, directory / name)
    (directory / 'ProxyLane.ini').write_text('[options]\nlanguage=zh-CN\n', encoding='utf-8')
    owner = child = None
    handle = memory = None
    try:
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(180)'],
                                 creationflags=subprocess.CREATE_NO_WINDOW)
        expected_time = datetime.fromtimestamp(psutil.Process(child.pid).create_time()).strftime('%Y-%m-%d %H:%M:%S')
        deny_child_queries(child)
        owner = subprocess.Popen([str(directory / 'ProxyLane64.exe')], cwd=directory,
                                 creationflags=subprocess.CREATE_NO_WINDOW)
        main = wait_for(lambda: next((w for w in windows(owner.pid) if not USER.GetParent(w)), None), 'GUI')
        pages = []

        @CALLBACK
        def visit(window, _):
            if USER.GetDlgItem(window, 1007):
                pages.append(window)
            return True

        def get_page():
            pages.clear()
            USER.EnumChildWindows(main, visit, 0)
            assert len(pages) <= 1, pages
            return pages[0] if pages else None

        page = wait_for(get_page, 'process page')
        view = USER.GetDlgItem(page, 1007)
        handle = open_process(0x38, False, owner.pid)  # Test GUI memory only.
        assert handle, C.get_last_error()
        memory = allocate(handle, None, 4096, 0x3000, 4)
        assert memory, C.get_last_error()

        def cell(row, column):
            item = Item(column=column, text=memory + 256, capacity=1024)
            assert write(handle, memory, C.byref(item), C.sizeof(item), None)
            USER.SendMessageW(view, 0x1073, row, memory)  # LVM_GETITEMTEXTW
            text = C.create_unicode_buffer(1024)
            assert read(handle, memory + 256, text, C.sizeof(text), None)
            return text.value

        def find_child():
            USER.SendMessageW(page, 0x111, 1009, 0)  # Refresh this owned page.
            count = USER.SendMessageW(view, 0x1004, 0, 0)
            for row in range(count):
                if cell(row, 0) == str(child.pid):
                    return [cell(row, column) for column in range(4)]
            return None

        row = wait_for(find_child, 'owned child in process list')
        assert Path(sys.executable).name.lower() in row[1].lower(), row
        assert row[2] == expected_time, (row, expected_time)
        assert Path(row[3]).resolve() == Path(sys.executable).resolve(), row
        child.terminate()
        child.wait(timeout=10)
        wait_for(lambda: find_child() is None, 'exited child removed on refresh')
        print('PASS: inaccessible child name, PID, creation time, full path and exited-row removal', flush=True)
        USER.PostMessageW(main, 0x10, 0, 0)
        owner.wait(timeout=10)
    finally:
        if memory:
            release(handle, memory, 0, 0x8000)
        if handle:
            close(handle)
        for process in (child, owner):
            if process:
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=10)


if __name__ == '__main__':
    run()
