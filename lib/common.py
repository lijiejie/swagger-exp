# -*- encoding: utf-8 -*-

import os
import platform


def get_chrome_path_win():
    try:
        import _winreg as reg
    except Exception as e:
        import winreg as reg
    # HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe\
    conn = reg.ConnectRegistry(None, reg.HKEY_LOCAL_MACHINE)
    _path = reg.QueryValue(conn, 'Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe\\')
    reg.CloseKey(conn)
    if not os.path.exists(_path):
        raise Exception('chrome.exe not found.')
    return _path


def get_chrome_path_linux():
    folders = ['/usr/local/sbin', '/usr/local/bin', '/usr/sbin', '/usr/bin', '/sbin', '/bin', '/opt/google/']
    names = ['google-chrome', 'chrome', 'chromium', 'chromium-browser']
    for folder in folders:
        for name in names:
            if os.path.exists(os.path.join(folder, name)):
                return os.path.join(folder, name)


def get_chrome_path():
    if platform.system() == 'Windows':
        return get_chrome_path_win()
    else:
        return get_chrome_path_linux()
