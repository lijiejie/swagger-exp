# -*- encoding: utf-8 -*-

import _winreg
import os
import platform


def get_chrome_path_win():
    # HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe\
    conn = _winreg.ConnectRegistry(None, _winreg.HKEY_LOCAL_MACHINE)
    _path = _winreg.QueryValue(conn, 'Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe\\')
    _winreg.CloseKey(conn)
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
