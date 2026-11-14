"""Local ignored control credential; restrict access before writing any bytes."""

import os
import re
import secrets
import stat
from pathlib import Path


def owner_only(path):
    if os.name != "nt":
        path.chmod(0o600)
        return
    import ctypes
    from ctypes import wintypes

    security = ctypes.WinDLL("advapi32", use_last_error=True)
    convert = security.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
    ]
    convert.restype = wintypes.BOOL
    descriptor = ctypes.c_void_p()
    if not convert("D:P(A;;FA;;;OW)", 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        set_security = security.SetFileSecurityW
        set_security.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
        set_security.restype = wintypes.BOOL
        # Protected DACL: owner rights only, no inherited Users/Everyone ACEs.
        if not set_security(str(path), 0x80000004, descriptor):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        free = ctypes.WinDLL("kernel32").LocalFree
        free.argtypes = [ctypes.c_void_p]
        free(descriptor)


def control_token(directory, *, create):
    path = Path(directory) / "control-token.secret"
    if create:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, "wb") as stream:
                owner_only(path)
                stream.write(secrets.token_hex(32).encode())
                stream.flush()
                os.fsync(stream.fileno())
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("control_token_not_private_regular_file")
    if os.name == "nt":
        owner_only(path)
    elif info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError("control_token_permissions")
    token = path.read_text(encoding="ascii")
    if re.fullmatch("[0-9a-f]{64}", token) is None:
        raise ValueError("control_token_invalid")
    return token
