"""Local credential protection. Secrets never appear in profile API responses."""
import base64
import ctypes
import os
import threading
from pathlib import Path


def _dpapi(data, decrypt=False):
    class Blob(ctypes.Structure):
        _fields_ = [('size', ctypes.c_uint32), ('data', ctypes.c_void_p)]
    buffer = ctypes.create_string_buffer(data)
    source, target = Blob(len(data), ctypes.cast(buffer, ctypes.c_void_p)), Blob()
    crypto = ctypes.WinDLL('crypt32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    if decrypt:
        function = crypto.CryptUnprotectData
        function.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(Blob)]
        description = None
    else:
        function = crypto.CryptProtectData
        function.argtypes = [ctypes.POINTER(Blob), ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(Blob)]
        description = 'AgAtlas local credentials'
    function.restype = ctypes.c_int
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    if not function(ctypes.byref(source), description, None, None, None, 1, ctypes.byref(target)):
        raise RuntimeError('Windows kimlik koruması başarısız. Aynı Windows kullanıcı hesabıyla çalıştırın.')
    try:
        return ctypes.string_at(target.data, target.size)
    finally:
        kernel.LocalFree(target.data)


class Vault:
    _lock=threading.Lock()
    def __init__(self, directory):
        self.directory = Path(directory)

    def fernet(self):
        try:
            from cryptography.fernet import Fernet
        except ImportError:
            raise RuntimeError('Toplayıcı bağımlılıkları eksik. TOPLAYICI_KUR.cmd dosyasını çalıştırın.') from None
        path = self.directory / 'credentials.key'
        self.directory.mkdir(parents=True, exist_ok=True)
        with self._lock:
            if not path.exists():
                try:
                    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(descriptor, 'wb') as file:
                        file.write(Fernet.generate_key())
                except FileExistsError:
                    pass
            return Fernet(path.read_bytes())

    def encrypt(self, value):
        data = value.encode('utf-8')
        if os.name == 'nt':
            return 'dpapi:' + base64.b64encode(_dpapi(data)).decode()
        return 'fernet:' + self.fernet().encrypt(data).decode()

    def decrypt(self, value):
        if not value:
            return '{}'
        try:
            if value.startswith('dpapi:'):
                if os.name != 'nt':
                    raise RuntimeError('Bu profil Windows kullanıcı hesabına bağlı. Yeni makinede kimlik bilgilerini yeniden girin.')
                return _dpapi(base64.b64decode(value[6:]), decrypt=True).decode('utf-8')
            if value.startswith('fernet:'):
                return self.fernet().decrypt(value[7:].encode()).decode('utf-8')
        except RuntimeError:
            raise
        except Exception:
            raise RuntimeError('Kimlik bilgileri açılamadı. Anahtar dosyasını ve çalışma hesabını kontrol edin.') from None
        raise RuntimeError('Bilinmeyen kimlik koruma biçimi.')
