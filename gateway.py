"""Apache Guacamole JSON authentication; remote passwords are never persisted."""
import base64
import hashlib
import hmac
import json
import secrets
import time
from urllib.parse import urlencode, urlsplit


def encrypt_session(payload, secret_key):
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.padding import PKCS7
    except ImportError:
        raise RuntimeError('Tarayıcı erişimi bağımlılığı eksik. TARAYICI_ERISIM_KUR.cmd dosyasını çalıştırın.') from None
    key = bytes.fromhex(secret_key)
    if len(key) != 16:
        raise ValueError('Erişim sunucusu anahtarı geçersiz.')
    plain = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode()
    signed = hmac.new(key, plain, hashlib.sha256).digest() + plain
    padder = PKCS7(128).padder()
    padded = padder.update(signed) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(b'\0' * 16)).encryptor()
    return base64.b64encode(cipher.update(padded) + cipher.finalize()).decode('ascii')


def session_url(device, protocol, credentials, config):
    if not config.get('enabled') or not config.get('secret_key'):
        raise RuntimeError('Tarayıcı erişimi kurulmamış. Önce TARAYICI_ERISIM_KUR.cmd dosyasını çalıştırın.')
    parsed = urlsplit(config.get('url', ''))
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ValueError('Guacamole adresi geçersiz.')
    if parsed.scheme == 'http' and parsed.hostname not in ('127.0.0.1', 'localhost'):
        raise ValueError('Uzak erişim sunucusu için HTTPS kullanın.')
    ports = device['ports']
    port = {'ssh': 22, 'rdp': 3389, 'vnc': next((p for p in (5900, 5901, 5902) if p in ports), None)}.get(protocol)
    if not port or port not in ports:
        raise RuntimeError('Bu protokol son kontrolde açık bulunamadı.')
    parameters = {'hostname': device['ip'], 'port': str(port)}
    for key in ('username', 'password', 'domain'):
        value = credentials.get(key, '')
        if not isinstance(value, str) or len(value) > 512 or '\x00' in value:
            raise ValueError('Bağlantı bilgileri geçersiz veya çok uzun.')
        if value and (key != 'domain' or protocol == 'rdp'):
            parameters[key] = value
    if protocol == 'ssh' and not parameters.get('username') and device.get('ssh_user'):
        parameters['username'] = device['ssh_user']
    # Guacamole client identifiers must remain ASCII across browser encoders.
    name = protocol.upper() + ' - ' + device['ip']
    payload = {'username': 'atlas-' + secrets.token_hex(12), 'expires': int((time.time() + 30) * 1000),
               'connections': {name: {'protocol': protocol, 'parameters': parameters}}}
    # This format is specified by Apache's guacamole-auth-json extension.
    # Short expiry limits replay of the encrypted launch request.
    return config['url'].rstrip('/') + '/?' + urlencode({'data': encrypt_session(payload, config['secret_key'])})
