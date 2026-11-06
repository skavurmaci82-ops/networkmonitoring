import base64
import hashlib
import hmac
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from urllib.parse import parse_qs, urlsplit

from gateway import encrypt_session, session_url
from gateway_setup import prepare
import test_app


KEY = '00112233445566778899aabbccddeeff'


def decrypt(value):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7
    cipher = Cipher(algorithms.AES(bytes.fromhex(KEY)), modes.CBC(b'\0'*16)).decryptor()
    raw = cipher.update(base64.b64decode(value)) + cipher.finalize()
    unpad = PKCS7(128).unpadder()
    raw = unpad.update(raw) + unpad.finalize()
    signature, plain = raw[:32], raw[32:]
    assert hmac.compare_digest(signature, hmac.new(bytes.fromhex(KEY), plain, hashlib.sha256).digest())
    return json.loads(plain)


class GatewayTests(unittest.TestCase):
    def test_encryption_and_short_lived_single_target_scope(self):
        device = {'ip': '192.168.10.12', 'ports': [22, 3389, 5900], 'ssh_user': 'admin'}
        credentials = {'username': 'remote-user', 'password': 'temporary-test-password'}
        url = session_url(device, 'ssh', credentials, {'enabled': True, 'secret_key': KEY, 'url': 'http://localhost:8088/guacamole'})
        self.assertNotIn('temporary-test-password', url)
        payload = decrypt(parse_qs(urlsplit(url).query)['data'][0])
        self.assertGreater(payload['expires'], time.time()*1000)
        self.assertLess(payload['expires'], (time.time()+31)*1000)
        self.assertEqual(len(payload['connections']), 1)
        connection = next(iter(payload['connections'].values()))
        self.assertEqual(connection['protocol'], 'ssh')
        self.assertEqual(connection['parameters']['hostname'], device['ip'])
        self.assertEqual(connection['parameters']['username'], 'remote-user')

    @unittest.skipUnless(shutil.which('openssl'), 'OpenSSL reference implementation unavailable')
    def test_apache_encryption_format_matches_independent_openssl(self):
        payload = {'username': 'test', 'connections': {}, 'expires': 2000000000000}
        plain = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode()
        signed = hmac.new(bytes.fromhex(KEY), plain, hashlib.sha256).digest() + plain
        reference = subprocess.run(['openssl', 'enc', '-aes-128-cbc', '-K', KEY, '-iv', '0'*32, '-nosalt'], input=signed, capture_output=True, check=True).stdout
        self.assertEqual(base64.b64decode(encrypt_session(payload, KEY)), reference)

    def test_unconfigured_gateway_closed_protocol_and_non_tls_remote_rejected(self):
        device = {'ip': '192.168.10.12', 'ports': []}
        with self.assertRaises(RuntimeError):
            session_url(device, 'rdp', {}, {})
        with self.assertRaises(RuntimeError):
            session_url(device, 'rdp', {}, {'enabled': True, 'secret_key': KEY, 'url': 'http://localhost:8088/guacamole'})
        with self.assertRaises(ValueError):
            session_url(device, 'rdp', {}, {'enabled': True, 'secret_key': KEY, 'url': 'http://remote.example/guacamole'})

    def test_setup_reuses_key_and_private_config(self):
        with tempfile.TemporaryDirectory() as directory:
            first = prepare(directory)
            self.assertEqual(prepare(directory)['secret_key'], first['secret_key'])
            self.assertEqual(len(bytes.fromhex(first['secret_key'])), 16)
            self.assertTrue((Path(directory)/'guacamole.env').exists())


class SessionHTTPTests(unittest.TestCase):
    setUp = test_app.HTTPTests.setUp
    tearDown = test_app.HTTPTests.tearDown
    request = test_app.HTTPTests.request

    def test_gateway_secrets_and_remote_credentials_not_saved_or_exposed(self):
        path = Path(self.store.path).parent/'gateway.json'
        path.write_text(json.dumps({'enabled': True, 'secret_key': KEY, 'url': 'http://localhost:8088/guacamole'}))
        self.store.record(test_app.result(ports=[22,3389,5900]))
        device_id = self.store.devices()[0]['id']
        status, session = self.request('POST', f'/api/devices/{device_id}/session', {'protocol': 'rdp', 'username': 'test-user', 'password': 'never-persist-this'})
        self.assertEqual(status, 200)
        self.assertTrue(session['url'].startswith('http://localhost:8088/guacamole/?data='))
        state = self.request('GET', '/api/state')[1]
        self.assertNotIn(KEY, json.dumps(state))
        self.assertNotIn('never-persist-this', Path(self.store.path).read_bytes().decode('latin-1'))
        self.assertNotIn('never-persist-this', json.dumps(state))
        self.assertTrue(state['capabilities']['browser_access'])
        self.server.token = 'local-test-access'
        self.assertEqual(self.request('POST', f'/api/devices/{device_id}/session', {'protocol':'rdp'})[0],401)


if __name__ == '__main__':
    unittest.main()
