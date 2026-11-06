"""Prepare private Guacamole settings and start the official Docker services."""
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import time
from http.client import HTTPConnection

ROOT = Path(__file__).resolve().parent


def prepare(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / 'gateway.json'
    if path.exists():
        config = json.loads(path.read_text())
        key = config['secret_key']
        if len(bytes.fromhex(key)) != 16:
            raise ValueError('Mevcut erişim anahtarı geçersiz; dosya korunuyor.')
    else:
        config = {'enabled': True, 'url': 'http://127.0.0.1:8088/guacamole', 'secret_key': secrets.token_hex(16)}
        with path.open('x', encoding='utf-8') as f:
            json.dump(config, f)
    env_path = directory / 'guacamole.env'
    # Keep the original shared key across updates and repeat setup runs.
    env_path.write_text('JSON_SECRET_KEY=' + config['secret_key'] + '\n', encoding='ascii')
    if os.name != 'nt':
        os.chmod(path, 0o600)
        os.chmod(env_path, 0o600)
    return config


def main():
    if not shutil.which('docker'):
        raise RuntimeError('Docker Desktop kurulu değil. Docker Desktop kurup Linux containers modunda başlatın.')
    subprocess.run(['docker', 'info', '--format', '{{.ServerVersion}}'], check=True, timeout=30)
    prepare(ROOT / 'data')
    subprocess.run(['docker', 'compose', '-f', str(ROOT / 'gateway' / 'compose.yaml'), 'up', '-d'], check=True)
    print('Tarayici erisim servisleri bekleniyor...')
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        connection = HTTPConnection('127.0.0.1', 8088, timeout=3)
        try:
            connection.request('GET', '/guacamole/')
            response = connection.getresponse()
            response.read()
            if response.status == 200:
                print('HAZIR. AgAtlas uygulamasini BASLAT.cmd ile yeniden baslatin.')
                return
        except OSError:
            pass
        finally:
            connection.close()
        time.sleep(2)
    raise RuntimeError('Servis 120 saniyede hazır olmadı. docker compose -f gateway/compose.yaml logs guacamole komutuyla günlüğü kontrol edin.')


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as exc:
        print('Kurulum tamamlanamadi:', exc)
        raise SystemExit(1)
