"""Real, local SSH transport with an isolated test account and verified key."""
import json
from pathlib import Path
import socket
import subprocess
import sys
import threading
import unittest

import paramiko
from collectors import fingerprint, linux


class SSHFixture:
    def __init__(self):
        self.key=paramiko.RSAKey.generate(2048)
        self.socket=socket.socket();self.socket.bind(('127.0.0.1',0));self.socket.listen(1);self.socket.settimeout(5)
        self.port=self.socket.getsockname()[1]
        self.auth_count=0;self.script_received=False;self.errors=[]
        self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()

    def run(self):
        fixture=self
        class Account(paramiko.ServerInterface):
            def get_allowed_auths(self,username):return 'password'
            def check_auth_password(self,username,password):
                fixture.auth_count+=1
                return paramiko.AUTH_SUCCESSFUL if username=='unit-reader' and password=='unit-only-password' else paramiko.AUTH_FAILED
            def check_channel_request(self,kind,channelid):
                return paramiko.OPEN_SUCCEEDED if kind=='session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
            def check_channel_exec_request(self,channel,command):
                return command==b'python3 -'
        transport=None
        try:
            sock,_=self.socket.accept();transport=paramiko.Transport(sock);transport.add_server_key(self.key)
            transport.start_server(server=Account());channel=transport.accept(5)
            if channel is None:return
            channel.settimeout(5);script=b''
            while True:
                data=channel.recv(32768)
                if not data:break
                script+=data
            expected=(Path(__file__).resolve().parents[1]/'collector_scripts/linux.py').read_bytes()
            if script!=expected:raise AssertionError('Unexpected remote script')
            self.script_received=True
            response=subprocess.run([sys.executable,'-'],input=script,capture_output=True,timeout=10,check=True)
            channel.sendall(response.stdout);channel.send_exit_status(0);channel.shutdown_write();channel.close()
        except (EOFError,ConnectionResetError):pass
        except Exception as exc:self.errors.append(type(exc).__name__)
        finally:
            if transport:transport.close()
            self.socket.close()

    def close(self):
        self.thread.join(7);self.socket.close()


class SSHIntegrationTests(unittest.TestCase):
    def test_verified_ssh_runs_real_read_only_linux_measurement(self):
        fixture=SSHFixture()
        try:
            result=linux('127.0.0.1',{'username':'unit-reader','port':fixture.port,'host_key':fingerprint(fixture.key)},{'password':'unit-only-password'})
            self.assertTrue(result['ok'],result.get('error'))
            self.assertTrue(fixture.script_received)
            self.assertEqual(fixture.auth_count,1)
            self.assertGreater(result['memory_total_bytes'],0)
            self.assertTrue(0<=result['cpu_percent']<=100)
            self.assertNotIn('unit-only-password',json.dumps(result))
            self.assertFalse(fixture.errors,fixture.errors)
        finally:fixture.close()

    def test_changed_server_key_is_rejected_before_password_authentication(self):
        fixture=SSHFixture()
        try:
            result=linux('127.0.0.1',{'username':'unit-reader','port':fixture.port,'host_key':'SHA256:'+'A'*43},{'password':'unit-only-password'})
            self.assertFalse(result['ok'])
            self.assertEqual(result['error_code'],'ssh_host_key_changed')
            self.assertEqual(fixture.auth_count,0)
        finally:fixture.close()


if __name__=='__main__':unittest.main()
