"""Real Guacamole browser/VNC integration. Requires running gateway compose.

The only remote desktop is a synthetic RFB server on this test machine.
GATEWAY_TEST_HOST must be this machine's Docker bridge gateway IP.
"""
import json
import os
from pathlib import Path
import socket
import struct
import tempfile
import threading
import time
from playwright.sync_api import sync_playwright

from app import ROOT, Server, Store


def receive(sock, count):
    data = b''
    while len(data) < count:
        part = sock.recv(count-len(data))
        if not part:
            raise EOFError()
        data += part
    return data


class Desktop:
    def __init__(self):
        self.socket = socket.socket()
        self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.socket.bind(('0.0.0.0',5900))
        self.socket.listen()
        self.socket.settimeout(1)
        self.stop = threading.Event()
        self.updated = threading.Event()
        self.connected = threading.Event()
        self.errors = []
        self.thread = threading.Thread(target=self.run,daemon=True)
        self.thread.start()

    def run(self):
        while not self.stop.is_set():
            try:
                sock,_ = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                with sock:
                    sock.settimeout(10)
                    sock.sendall(b'RFB 003.008\n')
                    receive(sock,12)
                    sock.sendall(b'\x01\x01')
                    receive(sock,1)
                    sock.sendall(struct.pack('!I',0))
                    receive(sock,1)
                    fmt = struct.pack('!BBBBHHHBBB3x',32,24,0,1,255,255,255,16,8,0)
                    name = b'AgAtlas isolated VNC test desktop'
                    sock.sendall(struct.pack('!HH',320,180)+fmt+struct.pack('!I',len(name))+name)
                    self.connected.set()
                    while not self.stop.is_set():
                        kind=receive(sock,1)[0]
                        if kind==0:
                            fmt=receive(sock,19)[3:]
                        elif kind==2:
                            header=receive(sock,3)
                            receive(sock,struct.unpack('!H',header[1:])[0]*4)
                        elif kind==3:
                            receive(sock,9)
                            bpp,depth,endian,true,red,green,blue,rs,gs,bs=struct.unpack('!BBBBHHHBBB3x',fmt)
                            pixel=((20<<rs)|(150<<gs)|(110<<bs)).to_bytes(bpp//8,'big' if endian else 'little')
                            frame=b'\x00\x00'+struct.pack('!H',1)+struct.pack('!HHHHi',0,0,320,180,0)+pixel*(320*180)
                            sock.sendall(frame)
                            self.updated.set()
                        elif kind==4:
                            receive(sock,7)
                        elif kind==5:
                            receive(sock,5)
                        elif kind==6:
                            size=struct.unpack('!I',receive(sock,7)[3:])[0]
                            receive(sock,size)
                        else:
                            raise ValueError('Unexpected RFB message '+str(kind))
            except (EOFError,ConnectionResetError,TimeoutError,BrokenPipeError):
                pass
            except Exception as exc:
                self.errors.append(str(exc))

    def close(self):
        self.stop.set()
        self.socket.close()
        self.thread.join(3)


def main():
    host=os.environ['GATEWAY_TEST_HOST']
    desktop=Desktop()
    with tempfile.TemporaryDirectory() as directory:
        config=json.loads((ROOT/'data/gateway.json').read_text())
        (Path(directory)/'gateway.json').write_text(json.dumps(config))
        store=Store(Path(directory)/'test.sqlite3')
        store.record({'ip':host,'reachable':True,'ports':[5900],'latency':1,'kind':'İş istasyonu'})
        device=store.devices()[0]
        server=Server(('127.0.0.1',0),store)
        worker=threading.Thread(target=server.serve_forever,daemon=True)
        worker.start()
        try:
            with sync_playwright() as p:
                options={'headless':True,'args':['--no-sandbox']}
                if os.environ.get('CHROMIUM_PATH'):
                    options['executable_path']=os.environ['CHROMIUM_PATH']
                browser=p.chromium.launch(**options)
                page=browser.new_page(viewport={'width':1280,'height':800})
                page.goto(f'http://127.0.0.1:{server.server_port}')
                page.wait_for_selector('[data-connect=vnc]')
                page.locator('[data-connect=vnc]').click()
                with page.expect_popup() as popup_info:
                    page.locator('#session-start').click()
                remote=popup_info.value
                remote.wait_for_url('**/guacamole/**')
                deadline=time.monotonic()+45
                while not desktop.updated.is_set() and time.monotonic()<deadline:
                    remote.wait_for_timeout(500)
                if not desktop.updated.is_set():
                    print('Guacamole visible text:',remote.locator('body').inner_text()[:1200])
                assert desktop.connected.is_set(),'guacd did not complete RFB handshake'
                assert desktop.updated.is_set(),'Browser did not receive a framebuffer update'
                remote.wait_for_selector('.client canvas',timeout=10000)
                assert not desktop.errors,desktop.errors
                assert page.locator('#session-password').input_value()==''
                browser.close()
                print('PASS: AgAtlas session API → real Guacamole JSON auth → guacd → synthetic VNC framebuffer → browser canvas')
        finally:
            server.shutdown();server.server_close();worker.join(3);desktop.close()


if __name__=='__main__':
    main()
