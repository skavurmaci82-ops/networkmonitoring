"""Browser check: no SNMP credentials, no gateway, automatic discovery + MAC."""
import os
from pathlib import Path
import tempfile
import threading

from playwright.sync_api import sync_playwright
from app import Server, Store


def main():
    with tempfile.TemporaryDirectory() as directory:
        store=Store(Path(directory)/'basic.sqlite3')
        server=Server(('127.0.0.1',0),store)
        server.monitor.probe=lambda ip:{'ip':ip,'reachable':True,'ports':[22,3389,5900],'latency':1,
                                       'kind':'Sunucu','snmp':{'status':'not_configured'},
                                       'arp':{'mac':'00:0B:86:00:12:34','scope':'local'}}
        worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
        try:
            with sync_playwright() as p:
                options={'headless':True,'args':['--no-sandbox']}
                if os.environ.get('CHROMIUM_PATH'):options['executable_path']=os.environ['CHROMIUM_PATH']
                browser=p.chromium.launch(**options)
                page=browser.new_page(viewport={'width':1440,'height':1000})
                errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
                page.goto(f'http://127.0.0.1:{server.server_port}')
                page.wait_for_function("() => document.querySelector('#connection').textContent.includes('Bağlı')")
                page.locator('.nav-item[data-view=settings]').click()
                self_fields=page.locator('.advanced-discovery')
                assert self_fields.get_attribute('open') is None
                page.locator('#ranges').fill('192.168.10.12/32')
                page.locator('#quick-discover').click()
                page.wait_for_function("() => document.querySelector('#online').textContent==='1'")
                assert not store.settings()['snmp_enabled']
                assert page.locator('.mac-cell').inner_text().startswith('00:0B:86:00:12:34')
                assert page.locator('[data-connect]').count()==3
                for protocol in ['rdp','ssh','vnc']:
                    page.locator(f'[data-connect={protocol}]').click()
                    assert page.locator('#session-start').is_disabled()
                    with page.expect_download() as download:
                        page.locator('#session-download').click()
                    file=download.value
                    assert file.suggested_filename.endswith({'rdp':'.rdp','ssh':'.cmd','vnc':'.vnc'}[protocol])
                    content=Path(file.path()).read_text()
                    assert '192.168.10.12' in content
                    page.locator('[data-close=session-dialog]').click()
                    page.wait_for_selector('#session-dialog',state='hidden')
                page.locator('.nav-item[data-view=settings]').click()
                page.locator('.advanced-discovery summary').click()
                page.locator('#snmp-enabled').check()
                page.locator('#quick-discover').click()
                page.wait_for_selector('#overview-view',state='visible')
                assert not store.settings()['snmp_enabled'], 'Blank community must not block basic discovery'
                assert not errors,errors
                browser.close()
                print('PASS: one-click discovery without SNMP, immediate MAC column, SSH/RDP/VNC native fallback without Docker; no browser errors')
        finally:
            server.monitor.stop.set()
            if server.monitor.thread:server.monitor.thread.join(5)
            server.shutdown();server.server_close();worker.join(3)


if __name__=='__main__':main()
