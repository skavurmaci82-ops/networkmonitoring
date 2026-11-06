"""Real browser profile wizard and measured inventory with controlled adapters."""
import json
import os
from pathlib import Path
import tempfile
import threading
from unittest.mock import patch
from playwright.sync_api import sync_playwright
from app import Server, Store


def fixture(target,profile,secret):
    return {'ok':True,'source':{'windows':'Windows CIM/DCOM','linux':'Linux SSH','snmp':'SNMP'}[profile['kind']],
            'name':profile['kind']+'-fixture','model':'Test '+profile['kind']+' model','manufacturer':'Test Vendor',
            'os':'Test OS','cpu_name':'Test CPU','cpu_percent':91,'memory_percent':48,'memory_total_bytes':8*1024**3,
            'macs':['00:0B:86:00:12:34'],'disks':[{'name':'system','used_percent':35,'total_bytes':10000,'free_bytes':6500}],
            'network':[{'name':'test-adapter','rx_bps':1200000,'tx_bps':300000}]}


def main():
    with tempfile.TemporaryDirectory() as directory:
        store=Store(Path(directory)/'profiles.sqlite3');server=Server(('127.0.0.1',0),store)
        worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
        try:
            with patch('profiles.collectors.collect',side_effect=fixture),patch('collectors.ssh_key',return_value={'ok':True,'fingerprint':'SHA256:'+'A'*43,'key_type':'test-key','verified':False}),sync_playwright() as p:
                options={'headless':True,'args':['--no-sandbox']}
                if os.environ.get('CHROMIUM_PATH'):options['executable_path']=os.environ['CHROMIUM_PATH']
                browser=p.chromium.launch(**options);page=browser.new_page(viewport={'width':1440,'height':1000})
                errors=[];page.on('pageerror',lambda e:errors.append(str(e)));page.on('console',lambda msg:errors.append(msg.text) if msg.type=='error' else None)
                page.goto(f'http://127.0.0.1:{server.server_port}');page.wait_for_function("() => document.querySelector('#connection').textContent.includes('Bağlı')")
                page.locator('.nav-item[data-view=profiles]').click()
                for index,kind in enumerate(['windows','linux','snmp']):
                    page.locator('#profile-add').click();page.locator('#profile-name').fill(kind+' test')
                    page.locator('#profile-kind').select_option(kind);page.locator('#profile-scope').fill('192.168.10.'+str(12+index))
                    if kind=='windows':page.locator('#profile-current').check()
                    elif kind=='linux':
                        page.locator('#profile-user').fill('test-reader');page.locator('#profile-password').fill('browser-secret')
                        page.locator('#profile-key-read').click();page.wait_for_function("() => document.querySelector('#profile-key-result').textContent.includes('SHA256:')")
                        page.locator('#profile-key-confirm').check()
                    else:page.locator('#profile-community').fill('browser-community')
                    page.locator('#profile-form button[type=submit]').click();page.wait_for_selector('#profile-dialog',state='hidden')
                    profile=next(v for v in store.profiles.list() if v['kind']==kind)
                    page.wait_for_selector(f'[data-profile-test="{profile["id"]}"]')
                    page.locator(f'[data-profile-test="{profile["id"]}"]').click()
                    page.wait_for_function("kind => document.querySelector('#profile-result').textContent.includes('Test '+kind+' model')",arg=kind)
                    assert page.locator('#profile-password').input_value()==''
                public=json.dumps(store.profiles.list())
                assert 'browser-secret' not in public and 'browser-community' not in public
                page.locator('.nav-item[data-view=inventory]').click()
                page.wait_for_function("() => document.querySelector('#total').textContent==='3'")
                assert page.locator('.device-row').count()==3
                assert page.locator('#device-rows').inner_text().count('CPU 91.0%')==3
                page.locator('.row-edit').first.click();page.wait_for_selector('#load-history rect')
                assert 'Windows CIM/DCOM' in page.locator('#metrics-details').inner_text()
                assert '91.0%' in page.locator('#metrics-details').inner_text()
                assert '1.20 Mbps' in page.locator('#metrics-details').inner_text()
                page.locator('[data-close=device-dialog]').click()
                assert not errors,errors
                browser.close();print('PASS: Windows/Linux/SNMP profile wizard, key confirmation, credential redaction, test results, measured inventory, load history, network rates')
        finally:
            server.shutdown();server.server_close();worker.join(3)


if __name__=='__main__':main()
