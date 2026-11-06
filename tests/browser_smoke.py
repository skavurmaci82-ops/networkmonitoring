"""Optional real-browser smoke test. Requires Playwright and Chromium."""
import os
from pathlib import Path
import tempfile
import threading
from playwright.sync_api import sync_playwright

from app import Server, Store
import json


def main():
    with tempfile.TemporaryDirectory() as directory:
        store = Store(Path(directory) / 'browser.sqlite3')
        (Path(directory)/'gateway.json').write_text(json.dumps({'enabled':True,'url':'http://127.0.0.1:8088/guacamole','secret_key':'00112233445566778899aabbccddeeff'}))
        server = Server(('127.0.0.1', 0), store)
        server.monitor.probe = lambda ip: {'ip': ip, 'reachable': True, 'ports': [22, 443, 3389, 5900], 'latency': 2.1, 'kind': 'Sunucu',
            'network_detail': {'interfaces': [{'index':1,'name':'1/1/7','mac':'00:0B:86:00:12:34','oper_status':1}],
                               'macs':['00:0B:86:00:12:34' if ip=='192.168.10.12' else '00:0B:86:00:56:78'],
                               'neighbors':[{'chassis_id':'00:0B:86:00:56:78','name':'test-switch','local_port':'1/1/7','remote_port':'1/1/24'}] if ip=='192.168.10.12' else [],
                               'lldp_status':'read'},
            'snmp': {'status': 'ok', 'model': 'Aruba 2930F', 'manufacturer': 'Aruba', 'serial': 'TEST-123', 'name': 'test-switch',
                     'description': 'Synthetic SNMP test fixture', 'source': 'SNMP ENTITY-MIB (chassis)', 'uptime': 3600}}
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with sync_playwright() as p:
                options = {'headless': True, 'args': ['--no-sandbox']}
                if os.environ.get('CHROMIUM_PATH'):
                    options['executable_path'] = os.environ['CHROMIUM_PATH']
                browser = p.chromium.launch(**options)
                page = browser.new_page(viewport={'width': 1440, 'height': 1080})
                errors = []
                page.on('pageerror', lambda error: errors.append(str(error)))
                page.on('console', lambda msg: errors.append(msg.text) if msg.type == 'error' else None)
                page.goto(f'http://127.0.0.1:{server.server_port}')
                page.wait_for_function("() => document.querySelector('#connection').textContent.includes('Bağlı')")
                assert page.locator('#total').inner_text() == '0'
                page.locator('.nav-item[data-view=settings]').click()
                assert page.locator('#ranges').input_value().splitlines() == ['192.168.10.0/23', '192.168.100.0/23', '192.168.24.0/24', '192.168.25.0/24']
                page.locator('.advanced-discovery summary').click()
                page.locator('#snmp-enabled').check()
                page.locator('#snmp-community').fill('local-browser-test')
                page.locator('#settings-form button[type=submit]').click()
                page.wait_for_function("() => document.querySelector('#networks').textContent==='4'")
                assert page.locator('#snmp-community').input_value() == ''
                assert store.snmp_settings()['community'] == 'local-browser-test'
                page.locator('#ranges').fill('192.168.10.12/32\n192.168.100.13/32')
                page.locator('#settings-form button[type=submit]').click()
                page.wait_for_function("() => document.querySelector('#networks').textContent==='2'")
                page.locator('.nav-item[data-view=inventory]').click()
                page.locator('#add-button').click()
                page.locator('[name=ip]').fill('192.168.10.12')
                page.locator('[name=name]').fill('Linux <b>sunucu</b>')
                page.locator('[name=kind]').select_option('Sunucu')
                page.locator('[name=os]').fill('Ubuntu 24.04')
                page.locator('[name=site]').fill('İstanbul')
                page.locator('[name=ram]').fill('64 GB')
                page.locator('[name=ssh_user]').fill('admin')
                page.locator('#device-form button[type=submit]').click()
                page.wait_for_function("() => document.querySelector('#total').textContent==='1'")
                assert page.locator('#device-rows b').count() == 0, 'Inventory must escape HTML'
                page.locator('#scan-button').click()
                page.wait_for_function("() => document.querySelector('#online').textContent==='2'")
                assert page.locator('.device-row').count() == 2
                assert page.locator('.network-row').count() == 2
                assert page.locator('#device-rows').inner_text().count('Aruba 2930F') == 2
                page.locator('#search').fill('bulunamayan')
                assert page.locator('#device-rows tr').count() == 0
                page.locator('#search').fill('İstanbul')
                assert page.locator('#device-rows .device-row').count() == 1
                page.locator('.row-edit').click()
                page.wait_for_selector('#history i')
                assert page.locator('[name=ram]').input_value() == '64 GB'
                page.locator('[name=owner]').fill('BT Ekibi')
                page.locator('#device-form button[type=submit]').click()
                page.wait_for_selector('#device-dialog', state='hidden')
                with page.expect_download() as download:
                    page.locator('#export-button').click()
                downloaded = download.value
                assert 'BT Ekibi' in Path(downloaded.path()).read_text(encoding='utf-8-sig')
                for protocol in ['rdp','ssh','vnc']:
                    page.locator(f'[data-connect={protocol}]').click()
                    assert page.locator('#session-dialog').is_visible()
                    assert page.locator('#session-title').inner_text().startswith(protocol.upper())
                    page.locator('#session-password').fill('not-saved')
                    page.locator('[data-close=session-dialog]').click()
                    page.wait_for_function("() => document.querySelector('#session-password').value===''")
                page.locator('#search').fill('')
                page.locator('.nav-item[data-view=overview]').click()
                page.locator('[data-network="192.168.10.12/32"]').click()
                assert page.locator('.device-row').count() == 1
                page.locator('#all-networks').click()
                assert page.locator('.device-row').count() == 2
                page.locator('.nav-item[data-view=topology]').click()
                assert page.locator('#topology-canvas .topology-node').count()==2
                assert page.locator('#topology-canvas .topology-edge').count()==1
                assert not page.locator('#topology-empty').is_visible()
                if os.environ.get('ATLAS_TOPOLOGY_SCREENSHOT'):
                    page.screenshot(path=os.environ['ATLAS_TOPOLOGY_SCREENSHOT'],full_page=True)
                with page.expect_download() as downloaded_topology:
                    page.locator('#topology-json').click()
                assert 'nodes' in json.loads(Path(downloaded_topology.value.path()).read_text())
                page.locator('.nav-item[data-view=overview]').click()
                if os.environ.get('ATLAS_SCREENSHOT'):

                    page.screenshot(path=os.environ['ATLAS_SCREENSHOT'], full_page=True)
                page.set_viewport_size({'width': 390, 'height': 844})
                assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'Mobile layout overflows'
                page.locator('.nav-item[data-view=inventory]').click()
                page.locator('.row-edit').first.click()
                page.on('dialog', lambda dialog: dialog.accept())
                page.locator('#delete-button').click()
                page.wait_for_function("() => document.querySelector('#total').textContent==='1'")
                assert not errors, errors
                browser.close()
                print('PASS: real-browser SNMP settings, model display, network groups, browser session dialogs, topology export, inventory, history, CSV, escaping, mobile layout; no browser errors')
        finally:
            server.shutdown()
            server.monitor.stop.set()
            if server.monitor.thread:
                server.monitor.thread.join(5)
            worker.join(5)
            server.server_close()


if __name__ == '__main__':
    main()
