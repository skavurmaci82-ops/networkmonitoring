"""Optional real-browser smoke test. Requires Playwright and Chromium."""
import os
from pathlib import Path
import tempfile
import threading
from playwright.sync_api import sync_playwright

from app import Server, Store


def main():
    with tempfile.TemporaryDirectory() as directory:
        store = Store(Path(directory) / 'browser.sqlite3')
        server = Server(('127.0.0.1', 0), store)
        server.monitor.probe = lambda ip: {'ip': ip, 'reachable': True, 'ports': [22, 443], 'latency': 2.1, 'kind': 'Sunucu'}
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
                page.locator('#settings-form button[type=submit]').click()
                page.wait_for_function("() => document.querySelector('#networks').textContent==='4'")
                page.locator('#ranges').fill('192.168.10.12/32')
                page.locator('#settings-form button[type=submit]').click()
                page.wait_for_function("() => document.querySelector('#networks').textContent==='1'")
                page.locator('.nav-item[data-view=inventory]').click()
                page.locator('#add-button').click()
                page.locator('[name=ip]').fill('192.168.10.12')
                page.locator('[name=name]').fill('Linux <b>sunucu</b>')
                page.locator('[name=kind]').select_option('Sunucu')
                page.locator('[name=os]').fill('Ubuntu 24.04')
                page.locator('[name=site]').fill('İstanbul')
                page.locator('[name=ram]').fill('64 GB')
                page.locator('#device-form button[type=submit]').click()
                page.wait_for_function("() => document.querySelector('#total').textContent==='1'")
                assert page.locator('#device-rows b').count() == 0, 'Inventory must escape HTML'
                page.locator('#scan-button').click()
                page.wait_for_function("() => document.querySelector('#online').textContent==='1'")
                page.locator('#search').fill('bulunamayan')
                assert page.locator('#device-rows tr').count() == 0
                page.locator('#search').fill('İstanbul')
                assert page.locator('#device-rows tr').count() == 1
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
                page.locator('.nav-item[data-view=overview]').click()
                assert page.locator('#health-percent').inner_text() == '100%'
                assert page.locator('#donut').evaluate("el=>getComputedStyle(el).backgroundImage").startswith('conic-gradient')
                if os.environ.get('ATLAS_SCREENSHOT'):
                    page.screenshot(path=os.environ['ATLAS_SCREENSHOT'], full_page=True)
                page.set_viewport_size({'width': 390, 'height': 844})
                assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'Mobile layout overflows'
                page.locator('.nav-item[data-view=inventory]').click()
                page.locator('.row-edit').click()
                page.on('dialog', lambda dialog: dialog.accept())
                page.locator('#delete-button').click()
                page.wait_for_function("() => document.querySelector('#total').textContent==='0'")
                assert not errors, errors
                browser.close()
                print('PASS: real-browser settings, inventory, scan, filters, history, CSV, escaping, mobile layout, deletion; no browser errors')
        finally:
            server.shutdown()
            server.monitor.stop.set()
            if server.monitor.thread:
                server.monitor.thread.join(5)
            worker.join(5)
            server.server_close()


if __name__ == '__main__':
    main()
