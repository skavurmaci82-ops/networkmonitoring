import csv
import io
import json
import socket
import tempfile
import threading
import time
import unittest
from http.client import HTTPConnection
from pathlib import Path
from unittest.mock import patch

from app import Monitor, Server, Store, csv_export, network, probe


def result(ip='192.168.10.12', reachable=True, ports=None):
    return {'ip': ip, 'reachable': reachable, 'ports': ([22] if reachable else []) if ports is None else ports,
            'latency': 1.25 if reachable else None, 'kind': 'Sunucu'}


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / 'test.sqlite3')

    def tearDown(self):
        self.temp.cleanup()

    def test_requested_networks_are_normalized(self):
        settings = self.store.save_settings({'ranges': ['192.168.10.0/23', '192.168.100.5/23', '192.168.24.1/24', '192.168.25.0/24'], 'interval': 60})
        self.assertEqual(settings['ranges'], ['192.168.10.0/23', '192.168.100.0/23', '192.168.24.0/24', '192.168.25.0/24'])
        self.assertEqual(sum(len(list(network(r).hosts())) for r in settings['ranges']), 1528)

    def test_invalid_or_public_networks_rejected(self):
        for value in ['0.0.0.0/0', '8.8.8.8', '127.0.0.1', '169.254.169.254', '10.0.0.0/8', '::1', '192168.25.0/24', '192.168.1.1; echo bad']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                network(value)

    def test_settings_limits(self):
        for value in [0, 59, 86401, True, '300']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.store.save_settings({'ranges': [], 'interval': value})
        with self.assertRaises(ValueError):
            self.store.save_settings({'ranges': ['192.168.1.1'] * 9})

    def test_inventory_persist_update_and_ip_immutable(self):
        device_id = self.store.save_device({'ip': '192.168.10.12', 'name': 'Sunucu', 'os': 'Linux', 'ram': '32 GB', 'owner': 'BT'})
        restored = Store(self.store.path)
        self.assertEqual(restored.devices()[0]['ram'], '32 GB')
        restored.save_device({'ip': '192.168.10.12', 'name': 'Yeni ad'}, device_id)
        self.assertEqual(restored.devices()[0]['name'], 'Yeni ad')
        with self.assertRaises(ValueError):
            restored.save_device({'ip': '192.168.10.13'}, device_id)

    def test_discovery_failure_threshold_and_recovery(self):
        self.store.record(result())
        device_id = self.store.devices()[0]['id']
        self.store.save_device({'ip': '192.168.10.12', 'name': 'Özel ad', 'os': 'Linux'}, device_id)
        self.store.record(result(reachable=False))
        self.assertEqual(self.store.devices()[0]['status'], 'degraded')
        self.store.record(result(reachable=False))
        self.assertEqual(len(self.store.events()), 1)
        self.store.record(result(reachable=False))
        self.assertEqual(self.store.devices()[0]['status'], 'unreachable')
        self.assertEqual(self.store.events()[0]['level'], 'warning')
        self.store.record(result(reachable=False))
        self.assertEqual(len(self.store.events()), 2)
        self.store.record(result())
        row = self.store.devices()[0]
        self.assertEqual(row['status'], 'online')
        self.assertEqual(row['name'], 'Özel ad')
        self.assertEqual(row['os'], 'Linux')
        self.assertEqual(self.store.events()[0]['level'], 'success')
        self.assertEqual(len(self.store.history(device_id)), 6)

    def test_unresponsive_unknown_hosts_not_added(self):
        self.store.record(result(reachable=False))
        self.assertEqual(self.store.devices(), [])
        self.assertEqual(self.store.events(), [])

    def test_delete_cascades_history_and_keeps_event(self):
        self.store.record(result())
        device_id = self.store.devices()[0]['id']
        self.store.delete_device(device_id)
        self.assertEqual(self.store.devices(), [])
        with self.store.db() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM checks').fetchone()[0], 0)
        self.assertIsNone(self.store.events()[0]['device_id'])

    def test_csv_unicode_and_formula_protection(self):
        self.store.save_device({'ip': '192.168.10.12', 'name': '=HYPERLINK("bad")', 'site': 'İstanbul', 'notes': '+bad'})
        rows = list(csv.reader(io.StringIO(csv_export(self.store.devices()).decode('utf-8-sig'))))
        self.assertEqual(rows[1][1], '\'=HYPERLINK("bad")')
        self.assertIn('İstanbul', rows[1])
        self.assertIn("'+bad", rows[1])

    def test_monitor_deduplicates_and_checks_manual_devices(self):
        self.store.save_device({'ip': '192.168.10.12'})
        checked = []
        def fake(ip):
            checked.append(ip)
            return result(ip)
        monitor = Monitor(self.store, fake)
        monitor.start(['192.168.10.12/32', '192.168.10.13/32'])
        monitor.thread.join(5)
        self.assertFalse(monitor.snapshot()['running'])
        self.assertIsNone(monitor.snapshot()['error'])
        self.assertEqual(monitor.snapshot()['done'], 2)
        self.assertEqual(sorted(checked), ['192.168.10.12', '192.168.10.13'])

    def test_concurrent_scan_is_rejected(self):
        gate = threading.Event()
        def fake(ip):
            gate.wait(3)
            return result(ip)
        monitor = Monitor(self.store, fake)
        monitor.start(['192.168.10.12'])
        try:
            with self.assertRaises(RuntimeError):
                monitor.start(['192.168.10.13'])
        finally:
            gate.set()
            monitor.thread.join(5)

    def test_scan_error_reported_and_lock_released(self):
        def fail(ip):
            raise OSError('expected test error')
        monitor = Monitor(self.store, fail)
        with self.assertLogs(level='ERROR'):
            monitor.start(['192.168.10.12'])
            monitor.thread.join(5)
        self.assertFalse(monitor.snapshot()['running'])
        self.assertIsNotNone(monitor.snapshot()['error'])

    def test_scheduler_runs_inventory_without_ranges(self):
        self.store.save_device({'ip': '192.168.10.12'})
        monitor = Monitor(self.store, lambda ip: result(ip))
        monitor.next_run = 0
        thread = threading.Thread(target=monitor.schedule)
        thread.start()
        try:
            deadline = time.monotonic() + 5
            while not self.store.devices()[0]['last_checked'] and time.monotonic() < deadline:
                time.sleep(.05)
            self.assertEqual(self.store.devices()[0]['status'], 'online')
        finally:
            monitor.stop.set()
            thread.join(3)
            if monitor.thread:
                monitor.thread.join(3)


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / 'http.sqlite3')
        self.server = Server(('127.0.0.1', 0), self.store)
        self.server.monitor.probe = lambda ip: result(ip)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.monitor.stop.set()
        if self.server.monitor.thread:
            self.server.monitor.thread.join(5)
        self.thread.join(5)
        self.server.server_close()
        self.temp.cleanup()

    def request(self, method, path, body=None, headers=None):
        connection = HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        h = {'Content-Type': 'application/json'}
        h.update(headers or {})
        connection.request(method, path, body=json.dumps(body) if body is not None else None, headers=h)
        response = connection.getresponse()
        status, content, kind = response.status, response.read(), response.getheader('Content-Type')
        connection.close()
        return status, json.loads(content) if 'application/json' in kind else content

    def test_full_inventory_and_scan_workflow(self):
        status, row = self.request('POST', '/api/devices', {'ip': '192.168.10.12', 'name': 'Linux sunucu'})
        self.assertEqual(status, 201)
        device_id = row['id']
        self.assertEqual(self.request('PUT', '/api/settings', {'ranges': ['192.168.10.12'], 'interval': 60})[0], 200)
        self.assertEqual(self.request('POST', '/api/scan', {})[0], 202)
        self.server.monitor.thread.join(5)
        status, state = self.request('GET', '/api/state')
        self.assertEqual(status, 200)
        self.assertEqual(state['devices'][0]['status'], 'online')
        self.assertEqual(state['devices'][0]['name'], 'Linux sunucu')
        self.assertEqual(len(self.request('GET', f'/api/devices/{device_id}/history')[1]), 1)
        self.assertIn('Linux sunucu'.encode(), self.request('GET', '/api/export')[1])
        self.assertEqual(self.request('DELETE', f'/api/devices/{device_id}')[0], 200)
        self.assertEqual(self.request('GET', '/api/state')[1]['devices'], [])

    def test_authentication_and_host_guard(self):
        self.assertEqual(self.request('GET', '/api/state', headers={'Host': 'evil.example'})[0], 401)
        self.server.token = 'private-test-token'
        self.assertEqual(self.request('GET', '/api/state')[0], 401)
        self.assertEqual(self.request('POST', '/api/scan', {}, {'Authorization': 'Bearer wrong'})[0], 401)
        self.assertEqual(self.request('GET', '/api/state', headers={'Authorization': 'Bearer private-test-token'})[0], 200)

    def test_bad_requests_duplicate_and_missing_devices(self):
        self.assertEqual(self.request('POST', '/api/devices', {'ip': '8.8.8.8'})[0], 400)
        self.assertEqual(self.request('POST', '/api/devices', {'ip': '192.168.10.12'})[0], 201)
        self.assertEqual(self.request('POST', '/api/devices', {'ip': '192.168.10.12'})[0], 409)
        self.assertEqual(self.request('DELETE', '/api/devices/999')[0], 404)
        self.assertEqual(self.request('GET', '/api/devices/999/history')[0], 404)
        self.assertEqual(self.request('POST', '/api/scan', {'ranges': ['8.8.8.8']})[0], 400)
        self.assertEqual(self.request('GET', '/../../app.py')[0], 404)

    def test_static_assets(self):
        for path, content in [('/', b'A\xc4\x9fAtlas'), ('/app.js', b'renderRows'), ('/style.css', b'.sidebar')]:
            with self.subTest(path=path):
                status, body = self.request('GET', path)
                self.assertEqual(status, 200)
                self.assertIn(content, body)


class ProbeTests(unittest.TestCase):
    def test_real_tcp_response_and_closed_port(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            port = listener.getsockname()[1]
            with patch('app.shutil.which', return_value=None):
                data = probe('127.0.0.1', [port])
            self.assertTrue(data['reachable'])
            self.assertEqual(data['ports'], [port])
            self.assertGreaterEqual(data['latency'], 0)
        with patch('app.shutil.which', return_value=None):
            data = probe('127.0.0.1', [port])
        self.assertFalse(data['reachable'])
        self.assertIsNone(data['latency'])

    def test_windows_ping_arguments(self):
        with patch('app.platform.system', return_value='Windows'), patch('app.shutil.which', return_value='ping'), patch('app.subprocess.run') as run:
            run.return_value.returncode = 0
            data = probe('192.168.10.12', ports=[])
            self.assertTrue(data['reachable'])
            self.assertEqual(run.call_args.args[0], ['ping', '-n', '1', '-w', '1000', '192.168.10.12'])

    def test_socket_permission_failure_is_not_device_outage(self):
        with patch('app.socket.create_connection', side_effect=PermissionError):
            with self.assertRaises(RuntimeError):
                probe('192.168.10.12')


if __name__ == '__main__':
    unittest.main()
