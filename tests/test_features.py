import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from app import Store, connection_file, network_groups, probe
import test_app
from test_app import result


class FeatureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / 'features.sqlite3')

    def tearDown(self):
        self.temp.cleanup()

    def test_overlapping_networks_choose_most_specific_and_unassigned_retained(self):
        self.store.save_settings({'ranges': ['192.168.10.0/23', '192.168.10.0/24'], 'interval': 300})
        for ip in ['192.168.10.12', '192.168.11.20', '192.168.25.12']:
            self.store.record(result(ip))
        devices = self.store.devices()
        self.assertEqual([d['network'] for d in devices], ['192.168.10.0/24', '192.168.10.0/23', 'Diğer ağlar'])
        groups = network_groups(devices, self.store.settings()['ranges'])
        self.assertEqual(sum(g['total'] for g in groups), 3)
        self.assertTrue(all(g['online'] == 1 for g in groups))

    def test_old_results_are_stale_instead_of_online(self):
        self.store.record(result())
        with self.store.db() as db:
            db.execute("UPDATE devices SET last_checked='2000-01-01T00:00:00+00:00'")
        device = self.store.devices()[0]
        self.assertEqual(device['status'], 'online')
        self.assertEqual(device['effective_status'], 'stale')
        self.assertEqual(network_groups([device], [])[0]['stale'], 1)

    def test_snmp_inventory_and_manual_overrides_survive_new_scans(self):
        data = result()
        data['snmp'] = {'status': 'ok', 'model': 'Aruba 2930F', 'serial': 'TEST-123', 'manufacturer': 'Aruba',
                        'name': 'core-switch', 'description': 'Aruba test system', 'object_id': '1.3.6.1.4.1.11', 'uptime': 3600,
                        'source': 'SNMP ENTITY-MIB (chassis)'}
        self.store.record(data)
        device = self.store.devices()[0]
        self.assertEqual(device['display_model'], 'Aruba 2930F')
        self.assertEqual(device['display_name'], 'core-switch')
        self.assertEqual(device['agent_uptime'], 3600)
        self.store.save_device({'ip': data['ip'], 'name': 'Ana switch', 'model': 'Elle model', 'kind': 'Switch'}, device['id'])
        data['snmp']['model'] = 'Aruba refreshed'
        self.store.record(data)
        device = self.store.devices()[0]
        self.assertEqual(device['display_model'], 'Elle model')
        self.assertEqual(device['detected_model'], 'Aruba refreshed')
        self.assertEqual(device['display_model_source'], 'Elle girildi')
        self.assertEqual(device['display_name'], 'Ana switch')
        data['snmp'] = {'status': 'no_response'}
        self.store.record(data)
        self.assertEqual(self.store.devices()[0]['detected_model'], 'Aruba refreshed')

    def test_snmp_settings_hidden_preserved_and_validated(self):
        self.store.save_settings({'ranges': [], 'interval': 300, 'snmp_enabled': True, 'snmp_community': 'local-test-secret'})
        self.assertNotIn('local-test-secret', json.dumps(self.store.settings()))
        self.assertTrue(self.store.settings()['snmp_configured'])
        self.store.save_settings({'ranges': [], 'interval': 60, 'snmp_community': ''})
        self.assertEqual(self.store.snmp_settings()['community'], 'local-test-secret')
        self.assertTrue(self.store.snmp_settings()['enabled'])
        with self.assertRaises(ValueError):
            self.store.save_settings({'ranges': [], 'snmp_version': '3'})
        with self.assertRaises(ValueError):
            self.store.save_settings({'ranges': [], 'snmp_clear': True})
        self.store.save_settings({'ranges': [], 'snmp_enabled': False, 'snmp_clear': True})
        self.assertFalse(self.store.settings()['snmp_configured'])

    def test_existing_database_migrates_without_inventory_loss(self):
        path = Path(self.temp.name) / 'legacy.sqlite3'
        with sqlite3.connect(path) as db:
            db.executescript("""CREATE TABLE devices(id INTEGER PRIMARY KEY, ip TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL DEFAULT 'Diğer',os TEXT NOT NULL DEFAULT '',
                cpu TEXT NOT NULL DEFAULT '',ram TEXT NOT NULL DEFAULT '',model TEXT NOT NULL DEFAULT '',
                serial TEXT NOT NULL DEFAULT '',site TEXT NOT NULL DEFAULT '',owner TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',status TEXT NOT NULL DEFAULT 'unknown',latency REAL,ports TEXT NOT NULL DEFAULT '[]',
                first_seen TEXT NOT NULL,last_seen TEXT,last_checked TEXT,failures INTEGER NOT NULL DEFAULT 0);
                INSERT INTO devices(ip,name,model,first_seen) VALUES('192.168.10.12','Eski cihaz','Elle model','2026-01-01T00:00:00+00:00');
                CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                INSERT INTO settings VALUES('monitor','{"ranges":["192.168.10.0/23"],"interval":300}');""")
        restored = Store(path)
        self.assertEqual(restored.devices()[0]['name'], 'Eski cihaz')
        self.assertEqual(restored.devices()[0]['display_model'], 'Elle model')
        self.assertEqual(restored.settings()['ranges'], ['192.168.10.0/23'])
        Store(path)  # Migration is idempotent.

    def test_connection_files_and_ssh_injection_guard(self):
        device = {'ip': '192.168.10.12', 'ports': [22, 3389, 5901], 'ssh_user': 'admin'}
        body, name = connection_file(device, 'rdp')
        self.assertTrue(name.endswith('.rdp'))
        self.assertIn(b'full address:s:192.168.10.12:3389', body)
        self.assertIn(b'prompt for credentials:i:1', body)
        self.assertIn(b'ssh -l "admin" 192.168.10.12', connection_file(device, 'ssh')[0])
        self.assertIn(b'port=5901', connection_file(device, 'vnc')[0])
        device['ssh_user'] = 'admin & calc'
        with self.assertRaises(ValueError):
            connection_file(device, 'ssh')
        device['ports'] = []
        with self.assertRaises(RuntimeError):
            connection_file(device, 'rdp')

    def test_snmp_only_device_is_discovered(self):
        with patch('app.shutil.which', return_value=None), patch('app.inspect_network', return_value=None), patch('app.identify', return_value={'status': 'ok', 'model': 'Aruba', 'latency': 2}):
            data = probe('192.168.10.12', ports=[], snmp_config={'enabled': True, 'community': 'local-test'})
        self.assertTrue(data['reachable'])
        self.assertEqual(data['ports'], [])
        self.assertEqual(data['latency'], 2)


class FeatureHTTPTests(unittest.TestCase):
    setUp = test_app.HTTPTests.setUp
    tearDown = test_app.HTTPTests.tearDown
    request = test_app.HTTPTests.request

    def test_credential_never_returned_and_download_requires_auth(self):
        status, settings = self.request('PUT', '/api/settings', {'ranges': [], 'interval': 60, 'snmp_enabled': True, 'snmp_community': 'local-test-secret'})
        self.assertEqual(status, 200)
        self.assertNotIn('local-test-secret', json.dumps(settings))
        self.store.record(result(ports=[22, 3389, 5900]))
        device_id = self.store.devices()[0]['id']
        status, state = self.request('GET', '/api/state')
        self.assertNotIn('local-test-secret', json.dumps(state))
        self.assertNotIn(b'local-test-secret', self.request('GET', '/api/export')[1])
        self.assertEqual(self.request('GET', f'/api/devices/{device_id}/connect/rdp')[0], 200)
        self.server.token = 'test-access-token'
        self.assertEqual(self.request('GET', f'/api/devices/{device_id}/connect/rdp')[0], 401)
        self.assertEqual(self.request('GET', f'/api/devices/{device_id}/connect/rdp', headers={'Authorization': 'Bearer test-access-token'})[0], 200)


if __name__ == '__main__':
    unittest.main()
