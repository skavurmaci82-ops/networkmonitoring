import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app import Store, network_groups
from discovery import ARP, IF, IP_IF, LLDP, REM, inspect_network, local_neighbors, mac_address, topology
from snmp import Reader, encode_oid, integer, response_packet, tlv
from test_app import result


class DiscoveryTests(unittest.TestCase):
    def test_binary_mac_is_preserved_and_invalid_macs_rejected(self):
        raw = bytes.fromhex('000b86001234')
        self.assertEqual(mac_address(raw), '00:0B:86:00:12:34')
        self.assertEqual(mac_address('00-0b-86-00-12-34'), '00:0B:86:00:12:34')
        for value in [b'\0'*6, 'ff:ff:ff:ff:ff:ff', '01:00:5e:00:00:01', 'not a mac', None]:
            self.assertEqual(mac_address(value), '')
        binding = tlv(0x30, encode_oid(IF + '.6.1') + tlv(4, raw))
        packet = tlv(0x30, integer(1) + tlv(4, b'test') + tlv(0xA2, integer(7) + integer(0) + integer(0) + tlv(0x30, binding)))
        self.assertEqual(response_packet(packet, 'test', 1, 7, raw_octets=True)[0][1], raw)

    def test_windows_arp_cache_does_not_assign_gateway_mac_to_other_ips(self):
        output = b'Interface: 192.168.10.5 --- 0x9\r\n  192.168.10.1  00-0b-86-00-12-34 dynamic\r\n  192.168.10.255 ff-ff-ff-ff-ff-ff static\r\n'
        with patch('discovery.platform.system', return_value='Windows'), patch('discovery.shutil.which', return_value='arp'), patch('discovery.subprocess.run') as run:
            run.return_value.stdout, run.return_value.returncode = output, 0
            rows = local_neighbors()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['ip'], '192.168.10.1')
        self.assertNotIn('192.168.100.10', [r['ip'] for r in rows])

    def test_lldp_interface_and_routed_arp_collection(self):
        chassis = bytes.fromhex('000b86001234')
        peer = bytes.fromhex('000b86005678')
        class Agent:
            def __init__(self, *args, **kwargs):
                self.walk_status = {REM + '.9': 'complete'}

            def query(self, oids, **kwargs):
                values = {LLDP + '.3.1.0': 4, LLDP + '.3.2.0': chassis,
                          REM + '.4.0.7.1': 4, REM + '.5.0.7.1': peer, REM + '.6.0.7.1': 5,
                          REM + '.7.0.7.1': b'1/1/24', REM + '.8.0.7.1': b'Uplink',
                          IF + '.2.5': b'VLAN 10', IF + '.7.5': 1, IF + '.8.5': 1, IF + '.5.5': 1000000000}
                return [(oid, values.get(oid)) for oid in oids]

            def walk(self, prefix, **kwargs):
                values = {REM + '.9': [(REM + '.9.0.7.1', b'access-switch')],
                          LLDP + '.3.7.1.3': [(LLDP + '.3.7.1.3.7', b'1/1/7')],
                          LLDP + '.4.2.1.3': [(LLDP + '.4.2.1.3.0.7.1.1.4.192.168.100.2', 2)],
                          IP_IF: [(IP_IF + '.192.168.10.1', 5)], IF + '.6': [(IF + '.6.5', chassis)],
                          ARP: [(ARP + '.5.192.168.10.20', peer)]}
                return iter(values.get(prefix, []))
        data = inspect_network('192.168.10.1', {'enabled': True, 'community': 'test'}, Agent)
        self.assertEqual(data['macs'], ['00:0B:86:00:12:34'])
        self.assertEqual(data['neighbors'][0]['local_port'], '1/1/7')
        self.assertEqual(data['neighbors'][0]['remote_port'], '1/1/24')
        self.assertEqual(data['neighbors'][0]['management_ip'], '192.168.100.2')
        self.assertEqual(data['interfaces'][0]['oper_status'], 1)
        self.assertEqual(data['arp'][0]['ip'], '192.168.10.20')


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / 'evidence.sqlite3')

    def tearDown(self):
        self.temp.cleanup()

    def seed(self):
        self.store.record(result('192.168.10.1'))
        self.store.record(result('192.168.10.2'))

    def test_cache_only_device_is_not_online_and_scope_is_respected(self):
        self.store.observe_macs([{'ip': '192.168.10.2', 'mac': '00:0b:86:00:12:34'}, {'ip': '192.168.100.2', 'mac': '00:0b:86:00:56:78'}], {'192.168.10.2'})
        devices = self.store.devices()
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]['effective_status'], 'observed')
        self.assertIsNone(devices[0]['last_seen'])
        self.assertEqual(network_groups(devices, [])[0]['observed'], 1)
        self.assertEqual(self.store.history(devices[0]['id']), [])

    def test_subnet_membership_never_creates_a_topology_edge(self):
        self.seed()
        graph = topology(self.store.devices())
        self.assertEqual(len(graph['nodes']), 2)
        self.assertEqual(graph['edges'], [])

    def test_forwarding_table_is_a_learned_relation_not_a_physical_link(self):
        self.seed()
        self.store.observe_macs([{'ip': '192.168.10.2', 'mac': '00:0b:86:00:56:78'}], {'192.168.10.2'})
        data = result('192.168.10.1')
        data['network_detail'] = {'interfaces': [], 'neighbors': [], 'lldp_status': 'read',
                                  'forwarding': [{'mac': '00:0B:86:00:56:78', 'port': '1/1/7'}], 'forwarding_status': 'complete'}
        self.store.record(data)
        graph = topology(self.store.devices())
        self.assertEqual(graph['edges'], [])
        self.assertEqual(len(graph['learned_edges']), 1)
        self.assertIn('not a cable', graph['learned_edges'][0]['evidence'])
        self.assertEqual(graph['learned_edges'][0]['source_port'], '1/1/7')

    def test_lldp_matches_mac_with_ports_and_unknown_neighbors_remain_unknown(self):
        self.seed()
        self.store.observe_macs([{'ip': '192.168.10.2', 'mac': '00:0b:86:00:56:78'}], {'192.168.10.2'})
        data = result('192.168.10.1')
        data['network_detail'] = {'interfaces': [], 'neighbors': [{'chassis_id': '00:0B:86:00:56:78', 'name': 'access', 'local_port': '1/1/7', 'remote_port': '1/1/24'},
                                                  {'name': 'unidentified', 'local_port': '1/1/8', 'remote_port': 'eth0'}],
                                   'lldp_status': 'read', 'chassis_id': '', 'macs': [], 'collection_limited': False}
        self.store.record(data)
        graph = topology(self.store.devices())
        self.assertEqual(len(graph['edges']), 2)
        self.assertEqual(graph['edges'][0]['target'], str(self.store.devices()[1]['id']))
        self.assertEqual(graph['edges'][0]['source_port'], '1/1/7')
        self.assertEqual(graph['edges'][0]['evidence'], 'LLDP')
        self.assertEqual(graph['nodes'][-1]['status'], 'observed')
        self.assertIsNone(graph['nodes'][-1]['device_id'])
        self.assertFalse(graph['edges'][0]['stale'])

    def test_failed_lldp_read_keeps_old_timestamp_and_marks_edges_stale(self):
        self.seed()
        data = result('192.168.10.1')
        data['network_detail'] = {'interfaces': [], 'neighbors': [{'name': 'old-peer', 'local_port': '7'}], 'lldp_status': 'read'}
        self.store.record(data)
        old_time = self.store.devices()[0]['lldp_checked_at']
        data['network_detail'] = None
        data['snmp'] = {'status': 'no_response'}
        self.store.record(data)
        graph = topology(self.store.devices())
        self.assertEqual(graph['edges'][0]['observed_at'], old_time)
        self.assertTrue(graph['edges'][0]['stale'])

    def test_duplicate_names_do_not_merge_distinct_devices(self):
        for ip in ['192.168.10.1', '192.168.10.2', '192.168.10.3']:
            data = result(ip)
            data['snmp'] = {'status': 'ok', 'name': 'duplicate'}
            self.store.record(data)
        data = result('192.168.10.1')
        data['network_detail'] = {'interfaces': [], 'neighbors': [{'name': 'duplicate', 'local_port': '7'}], 'lldp_status': 'read'}
        self.store.record(data)
        graph = topology(self.store.devices())
        self.assertTrue(graph['edges'][0]['target'].startswith('neighbor:'))


if __name__ == '__main__':
    unittest.main()
