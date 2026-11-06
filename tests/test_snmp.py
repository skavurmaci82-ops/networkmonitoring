import socket
import threading
import unittest

from snmp import (Client, ENTITY, HR_TYPE, MODEL, PRINTER, Reader, SYS_DESCR, SYS_NAME, SYS_OBJECT,
                  SYS_UPTIME, decode_oid, encode_oid, identify, integer, response_packet, tlv)


def response(community, version, request_id, bindings, error=0):
    rows = b''.join(tlv(0x30, encode_oid(oid) + tlv(tag, value)) for oid, tag, value in bindings)
    return tlv(0x30, integer(version) + tlv(4, community.encode()) + tlv(0xA2, integer(request_id) + integer(error) + integer(0) + tlv(0x30, rows)))


class SNMPTests(unittest.TestCase):
    def test_ber_lengths_oid_and_exception_values(self):
        oid = '1.3.6.1.4.1.99999.1000'
        self.assertEqual(decode_oid(Reader(encode_oid(oid)).read(6)[1]), oid)
        self.assertEqual(decode_oid(Reader(encode_oid('2.100.3')).read(6)[1]), '2.100.3')
        data = response('local-test', 1, 42, [(SYS_DESCR, 4, b'A' * 160), (SYS_OBJECT, 6, Reader(encode_oid(oid)).read(6)[1]), (SYS_NAME, 0x80, b'')])
        parsed = dict(response_packet(data, 'local-test', 1, 42))
        self.assertEqual(parsed[SYS_DESCR], 'A' * 160)
        self.assertEqual(parsed[SYS_OBJECT], oid)
        self.assertIsNone(parsed[SYS_NAME])

    def test_malformed_and_mismatched_responses_rejected(self):
        good = response('local-test', 1, 42, [(SYS_DESCR, 4, b'test')])
        for data in [b'', b'\x30\x80', good[:-1], good + b'junk', b'\x30\x84\xff\xff\xff\xff']:
            with self.subTest(data=data[:8]), self.assertRaises(ValueError):
                response_packet(data, 'local-test', 1, 42)
        for community, version, request_id in [('wrong', 1, 42), ('local-test', 0, 42), ('local-test', 1, 43)]:
            with self.assertRaises(ValueError):
                response_packet(good, community, version, request_id)
        self.assertEqual(response_packet(response('local-test', 0, 42, [], error=2), 'local-test', 0, 42), [])

    def test_real_udp_exchange_and_request_id_validation(self):
        errors = []
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.bind(('127.0.0.1', 0))
            server.settimeout(3)
            def answer():
                try:
                    packet, address = server.recvfrom(16384)
                    root = Reader(Reader(packet).read(0x30)[1])
                    version = root.number()
                    community = root.read(4)[1].decode()
                    pdu = Reader(root.read(0xA0)[1])
                    request_id = pdu.number()
                    server.sendto(response(community, version, request_id + 1, [(SYS_DESCR, 4, b'wrong response')]), address)
                    server.sendto(response(community, version, request_id, [(SYS_DESCR, 4, b'Aruba test agent')]), address)
                except Exception as exc:
                    errors.append(exc)
            thread = threading.Thread(target=answer)
            thread.start()
            client = Client('127.0.0.1', 'local-test', port=server.getsockname()[1], timeout=1)
            self.assertEqual(dict(client.query([SYS_DESCR]))[SYS_DESCR], 'Aruba test agent')
            thread.join(4)
            self.assertFalse(thread.is_alive())
            self.assertFalse(errors)

    def test_chassis_model_preferred_over_module_and_serial_from_mib(self):
        class Agent:
            def __init__(self, *args, **kwargs):
                pass

            def query(self, oids, next_value=False):
                values = {SYS_DESCR: 'Aruba operating system', SYS_OBJECT: '1.3.6.1.4.1.11', SYS_UPTIME: 360000, SYS_NAME: 'core-switch',
                          ENTITY + '.5.1': 9, ENTITY + '.11.1': 'MODULE', ENTITY + '.12.1': 'Aruba',
                          ENTITY + '.5.2': 3, ENTITY + '.11.2': 'CHASSIS', ENTITY + '.12.2': 'Aruba'}
                return [(oid, values.get(oid)) for oid in oids]

            def walk(self, prefix, limit=12):
                if prefix == MODEL:
                    yield MODEL + '.1', 'Transceiver module'
                    yield MODEL + '.2', 'JL256A 2930F-48G-PoE+-4SFP+'
        result = identify('192.168.10.12', {'enabled': True, 'community': 'local-test'}, Agent)
        self.assertEqual(result['model'], 'JL256A 2930F-48G-PoE+-4SFP+')
        self.assertEqual(result['serial'], 'CHASSIS')
        self.assertEqual(result['manufacturer'], 'Aruba')
        self.assertEqual(result['uptime'], 3600)
        self.assertEqual(result['name'], 'core-switch')

    def test_printer_model_fallback_uses_printer_device_type(self):
        class Agent:
            def __init__(self, *args, **kwargs):
                pass

            def query(self, oids, next_value=False):
                return [(oid, 'HP LaserJet M404dn' if oid.endswith('.25.3.2.1.3.7') else 'HP SNMP agent' if oid == SYS_DESCR else None) for oid in oids]

            def walk(self, prefix, limit=12):
                if prefix == HR_TYPE:
                    yield HR_TYPE + '.1', '1.3.6.1.2.1.25.3.1.3'  # CPU, not printer.
                    yield HR_TYPE + '.7', PRINTER
        result = identify('192.168.10.12', {'enabled': True, 'community': 'local-test'}, Agent)
        self.assertEqual(result['model'], 'HP LaserJet M404dn')
        self.assertIn('printer', result['source'])

    def test_v1_missing_optional_fields_does_not_hide_chassis_model(self):
        class Agent:
            def __init__(self, *args, **kwargs):
                pass

            def query(self, oids, next_value=False):
                if oids == [ENTITY + '.5.1']:
                    return [(oids[0], 3)]
                if len(oids) == 4:
                    return [(SYS_DESCR, 'Legacy switch')]
                return []  # Simulate v1 noSuchName for optional serial/vendor.

            def walk(self, prefix, limit=12):
                if prefix == MODEL:
                    yield MODEL + '.1', 'Legacy chassis model'
        result = identify('192.168.10.12', {'enabled': True, 'version': '1', 'community': 'local-test'}, Agent)
        self.assertEqual(result['model'], 'Legacy chassis model')
        self.assertEqual(result['serial'], '')

    def test_missing_model_not_invented_and_disabled_does_not_query(self):
        class Agent:
            def __init__(self, *args, **kwargs):
                pass

            def query(self, oids, next_value=False):
                return [(SYS_DESCR, 'Linux hostname kernel x86_64')]

            def walk(self, prefix, limit=12):
                return iter([])
        result = identify('192.168.10.12', {'enabled': True, 'community': 'local-test'}, Agent)
        self.assertEqual(result['status'], 'ok')
        self.assertNotIn('model', result)
        def unexpected(*args, **kwargs):
            self.fail('Disabled SNMP must not send a request')
        self.assertEqual(identify('192.168.10.12', {}, unexpected)['status'], 'not_configured')

    def test_walk_stops_on_repeated_oid(self):
        class Agent(Client):
            calls = 0
            def query(self, oids, next_value=False, **kwargs):
                self.calls += 1
                return [(MODEL + '.1', 'test')]
        agent = Agent('127.0.0.1', 'local-test')
        self.assertEqual(list(agent.walk(MODEL)), [(MODEL + '.1', 'test')])
        self.assertEqual(agent.calls, 2)

    def test_bulk_walk_yields_all_rows_and_marks_a_complete_table(self):
        class Agent(Client):
            calls = 0
            def query(self, oids, **kwargs):
                self.calls += 1
                self.used_bulk = kwargs.get('bulk')
                return [(MODEL+'.1','one'),(MODEL+'.2','two'),('1.3.6.1.2.1.48.1','outside')]
        agent = Agent('127.0.0.1','test')
        self.assertEqual(list(agent.walk(MODEL)),[(MODEL+'.1','one'),(MODEL+'.2','two')])
        self.assertTrue(agent.used_bulk)
        self.assertEqual(agent.calls,1)
        self.assertEqual(agent.walk_status[MODEL],'complete')


if __name__ == '__main__':
    unittest.main()
