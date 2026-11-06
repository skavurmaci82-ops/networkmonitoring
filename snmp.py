"""Bounded, read-only SNMP v1/v2c queries using Python's standard library.

Only GET and GETNEXT are implemented. No SET, login, or community guessing.
"""
import secrets
import socket
import time

SYS_DESCR = '1.3.6.1.2.1.1.1.0'
SYS_OBJECT = '1.3.6.1.2.1.1.2.0'
SYS_UPTIME = '1.3.6.1.2.1.1.3.0'
SYS_NAME = '1.3.6.1.2.1.1.5.0'
ENTITY = '1.3.6.1.2.1.47.1.1.1.1'
MODEL = ENTITY + '.13'
HR_TYPE = '1.3.6.1.2.1.25.3.2.1.2'
PRINTER = '1.3.6.1.2.1.25.3.1.5'
ENTERPRISE_VENDORS = {9: 'Cisco', 11: 'HPE', 232: 'HPE', 674: 'Dell', 6876: 'VMware',
                      14823: 'Aruba', 2636: 'Juniper', 12356: 'Fortinet', 14988: 'MikroTik',
                      2435: 'Brother', 1602: 'Canon', 253: 'Xerox'}


def tlv(tag, value):
    n = len(value)
    length = bytes([n]) if n < 128 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([tag]) + length + value


def integer(value):
    if value < 0:
        raise ValueError('Negative request integer')
    return tlv(2, value.to_bytes(max(1, (value.bit_length() + 8) // 8), 'big'))


def base128(value):
    parts = [value & 127]
    while value > 127:
        value >>= 7
        parts.insert(0, 128 | (value & 127))
    return bytes(parts)


def encode_oid(oid):
    parts = tuple(int(p) for p in oid.split('.'))
    if len(parts) < 2 or parts[0] not in (0, 1, 2) or parts[1] < 0 or (parts[0] < 2 and parts[1] > 39) or any(p < 0 for p in parts):
        raise ValueError('Invalid OID')
    return tlv(6, b''.join(base128(p) for p in (40 * parts[0] + parts[1], *parts[2:])))


def decode_oid(data):
    parts, value = [], 0
    if not data:
        raise ValueError('Empty OID')
    for byte in data:
        value = value * 128 + (byte & 127)
        if value.bit_length() > 64:
            raise ValueError('OID too large')
        if not byte & 128:
            parts.append(value)
            value = 0
    if data[-1] & 128:
        raise ValueError('Truncated OID')
    first = min(parts[0] // 40, 2)
    return '.'.join(map(str, (first, parts[0] - first * 40, *parts[1:])))


class Reader:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def read(self, expected=None):
        if self.pos + 2 > len(self.data):
            raise ValueError('Truncated BER')
        tag, length = self.data[self.pos:self.pos + 2]
        self.pos += 2
        if length & 128:
            count = length & 127
            if not 1 <= count <= 4 or self.pos + count > len(self.data):
                raise ValueError('Invalid BER length')
            length = int.from_bytes(self.data[self.pos:self.pos + count], 'big')
            self.pos += count
        if length > len(self.data) - self.pos or expected is not None and tag != expected:
            raise ValueError('Invalid BER value')
        value = self.data[self.pos:self.pos + length]
        self.pos += length
        return tag, value

    def number(self):
        data = self.read(2)[1]
        if not 1 <= len(data) <= 8:
            raise ValueError('Invalid integer')
        return int.from_bytes(data, 'big', signed=True)

    def end(self):
        if self.pos != len(self.data):
            raise ValueError('Unexpected BER data')


def request_packet(oids, community, version, request_id, operation=0xA0, repetitions=0):
    bindings = b''.join(tlv(0x30, encode_oid(oid) + tlv(5, b'')) for oid in oids)
    pdu = tlv(operation, integer(request_id) + integer(0) + integer(repetitions) + tlv(0x30, bindings))
    return tlv(0x30, integer(version) + tlv(4, community.encode()) + pdu)


def response_packet(data, community, version, request_id, raw_octets=False):
    root = Reader(data)
    message = Reader(root.read(0x30)[1])
    root.end()
    if message.number() != version or message.read(4)[1] != community.encode():
        raise ValueError('Unmatched SNMP message')
    pdu = Reader(message.read(0xA2)[1])
    message.end()
    if pdu.number() != request_id:
        raise ValueError('Unmatched request ID')
    error, _ = pdu.number(), pdu.number()
    bindings = Reader(pdu.read(0x30)[1])
    pdu.end()
    if error:
        return []  # v1 noSuchName and other agent errors are not model data.
    result = []
    while bindings.pos < len(bindings.data):
        if len(result) >= 64:
            raise ValueError('Too many bindings')
        binding = Reader(bindings.read(0x30)[1])
        oid = decode_oid(binding.read(6)[1])
        tag, value = binding.read()
        binding.end()
        if tag == 4:
            if not raw_octets:
                value = value.decode('utf-8', errors='replace').strip('\x00 \r\n')[:2000]
        elif tag == 6:
            value = decode_oid(value)
        elif tag in (2, 0x41, 0x42, 0x43, 0x46):
            if not 1 <= len(value) <= 9:
                raise ValueError('Invalid numeric value')
            value = int.from_bytes(value, 'big', signed=tag == 2)
        else:
            value = None
        result.append((oid, value))
    return result


class Client:
    def __init__(self, ip, community, version='2c', port=161, timeout=.65, budget=4):
        self.ip, self.community = ip, community
        self.version = 0 if version == '1' else 1
        self.port, self.timeout = port, timeout
        self.deadline = time.monotonic() + budget
        self.walk_status = {}

    def query(self, oids, next_value=False, raw_octets=False, bulk=False):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            return []
        request_id = secrets.randbelow(0x7ffffffe) + 1
        operation = 0xA5 if bulk else 0xA1 if next_value else 0xA0
        packet = request_packet(oids, self.community, self.version, request_id, operation, repetitions=16 if bulk else 0)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(min(self.timeout, remaining))
                sock.connect((self.ip, self.port))
                sock.send(packet)
                # Connected UDP pins the response source to the configured IP/port.
                for _ in range(3):
                    remaining = self.deadline - time.monotonic()
                    if remaining <= 0:
                        return []
                    sock.settimeout(min(self.timeout, remaining))
                    data = sock.recv(16384)
                    try:
                        values = response_packet(data, self.community, self.version, request_id, raw_octets=raw_octets)
                        if not next_value and not bulk and [o for o, _ in values] != list(oids):
                            continue
                        return values
                    except ValueError:
                        continue
        except PermissionError:
            raise RuntimeError('İzleme işleminin UDP bağlantısı açma izni yok.') from None
        except OSError:
            pass
        return []

    def walk(self, prefix, limit=12, raw_octets=False):
        current = prefix
        self.walk_status[prefix] = 'limited'
        count = 0
        while count < limit:
            options = {'next_value': True}
            if raw_octets:
                options['raw_octets'] = True
            if self.version == 1:
                options['bulk'] = True
            values = self.query([current], **options)
            if not values and options.pop('bulk', False):
                values = self.query([current], **options)
            if not values:
                self.walk_status[prefix] = 'unavailable'
                break
            for oid, value in values:
                if not oid.startswith(prefix + '.') or value is None:
                    self.walk_status[prefix] = 'complete'
                    return
                if tuple(map(int, oid.split('.'))) <= tuple(map(int, current.split('.'))):
                    self.walk_status[prefix] = 'invalid'
                    return
                yield oid, value
                current = oid
                count += 1
                if count >= limit:
                    return


def identify(ip, config, client_factory=Client):
    """Return confirmed identity fields; never infer a hardware model from a port."""
    if not config.get('enabled') or not config.get('community'):
        return {'status': 'not_configured'}
    client = client_factory(ip, config['community'], version=config.get('version', '2c'))
    start = time.monotonic()
    system = dict(client.query([SYS_DESCR, SYS_OBJECT, SYS_UPTIME, SYS_NAME]))
    if not any(value is not None for value in system.values()):
        return {'status': 'no_response'}
    result = {'status': 'ok', 'description': str(system.get(SYS_DESCR) or '')[:2000],
              'name': str(system.get(SYS_NAME) or '')[:200], 'object_id': str(system.get(SYS_OBJECT) or '')[:200],
              'latency': round((time.monotonic() - start) * 1000, 2)}
    uptime = system.get(SYS_UPTIME)
    result['uptime'] = uptime // 100 if isinstance(uptime, int) and uptime >= 0 else None
    parts = result['object_id'].split('.')
    if parts[:6] == ['1', '3', '6', '1', '4', '1'] and len(parts) > 6 and parts[6].isdigit():
        vendor = ENTERPRISE_VENDORS.get(int(parts[6]))
        if vendor:
            result['manufacturer'] = vendor
            result['manufacturer_source'] = 'SNMP sysObjectID enterprise'
    candidates = []
    for oid, model in client.walk(MODEL):
        if not isinstance(model, str) or not model.strip():
            continue
        suffix = oid[len(MODEL):]
        physical_class = dict(client.query([ENTITY + '.5' + suffix])).get(ENTITY + '.5' + suffix)
        if physical_class == 3:
            # v1 rejects a whole multi-OID request if an optional field is absent.
            # Keep the authoritative class/model independent of optional fields.
            attributes = dict(client.query([ENTITY + column + suffix for column in ('.11', '.12')]))
            candidates.append((True, model, attributes.get(ENTITY + '.11' + suffix), attributes.get(ENTITY + '.12' + suffix)))
            break
    # A chassis is authoritative. A single other physical row may be a module:
    # do not present it as the entire device's model.
    chassis = next((c for c in candidates if c[0]), None)
    if chassis:
        _, model, serial, manufacturer = chassis
        result.update(model=model[:200], serial=str(serial or '')[:200], manufacturer=str(manufacturer or result.get('manufacturer', ''))[:200], source='SNMP ENTITY-MIB (chassis)')
        if manufacturer:
            result['manufacturer_source'] = 'SNMP ENTITY-MIB'
    else:
        for oid, device_type in client.walk(HR_TYPE, limit=8):
            if device_type == PRINTER:
                suffix = oid[len(HR_TYPE):]
                descr_oid = '1.3.6.1.2.1.25.3.2.1.3' + suffix
                descr = dict(client.query([descr_oid])).get(descr_oid)
                if isinstance(descr, str) and descr.strip():
                    result.update(model=descr[:200], source='SNMP HOST-RESOURCES-MIB (printer)')
                break
    return result
