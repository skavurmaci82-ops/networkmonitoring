"""MAC evidence, interface inventory, and LLDP neighbors (no inferred cables)."""
import ipaddress
import json
import platform
import re
import shutil
import subprocess
import time
import ctypes
import socket
import struct

from snmp import Client

IF = '1.3.6.1.2.1.2.2.1'
IP_IF = '1.3.6.1.2.1.4.20.1.2'
ARP = '1.3.6.1.2.1.4.22.1.2'
FDB = '1.3.6.1.2.1.17.4.3.1.2'
BRIDGE_IF = '1.3.6.1.2.1.17.1.4.1.2'
LLDP = '1.0.8802.1.1.2.1'
REM = LLDP + '.4.1.1'


class ForwardRoute(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in (
        'destination', 'mask', 'policy', 'next_hop', 'interface', 'type', 'protocol',
        'age', 'next_hop_as', 'metric1', 'metric2', 'metric3', 'metric4', 'metric5')]


def windows_arp(ip, helper=None):
    """Use Windows IP Helper directly, only for on-link IPv4 destinations.

    Routing is checked first so an upstream gateway MAC is never presented as
    the remote host's MAC. No SNMP, third-party driver or admin shell required.
    """
    if platform.system() != 'Windows' and helper is None:
        return {'mac': '', 'scope': 'unknown'}
    try:
        address = str(ipaddress.IPv4Address(ip))
        destination = struct.unpack('=I', socket.inet_aton(address))[0]
        if helper is None:
            helper = ctypes.WinDLL('iphlpapi', use_last_error=True)
            helper.GetBestRoute.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.POINTER(ForwardRoute)]
            helper.GetBestRoute.restype = ctypes.c_uint32
            helper.SendARP.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_uint32)]
            helper.SendARP.restype = ctypes.c_uint32
        route = ForwardRoute()
        if helper.GetBestRoute(destination, 0, ctypes.byref(route)) != 0:
            return {'mac': '', 'scope': 'unknown'}
        if route.next_hop != 0:
            return {'mac': '', 'scope': 'routed'}
        # IP Helper's PULONG output is conventionally two DWORDs (8 bytes),
        # while the requested Ethernet address length is six bytes.
        storage = (ctypes.c_uint32 * 2)()
        buffer = ctypes.cast(storage, ctypes.POINTER(ctypes.c_ubyte))
        length = ctypes.c_uint32(6)
        start = time.monotonic()
        code = helper.SendARP(destination, 0, buffer, ctypes.byref(length))
        mac = mac_address(ctypes.string_at(storage, 6)) if code == 0 and length.value == 6 else ''
        return {'mac': mac, 'scope': 'local', 'latency': round((time.monotonic()-start)*1000, 2)}
    except (OSError, AttributeError, ValueError):
        return {'mac': '', 'scope': 'unknown'}


def mac_address(value):
    if isinstance(value, bytes):
        if len(value) != 6:
            return ''
        raw = value
    elif isinstance(value, str):
        if not re.fullmatch(r'(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', value.strip()):
            return ''
        raw = bytes.fromhex(value.strip().replace(':', '').replace('-', ''))
    else:
        return ''
    if raw == b'\0' * 6 or raw[0] & 1:
        return ''  # Null, broadcast and multicast are not host identifiers.
    return ':'.join(f'{b:02X}' for b in raw)


def text(value):
    if isinstance(value, bytes):
        value = value.decode('utf-8', errors='replace')
    return ''.join(c for c in str(value or '') if c.isprintable())[:500]


def local_neighbors():
    """Read the OS cache after probes. A routed IP is never assigned a gateway MAC."""
    ip_tool = shutil.which('ip') if platform.system() == 'Linux' else None
    command = [ip_tool, '-j', 'neigh'] if ip_tool else [shutil.which('arp'), '-a']
    if not command[0]:
        return []
    try:
        result = subprocess.run(command, capture_output=True, timeout=5, check=False)
        if result.returncode:
            return []
        output = result.stdout.decode('utf-8', errors='replace')
        if ip_tool:
            rows = [(row.get('dst', ''), row.get('lladdr', '')) for row in json.loads(output)]
        else:
            rows = re.findall(r'(\d{1,3}(?:\.\d{1,3}){3})[^\r\n]*?((?:[\da-fA-F]{2}[:-]){5}[\da-fA-F]{2})', output)
        found = []
        for ip, mac in rows:
            normalized = mac_address(mac)
            try:
                if normalized and ipaddress.ip_address(ip).version == 4:
                    found.append({'ip': ip, 'mac': normalized, 'source': 'Yerel ARP/komşu tablosu'})
            except ValueError:
                pass
        return found
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return []


def inspect_network(ip, config, client_factory=Client):
    """Separate bounded collection; absent tables never become fictional links."""
    if not config.get('enabled') or not config.get('community'):
        return None
    client = client_factory(ip, config['community'], version=config.get('version', '2c'), budget=10)
    started = time.monotonic()
    result = {'interfaces': [], 'neighbors': [], 'arp': [], 'macs': [], 'chassis_id': '', 'forwarding': [],
              'lldp_status': 'unavailable', 'collection_limited': False}
    # Read LLDP before large interface/ARP tables to keep topology within budget.
    local = dict(client.query([LLDP + '.3.1.0', LLDP + '.3.2.0'], raw_octets=True))
    if local.get(LLDP + '.3.1.0') == 4:
        result['chassis_id'] = mac_address(local.get(LLDP + '.3.2.0'))
    remote_names = list(client.walk(REM + '.9', limit=128, raw_octets=True))
    remote_state = getattr(client, 'walk_status', {}).get(REM + '.9', 'unavailable')
    if remote_state == 'complete' and (remote_names or any(v is not None for v in local.values())):
        result['lldp_status'] = 'read'
    elif remote_names:
        result['lldp_status'] = 'partial'
    local_ports = {}
    for oid, name in client.walk(LLDP + '.3.7.1.3', limit=128, raw_octets=True):
        local_ports[oid.rsplit('.', 1)[-1]] = text(name)
    management = {}
    prefix = LLDP + '.4.2.1.3'
    for oid, _ in client.walk(prefix, limit=128):
        suffix = oid[len(prefix) + 1:].split('.')
        if len(suffix) == 9 and suffix[3:5] == ['1', '4']:
            try:
                management['.'.join(suffix[:3])] = str(ipaddress.IPv4Address('.'.join(suffix[5:])))
            except ValueError:
                pass
    for oid, name in remote_names:
        index = oid[len(REM + '.9') + 1:]
        parts = index.split('.')
        if len(parts) != 3:
            continue
        keys = {column: REM + f'.{column}.' + index for column in (4, 5, 6, 7, 8)}
        values = dict(client.query(list(keys.values()), raw_octets=True))
        chassis = values.get(keys[5])
        chassis_mac = mac_address(chassis) if values.get(keys[4]) == 4 else ''
        port = values.get(keys[7])
        remote_port = mac_address(port) if values.get(keys[6]) == 3 else text(port)
        result['neighbors'].append({'name': text(name), 'chassis_id': chassis_mac,
                                    'chassis_label': chassis_mac or text(chassis), 'management_ip': management.get(index, ''),
                                    'local_port': local_ports.get(parts[1], 'LLDP port ' + parts[1]),
                                    'remote_port': remote_port, 'port_description': text(values.get(keys[8])), 'source': 'LLDP'})
    own_ip_interfaces = dict(client.walk(IP_IF, limit=256))
    own_if = own_ip_interfaces.get(IP_IF + '.' + ip)
    physical = list(client.walk(IF + '.6', limit=128, raw_octets=True))
    for oid, value in physical:
        index = oid.rsplit('.', 1)[-1]
        mac = mac_address(value)
        attrs = {column: IF + f'.{column}.' + index for column in (2, 7, 8, 5)}
        values = dict(client.query(list(attrs.values()), raw_octets=True))
        result['interfaces'].append({'index': int(index), 'name': text(values.get(attrs[2])) or 'ifIndex ' + index,
                                      'mac': mac, 'admin_status': values.get(attrs[7]), 'oper_status': values.get(attrs[8]),
                                      'speed_bps': values.get(attrs[5])})
        if mac and str(own_if) == index:
            result['macs'].append(mac)
    for oid, value in client.walk(ARP, limit=512, raw_octets=True):
        parts = oid[len(ARP) + 1:].split('.')
        mac = mac_address(value)
        if len(parts) == 5 and mac:
            try:
                address = str(ipaddress.IPv4Address('.'.join(parts[1:])))
                result['arp'].append({'ip': address, 'mac': mac, 'source': 'SNMP ARP · ' + ip})
            except ValueError:
                pass
    bridge = dict(client.walk(BRIDGE_IF, limit=128))
    interface_names = {i['index']: i['name'] for i in result['interfaces']}
    for oid, port in client.walk(FDB, limit=512):
        parts = oid[len(FDB) + 1:].split('.')
        if len(parts) != 6 or not isinstance(port, int) or port <= 0:
            continue
        try:
            mac = mac_address(bytes(int(p) for p in parts))
        except ValueError:
            continue
        if mac:
            ifindex = bridge.get(BRIDGE_IF + '.' + str(port))
            result['forwarding'].append({'mac': mac, 'port': interface_names.get(ifindex, 'bridge port ' + str(port)), 'ifindex': ifindex})
    result['forwarding_status'] = getattr(client, 'walk_status', {}).get(FDB, 'unavailable')
    result['collection_limited'] = (len(remote_names) == 128 or len(physical) == 128 or len(result['arp']) == 512
                                    or 'limited' in getattr(client, 'walk_status', {}).values()
                                    or time.monotonic() - started >= 9.5)
    return result


def topology(devices):
    """Match LLDP using unique management IP, chassis MAC, or exact SNMP name."""
    nodes = [{'id': str(d['id']), 'device_id': d['id'], 'label': d['display_name'], 'ip': d['ip'],
              'model': d['display_model'], 'status': d['effective_status'], 'network': d['network']} for d in devices]
    by_ip = {d['ip']: str(d['id']) for d in devices}
    by_mac, by_name = {}, {}
    for d in devices:
        for mac in set(d.get('mac_addresses', []) + ([d['chassis_id']] if d.get('chassis_id') else [])):
            by_mac.setdefault(mac, set()).add(str(d['id']))
        if d.get('detected_name'):
            by_name.setdefault(d['detected_name'].casefold().rstrip('.'), set()).add(str(d['id']))
    edges, external, learned = [], {}, []
    for d in devices:
        for i, neighbor in enumerate(d.get('lldp_neighbors', [])):
            candidates = by_mac.get(neighbor.get('chassis_id'), set())
            names = by_name.get(neighbor.get('name', '').casefold().rstrip('.'), set())
            target = by_ip.get(neighbor.get('management_ip'))
            if not target and len(candidates) == 1:
                target = next(iter(candidates))
            if not target and len(names) == 1:
                target = next(iter(names))
            if target == str(d['id']):
                continue
            if not target:
                # Unknown neighbors are kept separate when identity is ambiguous.
                key = neighbor.get('chassis_id') or f'{d["id"]}:{i}'
                target = 'neighbor:' + key
                if target not in external:
                    external[target] = {'id': target, 'device_id': None, 'label': neighbor.get('name') or neighbor.get('chassis_label') or 'LLDP komşusu',
                                        'ip': neighbor.get('management_ip') or '', 'model': '', 'status': 'observed', 'network': 'LLDP komşuları'}
            edges.append({'source': str(d['id']), 'target': target, 'source_port': neighbor.get('local_port', ''),
                          'target_port': neighbor.get('remote_port', ''), 'evidence': 'LLDP', 'observed_at': d.get('lldp_checked_at'),
                          'stale': d.get('lldp_status') != 'read' or d['effective_status'] != 'online'})
        for entry in d.get('forwarding', []):
            candidates = by_mac.get(entry.get('mac'), set())
            if len(candidates) == 1:
                target = next(iter(candidates))
                if target != str(d['id']):
                    learned.append({'source': str(d['id']), 'target': target, 'source_port': entry.get('port', ''), 'target_port': entry['mac'],
                                    'evidence': 'BRIDGE-MIB MAC learning (not a cable)', 'observed_at': d.get('forwarding_checked_at'),
                                    'stale': d.get('forwarding_status') != 'complete' or d['effective_status'] != 'online'})
    nodes.extend(external.values())
    return {'nodes': nodes, 'edges': edges, 'learned_edges': learned, 'evidence': 'LLDP', 'unlinked': sum(not any(e['source'] == n['id'] or e['target'] == n['id'] for e in edges) for n in nodes)}
