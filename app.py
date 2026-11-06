#!/usr/bin/env python3
"""AğAtlas — dependency-free, local network inventory and monitoring."""
import argparse
import csv
import hmac
import io
import ipaddress
import json
import logging
import os
import platform
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from snmp import identify
from discovery import inspect_network, local_neighbors, mac_address, topology, windows_arp
from gateway import session_url
import vendors
from profiles import Profiles
import collectors

ROOT = Path(__file__).resolve().parent
PRIVATE = tuple(ipaddress.ip_network(x) for x in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
PORTS = {22: 'SSH', 80: 'HTTP', 135: 'Windows RPC / WMI', 443: 'HTTPS / Aruba / VMware', 445: 'SMB', 3389: 'RDP', 5985: 'WinRM', 5986: 'WinRM HTTPS', 5900: 'VNC', 5901: 'VNC :1', 5902: 'VNC :2', 902: 'VMware', 8006: 'Proxmox', 9100: 'Yazıcı', 631: 'IPP', 515: 'LPD', 8080: 'HTTP alternatif'}
FIELDS = ('name', 'kind', 'os', 'cpu', 'ram', 'model', 'serial', 'site', 'owner', 'notes', 'ssh_user')
IDENTITY_COLUMNS = {'detected_model': "TEXT NOT NULL DEFAULT ''", 'detected_serial': "TEXT NOT NULL DEFAULT ''",
                    'detected_name': "TEXT NOT NULL DEFAULT ''", 'manufacturer': "TEXT NOT NULL DEFAULT ''",
                    'sys_description': "TEXT NOT NULL DEFAULT ''", 'sys_object_id': "TEXT NOT NULL DEFAULT ''",
                    'model_source': "TEXT NOT NULL DEFAULT ''", 'snmp_checked_at': 'TEXT',
                    'snmp_status': "TEXT NOT NULL DEFAULT 'not_configured'", 'agent_uptime': 'INTEGER',
                    'ssh_user': "TEXT NOT NULL DEFAULT ''", 'mac_addresses': "TEXT NOT NULL DEFAULT '[]'",
                    'mac_source': "TEXT NOT NULL DEFAULT ''", 'mac_checked_at': 'TEXT',
                    'interfaces': "TEXT NOT NULL DEFAULT '[]'", 'lldp_neighbors': "TEXT NOT NULL DEFAULT '[]'",
                    'chassis_id': "TEXT NOT NULL DEFAULT ''", 'network_checked_at': 'TEXT',
                    'network_status': "TEXT NOT NULL DEFAULT 'not_configured'", 'lldp_status': "TEXT NOT NULL DEFAULT 'unavailable'", 'lldp_checked_at': 'TEXT',
                    'forwarding': "TEXT NOT NULL DEFAULT '[]'", 'forwarding_status': "TEXT NOT NULL DEFAULT 'unavailable'", 'forwarding_checked_at': 'TEXT',
                    'mac_status': "TEXT NOT NULL DEFAULT 'unknown'", 'collected_os': "TEXT NOT NULL DEFAULT ''",
                    'collected_cpu': "TEXT NOT NULL DEFAULT ''", 'collected_ram': "TEXT NOT NULL DEFAULT ''",
                    'metrics': "TEXT NOT NULL DEFAULT '{}'", 'metrics_checked_at': 'TEXT', 'metrics_success_at': 'TEXT',
                    'collector_status': "TEXT NOT NULL DEFAULT 'not_configured'", 'collector_error': "TEXT NOT NULL DEFAULT ''"}


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def analyze_metrics(data):
    issues=[]
    for key,label in [('cpu_percent','CPU'),('memory_percent','RAM')]:
        value=data.get(key)
        if isinstance(value,(int,float)) and value>=90:
            issues.append({'code':key,'message':f'{label} kullanımı yüksek: %{value:g}'})
    for disk in data.get('disks',[]):
        if disk.get('used_percent',0)>=90:
            issues.append({'code':'disk:'+disk['name'],'message':f"Disk doluluğu yüksek: {disk['name']} %{disk['used_percent']:g}"})
    for interface in data.get('network',[])+data.get('interfaces',[]):
        if interface.get('new_errors',0)>0:
            issues.append({'code':'errors:'+interface['name'],'message':f"Arayüzde yeni paket hatası: {interface['name']}"})
        speed=interface.get('speed_bps')
        if speed and max(interface.get('rx_bps') or 0,interface.get('tx_bps') or 0)>=speed*.9:
            issues.append({'code':'bandwidth:'+interface['name'],'message':f"Arayüz kapasiteye yakın: {interface['name']}"})
    return issues


def counter_rates(metrics,previous):
    epoch=time.time();metrics['sample_epoch']=epoch
    elapsed=epoch-previous.get('sample_epoch',epoch)
    old={str(v.get('index',v.get('name'))):v for v in previous.get('network',[])}
    for row in metrics.get('network',[]):
        before=old.get(str(row.get('index',row.get('name'))))
        if not before or elapsed<=0 or 'counter_rx' not in row:
            continue
        reset=(metrics.get('uptime_ticks',0)<previous.get('uptime_ticks',0) or
               row.get('counter_discontinuity')!=before.get('counter_discontinuity'))
        for key,direction in [('counter_rx','rx_bps'),('counter_tx','tx_bps')]:
            value,prior=row.get(key),before.get(key)
            if reset or value is None or prior is None or value<prior:
                row['counter_reset']=True
                continue
            rate=round((value-prior)*8/elapsed,1)
            if row.get('speed_bps') and rate>row['speed_bps']*1.2:
                row['counter_reset']=True
                continue
            row[direction]=rate
        errors,prior=row.get('counter_errors'),before.get('counter_errors')
        if not reset and errors is not None and prior is not None and errors>=prior:
            row['new_errors']=errors-prior


def network(value):
    try:
        net = ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError:
        raise ValueError('Geçerli bir IPv4 adresi veya CIDR ağı girin.') from None
    if net.version != 4 or not any(net.subnet_of(p) for p in PRIVATE):
        raise ValueError('Yalnızca özel IPv4 ağları desteklenir (10/8, 172.16/12, 192.168/16).')
    if net.num_addresses > 1024:
        raise ValueError('Her ağ en fazla 1024 adres içerebilir (/22 veya daha dar).')
    return net


def ip_value(value):
    net = network(value)
    if net.prefixlen != 32:
        raise ValueError('Tek bir IPv4 adresi girin.')
    return str(net.network_address)


def group_for_ip(ip, ranges):
    address = ipaddress.ip_address(ip)
    matches = [network(r) for r in ranges if address in network(r)]
    return str(max(matches, key=lambda n: n.prefixlen)) if matches else 'Diğer ağlar'


def network_groups(devices, ranges):
    groups = {cidr: {'network': cidr, 'total': 0, 'online': 0, 'unreachable': 0, 'degraded': 0, 'unknown': 0, 'stale': 0, 'observed': 0} for cidr in ranges}
    for device in devices:
        name = device['network']
        group = groups.setdefault(name, {'network': name, 'total': 0, 'online': 0, 'unreachable': 0, 'degraded': 0, 'unknown': 0, 'stale': 0, 'observed': 0})
        group['total'] += 1
        group[device['effective_status']] += 1
    return list(groups.values())


def connection_file(device, protocol):
    ip = ip_value(device['ip'])
    ports = device['ports']
    if protocol == 'rdp' and 3389 in ports:
        content = f'full address:s:{ip}:3389\r\nprompt for credentials:i:1\r\nauthentication level:i:2\r\nscreen mode id:i:2\r\n'
        return content.encode('utf-8'), f'{ip}.rdp'
    if protocol == 'ssh' and 22 in ports:
        user = device.get('ssh_user', '')
        if any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-@\\' for c in user):
            raise ValueError('Geçersiz SSH kullanıcı adı.')
        login = f'-l "{user}" ' if user else ''
        content = f'@echo off\r\nssh {login}{ip}\r\npause\r\n'
        return content.encode('ascii'), f'SSH-{ip}.cmd'
    if protocol == 'vnc':
        port = next((p for p in (5900, 5901, 5902) if p in ports), None)
        if port:
            return f'[connection]\r\nhost={ip}\r\nport={port}\r\n'.encode('ascii'), f'{ip}.vnc'
    raise RuntimeError('Bu servisin portu son kontrolde açık bulunamadı.')


class Store:
    def __init__(self, path):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.db() as db:
            db.executescript('''
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY, ip TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL DEFAULT 'Diğer',
                    os TEXT NOT NULL DEFAULT '', cpu TEXT NOT NULL DEFAULT '', ram TEXT NOT NULL DEFAULT '',
                    model TEXT NOT NULL DEFAULT '', serial TEXT NOT NULL DEFAULT '',
                    site TEXT NOT NULL DEFAULT '', owner TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'unknown', latency REAL, ports TEXT NOT NULL DEFAULT '[]',
                    first_seen TEXT NOT NULL, last_seen TEXT, last_checked TEXT, failures INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS checks (
                    id INTEGER PRIMARY KEY, device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
                    checked_at TEXT NOT NULL, reachable INTEGER NOT NULL, latency REAL, ports TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS checks_device ON checks(device_id, id);
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY, device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
                    ip TEXT NOT NULL, message TEXT NOT NULL, level TEXT NOT NULL, created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS measurements(id INTEGER PRIMARY KEY,device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
                    profile_id INTEGER,measured_at TEXT NOT NULL,data TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS measurements_device ON measurements(device_id,id);
            ''')
            db.execute('INSERT OR IGNORE INTO settings VALUES (?, ?)', ('monitor', json.dumps({'ranges': [], 'interval': 300})))
            columns = {row['name'] for row in db.execute('PRAGMA table_info(devices)')}
            for name, definition in IDENTITY_COLUMNS.items():
                if name not in columns:
                    db.execute(f'ALTER TABLE devices ADD COLUMN {name} {definition}')
            db.execute('INSERT OR IGNORE INTO settings VALUES (?, ?)', ('snmp', json.dumps({'enabled': False, 'version': '2c', 'community': ''})))
        if os.name != 'nt':
            os.chmod(self.path, 0o600)
        self.profiles = Profiles(self)

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def devices(self):
        with self.db() as db:
            rows = [dict(r) for r in db.execute('SELECT * FROM devices')]
        settings = self.settings()
        vendor_registry = vendors.load(Path(self.path).parent / 'ieee-oui.json')
        for row in rows:
            row['ports'] = json.loads(row['ports'])
            for field in ('mac_addresses', 'interfaces', 'lldp_neighbors', 'forwarding'):
                row[field] = json.loads(row[field])
            row['mac_vendor'] = vendors.lookup(row['mac_addresses'], vendor_registry['prefixes'])
            row['metrics'] = json.loads(row['metrics'])
            row['analysis'] = analyze_metrics(row['metrics'])
            row['display_os'] = row['os'] or row['collected_os']
            row['display_cpu'] = row['cpu'] or row['collected_cpu']
            row['display_ram'] = row['ram'] or row['collected_ram']
            row['mac_note'] = ('Farklı ağ/VLAN: uzak cihazın MAC adresi yönlendirme üzerinden okunamaz.' if row['mac_status'] == 'routed'
                               else 'Yerel ARP yanıtında MAC bulunamadı.' if row['mac_status'] == 'local'
                               else 'MAC henüz okunamadı; yerel ağ bağlantısını kontrol edin.')
            row['display_name'] = row['name'] or row['detected_name'] or 'Adsız cihaz'
            row['display_model'] = row['model'] or row['detected_model']
            row['display_serial'] = row['serial'] or row['detected_serial']
            row['display_model_source'] = 'Elle girildi' if row['model'] else row['model_source']
            row['network'] = group_for_ip(row['ip'], settings['ranges'])
            row['effective_status'] = row['status']
            if row['last_checked']:
                age = (datetime.now(timezone.utc) - datetime.fromisoformat(row['last_checked'])).total_seconds()
                if age > settings['interval'] * 2 + 60:
                    row['effective_status'] = 'stale'
        return sorted(rows, key=lambda d: ipaddress.ip_address(d['ip']))

    def record_collection(self,ip,result,profile_id=None):
        stamp=now()
        with self.db() as db:
            old=db.execute('SELECT id,metrics FROM devices WHERE ip=?',(ip,)).fetchone()
            if not old:
                return
            if not result.get('ok'):
                db.execute('UPDATE devices SET collector_status=?,collector_error=?,metrics_checked_at=? WHERE id=?',
                           (result.get('error_code','error'),result.get('error','Veri okunamadı.'),stamp,old['id']))
                return
            metrics=collectors.normalize(result)
            previous_data=json.loads(old['metrics'])
            counter_rates(metrics,previous_data)
            previous={item['code'] for item in analyze_metrics(previous_data)}
            for issue in analyze_metrics(metrics):
                if issue['code'] not in previous:
                    self.event(db,old['id'],ip,issue['message'],'warning')
            db.execute("UPDATE devices SET metrics=?,collector_status='ok',collector_error='',metrics_checked_at=?,metrics_success_at=? WHERE id=?",
                       (json.dumps(metrics,ensure_ascii=False),stamp,stamp,old['id']))
            for field,key in [('detected_name','name'),('detected_model','model'),('detected_serial','serial'),('manufacturer','manufacturer'),('collected_os','os'),('collected_cpu','cpu_name')]:
                if metrics.get(key):
                    db.execute(f'UPDATE devices SET {field}=? WHERE id=?',(metrics[key],old['id']))
            if metrics.get('model'):
                db.execute('UPDATE devices SET model_source=? WHERE id=?',(metrics.get('inventory_source') or metrics['source'],old['id']))
            if metrics.get('memory_total_bytes'):
                size=metrics['memory_total_bytes']
                capacity=f'{size/1024**3:.1f} GB' if size>=1024**3 else f'{size/1024**2:.0f} MB'
                db.execute('UPDATE devices SET collected_ram=? WHERE id=?',(capacity,old['id']))
            if metrics.get('interfaces'):
                db.execute('UPDATE devices SET interfaces=? WHERE id=?',(json.dumps(metrics['interfaces']),old['id']))
            if metrics.get('macs'):
                db.execute('UPDATE devices SET mac_addresses=?,mac_source=?,mac_checked_at=? WHERE id=?',
                           (json.dumps(metrics['macs']),metrics['source']+' · yetkili envanter',stamp,old['id']))
            db.execute('INSERT INTO measurements(device_id,profile_id,measured_at,data) VALUES(?,?,?,?)',
                       (old['id'],profile_id,stamp,json.dumps(metrics,ensure_ascii=False)))
            db.execute('DELETE FROM measurements WHERE device_id=? AND id NOT IN (SELECT id FROM measurements WHERE device_id=? ORDER BY id DESC LIMIT 500)',(old['id'],old['id']))

    def measurement_history(self,device_id):
        with self.db() as db:
            return [{'measured_at':r['measured_at'],**json.loads(r['data'])} for r in db.execute('SELECT * FROM measurements WHERE device_id=? ORDER BY id DESC LIMIT 60',(device_id,))]

    def settings(self):
        with self.db() as db:
            settings = json.loads(db.execute("SELECT value FROM settings WHERE key='monitor'").fetchone()[0])
        snmp = self.snmp_settings()
        settings.update(snmp_enabled=snmp['enabled'], snmp_version=snmp['version'], snmp_configured=bool(snmp['community']))
        return settings

    def snmp_settings(self):
        with self.db() as db:
            return json.loads(db.execute("SELECT value FROM settings WHERE key='snmp'").fetchone()[0])

    def save_settings(self, data):
        ranges = data.get('ranges', [])
        interval = data.get('interval', 300)
        if not isinstance(ranges, list) or len(ranges) > 8:
            raise ValueError('En fazla 8 ağ eklenebilir.')
        ranges = list(dict.fromkeys(str(network(r)) for r in ranges))
        if isinstance(interval, bool) or not isinstance(interval, int) or not 60 <= interval <= 86400:
            raise ValueError('Kontrol aralığı 60–86400 saniye olmalıdır.')
        settings = {'ranges': ranges, 'interval': interval}
        snmp = self.snmp_settings()
        enabled, version = data.get('snmp_enabled', snmp['enabled']), data.get('snmp_version', snmp['version'])
        if not isinstance(enabled, bool) or version not in ('1', '2c'):
            raise ValueError('SNMP sürümü 1 veya 2c olmalıdır.')
        community = data.get('snmp_community', '')
        if not isinstance(community, str) or len(community.encode('utf-8')) > 255:
            raise ValueError('SNMP community en fazla 255 bayt olmalıdır.')
        if data.get('snmp_clear') is True:
            snmp['community'] = ''
        elif community:
            snmp['community'] = community
        if enabled and not snmp['community']:
            raise ValueError('SNMP için cihazlarda tanımlı salt okunur community değerini girin.')
        snmp.update(enabled=enabled, version=version)
        with self.db() as db:
            db.execute("UPDATE settings SET value=? WHERE key='monitor'", (json.dumps(settings),))
            db.execute("UPDATE settings SET value=? WHERE key='snmp'", (json.dumps(snmp),))
        return self.settings()

    def save_device(self, data, device_id=None):
        clean = {}
        for key in FIELDS:
            value = data.get(key, '')
            if not isinstance(value, str) or len(value) > (4000 if key == 'notes' else 200):
                raise ValueError(f'{key}: metin çok uzun veya geçersiz.')
            clean[key] = value.strip()
        if any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-@\\' for c in clean['ssh_user']) or len(clean['ssh_user']) > 64:
            raise ValueError('SSH kullanıcı adı yalnızca harf, rakam, nokta, tire, alt çizgi, @ ve ters eğik çizgi içerebilir (en fazla 64 karakter).')
        ip = ip_value(data.get('ip', ''))
        with self.db() as db:
            if device_id is None:
                row = db.execute('INSERT INTO devices (ip,first_seen) VALUES (?,?)', (ip, now()))
                device_id = row.lastrowid
            else:
                old = db.execute('SELECT ip FROM devices WHERE id=?', (device_id,)).fetchone()
                if not old:
                    raise LookupError('Cihaz bulunamadı.')
                if old['ip'] != ip:
                    raise ValueError('Kayıtlı cihazın IP adresi değiştirilemez; yeni kayıt oluşturun.')
            db.execute('UPDATE devices SET ' + ','.join(k + '=?' for k in FIELDS) + ' WHERE id=?', (*clean.values(), device_id))
        return device_id

    def delete_device(self, device_id):
        with self.db() as db:
            if not db.execute('DELETE FROM devices WHERE id=?', (device_id,)).rowcount:
                raise LookupError('Cihaz bulunamadı.')

    def event(self, db, device_id, ip, message, level):
        db.execute('INSERT INTO events(device_id,ip,message,level,created_at) VALUES (?,?,?,?,?)',
                   (device_id, ip, message, level, now()))

    def record(self, result):
        ip, reachable = result['ip'], result['reachable']
        with self.db() as db:
            old = db.execute('SELECT * FROM devices WHERE ip=?', (ip,)).fetchone()
            if not old and not reachable:
                return
            if not old:
                row = db.execute('INSERT INTO devices(ip,first_seen,kind) VALUES (?,?,?)', (ip, now(), result.get('kind', 'Diğer')))
                old = db.execute('SELECT * FROM devices WHERE id=?', (row.lastrowid,)).fetchone()
                self.event(db, old['id'], ip, 'Yeni cihaz keşfedildi', 'info')
            failures = 0 if reachable else old['failures'] + 1
            status = 'online' if reachable else ('unreachable' if failures >= 3 else 'degraded')
            if status == 'unreachable' and old['status'] != 'unreachable':
                self.event(db, old['id'], ip, 'Üç ardışık kontrolde yanıt alınamadı', 'warning')
            elif reachable and old['status'] == 'unreachable':
                self.event(db, old['id'], ip, 'Cihaz yeniden erişilebilir', 'success')
            stamp, ports = now(), json.dumps(result['ports'])
            db.execute('''UPDATE devices SET status=?,latency=?,ports=?,last_checked=?,last_seen=?,failures=? WHERE id=?''',
                       (status, result['latency'], ports, stamp, stamp if reachable else old['last_seen'], failures, old['id']))
            arp = result.get('arp')
            if arp:
                db.execute('UPDATE devices SET mac_status=? WHERE id=?', (arp.get('scope', 'unknown'), old['id']))
                if mac_address(arp.get('mac')):
                    db.execute('UPDATE devices SET mac_addresses=?,mac_source=?,mac_checked_at=? WHERE id=?',
                               (json.dumps([mac_address(arp['mac'])]), 'Windows SendARP · doğrudan yerel ağ', stamp, old['id']))
            snmp = result.get('snmp')
            if snmp:
                db.execute('UPDATE devices SET snmp_status=? WHERE id=?', (snmp['status'], old['id']))
                if snmp['status'] == 'ok':
                    db.execute('''UPDATE devices SET detected_name=?,sys_description=?,sys_object_id=?,agent_uptime=?,snmp_checked_at=? WHERE id=?''',
                               (snmp.get('name', ''), snmp.get('description', ''), snmp.get('object_id', ''), snmp.get('uptime'), stamp, old['id']))
                    if snmp.get('manufacturer'):
                        db.execute('UPDATE devices SET manufacturer=? WHERE id=?', (snmp['manufacturer'], old['id']))
                    if snmp.get('model'):
                        db.execute('''UPDATE devices SET detected_model=?,detected_serial=?,manufacturer=?,model_source=? WHERE id=?''',
                                   (snmp['model'], snmp.get('serial', ''), snmp.get('manufacturer', ''), snmp.get('source', ''), old['id']))
            detail = result.get('network_detail')
            if detail is not None:
                db.execute('UPDATE devices SET network_status=?,network_checked_at=?,lldp_status=? WHERE id=?',
                           ('partial' if detail.get('collection_limited') else 'ok', stamp, detail['lldp_status'], old['id']))
                if detail.get('interfaces'):
                    db.execute('UPDATE devices SET interfaces=? WHERE id=?', (json.dumps(detail['interfaces']), old['id']))
                if detail.get('neighbors') or detail['lldp_status'] == 'read':
                    db.execute('UPDATE devices SET lldp_neighbors=?,lldp_checked_at=? WHERE id=?', (json.dumps(detail['neighbors']), stamp, old['id']))
                if detail.get('chassis_id'):
                    db.execute('UPDATE devices SET chassis_id=? WHERE id=?', (detail['chassis_id'], old['id']))
                db.execute('UPDATE devices SET forwarding_status=? WHERE id=?', (detail.get('forwarding_status', 'unavailable'), old['id']))
                if detail.get('forwarding') or detail.get('forwarding_status') == 'complete':
                    db.execute('UPDATE devices SET forwarding=?,forwarding_checked_at=? WHERE id=?', (json.dumps(detail.get('forwarding', [])), stamp, old['id']))
                if detail.get('macs'):
                    db.execute('UPDATE devices SET mac_addresses=?,mac_source=?,mac_checked_at=? WHERE id=?',
                               (json.dumps(detail['macs']), 'SNMP IP-MIB / IF-MIB', stamp, old['id']))
            elif snmp and snmp['status'] != 'ok':
                db.execute('UPDATE devices SET network_status=?,lldp_status=? WHERE id=?', (snmp['status'], 'unavailable', old['id']))
                db.execute("UPDATE devices SET forwarding_status='unavailable' WHERE id=?", (old['id'],))
            db.execute('INSERT INTO checks(device_id,checked_at,reachable,latency,ports) VALUES (?,?,?,?,?)',
                       (old['id'], stamp, int(reachable), result['latency'], ports))
            # Keep the most recent 500 checks per device and 2000 global events.
            db.execute('DELETE FROM checks WHERE device_id=? AND id NOT IN (SELECT id FROM checks WHERE device_id=? ORDER BY id DESC LIMIT 500)', (old['id'], old['id']))
            db.execute('DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 2000)')

    def history(self, device_id):
        with self.db() as db:
            if not db.execute('SELECT 1 FROM devices WHERE id=?', (device_id,)).fetchone():
                raise LookupError('Cihaz bulunamadı.')
            return [dict(r) for r in db.execute('SELECT * FROM checks WHERE device_id=? ORDER BY id DESC LIMIT 60', (device_id,))]

    def observe_macs(self, observations, allowed_ips):
        """Cache evidence creates observed inventory, never an Online check."""
        with self.db() as db:
            for observation in observations:
                ip, mac = observation.get('ip'), mac_address(observation.get('mac'))
                if ip not in allowed_ips or not mac:
                    continue
                ip_value(ip)
                stamp = now()
                old = db.execute('SELECT id FROM devices WHERE ip=?', (ip,)).fetchone()
                if not old:
                    row = db.execute("INSERT INTO devices(ip,first_seen,status) VALUES(?,?,'observed')", (ip, stamp))
                    self.event(db, row.lastrowid, ip, 'MAC tablosunda görüldü · canlılık henüz doğrulanmadı', 'info')
                db.execute('UPDATE devices SET mac_addresses=?,mac_source=?,mac_checked_at=? WHERE ip=?',
                           (json.dumps([mac]), observation.get('source', 'ARP tablosu'), stamp, ip))

    def events(self):
        with self.db() as db:
            return [dict(r) for r in db.execute('SELECT * FROM events ORDER BY id DESC LIMIT 100')]


def probe(ip, ports=PORTS, timeout=0.35, snmp_config=None):
    """Connection handshakes, optional ICMP and configured read-only SNMP."""
    opened, latencies = [], []
    for port in ports:
        start = time.monotonic()
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                opened.append(port)
                latencies.append((time.monotonic() - start) * 1000)
        except PermissionError:
            raise RuntimeError('İzleme işleminin TCP bağlantısı açma izni yok.') from None
        except OSError:
            pass
    ping = shutil.which('ping')
    icmp = False
    if ping:
        start = time.monotonic()
        try:
            system = platform.system()
            command = [ping, '-n', '1', '-w', '1000', ip] if system == 'Windows' else [ping, '-n', '-c', '1', '-W', '1000' if system == 'Darwin' else '1', ip]
            icmp = subprocess.run(command, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, timeout=2).returncode == 0
            if icmp and not latencies:
                latencies.append((time.monotonic() - start) * 1000)
        except (OSError, subprocess.TimeoutExpired):
            pass
    kind = 'Yazıcı' if any(p in opened for p in (9100, 631, 515)) else 'Sunucu' if any(p in opened for p in (22, 445, 3389, 902, 8006)) else 'Diğer'
    snmp_start = time.monotonic()
    snmp = identify(ip, snmp_config or {})
    detail = inspect_network(ip, snmp_config or {}) if snmp['status'] == 'ok' else None
    if snmp['status'] == 'ok' and not latencies:
        latencies.append(snmp.get('latency', (time.monotonic() - snmp_start) * 1000))
    arp = windows_arp(ip)
    if arp.get('mac') and not latencies:
        latencies.append(arp.get('latency', 0))
    return {'ip': ip, 'reachable': bool(opened) or icmp or snmp['status'] == 'ok' or bool(arp.get('mac')), 'latency': round(min(latencies), 2) if latencies else None, 'ports': opened, 'kind': kind, 'snmp': snmp, 'network_detail': detail, 'arp': arp}


class Monitor:
    def __init__(self, store, probe_fn=None):
        self.store, self.probe = store, probe_fn
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.thread = None
        self.state = {'running': False, 'done': 0, 'total': 0, 'error': None, 'finished_at': None, 'started_at': None}
        self.next_run = time.monotonic() + store.settings()['interval']

    def snapshot(self):
        with self.lock:
            return dict(self.state)

    def start(self, ranges=None):
        settings = self.store.settings()
        ranges = settings['ranges'] if ranges is None else ranges
        if not isinstance(ranges, list) or len(ranges) > 8:
            raise ValueError('En fazla 8 ağ girin.')
        targets = {str(ip) for r in ranges for ip in network(r).hosts()}
        targets.update(d['ip'] for d in self.store.devices())
        if not targets:
            raise ValueError('Önce bir ağ veya envanter cihazı ekleyin.')
        if len(targets) > 8192:
            raise ValueError('Bir taramada en fazla 8192 adres kontrol edilebilir.')
        with self.lock:
            if self.state['running']:
                raise RuntimeError('Bir tarama zaten sürüyor.')
            self.state.update(running=True, done=0, total=len(targets), error=None, started_at=now())
            self.thread = threading.Thread(target=self.run, args=(sorted(targets),), daemon=True)
            self.thread.start()

    def run(self, targets):
        try:
            config = self.store.snmp_settings()
            observations = []
            with ThreadPoolExecutor(max_workers=32) as pool:
                pending = {pool.submit(self.probe, ip) if self.probe else pool.submit(self.collect_target,ip,config) for ip in targets}
                for future in as_completed(pending):
                    if self.stop.is_set():
                        for task in pending:
                            task.cancel()
                        break
                    result = future.result()
                    self.store.record(result)
                    if result.get('collection'):
                        self.store.record_collection(result['ip'],result['collection'],result.get('profile_id'))
                    observations.extend((result.get('network_detail') or {}).get('arp', []))
                    with self.lock:
                        self.state['done'] += 1
                        completed = self.state['done']
                    if completed % 32 == 0:
                        self.store.observe_macs(local_neighbors(), set(targets))
            if not self.stop.is_set():
                observations.extend(local_neighbors())
                self.store.observe_macs(observations, set(targets))
        except Exception:
            logging.exception('Tarama başarısız')
            with self.lock:
                self.state['error'] = 'Tarama tamamlanamadı. Sunucu günlüğünü kontrol edin.'
        finally:
            with self.lock:
                self.state.update(running=False, finished_at=now())
                self.next_run = time.monotonic() + self.store.settings()['interval']

    def collect_target(self,ip,fallback):
        snmp_config=self.store.profiles.snmp_config(ip,fallback)
        result=probe(ip,snmp_config=snmp_config)
        candidates=self.store.profiles.choose(ip)
        # Specific scopes take precedence. Never try a series of credentials.
        profile=next((p for p in candidates if p['kind']=='windows' and 135 in result['ports'] or p['kind']=='linux' and p['port'] in result['ports']),None)
        if profile:
            result['collection']=self.store.profiles.read(profile['id'],ip)
            result['profile_id']=profile['id']
        elif result.get('snmp',{}).get('status')=='ok':
            result['collection']=collectors.snmp_load(ip,snmp_config)
        if result.get('collection',{}).get('ok'):
            result['reachable']=True
        return result

    def schedule(self):
        while not self.stop.wait(1):
            if not self.snapshot()['running'] and time.monotonic() >= self.next_run:
                try:
                    self.start()
                except ValueError:
                    self.next_run = time.monotonic() + self.store.settings()['interval']
                except RuntimeError:
                    pass


def csv_export(devices):
    output = io.StringIO(newline='')
    writer = csv.writer(output)
    columns = ('ip', *FIELDS, 'status', 'latency', 'last_seen', 'last_checked', 'network', 'display_model', 'display_serial', 'display_model_source', 'snmp_status', 'mac_addresses', 'mac_source', 'mac_checked_at', 'manufacturer', 'mac_vendor','display_os','display_cpu','display_ram','cpu_percent','memory_percent','metrics_success_at','collector_status')
    writer.writerow(columns)
    for device in devices:
        values = []
        for key in columns:
            value = device.get(key)
            if key in ('cpu_percent','memory_percent'):
                value=device.get('metrics',{}).get(key)
            if value is None:
                value = ''
            if isinstance(value, list):
                value = ', '.join(map(str, value))
            if isinstance(value, str) and value.lstrip().startswith(('=', '+', '-', '@')):
                value = "'" + value
            values.append(value)
        writer.writerow(values)
    return ('\ufeff' + output.getvalue()).encode('utf-8')


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, store, token=''):
        self.store, self.token = store, token
        self.monitor = Monitor(store)
        super().__init__(address, Handler)

    def gateway_config(self):
        path = Path(self.store.path).parent / 'gateway.json'
        if not path.exists():
            return {'enabled': False}
        try:
            return json.loads(path.read_text(encoding='utf-8'))
        except (ValueError, OSError):
            return {'enabled': False}


class Handler(BaseHTTPRequestHandler):
    def send(self, status, payload, content_type='application/json; charset=utf-8', filename=None):
        body = json.dumps(payload, ensure_ascii=False).encode() if not isinstance(payload, bytes) else payload
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        if filename:
            self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
        elif self.path == '/api/export':
            self.send_header('Content-Disposition', 'attachment; filename="ag-atlas-envanter.csv"')
        self.end_headers()
        self.wfile.write(body)

    def authorized(self):
        # Host checking also prevents DNS rebinding against the local dashboard.
        allowed = {'localhost', '127.0.0.1', self.server.server_address[0]}
        host = self.headers.get('Host', '').split(':')[0]
        if self.server.token:
            return hmac.compare_digest(self.headers.get('Authorization', '').encode(), ('Bearer ' + self.server.token).encode())
        return host in allowed

    def body(self):
        try:
            length = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            raise ValueError('Geçersiz istek uzunluğu.') from None
        if not 0 < length <= 32768:
            raise ValueError('İstek gövdesi 1–32768 bayt olmalıdır.')
        if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
            raise ValueError('application/json gerekli.')
        try:
            data = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeDecodeError):
            raise ValueError('Geçersiz JSON.') from None
        if not isinstance(data, dict):
            raise ValueError('Bir JSON nesnesi gerekli.')
        return data

    def dispatch(self):
        path = self.path.split('?')[0]
        if self.command == 'GET' and path == '/favicon.ico':
            return self.send(204, b'', 'image/x-icon')
        if self.command == 'GET' and path in ('/', '/app.js', '/style.css'):
            files = {'/': ('index.html', 'text/html'), '/app.js': ('app.js', 'text/javascript'), '/style.css': ('style.css', 'text/css')}
            file, kind = files[path]
            return self.send(200, (ROOT / 'static' / file).read_bytes(), kind + '; charset=utf-8')
        if not self.authorized():
            return self.send(401, {'error': 'Erişim anahtarı gerekli veya geçersiz sunucu adresi.'})
        store = self.server.store
        if self.command == 'GET' and path == '/api/state':
            devices, settings = store.devices(), store.settings()
            return self.send(200, {'devices': devices, 'profiles': store.profiles.list(), 'topology': topology(devices), 'groups': network_groups(devices, settings['ranges']), 'events': store.events(), 'settings': settings,
                                   'scan': self.server.monitor.snapshot(), 'capabilities': {'icmp': bool(shutil.which('ping')), 'ports': PORTS, 'browser_access': bool(self.server.gateway_config().get('enabled'))}, 'server_time': now()})
        if self.command == 'GET' and path == '/api/topology':
            return self.send(200, topology(store.devices()))
        if path == '/api/profiles' and self.command == 'POST':
            return self.send(201,{'id':store.profiles.save(self.body())})
        if path == '/api/ssh-key' and self.command == 'POST':
            data=self.body();target=ip_value(data.get('target',''));port=data.get('port',22)
            if isinstance(port,bool) or not isinstance(port,int) or not 1<=port<=65535:
                raise ValueError('SSH portu geçersiz.')
            return self.send(200,collectors.ssh_key(target,port))
        if path.startswith('/api/profiles/'):
            parts=path.strip('/').split('/')
            if len(parts) not in (3,4) or not parts[2].isdigit():
                raise LookupError('Profil bulunamadı.')
            profile_id=int(parts[2])
            if len(parts)==3 and self.command=='PUT':
                return self.send(200,{'id':store.profiles.save(self.body(),profile_id)})
            if len(parts)==3 and self.command=='DELETE':
                store.profiles.delete(profile_id);return self.send(200,{'ok':True})
            if len(parts)==4 and parts[3]=='test' and self.command=='POST':
                target=ip_value(self.body().get('target',''))
                result=store.profiles.read(profile_id,target,manual=True)
                if result.get('ok'):
                    old=next((d for d in store.devices() if d['ip']==target),None)
                    store.record({'ip':target,'reachable':True,'latency':None,'ports':old['ports'] if old else [],'kind':'Diğer' if store.profiles.get(profile_id)['kind']=='snmp' else 'Sunucu',
                                  'snmp':result.get('snmp_identity'),'network_detail':result.get('network_detail')})
                store.record_collection(target,result,profile_id)
                return self.send(200,result)
        if self.command == 'POST' and path == '/api/vendors/update':
            self.body()
            try:
                count = vendors.update(Path(store.path).parent / 'ieee-oui.json')
            except (OSError, ValueError):
                raise RuntimeError('IEEE listesi indirilemedi. İnternet/HTTPS erişimini kontrol edin; mevcut liste korundu.') from None
            return self.send(200, {'prefixes': count})
        if self.command == 'GET' and path == '/api/export':
            return self.send(200, csv_export(store.devices()), 'text/csv; charset=utf-8')
        if path.startswith('/api/devices/'):
            parts = path.strip('/').split('/')
            if len(parts) not in (3, 4, 5) or not parts[2].isdigit():
                raise LookupError('Sayfa bulunamadı.')
            device_id = int(parts[2])
            if self.command == 'POST' and len(parts) == 4 and parts[3] == 'session':
                device = next((d for d in store.devices() if d['id'] == device_id), None)
                if not device:
                    raise LookupError('Cihaz bulunamadı.')
                if device['effective_status'] != 'online':
                    raise RuntimeError('Önce cihazın güncel Online durumunu taramayla doğrulayın.')
                data = self.body()
                url = session_url(device, data.get('protocol'), data, self.server.gateway_config())
                return self.send(200, {'url': url, 'expires_in': 30})
            if self.command == 'GET' and len(parts) == 5 and parts[3] == 'connect' and parts[4] in ('ssh', 'rdp', 'vnc'):
                device = next((d for d in store.devices() if d['id'] == device_id), None)
                if not device:
                    raise LookupError('Cihaz bulunamadı.')
                if device['effective_status'] != 'online':
                    raise RuntimeError('Bağlantı için önce cihazın güncel Online durumunu taramayla doğrulayın.')
                content, filename = connection_file(device, parts[4])
                return self.send(200, content, 'application/octet-stream', filename=filename)
            if self.command == 'GET' and len(parts) == 4 and parts[3] == 'history':
                return self.send(200, store.history(device_id))
            if self.command == 'GET' and len(parts) == 4 and parts[3] == 'measurements':
                return self.send(200,store.measurement_history(device_id))
            if len(parts) == 3:
                if self.command == 'PUT':
                    return self.send(200, {'id': store.save_device(self.body(), device_id)})
                if self.command == 'DELETE':
                    store.delete_device(device_id)
                    return self.send(200, {'ok': True})
        if self.command == 'POST' and path == '/api/devices':
            return self.send(201, {'id': store.save_device(self.body())})
        if self.command == 'PUT' and path == '/api/settings':
            settings = store.save_settings(self.body())
            with self.server.monitor.lock:
                self.server.monitor.next_run = time.monotonic() + settings['interval']
            return self.send(200, settings)
        if self.command == 'POST' and path == '/api/scan':
            data = self.body()
            self.server.monitor.start(data.get('ranges'))
            return self.send(202, {'ok': True})
        raise LookupError('Sayfa bulunamadı.')

    def handle_request(self):
        try:
            self.connection.settimeout(15)
            self.dispatch()
        except (ValueError, TypeError) as exc:
            self.send(400, {'error': str(exc)})
        except LookupError as exc:
            self.send(404, {'error': str(exc)})
        except sqlite3.IntegrityError:
            self.send(409, {'error': 'Bu IP adresi envanterde zaten var.'})
        except RuntimeError as exc:
            self.send(409, {'error': str(exc)})
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass
        except Exception:
            logging.exception('HTTP isteği başarısız')
            self.send(500, {'error': 'Sunucu hatası. Sunucu günlüğünü kontrol edin.'})

    do_GET = do_POST = do_PUT = do_DELETE = handle_request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', default=8080, type=int)
    parser.add_argument('--db', default=str(ROOT / 'data' / 'atlas.sqlite3'))
    args = parser.parse_args()
    token = os.environ.get('ATLAS_TOKEN', '')
    if args.host not in ('localhost', '127.0.0.1') and len(token) < 24:
        parser.error('Ağa açmak için en az 24 karakterlik ATLAS_TOKEN ayarlayın. TLS sağlayan bir ters proxy kullanın.')
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    server = Server((args.host, args.port), Store(args.db), token)
    scheduler = threading.Thread(target=server.monitor.schedule, daemon=True)
    scheduler.start()
    logging.info('AğAtlas başlatıldı: %s:%s — veritabanı: %s', args.host, server.server_port, args.db)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.monitor.stop.set()
        server.server_close()


if __name__ == '__main__':
    main()
