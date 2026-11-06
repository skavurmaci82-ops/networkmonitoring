"""Read-only Linux inventory. Sent over an authenticated SSH channel."""
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import subprocess
import time


def read(path):
    try:
        return Path(path).read_text(errors='replace').strip()
    except OSError:
        return ''


def counters():
    cpu = [int(v) for v in read('/proc/stat').splitlines()[0].split()[1:9]]
    network = {}
    for line in read('/proc/net/dev').splitlines()[2:]:
        name, values = line.split(':', 1)
        network[name.strip()] = [int(v) for v in values.split()]
    return cpu, network


def collect():
    first_cpu, first_net = counters()
    started = time.monotonic()
    time.sleep(.3)
    cpu, net = counters()
    elapsed = time.monotonic() - started
    total = sum(cpu) - sum(first_cpu)
    idle = sum(cpu[3:5]) - sum(first_cpu[3:5])
    memory = {}
    for line in read('/proc/meminfo').splitlines():
        key, value = line.split(':', 1)
        memory[key] = int(value.strip().split()[0]) * 1024
    total_memory = memory.get('MemTotal', 0)
    available = memory.get('MemAvailable', memory.get('MemFree', 0))
    disks, seen = [], set()
    for line in read('/proc/mounts').splitlines():
        parts = line.split()
        if len(parts) < 3 or not (parts[0].startswith('/dev/') or parts[1] == '/'):
            continue
        path = parts[1].replace('\\040', ' ')
        try:
            identity = os.stat(path).st_dev
            if identity in seen:
                continue
            seen.add(identity)
            stat = os.statvfs(path)
            if stat.f_blocks:
                disks.append({'name': path, 'total_bytes': stat.f_blocks * stat.f_frsize,
                              'free_bytes': stat.f_bavail * stat.f_frsize,
                              'used_percent': round(100 * (stat.f_blocks-stat.f_bfree)/stat.f_blocks, 1)})
        except OSError:
            pass
        if len(disks) >= 32:
            break
    interfaces, macs = [], []
    ip_tool = shutil.which('ip')
    addresses = {}
    if ip_tool:
        try:
            response = subprocess.run([ip_tool, '-j', 'address', 'show'], capture_output=True, timeout=3, check=True)
            addresses = {row['ifname']: [v['local'] for v in row.get('addr_info', []) if v.get('family') == 'inet'] for row in json.loads(response.stdout)}
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
    for name, values in net.items():
        mac = read('/sys/class/net/' + name + '/address').upper()
        valid = bool(re.fullmatch(r'(?:[0-9A-F]{2}:){5}[0-9A-F]{2}', mac)) and mac != '00:00:00:00:00:00' and not int(mac[:2], 16) & 1
        if valid:
            macs.append(mac)
        old = first_net.get(name)
        rates = {}
        if old and values[0] >= old[0] and values[8] >= old[8]:
            rates = {'rx_bps': round((values[0]-old[0])*8/elapsed, 1), 'tx_bps': round((values[8]-old[8])*8/elapsed, 1),
                     'new_errors': max(0, values[2]-old[2]) + max(0, values[10]-old[10])}
        state=read('/sys/class/net/'+name+'/operstate')
        speed=read('/sys/class/net/'+name+'/speed')
        interfaces.append({'name': name, 'mac': mac if valid else '', 'addresses': addresses.get(name, []),
                           'oper_status': 1 if state=='up' else 2 if state=='down' else 4,
                           'speed_bps':int(speed)*1000000 if speed.isdigit() and int(speed)>0 else None, **rates})
    os_release = {}
    for line in read('/etc/os-release').splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            os_release[key] = value.strip('"')
    cpu_name = next((line.split(':', 1)[1].strip() for line in read('/proc/cpuinfo').splitlines() if line.startswith('model name')), platform.machine())
    return {'ok': True, 'source': 'Linux SSH', 'name': socket.gethostname(),
            'manufacturer': read('/sys/class/dmi/id/sys_vendor'), 'model': read('/sys/class/dmi/id/product_name'),
            'serial': read('/sys/class/dmi/id/product_serial'), 'os': os_release.get('PRETTY_NAME', platform.system()),
            'cpu_name': cpu_name, 'cpu_percent': round(100*(total-idle)/total, 1) if total > 0 else None,
            'memory_total_bytes': total_memory or None,
            'memory_percent': round(100*(total_memory-available)/total_memory, 1) if total_memory else None,
            'disks': disks, 'macs': sorted(set(macs)), 'interfaces': interfaces}


if __name__ == '__main__':
    try:
        print(json.dumps(collect(), ensure_ascii=False))
    except Exception:
        print(json.dumps({'ok': False, 'error_code': 'linux_collection_failed'}))
