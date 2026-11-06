"""Authorized, read-only host measurements; no credentials in command lines."""
import base64
import hashlib
import hmac
import io
import ipaddress
import json
import math
from pathlib import Path
import platform
import socket
import subprocess

from discovery import mac_address, inspect_network
from snmp import Client, SYS_UPTIME, identify

SCRIPTS = Path(__file__).resolve().parent / 'collector_scripts'
ERRORS = {
    'unsupported_platform': 'Windows CIM toplayıcısını Windows üzerinde çalıştırın.',
    'dependency_missing': 'TOPLAYICI_KUR.cmd ile toplayıcı bağımlılıklarını kurun.',
    'authentication_failed': 'Kimlik doğrulama başarısız. Kullanıcı/parolayı kontrol edin; otomatik profil duraklatıldı.',
    'access_denied': 'Hesabın WMI/CIM okuma yetkisi yok. Hedefte WMI yetkisini kontrol edin.',
    'windows_connection_failed': 'Windows bağlantısı kurulamadı. Hedefte WMI/DCOM, RPC 135 ve güvenlik duvarını kontrol edin.',
    'local_current_account_required': 'Kendi bilgisayarınız için “Mevcut Windows hesabımı kullan” seçeneğini işaretleyin.',
    'ssh_host_key_required': 'SSH sunucu anahtarı doğrulanmamış. Parmak izini hedefte kontrol edip profile kaydedin.',
    'ssh_host_key_changed': 'SSH sunucu anahtarı eşleşmiyor. Otomatik profil duraklatıldı; hedef kimliğini doğrulayın.',
    'ssh_connection_failed': 'SSH bağlantısı kurulamadı. IP, port, SSH hizmeti ve ağ erişimini kontrol edin.',
    'linux_collection_failed': 'Linux verisi okunamadı. Hedefte Python 3, /proc ve okuma izinlerini kontrol edin.',
    'timeout': 'Veri okuma süresi aşıldı. Hedef erişimini ve güvenlik duvarını kontrol edin.',
    'snmp_no_response': 'SNMP yanıtı yok. Sürüm, salt okunur community ve UDP 161 erişimini kontrol edin.',
    'invalid_data': 'Toplayıcı geçerli ölçüm verisi döndürmedi.',
    'profile_error': 'Profil kimlik bilgileri açılamadı; profili çalışma hesabınızda yeniden kaydedin.'}


def failure(code, **extra):
    return {'ok': False, 'error_code': code, 'error': ERRORS.get(code, 'Veri okunamadı.'), **extra}


def normalize(data):
    if not isinstance(data, dict) or not data.get('ok'):
        return failure(data.get('error_code', 'invalid_data') if isinstance(data, dict) else 'invalid_data')
    result = {'ok': True}
    for key in ('source', 'inventory_source', 'name', 'manufacturer', 'model', 'serial', 'os', 'cpu_name'):
        result[key] = str(data.get(key) or '')[:250]
    for key in ('cpu_percent', 'memory_percent'):
        value = data.get(key)
        result[key] = round(value, 1) if isinstance(value, (int,float)) and not isinstance(value,bool) and 0 <= value <= 100 else None
    value = data.get('memory_total_bytes')
    result['memory_total_bytes'] = int(value) if isinstance(value,(int,float)) and 0 < value < 2**64 else None
    result['macs'] = sorted(set(filter(None, (mac_address(v) for v in data.get('macs', []) if isinstance(v, str)))))[:128]
    result['disks'] = []
    for disk in (data.get('disks') or [])[:64]:
        percent = disk.get('used_percent')
        if isinstance(percent,(int,float)) and 0 <= percent <= 100:
            result['disks'].append({'name': str(disk.get('name',''))[:200], 'used_percent': round(percent,1),
                                    'total_bytes': disk.get('total_bytes'), 'free_bytes': disk.get('free_bytes')})
    for key in ('interfaces','network'):
        result[key] = []
        for row in (data.get(key) or [])[:128]:
            if not isinstance(row,dict):
                continue
            clean={'name':str(row.get('name',''))[:200]}
            clean['addresses']=[]
            for address in (row.get('addresses') or [])[:16]:
                try:
                    clean['addresses'].append(str(ipaddress.ip_address(address)))
                except ValueError:
                    pass
            if mac_address(row.get('mac')):
                clean['mac']=mac_address(row['mac'])
            if row.get('oper_status') in (1,2,3,4,5,6,7):
                clean['oper_status']=row['oper_status']
            for metric in ('rx_bps','tx_bps','new_errors','speed_bps','index','counter_rx','counter_tx','counter_errors','counter_discontinuity'):
                value=row.get(metric)
                if isinstance(value,(int,float)) and not isinstance(value,bool) and math.isfinite(value) and 0<=value<=2**64:
                    clean[metric]=value
            result[key].append(clean)
    if isinstance(data.get('uptime_ticks'),int) and data['uptime_ticks']>=0:
        result['uptime_ticks']=data['uptime_ticks']
    result['unavailable']=[label for present,label in (
        (bool(result['model']),'Model bilgisi veri kaynağından alınamadı.'),
        (bool(result['macs']),'MAC bilgisi veri kaynağından alınamadı.'),
        (result['cpu_percent'] is not None,'CPU ölçümü sunulmadı.'),
        (result['memory_percent'] is not None,'RAM ölçümü sunulmadı.')) if not present]
    return result


def windows(target, profile, secret, runner=subprocess.run):
    if platform.system() != 'Windows':
        return failure('unsupported_platform')
    script = (SCRIPTS/'windows.ps1').read_text(encoding='utf-8')
    command = ['powershell.exe','-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(script.encode('utf-16le')).decode()]
    payload = {'target': str(ipaddress.IPv4Address(target)), 'username': profile.get('username',''),
               'password': secret.get('password',''), 'use_current_user': profile.get('use_current_user',False)}
    try:
        response = runner(command,input=json.dumps(payload,ensure_ascii=False),capture_output=True,encoding='utf-8',timeout=40)
        return normalize(json.loads(response.stdout.lstrip('\ufeff').strip()))
    except subprocess.TimeoutExpired:
        return failure('timeout')
    except (OSError, ValueError):
        return failure('windows_connection_failed')


def fingerprint(key):
    return 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')


def ssh_key(target, port=22):
    """Read a public key before authentication. User must verify it out-of-band."""
    try:
        import paramiko
    except ImportError:
        return failure('dependency_missing')
    try:
        with socket.create_connection((str(ipaddress.IPv4Address(target)),port),timeout=5) as sock:
            transport = paramiko.Transport(sock)
            try:
                transport.start_client(timeout=6)
                key = transport.get_remote_server_key()
                return {'ok': True, 'fingerprint': fingerprint(key), 'key_type': key.get_name(), 'verified': False}
            finally:
                transport.close()
    except (OSError,paramiko.SSHException):
        return failure('ssh_connection_failed')


def linux(target, profile, secret):
    try:
        import paramiko
    except ImportError:
        return failure('dependency_missing')
    expected = profile.get('host_key','')
    if not expected:
        return failure('ssh_host_key_required')
    class VerifiedKey(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, client, hostname, key):
            if not hmac.compare_digest(fingerprint(key),expected):
                raise paramiko.BadHostKeyException(hostname,key,key)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(VerifiedKey())
    try:
        pkey = None
        if secret.get('private_key'):
            for kind in (paramiko.Ed25519Key,paramiko.RSAKey,paramiko.ECDSAKey):
                try:
                    pkey = kind.from_private_key(io.StringIO(secret['private_key']),password=secret.get('key_passphrase') or None)
                    break
                except (paramiko.SSHException,ValueError):
                    continue
            if pkey is None:
                return failure('authentication_failed')
        client.connect(str(ipaddress.IPv4Address(target)),port=profile.get('port',22),username=profile['username'],
                       password=None if pkey else secret.get('password') or None,pkey=pkey,
                       allow_agent=False,look_for_keys=False,timeout=5,auth_timeout=8,banner_timeout=5)
        stdin, stdout, stderr = client.exec_command('python3 -',timeout=25)
        stdin.write((SCRIPTS/'linux.py').read_text(encoding='utf-8'))
        stdin.flush();stdin.channel.shutdown_write()
        raw = stdout.read(1024*1024+1)
        if len(raw)>1024*1024:
            return failure('invalid_data')
        return normalize(json.loads(raw.decode('utf-8')))
    except paramiko.BadHostKeyException:
        return failure('ssh_host_key_changed')
    except paramiko.AuthenticationException:
        return failure('authentication_failed')
    except (TimeoutError,socket.timeout):
        return failure('timeout')
    except (paramiko.SSHException,OSError):
        return failure('ssh_connection_failed')
    except (ValueError,UnicodeError):
        return failure('linux_collection_failed')
    finally:
        client.close()


def snmp_load(target, config, client_factory=Client):
    client = client_factory(target,config['community'],version=config.get('version','2c'),budget=4)
    uptime = dict(client.query([SYS_UPTIME])).get(SYS_UPTIME)
    if uptime is None:
        return failure('snmp_no_response')
    load_oid = '1.3.6.1.2.1.25.3.3.1.2'
    loads = [v for _,v in client.walk(load_oid,limit=64) if isinstance(v,int) and 0<=v<=100]
    if not loads:
        hp_cpu = '1.3.6.1.4.1.11.2.14.11.1.2.6.1.0'
        value = dict(client.query([hp_cpu])).get(hp_cpu)
        if isinstance(value,int) and 0<=value<=100:
            loads=[value]
    storage = '1.3.6.1.2.1.25.2.3.1'
    types = list(client.walk(storage+'.2',limit=64))
    data = {'ok':True,'source':'SNMP HOST-RESOURCES / HPE CPU MIB','cpu_percent':round(sum(loads)/len(loads),1) if loads else None,'disks':[]}
    data['uptime_ticks']=uptime
    data['network']=[]
    high='1.3.6.1.2.1.31.1.1.1'
    incoming=list(client.walk(high+'.6',limit=128))
    legacy=not incoming
    if legacy:
        incoming=list(client.walk('1.3.6.1.2.1.2.2.1.10',limit=128))
    for oid,value in incoming:
        if not isinstance(value,int):
            continue
        index=oid.rsplit('.',1)[-1]
        prefix='1.3.6.1.2.1.2.2.1'
        out=(prefix+'.16.' if legacy else high+'.10.')+index
        fields=[out,prefix+'.2.'+index,prefix+'.14.'+index,prefix+'.20.'+index,high+'.15.'+index,high+'.19.'+index]
        row=dict(client.query(fields))
        item={'index':int(index),'name':str(row.get(fields[1]) or 'ifIndex '+index),'counter_rx':value}
        if isinstance(row.get(out),int):item['counter_tx']=row[out]
        if all(isinstance(row.get(k),int) for k in fields[2:4]):item['counter_errors']=sum(row[k] for k in fields[2:4])
        if isinstance(row.get(fields[4]),int) and row[fields[4]]>0:item['speed_bps']=row[fields[4]]*1000000
        if isinstance(row.get(fields[5]),int):item['counter_discontinuity']=row[fields[5]]
        data['network'].append(item)
    for oid,kind in types:
        if kind not in ('1.3.6.1.2.1.25.2.1.2','1.3.6.1.2.1.25.2.1.4'):
            continue
        index=oid.rsplit('.',1)[-1]
        keys={part:storage+f'.{part}.'+index for part in (3,4,5,6)}
        row=dict(client.query(list(keys.values())))
        units,size,used=(row.get(keys[k]) for k in (4,5,6))
        if not all(isinstance(v,int) for v in (units,size,used)) or units<=0 or size<=0 or not 0<=used<=size:
            continue
        percent=round(used/size*100,1)
        if kind.endswith('.2'):
            data.update(memory_total_bytes=units*size,memory_percent=percent)
        else:
            data['disks'].append({'name':str(row.get(keys[3]) or index),'used_percent':percent,'total_bytes':units*size,'free_bytes':units*(size-used)})
    return normalize(data)


def collect(target, profile, secret):
    try:
        if profile['kind']=='windows':
            return windows(target,profile,secret)
        if profile['kind']=='linux':
            return linux(target,profile,secret)
        config={'enabled':True,'community':secret['community'],'version':profile.get('version','2c')}
        identity=identify(target,config)
        if identity['status']!='ok':
            return failure('snmp_no_response')
        detail=inspect_network(target,config)
        data=snmp_load(target,config)
        if not data.get('ok'):
            data=normalize({'ok':True,'source':'SNMP'})
        data.update(name=identity.get('name',''),model=identity.get('model',''),serial=identity.get('serial',''),
                    manufacturer=identity.get('manufacturer',''),macs=(detail or {}).get('macs',[]),
                    inventory_source=identity.get('source','SNMP'),snmp_identity=identity,network_detail=detail)
        return data
    except Exception:
        # SDK errors may contain user-provided credentials. Never return/log them.
        return failure('invalid_data')
