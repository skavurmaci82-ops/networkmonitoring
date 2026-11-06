"""Scoped collection profiles; one selected profile, no credential guessing."""
import ipaddress
import json
import re
import threading

from credential_vault import Vault
import collectors


class Profiles:
    def __init__(self, store):
        self.store = store
        from pathlib import Path
        self.vault = Vault(Path(store.path).parent)
        self.guard, self.locks = threading.Lock(), {}
        with store.db() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS profiles(id INTEGER PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL,
                scope TEXT NOT NULL, username TEXT NOT NULL, port INTEGER NOT NULL, version TEXT NOT NULL,
                use_current_user INTEGER NOT NULL, host_key TEXT NOT NULL, enabled INTEGER NOT NULL,
                secret TEXT NOT NULL, last_result TEXT NOT NULL DEFAULT '')''')

    def list(self):
        with self.store.db() as db:
            rows=[dict(r) for r in db.execute('SELECT * FROM profiles ORDER BY id')]
        for row in rows:
            row['secret_configured']=bool(row.pop('secret'))
            for field in ('use_current_user','enabled'):
                row[field]=bool(row[field])
        return rows

    def get(self, profile_id):
        with self.store.db() as db:
            row=db.execute('SELECT * FROM profiles WHERE id=?',(profile_id,)).fetchone()
        if not row:
            raise LookupError('Profil bulunamadı.')
        return dict(row)

    def save(self,data,profile_id=None):
        from app import network
        name,kind=data.get('name',''),data.get('kind','')
        if not isinstance(name,str) or not 0<len(name.strip())<=100 or kind not in ('windows','linux','snmp'):
            raise ValueError('Profil adı ve Windows/Linux/SNMP türü gerekli.')
        scope=str(network(data.get('scope','')))
        username=data.get('username','')
        current=data.get('use_current_user',False)
        enabled=data.get('enabled',False)
        port=data.get('port',22)
        version=data.get('version','2c')
        host_key=data.get('host_key','')
        if not isinstance(host_key,str):
            raise ValueError('SSH parmak izi metin olmalıdır.')
        host_key=host_key.strip()
        if not isinstance(username,str) or len(username)>200 or not isinstance(current,bool) or not isinstance(enabled,bool):
            raise ValueError('Profil alanları geçersiz.')
        if isinstance(port,bool) or not isinstance(port,int) or not 1<=port<=65535 or version not in ('1','2c'):
            raise ValueError('Port veya SNMP sürümü geçersiz.')
        if host_key and not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}',host_key):
            raise ValueError('SSH parmak izi SHA256: biçiminde olmalıdır.')
        old=self.get(profile_id) if profile_id is not None else None
        secrets=json.loads(self.vault.decrypt(old['secret'])) if old and old['secret'] else {}
        for key,limit in (('password',512),('private_key',16000),('key_passphrase',512),('community',255)):
            value=data.get(key,'')
            if not isinstance(value,str) or len(value)>limit:
                raise ValueError('Kimlik bilgisi alanı geçersiz veya çok uzun.')
            if value:
                secrets[key]=value
        if kind=='snmp' and not secrets.get('community'):
            raise ValueError('SNMP profilinde salt okunur community gerekli.')
        if kind in ('windows','linux') and not (kind=='windows' and current):
            if not username or not (secrets.get('password') or kind=='linux' and secrets.get('private_key')):
                raise ValueError('Kullanıcı adı ve parola/SSH anahtarı gerekli.')
        if enabled and kind=='linux' and not host_key:
            raise ValueError('Otomatik Linux okumasından önce SSH anahtarını doğrulayın.')
        encrypted=self.vault.encrypt(json.dumps(secrets)) if secrets else ''
        with self.store.db() as db:
            if old is None:
                if db.execute('SELECT COUNT(*) FROM profiles').fetchone()[0]>=32:
                    raise ValueError('En fazla 32 profil eklenebilir.')
                cursor=db.execute('INSERT INTO profiles(name,kind,scope,username,port,version,use_current_user,host_key,enabled,secret) VALUES(?,?,?,?,?,?,?,?,?,?)',
                                  (name.strip(),kind,scope,username,port,version,int(current),host_key,int(enabled),encrypted))
                profile_id=cursor.lastrowid
            else:
                db.execute('UPDATE profiles SET name=?,kind=?,scope=?,username=?,port=?,version=?,use_current_user=?,host_key=?,enabled=?,secret=? WHERE id=?',
                           (name.strip(),kind,scope,username,port,version,int(current),host_key,int(enabled),encrypted,profile_id))
        return profile_id

    def delete(self,profile_id):
        with self.store.db() as db:
            if not db.execute('DELETE FROM profiles WHERE id=?',(profile_id,)).rowcount:
                raise LookupError('Profil bulunamadı.')

    def choose(self,target,kind=None):
        candidates=[p for p in self.list() if p['enabled'] and (kind is None or p['kind']==kind) and ipaddress.ip_address(target) in ipaddress.ip_network(p['scope'])]
        return sorted(candidates,key=lambda p:(-ipaddress.ip_network(p['scope']).prefixlen,p['id']))

    def snmp_config(self,target,fallback):
        candidates=self.choose(target,'snmp')
        if not candidates:
            return fallback
        row=self.get(candidates[0]['id'])
        try:
            secret=json.loads(self.vault.decrypt(row['secret']))
            return {'enabled':True,'community':secret['community'],'version':row['version']}
        except Exception:
            return {'enabled':False,'community':''}

    def read(self,profile_id,target,manual=False):
        with self.guard:
            lock=self.locks.setdefault(profile_id,threading.Lock())
        with lock:
            row=self.get(profile_id)
            if ipaddress.ip_address(target) not in ipaddress.ip_network(row['scope']):
                raise ValueError('Test IP adresi profil kapsamının dışında.')
            if not manual and not row['enabled']:
                return {'ok':False,'error_code':'paused','error':'Profil otomatik okuma için kapalı.'}
            try:
                secret=json.loads(self.vault.decrypt(row['secret']))
                result=collectors.collect(target,row,secret)
            except Exception:
                result=collectors.failure('profile_error')
            message='Başarılı · '+result.get('source',row['kind']) if result.get('ok') else result.get('error','Veri alınamadı.')
            with self.store.db() as db:
                db.execute('UPDATE profiles SET last_result=? WHERE id=?',(message,profile_id))
                if result.get('error_code') in ('authentication_failed','ssh_host_key_changed','access_denied'):
                    db.execute('UPDATE profiles SET enabled=0 WHERE id=?',(profile_id,))
            return result
