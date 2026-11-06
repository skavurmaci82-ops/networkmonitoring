import base64
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from app import Store, analyze_metrics, counter_rates
from collectors import fingerprint, linux, normalize, snmp_load, windows
from credential_vault import Vault
from test_app import result
import test_app


class CollectorTests(unittest.TestCase):
    def test_real_linux_read_only_script_returns_load_and_hardware(self):
        script=Path(__file__).resolve().parents[1]/'collector_scripts/linux.py'
        response=subprocess.run([sys.executable,str(script)],capture_output=True,text=True,timeout=10,check=True)
        data=normalize(json.loads(response.stdout))
        self.assertTrue(data['ok'])
        self.assertGreater(data['memory_total_bytes'],0)
        self.assertTrue(0<=data['cpu_percent']<=100)
        self.assertTrue(0<=data['memory_percent']<=100)
        self.assertTrue(data['name'])

    def test_windows_credentials_only_on_stdin_and_result_normalized(self):
        captured={}
        def runner(command,**kwargs):
            captured.update(command=command,**kwargs)
            return subprocess.CompletedProcess(command,0,json.dumps({'ok':True,'source':'Windows CIM/DCOM','name':'TEST-WIN','model':'Test Model','cpu_percent':35,'memory_percent':50,'macs':['00-0b-86-00-12-34']}),'')
        with patch('collectors.platform.system',return_value='Windows'):
            data=windows('192.168.10.12',{'username':'DOMAIN\\reader'},{'password':'test-only-secret'},runner)
        self.assertEqual(data['model'],'Test Model')
        self.assertEqual(data['macs'],['00:0B:86:00:12:34'])
        self.assertNotIn('test-only-secret',' '.join(captured['command']))
        self.assertEqual(json.loads(captured['input'])['password'],'test-only-secret')
        self.assertIn('PacketPrivacy',base64.b64decode(captured['command'][-1]).decode('utf-16le'))

    def test_unknown_metrics_are_not_zero_and_extraneous_keys_not_stored(self):
        data=normalize({'ok':True,'cpu_percent':None,'memory_percent':200,'password':'must-disappear','interfaces':[{'name':'eth0','password':'must-disappear','rx_bps':20}]})
        self.assertIsNone(data['cpu_percent']);self.assertIsNone(data['memory_percent'])
        self.assertNotIn('must-disappear',json.dumps(data))

    def test_snmp_profile_test_combines_identity_macs_and_metrics(self):
        from collectors import collect
        with patch('collectors.identify',return_value={'status':'ok','model':'Switch model','name':'SW-TEST','manufacturer':'Aruba','source':'ENTITY-MIB'}),patch('collectors.inspect_network',return_value={'macs':['00:0B:86:00:12:34'],'interfaces':[],'neighbors':[],'lldp_status':'read'}),patch('collectors.snmp_load',return_value=normalize({'ok':True,'source':'SNMP','cpu_percent':15})):
            data=collect('192.168.10.12',{'kind':'snmp','version':'2c'},{'community':'test'})
        self.assertTrue(data['ok'])
        self.assertEqual(data['model'],'Switch model')
        self.assertEqual(data['macs'],['00:0B:86:00:12:34'])
        self.assertEqual(data['cpu_percent'],15)
        self.assertNotIn('community',data)

    def test_snmp_standard_cpu_ram_and_disk(self):
        from snmp import SYS_UPTIME
        class Agent:
            def __init__(self,*args,**kwargs):pass
            def query(self,oids,**kwargs):
                values={SYS_UPTIME:1000,
                        '1.3.6.1.2.1.25.2.3.1.3.1':'RAM','1.3.6.1.2.1.25.2.3.1.4.1':1024,'1.3.6.1.2.1.25.2.3.1.5.1':1000,'1.3.6.1.2.1.25.2.3.1.6.1':400,
                        '1.3.6.1.2.1.25.2.3.1.3.2':'disk','1.3.6.1.2.1.25.2.3.1.4.2':4096,'1.3.6.1.2.1.25.2.3.1.5.2':100,'1.3.6.1.2.1.25.2.3.1.6.2':95}
                return [(oid,values.get(oid)) for oid in oids]
            def walk(self,prefix,**kwargs):
                if prefix=='1.3.6.1.2.1.25.3.3.1.2':return iter([(prefix+'.1',20),(prefix+'.2',40)])
                if prefix=='1.3.6.1.2.1.25.2.3.1.2':return iter([(prefix+'.1','1.3.6.1.2.1.25.2.1.2'),(prefix+'.2','1.3.6.1.2.1.25.2.1.4')])
                return iter([])
        data=snmp_load('192.168.10.12',{'community':'test'},Agent)
        self.assertEqual(data['cpu_percent'],30)
        self.assertEqual(data['memory_percent'],40)
        self.assertEqual(data['disks'][0]['used_percent'],95)
        self.assertEqual(analyze_metrics(data)[0]['code'],'disk:disk')

    def test_network_rates_require_two_samples_and_reset_is_not_spike(self):
        previous={'sample_epoch':100,'uptime_ticks':1000,'network':[{'index':1,'counter_rx':100,'counter_tx':200,'counter_errors':1,'counter_discontinuity':0}]}
        current={'uptime_ticks':2000,'network':[{'index':1,'counter_rx':1100,'counter_tx':2200,'counter_errors':3,'counter_discontinuity':0}]}
        with patch('app.time.time',return_value=110):counter_rates(current,previous)
        self.assertEqual(current['network'][0]['rx_bps'],800)
        self.assertEqual(current['network'][0]['tx_bps'],1600)
        self.assertEqual(current['network'][0]['new_errors'],2)
        reset={'uptime_ticks':10,'network':[{'index':1,'counter_rx':10,'counter_tx':10,'counter_errors':0,'counter_discontinuity':0}]}
        with patch('app.time.time',return_value=120):counter_rates(reset,current)
        self.assertNotIn('rx_bps',reset['network'][0])
        self.assertTrue(reset['network'][0]['counter_reset'])


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.store=Store(Path(self.temp.name)/'profiles.sqlite3')
    def tearDown(self):self.temp.cleanup()
    def profile(self,**extra):
        return self.store.profiles.save({'name':'Linux test','kind':'linux','scope':'192.168.10.12','username':'reader','password':'unit-test-password',**extra})

    def test_credentials_encrypted_preserved_and_api_metadata_only(self):
        profile_id=self.profile()
        row=self.store.profiles.get(profile_id)
        self.assertNotIn('unit-test-password',row['secret'])
        self.assertNotIn('unit-test-password',Path(self.store.path).read_bytes().decode('latin-1'))
        self.assertNotIn('unit-test-password',json.dumps(self.store.profiles.list()))
        self.store.profiles.save({'name':'updated','kind':'linux','scope':'192.168.10.12','username':'reader','password':''},profile_id)
        secret=json.loads(self.store.profiles.vault.decrypt(self.store.profiles.get(profile_id)['secret']))
        self.assertEqual(secret['password'],'unit-test-password')

    def test_scope_and_verified_key_are_required_for_automatic_read(self):
        with self.assertRaises(ValueError):self.profile(enabled=True)
        profile_id=self.profile()
        with self.assertRaises(ValueError):self.store.profiles.read(profile_id,'192.168.100.12',manual=True)
        self.assertEqual(self.store.profiles.choose('192.168.10.12'),[])

    def test_bad_auth_pauses_profile_before_next_target(self):
        profile_id=self.profile(enabled=True,host_key='SHA256:'+'A'*43,scope='192.168.10.0/24')
        with patch('profiles.collectors.collect',return_value={'ok':False,'error_code':'authentication_failed','error':'Authentication failed'}) as collect:
            self.store.profiles.read(profile_id,'192.168.10.12')
            self.store.profiles.read(profile_id,'192.168.10.13')
        self.assertEqual(collect.call_count,1)
        self.assertFalse(self.store.profiles.list()[0]['enabled'])

    def test_inventory_and_metrics_are_persisted_without_manual_overwrite(self):
        self.store.record(result())
        device_id=self.store.devices()[0]['id']
        self.store.save_device({'ip':'192.168.10.12','name':'Manual name','model':'Manual model'},device_id)
        data={'ok':True,'source':'Windows CIM/DCOM','name':'WIN-PC','model':'Real Model','manufacturer':'Test Vendor','os':'Windows test','cpu_name':'Test CPU','cpu_percent':95,'memory_percent':45,'memory_total_bytes':8*1024**3,'macs':['00:0B:86:00:12:34'],'disks':[]}
        self.store.record_collection('192.168.10.12',data)
        self.store.record_collection('192.168.10.12',{**data,'cpu_percent':96})
        device=self.store.devices()[0]
        self.assertEqual(device['display_model'],'Manual model')
        self.assertEqual(device['detected_model'],'Real Model')
        self.assertEqual(device['display_name'],'Manual name')
        self.assertEqual(device['display_os'],'Windows test')
        self.assertEqual(len(self.store.measurement_history(device_id)),2)
        warnings=[e for e in self.store.events() if e['level']=='warning']
        self.assertEqual(len(warnings),1)
        self.store.record_collection('192.168.10.12',{'ok':False,'error_code':'timeout','error':'Timed out'})
        self.assertEqual(self.store.devices()[0]['metrics']['cpu_percent'],96)
        self.assertEqual(self.store.devices()[0]['collector_status'],'timeout')


class ProfileHTTPTests(unittest.TestCase):
    setUp=test_app.HTTPTests.setUp
    tearDown=test_app.HTTPTests.tearDown
    request=test_app.HTTPTests.request
    def test_profile_crud_and_single_host_test(self):
        status,created=self.request('POST','/api/profiles',{'name':'Windows test','kind':'windows','scope':'192.168.10.12','use_current_user':True})
        self.assertEqual(status,201)
        profile_id=created['id']
        with patch('profiles.collectors.collect',return_value={'ok':True,'source':'Windows CIM/DCOM','name':'WIN-TEST','model':'Real test model','cpu_percent':20,'memory_percent':30,'macs':['00:0B:86:00:12:34']}):
            status,data=self.request('POST',f'/api/profiles/{profile_id}/test',{'target':'192.168.10.12'})
        self.assertEqual(status,200);self.assertTrue(data['ok'])
        state=self.request('GET','/api/state')[1]
        self.assertEqual(state['devices'][0]['display_model'],'Real test model')
        self.assertEqual(state['devices'][0]['metrics']['cpu_percent'],20)
        self.assertEqual(self.request('POST',f'/api/profiles/{profile_id}/test',{'target':'192.168.100.12'})[0],400)
        self.assertEqual(self.request('DELETE',f'/api/profiles/{profile_id}')[0],200)


if __name__=='__main__':unittest.main()
