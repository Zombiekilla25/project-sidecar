import json,socket,threading,time,unittest
from dataclasses import replace
from sidecar_miner.stratum import StratumClient,StratumError
from sidecar_miner.verification import verify_candidate
from sidecar_miner.pearlhash import PearlHashCpuVerifier
from sidecar_miner.reconnect import ReconnectPolicy
from sidecar_miner.telemetry import Telemetry
from tests.reference_support import fixture_job,canonical_proof,candidate_for

class MockKryptex:
    """Local deterministic PRL flow fixture. It only binds loopback."""
    def __init__(self):
        self.job=fixture_job(); self.server=socket.socket(); self.server.bind(('127.0.0.1',0)); self.server.listen(); self.port=self.server.getsockname()[1]
        self.messages=[]; self.submit_count=0; self.lock=threading.Lock(); self.thread=threading.Thread(target=self.run,daemon=True); self.thread.start()
    def send(self,c,obj): c.sendall((json.dumps(obj,separators=(',',':'))+'\n').encode())
    def run(self):
        while True:
            try: c,_=self.server.accept()
            except OSError: return
            threading.Thread(target=self.handle,args=(c,),daemon=True).start()
    def handle(self,c):
        buf=b''
        try:
            while True:
                d=c.recv(4096)
                if not d:return
                buf+=d
                while b'\n' in buf:
                    line,buf=buf.split(b'\n',1); m=json.loads(line)
                    with self.lock:self.messages.append(m)
                    if m['method']=='mining.authorize':
                        self.send(c,{'id':m['id'],'result':True,'error':None})
                        self.send(c,{'id':None,'method':'mining.set_difficulty','params':[4]})
                        self.send(c,{'id':None,'method':'mining.notify','params':{'job_id':self.job.job_id,'header':self.job.header.hex(),'height':self.job.height,'target':f'{self.job.target:064x}','cert_version':self.job.cert_version}})
                    elif m['method']=='mining.submit':
                        with self.lock:
                            self.submit_count+=1; accepted=self.submit_count==1
                        self.send(c,{'id':900001,'result':True,'error':None})
                        self.send(c,{'id':m['id'],'result':accepted,'error':None if accepted else {'code':22,'message':'fixture rejection'}})
        except (OSError,ValueError,KeyError): pass
        finally:
            try:c.close()
            except OSError:pass
    def close(self):
        self.server.close(); self.thread.join(timeout=1)

def connect(f,telemetry=None):
    c=StratumClient('127.0.0.1',f.port,'offline.worker',timeout=2,telemetry=telemetry); c.connect(); return c

class KryptexOfflineSessionTests(unittest.TestCase):
    def test_full_authorize_verify_submit_reject_clean_stale_reconnect(self):
        fixture=MockKryptex(); telemetry=Telemetry()
        try:
            proof=canonical_proof(fixture.job); verifier=PearlHashCpuVerifier()
            client=connect(fixture,telemetry); job=client.next_job(2)
            self.assertEqual(job.job_id,fixture.job.job_id); self.assertEqual(job.difficulty,4.0)
            methods=[x['method'] for x in fixture.messages[:3]]
            self.assertEqual(methods,['mining.configure','mining.subscribe','mining.authorize'])
            first=candidate_for(job,proof,nonce=1); verified=verify_candidate(job,first,verifier.verify,telemetry)
            self.assertTrue(verified.accepted,verified.reason); self.assertTrue(client.submit(verified)['result'])
            rejected=verify_candidate(job,replace(first,nonce=2),verifier.verify)
            self.assertTrue(rejected.accepted); self.assertFalse(client.submit(rejected)['result'])
            self.assertTrue(any(e[0]=='orphan_response' for e in list(client.events.queue)))
            old=verify_candidate(job,first,verifier.verify); self.assertTrue(old.accepted)
            newer=replace(job,job_id='offline-job-clean',sequence=job.sequence+1,clean=True)
            client._dispatch({'id':None,'method':'mining.notify','params':{'job_id':newer.job_id,'header':newer.header.hex(),'height':newer.height,'target':f'{newer.target:064x}','cert_version':newer.cert_version,'clean':True}})
            self.assertTrue(client.next_job(1).clean)
            with self.assertRaises(StratumError):client.submit(old)
            client.close(); events=[]
            while 'disconnect' not in events:events.append(client.events.get(timeout=2)[0])
            again=connect(fixture); self.assertEqual(again.next_job(2).job_id,fixture.job.job_id); again.close()
            self.assertIn('job_parse',telemetry.stage_seconds); self.assertIn('verification',telemetry.stage_seconds)
            self.assertIn('submission_encoding',telemetry.stage_seconds); self.assertIn('submission',telemetry.stage_seconds)
        finally:fixture.close()
    def test_malformed_notification_and_invalid_difficulty(self):
        f=MockKryptex()
        try:
            c=connect(f); c.next_job(2)
            c._dispatch({'id':None,'method':'mining.set_difficulty','params':[float('nan')]})
            c._dispatch({'id':None,'method':'mining.notify','params':{'job_id':'broken'}})
            kinds=[]
            while 'malformed' not in kinds:kinds.append(c.events.get(timeout=1)[0])
            self.assertIn('malformed',kinds); c.close()
        finally:f.close()
