import json, socket, threading, time, unittest
from sidecar_miner.stratum import StratumClient, StratumError
from sidecar_miner.models import Candidate
from sidecar_miner.verification import verify_candidate
from sidecar_miner.reconnect import ReconnectPolicy

class Fixture:
    """Deterministic local PRL-shaped JSON-lines fixture; never contacts a pool."""
    def __init__(self):
        self.s=socket.socket(); self.s.bind(('127.0.0.1',0)); self.s.listen(); self.port=self.s.getsockname()[1]
        self.thread=threading.Thread(target=self.run,daemon=True); self.thread.start(); self.messages=[]
    def send(self,c,o): c.sendall((json.dumps(o)+'\n').encode())
    def run(self):
        while True:
            try: c,_=self.s.accept()
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
                    line,buf=buf.split(b'\n',1); m=json.loads(line); self.messages.append(m)
                    if m['method']=='mining.authorize':
                        self.send(c,{'id':m['id'],'result':True,'error':None})
                        self.send(c,{'id':None,'method':'mining.set_difficulty','params':[4.0]})
                        self.send(c,{'id':None,'method':'mining.notify','params':{'job_id':'j1','header':bytes(range(76)).hex(),'height':1,'target':f'{1<<255:064x}','cert_version':2}})
                    elif m['method']=='mining.submit':
                        # An unsolicited response arrives first; correct ID matching must ignore it.
                        self.send(c,{'id':900001,'result':True,'error':None})
                        accepted=m['params'].get('plain_proof')=='accepted'
                        self.send(c,{'id':m['id'],'result':accepted,'error':None if accepted else {'code':22}})
        except (OSError,ValueError): pass
        finally:
            try: c.close()
            except OSError: pass
    def close(self):
        self.s.close()
        self.thread.join(timeout=1)

def connect(f):
    c=StratumClient('127.0.0.1',f.port,'fixture.worker',timeout=2); c.connect(); return c

class StratumFixtureTests(unittest.TestCase):
    def test_prl_fixture_handshake_jobs_difficulty_submit_order_and_reconnect(self):
        f=Fixture()
        try:
            c=connect(f); j=c.next_job(2)
            self.assertEqual((j.job_id,j.difficulty),('j1',4.0))
            methods=[m['method'] for m in f.messages]
            self.assertEqual(methods[:3],['mining.configure','mining.subscribe','mining.authorize'])
            # Candidate must pass local reference verification before any submit call.
            for proof,expected in [('accepted',True),('rejected',False)]:
                cand=Candidate(j.job_id,j.fingerprint,{},0,{'job_id':j.job_id,'type':'v2','plain_proof':proof})
                checked=verify_candidate(j,cand,lambda *_:True)
                self.assertTrue(checked.accepted)
                response=c.submit(checked)
                self.assertIs(response['result'],expected)
            self.assertTrue(any(e[0]=='orphan_response' for e in list(c.events.queue)))
            c.close()
            time.sleep(.05)
            c2=connect(f); self.assertEqual(c2.next_job(2).job_id,'j1'); c2.close()
            policy=ReconnectPolicy(1,4,jitter=0); self.assertEqual([policy.next_delay() for _ in range(3)],[1,2,4])
        finally: f.close()
    def test_unverified_share_is_blocked_at_transport_boundary(self):
        f=Fixture()
        try:
            c=connect(f); j=c.next_job(2)
            cand=Candidate(j.job_id,j.fingerprint,{},0,{'job_id':j.job_id,'type':'v2','plain_proof':'accepted'})
            rejected=verify_candidate(j,cand,lambda *_:False)
            with self.assertRaises(StratumError): c.submit(rejected)
            c.close()
        finally: f.close()

    def test_clean_job_replacement_malformed_and_disconnect(self):
        f=Fixture()
        try:
            c=connect(f); first=c.next_job(2)
            old_candidate=Candidate(first.job_id,first.fingerprint,{},0,{'job_id':first.job_id,'type':'v2','plain_proof':'accepted'})
            old_verified=verify_candidate(first,old_candidate,lambda *_:True)
            c._dispatch({'id':None,'method':'mining.notify','params':{'job_id':'j2','header':(bytes([1])*76).hex(),'height':2,'target':f'{1<<255:064x}','cert_version':2,'clean':True}})
            second=c.next_job(1); self.assertTrue(second.clean and second.sequence>first.sequence)
            with self.assertRaises(StratumError): c.submit(old_verified)
            c._dispatch({'id':None,'method':'mining.notify','params':{'job_id':'bad','header':'00','target':'ff'}})
            seen=[]
            while 'malformed' not in seen: seen.append(c.events.get(timeout=1)[0])
            self.assertIn('job',seen)
            c.close()
            events=[]
            while not events or events[-1] != 'disconnect': events.append(c.events.get(timeout=2)[0])
            self.assertIn('disconnect',events)
        finally: f.close()
