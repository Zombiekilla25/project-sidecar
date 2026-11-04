"""Deterministic, loopback-only Stratum fixture used by --dry-run and integration tests."""
from __future__ import annotations
import json,socket,threading
from .models import MiningJob

class MockKryptexServer:
    def __init__(self,job:MiningJob,reject_shares=False):
        self.job=job;self.reject_shares=reject_shares;self.messages=[];self.submissions=[]
        self.server=socket.socket();self.server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);self.server.bind(('127.0.0.1',0));self.server.listen();self.server.settimeout(.2);self.port=self.server.getsockname()[1]
        self.thread=threading.Thread(target=self._serve,daemon=True);self.thread.start()
    def _send(self,c,obj):c.sendall((json.dumps(obj,separators=(',',':'))+'\n').encode())
    def _serve(self):
        while True:
            try:c,_=self.server.accept()
            except socket.timeout:continue
            except OSError:return
            threading.Thread(target=self._handle,args=(c,),daemon=True).start()
    def _handle(self,c):
        buf=b''
        try:
            while True:
                d=c.recv(4096)
                if not d:return
                buf+=d
                while b'\n' in buf:
                    line,buf=buf.split(b'\n',1);m=json.loads(line);self.messages.append(m)
                    if m.get('method')=='mining.authorize':
                        self._send(c,{'id':m['id'],'result':True,'error':None})
                        self._send(c,{'id':None,'method':'mining.set_difficulty','params':[1]})
                        self._send(c,{'id':None,'method':'mining.notify','params':{'job_id':self.job.job_id,'header':self.job.header.hex(),'target':f'{self.job.target:064x}','height':self.job.height,'cert_version':self.job.cert_version,'clean':True}})
                    elif m.get('method')=='mining.submit':
                        self.submissions.append(m)
                        valid=set(m.get('params',{}))=={'job_id','plain_proof'} and m['params'].get('job_id')==self.job.job_id
                        accepted=valid and not self.reject_shares
                        self._send(c,{'id':m['id'],'result':accepted,'error':None if accepted else {'code':22,'message':'offline fixture rejected'}})
        except (OSError,ValueError,KeyError,TypeError):pass
        finally:
            try:c.close()
            except OSError:pass
    def close(self):
        try:self.server.shutdown(socket.SHUT_RDWR)
        except OSError:pass
        try:self.server.close()
        except OSError:pass
        self.thread.join(timeout=1)
