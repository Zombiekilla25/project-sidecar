"""JSON-lines PRL/Kryptex Stratum transport. No production proof encoder is assumed."""
from __future__ import annotations
import json, socket, ssl, threading, time
from queue import Queue, Empty
from .models import MiningJob
from .verification import Verification

class StratumError(RuntimeError): pass

class StratumClient:
    def __init__(self, host, port, worker, password="x", tls=False, timeout=5.0):
        self.host,self.port,self.worker,self.password,self.tls,self.timeout=host,port,worker,password,tls,timeout
        self.sock=None; self.reader=None; self.stop_event=threading.Event(); self.lock=threading.Lock(); self.next_id=10
        self.pending={}; self.jobs=Queue(); self.events=Queue(); self.sequence=0; self.difficulty=None; self.connected=False; self.current_job=None
    def connect(self):
        raw=socket.create_connection((self.host,self.port),timeout=self.timeout)
        self.sock=ssl.create_default_context().wrap_socket(raw,server_hostname=self.host) if self.tls else raw
        self.sock.settimeout(.25); self.stop_event.clear()
        self.reader=threading.Thread(target=self._read_loop,daemon=True); self.reader.start()
        self._send({"id":1,"method":"mining.configure","params":[["pearl/v1"],{}]})
        self._send({"id":2,"method":"mining.subscribe","params":["sidecar-miner/0.1.0"]})
        response=self._request("mining.authorize",[self.worker,self.password])
        if response.get("result") is not True: self.close(); raise StratumError(f"authorization rejected: {response}")
        self.connected=True
    def _send(self,obj):
        if self.sock is None: raise StratumError("not connected")
        data=(json.dumps(obj,separators=(",",":"))+"\n").encode()
        with self.lock: self.sock.sendall(data)
    def _request(self,method,params):
        with self.lock:
            self.next_id+=1; rid=self.next_id; q=Queue(maxsize=1); self.pending[rid]=q
        self._send({"id":rid,"method":method,"params":params})
        try: return q.get(timeout=self.timeout)
        except Empty: raise StratumError(f"timeout waiting for {method}")
        finally:
            with self.lock: self.pending.pop(rid,None)
    def submit(self,verification):
        if not isinstance(verification, Verification) or not verification.authentic or not verification.accepted or verification.share is None:
            raise StratumError("only locally verified candidates may be submitted")
        share=verification.share
        if self.current_job is None or share.job_fingerprint != self.current_job.fingerprint:
            raise StratumError("share belongs to a stale or unknown job")
        params=dict(share.submit_params)
        if params.get("job_id") != share.job_id: raise StratumError("submit job_id mismatch")
        if "plain_proof" not in params: raise StratumError("PRL submit adapter must provide object params with plain_proof")
        return self._request("mining.submit",params)
    def next_job(self,timeout=None): return self.jobs.get(timeout=timeout)
    def _read_loop(self):
        buf=b""
        while not self.stop_event.is_set():
            try: data=self.sock.recv(65536)
            except socket.timeout: continue
            except OSError as e:
                self.events.put(("disconnect",str(e))); break
            if not data: self.events.put(("disconnect","eof")); break
            buf+=data
            while b"\n" in buf:
                line,buf=buf.split(b"\n",1)
                if not line.strip(): continue
                try: msg=json.loads(line)
                except (ValueError,UnicodeDecodeError): self.events.put(("malformed",line.decode(errors="replace"))); continue
                self._dispatch(msg)
    def _dispatch(self,msg):
        if not isinstance(msg,dict): self.events.put(("malformed","message must be object")); return
        rid=msg.get("id")
        if rid is not None:
            with self.lock: q=self.pending.get(rid)
            if q:
                try: q.put_nowait(msg)
                except: pass
            else: self.events.put(("orphan_response",msg))
            return
        method=msg.get("method"); params=msg.get("params")
        if method=="mining.notify":
            try:
                self.sequence+=1
                job=MiningJob.from_notify(params,self.sequence,self.difficulty)
                self.current_job=job
                self.jobs.put(job); self.events.put(("job",job))
            except (ValueError,TypeError) as e: self.events.put(("malformed",str(e)))
        elif method=="mining.set_difficulty":
            val=params
            if isinstance(params,list) and params: val=params[0]
            try: self.difficulty=float(val)
            except (TypeError,ValueError): self.events.put(("malformed","invalid set_difficulty")); return
            self.events.put(("difficulty",self.difficulty))
        else: self.events.put(("notification",msg))
    def close(self):
        self.stop_event.set(); self.connected=False
        if self.sock:
            try: self.sock.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            try: self.sock.close()
            except OSError: pass
            self.sock=None
