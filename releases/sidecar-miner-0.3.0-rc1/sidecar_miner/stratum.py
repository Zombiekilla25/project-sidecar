"""JSON-lines PRL/Kryptex Stratum transport. No production proof encoder is assumed."""
from __future__ import annotations
import json, socket, ssl, threading, time
from queue import Queue, Empty
from .models import MiningJob
from .prl_job import decode_prl_notify
from .share_encoder import build_prl_submit_params
from .telemetry import Telemetry
from .verification import Verification

class StratumError(RuntimeError): pass

class StratumClient:
    def __init__(self, host, port, worker, password="x", tls=False, timeout=5.0, telemetry=None):
        self.host,self.port,self.worker,self.password,self.tls,self.timeout=host,port,worker,password,tls,timeout
        self.telemetry=telemetry or Telemetry()
        self.sock=None; self.reader=None; self.stop_event=threading.Event(); self.lock=threading.Lock(); self.next_id=10
        self.pending={}; self.jobs=Queue(); self.events=Queue(); self.job_listeners=[]; self.sequence=0; self.difficulty=None; self.connected=False; self.current_job=None
    def connect(self):
        raw=socket.create_connection((self.host,self.port),timeout=self.timeout)
        self.sock=ssl.create_default_context().wrap_socket(raw,server_hostname=self.host) if self.tls else raw
        self.sock.settimeout(.25); self.stop_event.clear()
        self.reader=threading.Thread(target=self._read_loop,daemon=True); self.reader.start()
        self._send({"id":1,"method":"mining.configure","params":[["pearl/v1"],{}]})
        self._send({"id":2,"method":"mining.subscribe","params":["sidecar-miner/0.1.0"]})
        response=self._request("mining.authorize",[self.worker,self.password])
        if response.get("result") is not True: self.close(); raise StratumError(f"authorization rejected: {response}")
        self.connected=True; self.telemetry.pool_state="authorized"
    def _send(self,obj,on_attempt=None):
        if self.sock is None: raise StratumError("not connected")
        data=(json.dumps(obj,separators=(",",":"))+"\n").encode()
        with self.lock:
            if on_attempt:on_attempt()
            self.sock.sendall(data)
    def _request(self,method,params,on_attempt=None):
        with self.lock:
            self.next_id+=1; rid=self.next_id; q=Queue(maxsize=1); self.pending[rid]=q
        self._send({"id":rid,"method":method,"params":params},on_attempt=on_attempt)
        try: return q.get(timeout=self.timeout)
        except Empty: raise StratumError(f"timeout waiting for {method}")
        finally:
            with self.lock: self.pending.pop(rid,None)
    def submit(self,verification,on_attempt=None):
        if not isinstance(verification, Verification) or not verification.authentic or not verification.accepted or verification.share is None:
            raise StratumError("only locally verified candidates may be submitted")
        share=verification.share
        if self.current_job is None or share.job_fingerprint != self.current_job.fingerprint or share.candidate.generation != self.current_job.generation:
            self.telemetry.stale_shares+=1
            raise StratumError("share belongs to a stale or unknown job")
        params=build_prl_submit_params(self.current_job,share.candidate,self.telemetry)
        return self._submit_prepared(params,on_attempt)
    def submit_encoded(self,verification,params,on_attempt=None):
        if not isinstance(verification,Verification) or not verification.authentic or not verification.accepted or verification.share is None:
            raise StratumError("only locally verified candidates may be submitted")
        share=verification.share
        if self.current_job is None or share.job_fingerprint!=self.current_job.fingerprint or share.candidate.generation!=self.current_job.generation:
            self.telemetry.stale_shares+=1
            raise StratumError("share belongs to a stale or unknown job")
        expected=build_prl_submit_params(self.current_job,share.candidate,self.telemetry)
        if params!=expected:raise StratumError("encoded share does not match verified candidate")
        return self._submit_prepared(params,on_attempt)
    def _submit_prepared(self,params,on_attempt=None):
        started=time.perf_counter()
        try:
            response=self._request("mining.submit",params,on_attempt=on_attempt)
            if response.get("result") is True and not response.get("error"): self.telemetry.accepted_shares+=1
            else: self.telemetry.rejected_shares+=1
            return response
        finally: self.telemetry.record_stage("submission",time.perf_counter()-started)
    def next_job(self,timeout=None): return self.jobs.get(timeout=timeout)
    def add_job_listener(self,listener):
        if not callable(listener):raise TypeError("job listener must be callable")
        self.job_listeners.append(listener)
    def _read_loop(self):
        buf=b""
        while not self.stop_event.is_set():
            try: data=self.sock.recv(65536)
            except socket.timeout: continue
            except OSError as e:
                self.telemetry.pool_state="disconnected"
                self.events.put(("disconnect",str(e))); break
            if not data:
                self.telemetry.pool_state="disconnected"
                self.events.put(("disconnect","eof")); break
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
                job=decode_prl_notify({"id":None,"method":method,"params":params},self.sequence,self.difficulty,self.telemetry)
                self.current_job=job
                self.telemetry.current_job_id=job.job_id; self.telemetry.job_received_at=job.received_at
                for listener in tuple(self.job_listeners):listener(job)
                self.jobs.put(job); self.events.put(("job",job))
            except (ValueError,TypeError) as e: self.events.put(("malformed",str(e)))
        elif method=="mining.set_difficulty":
            val=params
            if isinstance(params,list) and params: val=params[0]
            try:
                import math
                new_difficulty=float(val)
                if new_difficulty<=0 or not math.isfinite(new_difficulty): raise ValueError()
            except (TypeError,ValueError): self.events.put(("malformed","invalid set_difficulty")); return
            self.difficulty=new_difficulty
            self.events.put(("difficulty",self.difficulty))
        else: self.events.put(("notification",msg))
    def close(self):
        self.stop_event.set(); self.connected=False; self.telemetry.pool_state="disconnected"
        if self.sock:
            try: self.sock.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            try: self.sock.close()
            except OSError: pass
            self.sock=None
