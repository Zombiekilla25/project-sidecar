"""Fail-closed execution supervisor for staged Sidecar miner operation.

The supervisor owns lifecycle, preflight, share-attempt limits, evidence and
shutdown ordering. It receives transport/backend operations through an
injected adapter; importing this module has no network, CUDA or USB effects.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Protocol
from collections import deque
import json
import logging
import os
import re
import signal
import tempfile
import time

from .config import Config
from .verification import Verification


class SupervisorState(str, Enum):
    CREATED="CREATED"; PREFLIGHT="PREFLIGHT"; CONNECTING="CONNECTING"
    CONNECTED="CONNECTED"; AUTHORIZED="AUTHORIZED"; JOB_READY="JOB_READY"
    BACKEND_READY="BACKEND_READY"; MINING="MINING"; SHARE_CANARY="SHARE_CANARY"
    RUNNING="RUNNING"; DEGRADED="DEGRADED"; RECOVERING="RECOVERING"
    STOPPING="STOPPING"; STOPPED="STOPPED"; FAILED="FAILED"


_TRANSITIONS={
    SupervisorState.CREATED:{SupervisorState.PREFLIGHT,SupervisorState.STOPPING,SupervisorState.FAILED},
    SupervisorState.PREFLIGHT:{SupervisorState.CONNECTING,SupervisorState.STOPPING,SupervisorState.FAILED},
    SupervisorState.CONNECTING:{SupervisorState.CONNECTED,SupervisorState.RECOVERING,SupervisorState.STOPPING,SupervisorState.FAILED},
    SupervisorState.CONNECTED:{SupervisorState.AUTHORIZED,SupervisorState.RECOVERING,SupervisorState.STOPPING,SupervisorState.FAILED},
    SupervisorState.AUTHORIZED:{SupervisorState.JOB_READY,SupervisorState.RECOVERING,SupervisorState.STOPPING,SupervisorState.FAILED},
    SupervisorState.JOB_READY:{SupervisorState.BACKEND_READY,SupervisorState.RECOVERING,SupervisorState.STOPPING,SupervisorState.FAILED},
    SupervisorState.BACKEND_READY:{SupervisorState.MINING,SupervisorState.RECOVERING,SupervisorState.STOPPING,SupervisorState.FAILED},
    SupervisorState.MINING:{SupervisorState.SHARE_CANARY,SupervisorState.RUNNING,SupervisorState.DEGRADED,SupervisorState.RECOVERING,SupervisorState.STOPPING,SupervisorState.FAILED},
    SupervisorState.SHARE_CANARY:{SupervisorState.RUNNING,SupervisorState.STOPPING,SupervisorState.FAILED},
    SupervisorState.RUNNING:{SupervisorState.JOB_READY,SupervisorState.DEGRADED,SupervisorState.RECOVERING,SupervisorState.STOPPING,SupervisorState.FAILED},
    SupervisorState.DEGRADED:{SupervisorState.RECOVERING,SupervisorState.STOPPING,SupervisorState.FAILED},
    SupervisorState.RECOVERING:{SupervisorState.CONNECTING,SupervisorState.JOB_READY,SupervisorState.BACKEND_READY,SupervisorState.FAILED,SupervisorState.STOPPING},
    SupervisorState.STOPPING:{SupervisorState.STOPPED,SupervisorState.FAILED},
    SupervisorState.FAILED:{SupervisorState.RECOVERING,SupervisorState.STOPPING},
    SupervisorState.STOPPED:set(),
}


class PoolResponseState(str, Enum):
    ACCEPTED="accepted"; REJECTED="rejected"; STALE="stale"; DUPLICATE="duplicate"
    UNAUTHORIZED="unauthorized"; SERVER_ERROR="server-error"; TIMEOUT="timeout"; DISCONNECT="disconnect"


class ControlledStop(Exception):pass
class StaleSubmissionError(Exception):pass


_SECRET_KEYS={"wallet","user","worker","password","pool_password","token","serial","dna","usb_path"}
_WALLET_RE=re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9]{16,}(?![A-Za-z0-9])")


def _redact(value: Any, key: str="") -> Any:
    if key.lower() in _SECRET_KEYS:return "<redacted>"
    if isinstance(value,dict):return {str(k):_redact(v,str(k)) for k,v in value.items()}
    if isinstance(value,(list,tuple)):return [_redact(v) for v in value]
    if isinstance(value,str):
        if key.lower().endswith("sha256") or "fingerprint" in key.lower():return value
        return _WALLET_RE.sub("<redacted>",value)
    return value


class StructuredEventLog:
    """Bounded rotating JSONL logger; secrets are removed before writing."""
    def __init__(self,path: str|Path|None=None,max_bytes: int=1_048_576,backups: int=3):
        self.path=Path(path) if path else None;self.records=deque(maxlen=1024);self.logger=None
        if self.path:
            self.path.parent.mkdir(parents=True,exist_ok=True)
            self.logger=logging.getLogger(f"sidecar.supervisor.{id(self)}");self.logger.setLevel(logging.INFO);self.logger.propagate=False
            handler=RotatingFileHandler(self.path,maxBytes=max_bytes,backupCount=backups,encoding="utf-8")
            handler.setFormatter(logging.Formatter("%(message)s"));self.logger.addHandler(handler)
    def emit(self,event: str,**fields):
        row={"timestamp_utc":datetime.now(timezone.utc).isoformat(),"event":event,**fields}
        row=_redact(row);self.records.append(row)
        if self.logger:self.logger.info(json.dumps(row,sort_keys=True,separators=(",",":")))
        return row
    def close(self):
        if self.logger:
            for handler in tuple(self.logger.handlers):handler.flush();handler.close();self.logger.removeHandler(handler)


@dataclass(frozen=True)
class BackendQualificationState:
    gpu_qualified: bool
    fk_qualified: bool
    gpu_evidence_sha256: str|None=None
    fk_evidence_sha256: str|None=None
    gpu_artifact_sha256: str|None=None
    fk_artifact_sha256: str|None=None


@dataclass(frozen=True)
class SupervisorPreflight:
    pool_host: str
    pool_port: int
    selected_backend: str
    qualification: BackendQualificationState
    live: bool
    scheduler_decision: str="INSUFFICIENT_DATA"


def parse_pool_endpoint(value: str) -> tuple[str,int]:
    if not isinstance(value,str) or not value.strip():raise ValueError("pool host:port is required")
    text=value.strip()
    if text.startswith("["):
        m=re.fullmatch(r"\[([^]]+)\]:(\d+)",text)
        if not m:raise ValueError("pool IPv6 endpoint must use [host]:port")
        host,port=m.group(1),int(m.group(2))
    else:
        if text.count(":")!=1:raise ValueError("pool endpoint must be host:port")
        host,p=text.rsplit(":",1)
        if not p.isdigit():raise ValueError("pool port must be numeric")
        port=int(p)
    if not host or not 1<=port<=65535:raise ValueError("pool endpoint host/port is invalid")
    return host,port


def qualified_backends_for_mode(mode: str, qualifications: BackendQualificationState) -> tuple[str,...]:
    """Return selectable execution paths, always retaining qualified GPU fallback."""
    if mode not in ("gpu-only","sidecar","auto"):raise ValueError("unknown mining mode")
    if mode=="gpu-only":return ("gpu",) if qualifications.gpu_qualified else ()
    if mode=="sidecar":return ("gpu+fk",) if qualifications.gpu_qualified and qualifications.fk_qualified else ()
    if not qualifications.gpu_qualified:return ()
    return ("gpu+fk","gpu") if qualifications.fk_qualified else ("gpu",)


def backend_failure_fallback(mode: str,failed_backend: str,qualifications: BackendQualificationState) -> str|None:
    """Return only a qualified remaining path; FK is never a GPU work producer."""
    if mode not in ("gpu-only","sidecar","auto"):return None
    if failed_backend in ("fk","gpu+fk") and qualifications.gpu_qualified:
        return "gpu"
    # The current PearlHash work path needs GPU-produced work even when FK is
    # healthy, so losing GPU cannot be recovered by moving to FK alone.
    return None


def classify_pool_response(response: Any=None, *, error: BaseException|None=None) -> PoolResponseState:
    if error is not None:
        if isinstance(error,StaleSubmissionError) or "stale" in str(error).lower():return PoolResponseState.STALE
        if isinstance(error,TimeoutError):return PoolResponseState.TIMEOUT
        if isinstance(error,(ConnectionError,OSError)):return PoolResponseState.DISCONNECT
        message=str(error).lower()
        if "timeout" in message or "timed out" in message:return PoolResponseState.TIMEOUT
        if "disconnect" in message or "not connected" in message:return PoolResponseState.DISCONNECT
        return PoolResponseState.SERVER_ERROR
    if not isinstance(response,dict):return PoolResponseState.SERVER_ERROR
    if response.get("result") is True and not response.get("error"):return PoolResponseState.ACCEPTED
    err=response.get("error")
    text=json.dumps(err,sort_keys=True).lower()
    if any(x in text for x in ("unauthorized","not authorized","auth")):return PoolResponseState.UNAUTHORIZED
    if "stale" in text or "job not found" in text:return PoolResponseState.STALE
    if "duplicate" in text:return PoolResponseState.DUPLICATE
    if any(x in text for x in ("server error","internal error","temporarily unavailable")):return PoolResponseState.SERVER_ERROR
    if err:return PoolResponseState.REJECTED
    return PoolResponseState.SERVER_ERROR


class CanaryAdapter(Protocol):
    backend_name: str
    def connect(self) -> None: ...
    def authorize(self) -> bool: ...
    def receive_job(self,timeout: float) -> Any: ...
    def backend_ready(self,mode: str) -> bool: ...
    def execute_job(self,job: Any) -> Verification: ...
    def current_job(self) -> Any: ...
    def encode_share(self,verification: Verification) -> Any: ...
    def submit_encoded(self,verification: Verification,encoded: Any,*,on_attempt) -> dict: ...
    def stop_accepting_work(self) -> None: ...
    def cancel_queued(self) -> None: ...
    def wait_active(self,timeout: float) -> None: ...
    def close_backend(self) -> None: ...
    def disconnect(self) -> None: ...


class OfflineFixtureAdapter:
    """Marker base for test/loopback adapters; never use for live transports."""
    offline_fixture=True


@dataclass(frozen=True)
class CanaryResult:
    success: bool
    share_attempts: int
    share_verified: int
    share_submitted: int
    pool_response: str
    shutdown_clean: bool
    error: str|None=None
    evidence_path: str|None=None


class SidecarMinerSupervisor:
    def __init__(self,config: Config,*,qualifications: BackendQualificationState|None=None,
                 cuda_qualification_path: str|Path|None=None,fk_qualification_path: str|Path|None=None,
                 cuda_expected: dict|None=None,fk_expected_bitstream_sha256: str|None=None,
                 cpu_verifier_available: bool=True,share_encoder_available: bool=True,
                 log_path: str|Path|None=None,event_log: StructuredEventLog|None=None,
                 recovery_path: str|Path|None=None,canary_shares: int|None=None,
                 shutdown_timeout: float=5.0):
        self.config=config;self._qualification_fixture=qualifications
        self.cuda_qualification_path=Path(cuda_qualification_path) if cuda_qualification_path else None
        self.fk_qualification_path=Path(fk_qualification_path) if fk_qualification_path else None
        self.cuda_expected=cuda_expected or {};self.fk_expected_bitstream_sha256=fk_expected_bitstream_sha256
        self.cpu_verifier_available=cpu_verifier_available;self.share_encoder_available=share_encoder_available
        self.events=event_log or StructuredEventLog(log_path);self.recovery_path=Path(recovery_path) if recovery_path else None
        self.canary_limit=config.canary_shares if canary_shares is None else canary_shares
        if isinstance(self.canary_limit,bool) or not isinstance(self.canary_limit,int) or self.canary_limit<0:
            raise ValueError("canary share limit must be a non-negative integer")
        self.shutdown_timeout=shutdown_timeout;self.state=SupervisorState.CREATED;self.created_monotonic=time.monotonic()
        self.started_utc=datetime.now(timezone.utc).isoformat();self.pool_state="offline";self.job_generation=None
        self.job_id=None;self.job_fingerprint=None;self.candidate_verification="not-run"
        self.mode=config.mode;self.active_backend=None;self.last_share_result=None
        self.error=None;self.share_attempts=0;self.share_verified=0;self.share_submitted=0
        self.last_submitted_share_id=None;self.last_pool_response=None;self._shutdown_clean=False
        self.stop_requested=False
        self._adapter=None;self._qualification=None;self._ever_connected=False
        self.events.emit("state_transition",previous=None,current=SupervisorState.CREATED.value,generation=None)

    def _transition(self,new_state: SupervisorState):
        if new_state not in _TRANSITIONS[self.state]:
            raise ValueError(f"illegal supervisor transition {self.state.value}->{new_state.value}")
        old=self.state;self.state=new_state
        self.events.emit("state_transition",previous=old.value,current=new_state.value,generation=self.job_generation)
        self._persist_recovery()

    def _resolve_qualifications(self,live: bool) -> BackendQualificationState:
        if not live:
            return self._qualification_fixture or BackendQualificationState(False,False)
        from .qualification import load_qualification_artifact,artifact_sha256,pinned_source_hashes
        from .qualification_store import QualificationStore
        gpu_ok=fk_ok=False;gpu_sha=fk_sha=None
        gpu_artifact=fk_artifact=None
        cuda_path=self.cuda_qualification_path or (Path(self.config.cuda_qualification) if self.config.cuda_qualification else None)
        expected_cuda=self.cuda_expected or {k:v for k,v in {
            "expected_library_sha256":self.config.cuda_library_sha256 or None,
            "expected_source_sha256":self.config.cuda_source_sha256 or None,
            "expected_fixture_sha256":self.config.cuda_fixture_sha256 or None}.items() if v}
        fk_path=self.fk_qualification_path or (Path(self.config.fk_qualification) if self.config.fk_qualification else None)
        expected_bitstream=self.fk_expected_bitstream_sha256 or self.config.fk_bitstream_sha256 or None
        if not cuda_path:
            cuda_path=QualificationStore(self.config.qualification_store or None).find("cuda-pearlhash",
                expected_library_sha256=expected_cuda.get("expected_library_sha256"),
                expected_source_sha256=expected_cuda.get("expected_source_sha256"),
                expected_fixture_sha256=expected_cuda.get("expected_fixture_sha256"))
        if not fk_path and expected_bitstream:
            fk_path=QualificationStore(self.config.qualification_store or None).find("fk33-phk1",
                expected_bitstream_sha256=expected_bitstream)
        if cuda_path and expected_cuda:
            q=load_qualification_artifact(cuda_path,expected_backend_type="cuda-pearlhash",**expected_cuda)
            gpu_ok=q.qualified;gpu_sha=q.library_sha256;gpu_artifact=artifact_sha256(cuda_path)
        if fk_path and expected_bitstream:
            runner,backend=pinned_source_hashes()
            q=load_qualification_artifact(fk_path,expected_backend_type="fk33-phk1",
                expected_runner_sha256=runner,
                expected_backend_sha256=backend,expected_bitstream_sha256=expected_bitstream)
            fk_ok=q.qualified;fk_sha=q.backend_sha256;fk_artifact=artifact_sha256(fk_path)
        return BackendQualificationState(gpu_ok,fk_ok,gpu_sha,fk_sha,gpu_artifact,fk_artifact)

    def preflight(self,*,live: bool=False,log_path: str|Path|None=None) -> SupervisorPreflight:
        self._transition(SupervisorState.PREFLIGHT)
        try:
            host,port=parse_pool_endpoint(self.config.pool)
            if not self.config.wallet.strip():raise ValueError("wallet/user is required")
            if not self.config.worker.strip():raise ValueError("worker is required")
            if self.config.mode not in ("gpu-only","sidecar","auto"):raise ValueError("invalid mode")
            if self.config.gpu_id is not None and (isinstance(self.config.gpu_id,bool) or not isinstance(self.config.gpu_id,int) or self.config.gpu_id<0):
                raise ValueError("GPU ID must be a non-negative integer")
            if live and self.config.gpu_id is None:raise ValueError("an explicit GPU ID is required for live startup preflight")
            if live and not self.config.live_enabled:raise ValueError("live network execution requires explicit LIVE_ENABLED=true")
            if not self.cpu_verifier_available:raise ValueError("CPU/reference verifier is unavailable")
            if not self.share_encoder_available:raise ValueError("PRL share encoder is unavailable")
            path=Path(log_path) if log_path else self.events.path
            if live and path is None:raise ValueError("structured event log path is required for live startup")
            if path:
                parent=path.parent
                if not parent.exists() or not os.access(parent,os.W_OK):raise ValueError("structured event log location is not writable")
            qualifications=self._resolve_qualifications(live)
            choices=qualified_backends_for_mode(self.config.mode,qualifications)
            if not choices:raise ValueError("no qualified compute backend for selected mode")
            selected="gpu" if self.config.mode=="auto" else choices[0]
            decision="INSUFFICIENT_DATA" if self.config.mode!="auto" else (
                "FK_UNAVAILABLE" if not qualifications.fk_qualified else "INSUFFICIENT_DATA")
            decision_reason="operator-selected mode" if self.config.mode!="auto" else (
                "FK qualification unavailable; use GPU" if not qualifications.fk_qualified else
                "matched measured timing unavailable; use GPU")
            if self.config.mode=="auto" and qualifications.fk_qualified and self.config.gpu_timing and self.config.fk_timing:
                # The existing scheduler accepts only matched measured timing.
                # Missing, synthetic, or mismatched data stays GPU-only.
                from .integrated_scheduler import IntegratedScheduler,load_timing_inputs
                gpu_timing,fk_timing=load_timing_inputs(self.config.gpu_timing,self.config.fk_timing)
                class QualifiedFk:
                    healthy=True
                choice=IntegratedScheduler("auto",gpu_timing,fk_timing,[QualifiedFk()]).choose()
                selected="gpu+fk" if choice.mode=="sidecar" else "gpu"
                decision=choice.decision.value
                decision_reason=choice.reason
            self.events.emit("scheduler_decision",decision=decision,mode=selected,reason=decision_reason)
            if live and self.canary_limit==0:raise ValueError("live startup requires a positive share canary limit")
            self._qualification=qualifications
            self.active_backend=selected
            self.events.emit("preflight_pass",live=live,mode=self.config.mode,backend=selected)
            return SupervisorPreflight(host,port,selected,qualifications,live,decision)
        except Exception as exc:
            self.error=str(exc);self.events.emit("preflight_failed",reason=self.error)
            self._transition(SupervisorState.FAILED)
            raise

    def _same_current_job(self,job):
        current=self._adapter.current_job()
        return current is not None and getattr(current,"fingerprint",None)==getattr(job,"fingerprint",None) and getattr(current,"generation",None)==getattr(job,"generation",None)

    def _check_stop(self):
        if self.stop_requested:raise ControlledStop("controlled stop requested")

    @staticmethod
    def _verified_for_job(verification,job) -> bool:
        if not isinstance(verification,Verification) or not verification.authentic or not verification.accepted:
            return False
        share=verification.share
        if share is None:return False
        candidate=share.candidate
        verified_result=verification.computed_result
        if verified_result is None:verified_result=verification.backend_reported_result
        return (share.job_id==job.job_id and share.job_fingerprint==job.fingerprint and
            candidate.job_id==job.job_id and candidate.job_fingerprint==job.fingerprint and
            candidate.generation==job.generation and verification.candidate_valid and
            verification.meets_share_target and verification.target is not None and
            verified_result is not None and verified_result<=verification.target)

    def _shutdown(self,adapter):
        if self.state not in (SupervisorState.STOPPING,SupervisorState.STOPPED):
            self._transition(SupervisorState.STOPPING)
        errors=[]
        for name,call in (("stop_accepting",adapter.stop_accepting_work),("cancel_queued",adapter.cancel_queued),
                          ("wait_active",lambda:adapter.wait_active(self.shutdown_timeout)),
                          ("close_backend",adapter.close_backend),("disconnect",adapter.disconnect)):
            try:call();self.events.emit("shutdown_step",step=name,status="ok")
            except Exception as exc:errors.append(name);self.events.emit("shutdown_step",step=name,status="failed",reason=str(exc))
        flush=getattr(adapter,"flush_evidence",None)
        if callable(flush):
            try:flush()
            except Exception as exc:errors.append("flush_evidence");self.events.emit("evidence_flush_failed",reason=str(exc))
        self._shutdown_clean=not errors
        self.pool_state="disconnected"
        if errors:
            self.error=self.error or "shutdown steps failed: "+",".join(errors)
            self._transition(SupervisorState.FAILED)
        else:self._transition(SupervisorState.STOPPED)
        self.events.emit("shutdown",clean=self._shutdown_clean,state=self.state.value)
        self._persist_recovery()

    def run_one_share_canary(self,adapter: CanaryAdapter,*,live: bool=False,
                             evidence_path: str|Path|None=None) -> CanaryResult:
        """Run at most the configured actual submissions; mock adapters are offline."""
        if live and isinstance(adapter,OfflineFixtureAdapter):
            raise RuntimeError("live canary refuses mock/offline backends")
        if not live and not isinstance(adapter,OfflineFixtureAdapter):
            raise RuntimeError("offline execution requires an OfflineFixtureAdapter; live transports must pass validated live preflight")
        self._adapter=adapter;self.active_backend=getattr(adapter,"backend_name","unknown")
        preflight=None;verified=0;submitted=0;response_state="none";error=None
        try:
            preflight=self.preflight(live=live)
            self._check_stop()
            self.active_backend=preflight.selected_backend
            self._transition(SupervisorState.CONNECTING);self.pool_state="connecting"
            adapter.connect();self._ever_connected=True;self.pool_state="connected";self.events.emit("pool_connection",state="connected");self._check_stop()
            self._transition(SupervisorState.CONNECTED)
            if not adapter.authorize():raise RuntimeError("pool authorization failed")
            self._check_stop()
            self.pool_state="authorized";self.events.emit("authorization",status="accepted")
            self._transition(SupervisorState.AUTHORIZED)
            job=adapter.receive_job(timeout=self.shutdown_timeout)
            self._check_stop()
            if job is None:raise TimeoutError("no PRL job received before deadline")
            self.job_generation=job.generation;self.job_id=job.job_id;self.job_fingerprint=job.fingerprint
            self.events.emit("job",job_id=job.job_id,generation=job.generation,fingerprint=job.fingerprint)
            self._transition(SupervisorState.JOB_READY)
            if not adapter.backend_ready(preflight.selected_backend):raise RuntimeError("selected backend is unavailable or unhealthy")
            self._check_stop()
            self._transition(SupervisorState.BACKEND_READY);self.events.emit("backend_selection",backend=self.active_backend,mode=self.config.mode)
            self._transition(SupervisorState.MINING)
            try:verification=adapter.execute_job(job)
            except Exception as backend_exc:
                failed_backend=getattr(adapter,"failed_backend",None)
                fallback=backend_failure_fallback(self.config.mode,failed_backend,self._qualification)
                fallback_execute=getattr(adapter,"fallback_execute",None)
                if not fallback or not callable(fallback_execute):raise
                self._transition(SupervisorState.DEGRADED)
                self._transition(SupervisorState.RECOVERING)
                self.active_backend=fallback
                self.events.emit("fallback",failed_backend=failed_backend,selected_backend=fallback,reason=str(backend_exc))
                self._transition(SupervisorState.BACKEND_READY)
                self._transition(SupervisorState.MINING)
                verification=fallback_execute(fallback,job)
            self.events.emit("candidate",generation=job.generation)
            submission_gate=self._verified_for_job(verification,job)
            self.candidate_verification="pass" if submission_gate else "fail"
            self._check_stop()
            if not self._same_current_job(job):
                self.last_share_result="stale";self.events.emit("stale_candidate",generation=job.generation)
                response_state="stale";error="job changed before submission"
            elif not submission_gate:
                self.last_share_result="verification-failed";self.events.emit("verification",status="rejected",reason=getattr(verification,"reason","invalid verification"))
                response_state="verification-failed";error="candidate failed submission safety gate"
            else:
                self.candidate_verification="pass"
                self.share_verified+=1;verified+=1;self.events.emit("verification",status="accepted",generation=job.generation)
                if self.canary_limit<=0:raise RuntimeError("canary share limit is zero")
                # Encoding and all local gates precede the attempt counter.
                encoded=adapter.encode_share(verification)
                self._check_stop()
                if not self._same_current_job(job):
                    self.last_share_result="stale";response_state="stale";error="job changed during encoding"
                else:
                    self._transition(SupervisorState.SHARE_CANARY)
                    if self.canary_limit>0:
                        if not self._same_current_job(job):
                            response_state="stale";self.last_share_result=response_state
                        else:
                            attempt_marked=False
                            def mark_attempt():
                                nonlocal attempt_marked,submitted
                                if attempt_marked:raise RuntimeError("submit adapter marked one network attempt more than once")
                                if not self._same_current_job(job):raise StaleSubmissionError("job became stale at submit boundary")
                                if self.share_attempts>=self.canary_limit:raise RuntimeError("share attempt limit reached")
                                attempt_marked=True;self.share_attempts+=1;self.share_submitted+=1;submitted+=1
                                self.last_submitted_share_id=f"{job.generation}:{self.share_attempts}:{job.fingerprint[:16]}"
                                self.events.emit("share_submit",attempt=self.share_attempts,share_id=self.last_submitted_share_id)
                            try:
                                response=adapter.submit_encoded(verification,encoded,on_attempt=mark_attempt)
                                if not attempt_marked:raise RuntimeError("submit adapter returned without marking a network attempt")
                                response_state=classify_pool_response(response)
                                if response_state!=PoolResponseState.ACCEPTED:
                                    reason=response.get("error") if isinstance(response,dict) else response
                                    error=json.dumps(_redact({"reason":reason}),sort_keys=True)
                            except Exception as exc:
                                response_state=classify_pool_response(error=exc);error=str(exc)
                            self.last_pool_response=response_state.value;self.last_share_result=response_state.value
                            self.events.emit("pool_response",state=response_state.value,attempt=self.share_attempts,
                                reason=error if error else None)
        except Exception as exc:
            if isinstance(exc,ControlledStop):
                self.error=str(exc);error=self.error
                self.events.emit("controlled_stop",state=self.state.value)
            else:
                self.error=f"{type(exc).__name__}: {exc}";error=self.error
                self.events.emit("supervisor_error",reason=self.error,state=self.state.value)
            if not isinstance(exc,ControlledStop) and self.state not in (SupervisorState.FAILED,SupervisorState.STOPPING,SupervisorState.STOPPED):
                try:self._transition(SupervisorState.FAILED)
                except ValueError:pass
        finally:
            if self.state!=SupervisorState.STOPPED:
                try:self._shutdown(adapter)
                except Exception as exc:
                    self._shutdown_clean=False;self.error=self.error or str(exc)
            if evidence_path:
                result=CanaryResult(self.last_share_result==PoolResponseState.ACCEPTED.value and self._shutdown_clean,
                    self.share_attempts,self.share_verified,self.share_submitted,
                    self.last_share_result or response_state,self._shutdown_clean,error)
                try:write_canary_evidence(evidence_path,result,started_utc=self.started_utc,mode=self.config.mode,
                    backend=self.active_backend,pool_connected=self._ever_connected,job_received=self.job_id is not None,
                    job_identity=self.job_fingerprint,candidate_verification=self.candidate_verification,
                    qualification_identity=self._evidence_qualification_identity())
                except Exception as exc:self.events.emit("evidence_write_failed",reason=str(exc))
            self.events.close()
        success=self.last_share_result==PoolResponseState.ACCEPTED.value and self._shutdown_clean
        return CanaryResult(success,self.share_attempts,self.share_verified,self.share_submitted,
            self.last_share_result or response_state,self._shutdown_clean,error)

    def request_stop(self,reason: str="requested"):
        self.stop_requested=True
        self.events.emit("stop_requested",reason=reason)
        if self.state not in (SupervisorState.STOPPING,SupervisorState.STOPPED):self._transition(SupervisorState.STOPPING)

    def _evidence_qualification_identity(self):
        q=self._qualification
        if q and self.active_backend=="gpu" and q.gpu_artifact_sha256:
            return {"backend_type":"cuda-pearlhash","artifact_sha256":q.gpu_artifact_sha256}
        if q and self.active_backend=="gpu+fk" and q.fk_artifact_sha256:
            return {"backend_type":"fk33-phk1","artifact_sha256":q.fk_artifact_sha256}
        return {"backend_type":"mock","artifact_sha256":"0"*64}

    def status(self) -> dict:
        return {"state":self.state.value,"pool_state":self.pool_state,"job_id":self.job_id,
            "job_generation":self.job_generation,"mode":self.mode,"active_backend":self.active_backend,
            "backend_qualification":asdict(self._qualification) if self._qualification else None,
            "last_share_result":self.last_share_result,"share_attempts":self.share_attempts,
            "uptime_seconds":round(time.monotonic()-self.created_monotonic,3),"error":_redact({"error":self.error})["error"],
            "shutdown_clean":self._shutdown_clean}

    def render_status_text(self) -> str:
        return self.render_status_text_from(self.status())

    @staticmethod
    def render_status_text_from(s: dict) -> str:
        return (f"{s['state']} | pool={s['pool_state']} | mode={s['mode']} | "
            f"backend={s['active_backend'] or 'none'} | job_generation={s['job_generation']} | "
            f"share={s['last_share_result'] or 'none'} | uptime={s['uptime_seconds']:.1f}s"+
            (f" | error={s['error']}" if s['error'] else ""))

    def _persist_recovery(self):
        if not self.recovery_path:return
        data={"schema":"sidecar-miner-recovery-v1","state":self.state.value,"pool_state":self.pool_state,
            "job_generation":self.job_generation,"job_id":self.job_id,"mode":self.mode,
            "active_backend":self.active_backend,"last_share_result":self.last_share_result,
            "share_attempts":self.share_attempts,
            "last_submitted_share_id":self.last_submitted_share_id,"last_pool_response":self.last_pool_response,
            "shutdown_clean":self._shutdown_clean,"error":self.error,
            "updated_at_utc":datetime.now(timezone.utc).isoformat()}
        atomic_write_json(self.recovery_path,data)


def atomic_write_json(path: str|Path,value: dict):
    target=Path(path);target.parent.mkdir(parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(prefix=target.name+".",dir=target.parent,text=True)
    try:
        with os.fdopen(fd,"w",encoding="utf-8") as f:
            json.dump(_redact(value),f,sort_keys=True,separators=(",",":"));f.write("\n");f.flush();os.fsync(f.fileno())
        os.replace(tmp,target)
    finally:
        try:os.unlink(tmp)
        except FileNotFoundError:pass


def write_canary_evidence(path: str|Path,result: CanaryResult,*,started_utc: str,mode: str,
                          backend: str,pool_connected: bool,job_received: bool,
                          job_identity: str|None=None,candidate_verification: str="not-run",
                          timings: dict|None=None,qualification_identity: dict|None=None):
    data={"schema":"sidecar-live-miner-canary-result-v1","started_at_utc":started_utc,
        "ended_at_utc":datetime.now(timezone.utc).isoformat(),"mode":mode,"backend":backend,
        "pool_connection":bool(pool_connected),"job_received":bool(job_received),
        "job_identity":job_identity,"candidate_verification":candidate_verification,
        "share_attempts":result.share_attempts,"share_verified":result.share_verified,
        "share_submitted":result.share_submitted,"pool_response":result.pool_response,
        "pool_response_reason":str(_redact({"reason":getattr(result,"error",None)})["reason"] or "")[:512],
        "timings":timings or {},
        "qualification_identity":qualification_identity or {"backend_type":"mock","artifact_sha256":"0"*64},
        "shutdown_clean":result.shutdown_clean,"outcome":"PASS" if result.success else "FAIL"}
    atomic_write_json(path,data)
    return data


class SignalStopController:
    """Install/restore controlled stop handlers; tests call dispatch directly."""
    def __init__(self,supervisor: SidecarMinerSupervisor):self.supervisor=supervisor;self._previous={}
    def dispatch(self,signum,frame=None):
        name=signal.Signals(signum).name if signum in signal.valid_signals() else "SIGNAL"
        self.supervisor.request_stop(name)
    def __enter__(self):
        for sig in (signal.SIGINT,signal.SIGTERM):self._previous[sig]=signal.getsignal(sig);signal.signal(sig,self.dispatch)
        return self
    def __exit__(self,*exc):
        for sig,handler in self._previous.items():signal.signal(sig,handler)


def load_recovery_status(path: str|Path,config: Config) -> dict:
    """Load last atomic public-safe supervisor snapshot for a status invocation."""
    supervisor=SidecarMinerSupervisor(config)
    current=supervisor.status()
    try:obj=json.loads(Path(path).read_text())
    except (OSError,ValueError):return current
    if not isinstance(obj,dict) or obj.get("schema")!="sidecar-miner-recovery-v1":return current
    for key in ("state","pool_state","job_generation","job_id","mode","active_backend","last_share_result",
                "share_attempts","last_submitted_share_id","last_pool_response","shutdown_clean","error"):
        if key in obj:current[key]=_redact({key:obj[key]})[key]
    current["recovery_updated_at_utc"]=obj.get("updated_at_utc")
    return current
