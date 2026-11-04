"""Offline-safe FK33 fleet lifecycle, scheduling, rollout, and rollback model.

This module has no USB, FTDI, JTAG, CUDA, Stratum, or network implementation.
Hardware lifecycle operations are expressed as a protocol and exercised only
through MockFleetHardwareAdapter in this worktree.
"""
from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import math
import os
from pathlib import Path
import statistics
import tempfile
import time
from typing import Any, Protocol

from .contracts import BackendResult, ReferenceBackend, raw_canonical_match
from .qualification import (PHK1_BACKEND, load_qualification_artifact,
    pinned_source_hashes)


class FleetError(RuntimeError):pass
class InvalidFleetTransition(FleetError):pass
class QualificationGateError(FleetError):pass
class TargetBindingError(FleetError):pass
class StageHealthError(FleetError):pass
class DuplicateWorkError(FleetError):pass


class CardState(str,Enum):
    UNKNOWN="UNKNOWN"; UNQUALIFIED="UNQUALIFIED"; READY="READY"; STAGING="STAGING"
    PROGRAMMING="PROGRAMMING"; STARTING="STARTING"; HEALTHCHECK="HEALTHCHECK"
    ACTIVE="ACTIVE"; DEGRADED="DEGRADED"; FAILED="FAILED"; ROLLING_BACK="ROLLING_BACK"
    RESTORED="RESTORED"; QUARANTINED="QUARANTINED"; DISABLED="DISABLED"


class RolloutStage(str,Enum):
    CANARY_1="CANARY_1"; EXPAND_2="EXPAND_2"; EXPAND_4="EXPAND_4"; FULL_8="FULL_8"

STAGE_SIZE={RolloutStage.CANARY_1:1,RolloutStage.EXPAND_2:2,
    RolloutStage.EXPAND_4:4,RolloutStage.FULL_8:8}
NEXT_STAGE={RolloutStage.CANARY_1:RolloutStage.EXPAND_2,
    RolloutStage.EXPAND_2:RolloutStage.EXPAND_4,
    RolloutStage.EXPAND_4:RolloutStage.FULL_8,RolloutStage.FULL_8:None}


TRANSITIONS={
    CardState.UNKNOWN:{CardState.READY,CardState.UNQUALIFIED,CardState.DISABLED},
    CardState.UNQUALIFIED:{CardState.READY,CardState.DISABLED},
    CardState.READY:{CardState.STAGING,CardState.DISABLED,CardState.UNQUALIFIED},
    CardState.STAGING:{CardState.PROGRAMMING,CardState.ROLLING_BACK,CardState.FAILED,CardState.DISABLED},
    CardState.PROGRAMMING:{CardState.STARTING,CardState.ROLLING_BACK,CardState.FAILED},
    CardState.STARTING:{CardState.HEALTHCHECK,CardState.ROLLING_BACK,CardState.FAILED},
    CardState.HEALTHCHECK:{CardState.ACTIVE,CardState.ROLLING_BACK,CardState.DEGRADED,CardState.FAILED,CardState.QUARANTINED},
    CardState.ACTIVE:{CardState.DEGRADED,CardState.FAILED,CardState.ROLLING_BACK,CardState.DISABLED},
    CardState.DEGRADED:{CardState.HEALTHCHECK,CardState.ROLLING_BACK,CardState.FAILED,CardState.DISABLED,CardState.QUARANTINED},
    CardState.FAILED:{CardState.ROLLING_BACK,CardState.DISABLED,CardState.QUARANTINED},
    CardState.ROLLING_BACK:{CardState.RESTORED,CardState.FAILED},
    CardState.RESTORED:{CardState.READY,CardState.DISABLED,CardState.QUARANTINED,CardState.UNQUALIFIED},
    CardState.QUARANTINED:{CardState.HEALTHCHECK,CardState.DISABLED,CardState.UNQUALIFIED},
    CardState.DISABLED:{CardState.READY,CardState.UNQUALIFIED},
}


class FailureKind(str,Enum):
    WRONG_RAW_RESULT="wrong_raw_result"; WRONG_CANONICAL_RESULT="wrong_canonical_result"
    CPU_MISMATCH="cpu_mismatch"; TRANSPORT_FAILURE="transport_failure"
    PROCESS_CRASH="process_crash"; MISSING_HEARTBEAT="missing_heartbeat"
    TIMEOUT_THRESHOLD="timeout_threshold"; QUALIFICATION_MISMATCH="qualification_mismatch"
    BITSTREAM_MISMATCH="bitstream_mismatch"; PROTOCOL_MISMATCH="protocol_mismatch"
    SHARED_TRANSPORT_CORRUPTION="shared_transport_corruption"
    SCHEDULER_FAILURE="scheduler_failure"; STALE_RESULT="stale_result"

# A single wrong card is locally rolled back/quarantined. Identity, protocol,
# shared transport, scheduler, or correlated fleet failures abort the stage.
ROLLBACK_TRIGGERS={kind:{"rollback_card":True,"abort_stage":False} for kind in FailureKind}
for _k in (FailureKind.QUALIFICATION_MISMATCH,FailureKind.BITSTREAM_MISMATCH,
        FailureKind.PROTOCOL_MISMATCH,FailureKind.SHARED_TRANSPORT_CORRUPTION,
        FailureKind.SCHEDULER_FAILURE):
    ROLLBACK_TRIGGERS[_k]={"rollback_card":True,"abort_stage":True}

TIMING_FIELDS=("host_pack_us","transport_in_us","fpga_compute_us","transport_out_us",
    "compose_us","verify_us","total_us")
ALLOWED_CARD_FIELDS={"logical_id","physical_binding_id","expected_bitstream_sha256",
    "expected_runner_sha256","expected_backend_sha256","expected_protocol_version",
    "rollback_image_sha256","enabled","measured_jobs_per_second"}
FORBIDDEN_IDENTITY_KEYS={"serial","serial_number","dna","usb_path","device_path","wallet","password"}


def _sha(value,field_name,*,optional=False):
    if optional and value is None:return None
    if not isinstance(value,str) or len(value)!=64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError(f"{field_name} must be a lowercase SHA256")
    return value


@dataclass
class CardTelemetry:
    jobs_assigned:int=0; jobs_completed:int=0; raw_results:int=0; verified_results:int=0
    bad_results:int=0; timeouts:int=0; transport_errors:int=0; stale_results:int=0
    restart_count:int=0; rollback_count:int=0; rejoin_attempts:int=0
    latencies_us:deque=field(default_factory=lambda:deque(maxlen=4096))
    result_times:deque=field(default_factory=lambda:deque(maxlen=4096))
    started_at:float|None=None; last_result_time:float|None=None

    def add_latency(self,value):
        if value is not None and math.isfinite(value) and value>=0:self.latencies_us.append(float(value))
    def latency_summary(self):
        values=sorted(self.latencies_us)
        def pct(p):return values[min(len(values)-1,math.ceil(p*len(values))-1)] if values else None
        return {"average_us":statistics.fmean(values) if values else None,
            "p50_us":pct(.50),"p95_us":pct(.95)}
    def jobs_per_second(self,now=None):
        if self.started_at is None or self.jobs_completed<=0:return None
        seconds=(now if now is not None else time.monotonic())-self.started_at
        return self.jobs_completed/seconds if seconds>0 else None


@dataclass
class FleetCard:
    logical_id:str
    physical_binding_id:str|None=None
    expected_bitstream_sha256:str|None=None
    expected_runner_sha256:str|None=None
    expected_backend_sha256:str|None=None
    expected_protocol_version:int=1
    rollback_image_sha256:str|None=None
    enabled:bool=True
    measured_jobs_per_second:float|None=None
    qualified:bool=False
    qualification_sha256:str|None=None
    backend_state:str="uninitialized"
    state:CardState=CardState.UNQUALIFIED
    health:str="unknown"
    current_job_fingerprint:str|None=None
    current_generation:int|None=None
    last_result_time:float|None=None
    error_count:int=0
    consecutive_failures:int=0
    quarantined:bool=False
    rollback_state:str="not-needed"
    performance:dict=field(default_factory=dict)
    telemetry:CardTelemetry=field(default_factory=CardTelemetry)
    errors:list=field(default_factory=list)

    def __post_init__(self):
        if self.logical_id not in {f"fk{i}" for i in range(8)}:raise ValueError("logical_id must be fk0 through fk7")
        if self.physical_binding_id is not None:
            if not isinstance(self.physical_binding_id,str) or not self.physical_binding_id.strip() or len(self.physical_binding_id)>256:
                raise ValueError("physical binding placeholder is invalid")
            if any(ord(c)<32 for c in self.physical_binding_id):raise ValueError("physical binding placeholder contains controls")
        for attr in ("expected_bitstream_sha256","expected_runner_sha256","expected_backend_sha256","rollback_image_sha256"):
            _sha(getattr(self,attr),attr,optional=True)
        if isinstance(self.expected_protocol_version,bool) or self.expected_protocol_version<=0:raise ValueError("protocol version must be positive")
        if self.measured_jobs_per_second is not None and (not math.isfinite(self.measured_jobs_per_second) or self.measured_jobs_per_second<=0):
            raise ValueError("measured jobs/sec must be positive when known")


@dataclass(frozen=True)
class WorkAssignment:
    assignment_id:str
    work_id:str
    card_id:str
    job_fingerprint:str
    generation:int
    batch_id:str
    state:str="queued"
    redundant:bool=False
    created_monotonic:float=field(default_factory=time.monotonic)


@dataclass(frozen=True)
class RolloutHealthGate:
    minimum_successful_transactions:int|None=None
    maximum_timeout_rate:float|None=None
    maximum_transport_error_rate:float|None=None
    minimum_observation_seconds:float|None=None
    require_zero_incorrect_results:bool=True
    def validate(self):
        if self.minimum_successful_transactions is None or self.minimum_successful_transactions<1:
            raise ValueError("rollout gate must set minimum_successful_transactions")
        if self.minimum_observation_seconds is None or self.minimum_observation_seconds<0:
            raise ValueError("rollout gate must set minimum_observation_seconds")
        for name in ("maximum_timeout_rate","maximum_transport_error_rate"):
            v=getattr(self,name)
            if v is None or not 0<=v<=1:raise ValueError(f"rollout gate must set {name} between zero and one")


@dataclass(frozen=True)
class RolloutSoakPolicy:
    minimum_transactions:int|None=None
    minimum_elapsed_seconds:float|None=None
    def validate(self):
        if self.minimum_transactions is None and self.minimum_elapsed_seconds is None:
            raise ValueError("soak policy requires transaction count and/or elapsed time")
        if self.minimum_transactions is not None and self.minimum_transactions<1:raise ValueError("minimum transactions must be positive")
        if self.minimum_elapsed_seconds is not None and self.minimum_elapsed_seconds<0:raise ValueError("minimum elapsed must be nonnegative")
    def satisfied(self,transactions:int,elapsed_seconds:float):
        self.validate()
        checks=[]
        if self.minimum_transactions is not None:checks.append(transactions>=self.minimum_transactions)
        if self.minimum_elapsed_seconds is not None:checks.append(elapsed_seconds>=self.minimum_elapsed_seconds)
        return any(checks)


@dataclass(frozen=True)
class HealthWeights:
    bad_result:float=40.0; timeout:float=20.0; transport_error:float=15.0; restart:float=5.0
    def __post_init__(self):
        if min(self.bad_result,self.timeout,self.transport_error,self.restart)<0:raise ValueError("health weights must be nonnegative")


class FleetHardwareAdapter(Protocol):
    """Future lifecycle boundary. Implementations bind one target per call."""
    offline_mock:bool
    def acquire_card(self,card:FleetCard)->str:...
    def release_card(self,card:FleetCard)->None:...
    def program_phk1(self,card:FleetCard,image_sha256:str)->None:...
    def start_runner(self,card:FleetCard)->None:...
    def health_check(self,card:FleetCard)->bool:...
    def rollback_xbt(self,card:FleetCard,image_sha256:str)->None:...
    def restore_production(self,card:FleetCard)->None:...


class MockFleetHardwareAdapter:
    offline_mock=True
    def __init__(self,*,binding_overrides=None,image_overrides=None,fail_actions=None):
        self.binding_overrides=binding_overrides or {};self.image_overrides=image_overrides or {}
        self.fail_actions=set(fail_actions or ());self.actions=[]
    def _do(self,name,card,detail=None):
        self.actions.append({"action":name,"logical_id":card.logical_id,"detail":detail})
        if name in self.fail_actions:raise RuntimeError(f"mock {name} failure")
    def acquire_card(self,card):self._do("acquire",card);return self.binding_overrides.get(card.logical_id,card.physical_binding_id or "")
    def release_card(self,card):self._do("release",card)
    def program_phk1(self,card,image_sha256):self._do("program_phk1",card,image_sha256);return self.image_overrides.get(card.logical_id,image_sha256)
    def start_runner(self,card):self._do("start_runner",card)
    def health_check(self,card):self._do("health_check",card);return "health_check" not in self.fail_actions
    def rollback_xbt(self,card,image_sha256):self._do("rollback_xbt",card,image_sha256)
    def restore_production(self,card):self._do("restore_production",card)


class MockFk33Backend:
    """Deterministic per-card mock. latency_us is metadata, never a real timing claim."""
    def __init__(self,logical_id,*,latency_us=100.0,behavior="success"):
        self.backend_id=logical_id;self.latency_us=latency_us;self.behavior=behavior;self.healthy=True
    def execute(self,assignment:WorkAssignment):
        if self.behavior=="crash":raise RuntimeError("mock runner crash")
        if self.behavior=="timeout":return BackendResult(assignment.job_fingerprint,assignment.generation,
            assignment.batch_id,self.backend_id,"raw","raw",None,elapsed_us=self.latency_us,
            healthy=False,timed_out=True)
        raw=f"result:{assignment.work_id}"
        canonical=raw
        correctness=True
        generation=assignment.generation
        if self.behavior=="wrong_raw":raw+="-wrong"
        elif self.behavior=="wrong_canonical":canonical+="-wrong"
        elif self.behavior=="wrong_result":correctness=False
        elif self.behavior=="stale":generation=max(0,generation-1)
        return BackendResult(assignment.job_fingerprint,generation,assignment.batch_id,self.backend_id,
            raw,canonical,correctness,payload={"work_id":assignment.work_id},elapsed_us=self.latency_us,
            healthy=self.healthy,verification_status="candidate",timings_us={"total_us":self.latency_us})


class FleetController:
    def __init__(self,cards:list[FleetCard],*,stage:RolloutStage=RolloutStage.CANARY_1,
            qualification_artifact:str|Path|None=None,expected_runner_sha256:str|None=None,
            expected_backend_sha256:str|None=None,protocol_version:int=1,
            quarantine_threshold:int=3,max_rejoin_attempts:int=1,max_queue_depth:int=4096,
            health_weights:HealthWeights|None=None,clock=time.monotonic):
        if not 1<=len(cards)<=8:raise ValueError("fleet must contain between one and eight FK33 cards")
        if RolloutStage(stage)!=RolloutStage.CANARY_1:raise ValueError("new fleet controllers must begin at CANARY_1")
        ids=[c.logical_id for c in cards]
        if len(ids)!=len(set(ids)):raise ValueError("duplicate logical FK ID")
        if len(ids)>8:raise ValueError("fleet supports at most eight cards")
        if quarantine_threshold<1 or max_rejoin_attempts<0 or max_queue_depth<1:raise ValueError("invalid fleet limits")
        self.cards={c.logical_id:c for c in cards};self.stage=RolloutStage(stage)
        self.qualification_artifact=Path(qualification_artifact) if qualification_artifact else None
        self.expected_runner_sha256=expected_runner_sha256;self.expected_backend_sha256=expected_backend_sha256
        self.protocol_version=protocol_version;self.quarantine_threshold=quarantine_threshold
        self.max_rejoin_attempts=max_rejoin_attempts;self.max_queue_depth=max_queue_depth
        self.health_weights=health_weights or HealthWeights();self.clock=clock
        self.current_job_fingerprint=None;self.current_generation=None;self.assignments={};self.work_ids=defaultdict(list)
        self.outstanding_by_card=Counter();self.completed_work=set();self.stale_result_count=0
        self.unverified_share_submission_count=0;self.accidental_duplicate_work_count=0
        self.unqualified_activation_count=0;self.wrong_image_activation_count=0
        self.scheduler_queue_depth=0;self._round_robin_cursor=0;self._weighted_credit=Counter()
        self.stage_started_at=self.clock();self.stage_started_verified=0;self.stage_aborted=False;self.stage_abort_reason=None
        self.stage_cohort=set();self.stage_successful_transactions=0;self.stage_bad_results=0
        self.stage_successful_by_card=Counter()
        self.stage_attempts=0;self.stage_timeouts=0;self.stage_transport_errors=0
        self.bad_result_signatures=defaultdict(set);self.recent_failures=deque(maxlen=256)
        self.qualification=None;self.requires_revalidation=False;self.physical_binding_failures=0
        self.lifecycle_adapter=None
        self._refresh_qualification()

    @classmethod
    def from_config(cls,path:str|Path,**kwargs):
        obj=json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(obj,dict) or set(obj)-{"schema_version","rollout_stage","qualification_artifact","expected_runner_sha256","expected_backend_sha256","protocol_version","cards"}:
            raise ValueError("invalid fleet config fields")
        if obj.get("schema_version")!=1 or not isinstance(obj.get("cards"),list):raise ValueError("unsupported fleet config")
        cards=[]
        for row in obj["cards"]:
            if not isinstance(row,dict):raise ValueError("fleet card entry must be an object")
            forbidden=set(k.lower() for k in row)&FORBIDDEN_IDENTITY_KEYS
            if forbidden:raise ValueError("fleet config must use abstract physical bindings, not private hardware identity fields")
            unknown=set(row)-ALLOWED_CARD_FIELDS
            if unknown:raise ValueError(f"unknown fleet card fields: {sorted(unknown)}")
            cards.append(FleetCard(**row))
        if obj.get("rollout_stage","CANARY_1")!="CANARY_1":raise ValueError("fleet config rollout stage must begin at CANARY_1")
        return cls(cards,stage=RolloutStage.CANARY_1,
            qualification_artifact=obj.get("qualification_artifact"),
            expected_runner_sha256=obj.get("expected_runner_sha256"),
            expected_backend_sha256=obj.get("expected_backend_sha256"),
            protocol_version=obj.get("protocol_version",1),**kwargs)

    def _transition(self,card:FleetCard,target:CardState):
        target=CardState(target)
        if target not in TRANSITIONS[card.state]:
            raise InvalidFleetTransition(f"illegal transition {card.logical_id}: {card.state.value}->{target.value}")
        card.state=target
        if target==CardState.ACTIVE:
            card.backend_state="ready";card.health="healthy"
            if card.telemetry.started_at is None:card.telemetry.started_at=self.clock()
        elif target in (CardState.QUARANTINED,CardState.DISABLED,CardState.FAILED):
            card.backend_state=target.value.lower();card.health="unhealthy"

    def _binding_is_unique(self,card):
        binding=card.physical_binding_id
        return bool(binding and sum(1 for c in self.cards.values() if c.physical_binding_id==binding)==1)

    def _validate_card_qualification(self,card):
        if not self.qualification_artifact or not card.expected_bitstream_sha256:return None
        runner=card.expected_runner_sha256 or self.expected_runner_sha256
        backend=card.expected_backend_sha256 or self.expected_backend_sha256
        if not runner or not backend:return None
        try:
            q=load_qualification_artifact(self.qualification_artifact,expected_backend_type=PHK1_BACKEND,
                expected_runner_sha256=runner,expected_backend_sha256=backend,
                expected_bitstream_sha256=card.expected_bitstream_sha256,
                expected_protocol_version=card.expected_protocol_version)
            return q
        except (OSError,ValueError,TypeError):return None

    def _refresh_qualification(self):
        seen_bindings=Counter(c.physical_binding_id for c in self.cards.values() if c.physical_binding_id)
        for card in self.cards.values():
            q=self._validate_card_qualification(card)
            card.qualified=bool(q and q.qualified);card.qualification_sha256=q.qualification_sha256 if q else None
            if card.qualified and card.rollback_image_sha256 and card.physical_binding_id and seen_bindings[card.physical_binding_id]==1:
                if card.enabled and not card.quarantined and card.state in (CardState.UNQUALIFIED,CardState.RESTORED,CardState.DISABLED,CardState.UNKNOWN):
                    self._transition(card,CardState.READY)
            elif card.state not in (CardState.DISABLED,CardState.QUARANTINED):
                card.state=CardState.UNQUALIFIED;card.health="unqualified";card.backend_state="uninitialized"
        self.qualification=next((self._validate_card_qualification(c) for c in self.cards.values() if self._validate_card_qualification(c)),None)

    def qualification_gate(self,card_id):
        card=self.cards[card_id];q=self._validate_card_qualification(card)
        if not q or not q.qualified:raise QualificationGateError(f"{card_id} lacks matching PHK1 qualification")
        if not self._binding_is_unique(card):raise QualificationGateError(f"{card_id} physical binding missing or ambiguous")
        if not card.rollback_image_sha256:raise QualificationGateError(f"{card_id} rollback image identity is unknown")
        if card.expected_protocol_version!=q.protocol_version:raise QualificationGateError(f"{card_id} protocol identity mismatch")
        if not card.enabled or card.quarantined:raise QualificationGateError(f"{card_id} is disabled or quarantined")
        return q

    def eligible_cards(self):
        eligible=[]
        for card in self.cards.values():
            try:self.qualification_gate(card.logical_id)
            except QualificationGateError:continue
            if card.state in (CardState.READY,CardState.ACTIVE):eligible.append(card)
        return sorted(eligible,key=lambda c:c.logical_id)

    def schedulable_cards(self):
        """Only ACTIVE cards receive PHK1 work; READY cards await rollout selection."""
        return sorted((c for c in self.cards.values() if c.state==CardState.ACTIVE and c.qualified
            and c.enabled and not c.quarantined),key=lambda c:c.logical_id)

    def scheduler_resources(self):
        """Expose active FK resources without leaking physical target bindings."""
        return [{"backend_id":c.logical_id,"healthy":c.health=="healthy",
            "measured_jobs_per_second":c.measured_jobs_per_second,
            "queue_depth":self.outstanding_by_card[c.logical_id],
            "qualification_sha256":c.qualification_sha256}
            for c in self.schedulable_cards()]

    def rollout_plan(self,stage:RolloutStage|str|None=None):
        stage=RolloutStage(stage or self.stage);target=STAGE_SIZE[stage]
        if self.stage_aborted:raise StageHealthError(f"rollout stage aborted: {self.stage_abort_reason}")
        eligible=self.eligible_cards()
        active=[c for c in eligible if c.state==CardState.ACTIVE]
        selected=list(active[:target])
        selected.extend(c for c in eligible if c not in selected and len(selected)<target)
        if len(selected)<target:raise QualificationGateError(f"stage {stage.value} needs {target} qualified, uniquely bound cards; found {len(selected)}")
        actions=[]
        for c in selected:
            if c.state!=CardState.ACTIVE:
                actions.extend(({"action":"validate_binding","card":c.logical_id},
                    {"action":"program_phk1","card":c.logical_id,"image_sha256":c.expected_bitstream_sha256},
                    {"action":"start_runner","card":c.logical_id},{"action":"health_check","card":c.logical_id}))
        return {"current_stage":self.stage.value,"requested_stage":stage.value,
            "target_active_count":target,"eligible_cards":[c.logical_id for c in eligible],
            "selected_cards":[c.logical_id for c in selected],"actions":actions,
            "rollback_actions":[{"action":"rollback_xbt_then_restore_production","card":c.logical_id,
                "rollback_image_sha256":c.rollback_image_sha256} for c in selected],
            "dry_run":True,"hardware_access":"none"}

    def apply_stage(self,adapter:FleetHardwareAdapter,*,stage:RolloutStage|str|None=None):
        if not getattr(adapter,"offline_mock",False):raise FleetError("fleet apply accepts only the offline mock adapter in this build")
        self.lifecycle_adapter=adapter
        plan=self.rollout_plan(stage);target_stage=RolloutStage(stage or self.stage)
        if target_stage!=self.stage:raise StageHealthError("stage must pass advance_stage health gate before apply")
        selected=plan["selected_cards"];stage_was_unstarted=not self.stage_cohort
        try:
            for logical_id in selected:
                card=self.cards[logical_id]
                if card.state==CardState.ACTIVE:
                    self.stage_cohort.add(logical_id);continue
                self.qualification_gate(logical_id)
                self._transition(card,CardState.STAGING)
                bound=adapter.acquire_card(card)
                if bound!=card.physical_binding_id:
                    self.physical_binding_failures+=1
                    raise TargetBindingError(f"{logical_id} target binding did not match its unique configured placeholder")
                self._transition(card,CardState.PROGRAMMING)
                if card.expected_bitstream_sha256 is None:raise QualificationGateError("expected image hash missing")
                image=adapter.program_phk1(card,card.expected_bitstream_sha256)
                if image!=card.expected_bitstream_sha256:
                    self.wrong_image_activation_count+=1
                    raise FleetError("programmed image identity mismatch")
                self._transition(card,CardState.STARTING);adapter.start_runner(card)
                self._transition(card,CardState.HEALTHCHECK)
                if not adapter.health_check(card):raise FleetError(f"{logical_id} health check failed")
                self._transition(card,CardState.ACTIVE);card.current_job_fingerprint=self.current_job_fingerprint
                self.stage_cohort.add(logical_id)
            self.stage=target_stage
            if stage_was_unstarted:
                self.stage_started_at=self.clock();self.stage_started_verified=0
            return plan
        except Exception as exc:
            failed=logical_id if "logical_id" in locals() else None
            if isinstance(exc,TargetBindingError):
                # Binding failed before programming. Never rollback through an
                # ambiguous target or fall through to another physical card.
                if failed and failed in self.cards:
                    card=self.cards[failed]
                    card.error_count+=1;card.consecutive_failures+=1
                    card.health="unhealthy";card.backend_state="target-binding-failed"
                    self._transition(card,CardState.FAILED)
                self.stage_aborted=True;self.stage_abort_reason=str(exc)
                raise
            if failed and failed in self.cards:
                if isinstance(exc,QualificationGateError) and not self._validate_card_qualification(self.cards[failed]):
                    self.unqualified_activation_count+=1
                self.handle_failure(failed,FailureKind.BITSTREAM_MISMATCH if "image identity" in str(exc)
                    else FailureKind.QUALIFICATION_MISMATCH if isinstance(exc,QualificationGateError)
                    else FailureKind.PROCESS_CRASH,str(exc),adapter=adapter)
            raise

    def advance_stage(self,gate:RolloutHealthGate,*,now:float|None=None):
        gate.validate();next_stage=NEXT_STAGE[self.stage]
        if next_stage is None:raise StageHealthError("FULL_8 is already the terminal rollout stage")
        if self.stage_aborted:raise StageHealthError(f"stage aborted: {self.stage_abort_reason}")
        now=self.clock() if now is None else now;elapsed=now-self.stage_started_at
        active=self.schedulable_cards()
        timeout_rate=self.stage_timeouts/self.stage_attempts if self.stage_attempts else 0.0
        transport_rate=self.stage_transport_errors/self.stage_attempts if self.stage_attempts else 0.0
        per_card_success=all(self.stage_successful_by_card[card.logical_id]>=gate.minimum_successful_transactions for card in active)
        if len(active)!=STAGE_SIZE[self.stage] or not per_card_success or elapsed<gate.minimum_observation_seconds:
            raise StageHealthError("stage transaction/observation criteria have not passed")
        if timeout_rate>gate.maximum_timeout_rate or transport_rate>gate.maximum_transport_error_rate:
            raise StageHealthError("stage timeout/transport rate exceeds configured gate")
        if gate.require_zero_incorrect_results and self.stage_bad_results:
            raise StageHealthError("stage contains incorrect results")
        self.stage=next_stage;self.stage_started_at=now
        self.stage_started_verified=sum(c.telemetry.verified_results for c in active)
        self.stage_successful_transactions=0;self.stage_bad_results=0;self.stage_cohort.clear()
        self.stage_successful_by_card.clear()
        self.stage_attempts=0;self.stage_timeouts=0;self.stage_transport_errors=0
        return self.rollout_plan(self.stage)

    def set_job(self,fingerprint:str,generation:int):
        if not fingerprint or generation<0:raise ValueError("invalid job identity")
        if self.current_generation is not None and generation<=self.current_generation and fingerprint!=self.current_job_fingerprint:
            raise ValueError("job generation must increase when job identity changes")
        if fingerprint==self.current_job_fingerprint and generation==self.current_generation:return 0
        stale=0
        for assignment in list(self.assignments.values()):
            if assignment.state=="queued" and assignment.generation!=generation:
                self.assignments[assignment.assignment_id]=WorkAssignment(**{**asdict(assignment),"state":"stale"})
                self.outstanding_by_card[assignment.card_id]=max(0,self.outstanding_by_card[assignment.card_id]-1)
                self.cards[assignment.card_id].telemetry.stale_results+=1;stale+=1
        self.scheduler_queue_depth=sum(1 for a in self.assignments.values() if a.state=="queued")
        self.current_job_fingerprint=fingerprint;self.current_generation=generation
        for card in self.cards.values():
            if card.state==CardState.ACTIVE:card.current_job_fingerprint=fingerprint;card.current_generation=generation
        return stale

    def assign_work(self,work_units:list[str],*,policy="round_robin",allow_redundancy=False,
            batch_prefix="fleet"):
        if self.current_job_fingerprint is None or self.current_generation is None:raise FleetError("no current mining job")
        if policy not in ("round_robin","least_busy","measured_throughput_weighted"):raise ValueError("unknown fleet scheduling policy")
        if not isinstance(work_units,list) or any(not isinstance(w,str) or not w for w in work_units):raise ValueError("work units must have nonempty IDs")
        if len(work_units)>self.max_queue_depth-self.scheduler_queue_depth:
            raise FleetError("fleet backpressure: requested batch exceeds bounded queue capacity")
        cards=self.schedulable_cards()
        if not cards and work_units:raise FleetError("no active qualified FK cards")
        results=[];weights={c.logical_id:(c.measured_jobs_per_second or 1.0) for c in cards};weight_sum=sum(weights.values())
        for i,work_id in enumerate(work_units):
            work_key=(self.current_generation,work_id)
            if not allow_redundancy and (work_key in self.work_ids or work_key in self.completed_work):
                self.accidental_duplicate_work_count+=1;raise DuplicateWorkError(f"work unit already assigned: {work_id}")
            if self.scheduler_queue_depth>=self.max_queue_depth:raise FleetError("fleet backpressure: bounded queue is full")
            if policy=="round_robin":
                card=cards[self._round_robin_cursor%len(cards)];self._round_robin_cursor+=1
            elif policy=="least_busy":
                card=min(cards,key=lambda c:(self.outstanding_by_card[c.logical_id],c.logical_id))
            else:
                for c in cards:self._weighted_credit[c.logical_id]+=weights[c.logical_id]
                card=max(cards,key=lambda c:(self._weighted_credit[c.logical_id],c.logical_id))
                self._weighted_credit[card.logical_id]-=weight_sum
            idx=len(self.work_ids[work_key])
            aid=f"{self.current_generation}:{work_id}:{card.logical_id}:{idx}"
            assignment=WorkAssignment(aid,work_id,card.logical_id,self.current_job_fingerprint,
                self.current_generation,f"{batch_prefix}-{self.current_generation}-{i}",redundant=allow_redundancy)
            self.assignments[aid]=assignment;self.work_ids[work_key].append(aid)
            self.outstanding_by_card[card.logical_id]+=1;card.telemetry.jobs_assigned+=1
            card.current_job_fingerprint=self.current_job_fingerprint;card.current_generation=self.current_generation
            self.scheduler_queue_depth+=1;results.append(assignment)
            if card.logical_id in self.stage_cohort:self.stage_attempts+=1
        return results

    def complete_assignment(self,assignment_id):
        assignment=self.assignments.get(assignment_id)
        if assignment is None:raise FleetError("unknown work assignment")
        if assignment.state!="queued":return False
        self.assignments[assignment_id]=WorkAssignment(**{**asdict(assignment),"state":"completed"})
        self.outstanding_by_card[assignment.card_id]=max(0,self.outstanding_by_card[assignment.card_id]-1)
        self.scheduler_queue_depth=max(0,self.scheduler_queue_depth-1);self.completed_work.add((assignment.generation,assignment.work_id))
        return True

    def accept_result(self,assignment_id,result:BackendResult,reference:ReferenceBackend,*,now:float|None=None):
        assignment=self.assignments.get(assignment_id)
        if assignment is None:raise FleetError("unknown assignment result")
        card=self.cards[assignment.card_id]
        if assignment.state!="queued" or assignment.generation!=self.current_generation or assignment.job_fingerprint!=self.current_job_fingerprint:
            card.telemetry.stale_results+=1;self.stale_result_count+=1
            self.complete_assignment(assignment_id);return False,"stale"
        if result.backend_id!=card.logical_id or result.batch_id!=assignment.batch_id:
            self.handle_failure(card.logical_id,FailureKind.WRONG_CANONICAL_RESULT,"backend/batch identity mismatch")
            self.complete_assignment(assignment_id);return False,"identity-mismatch"
        if result.job_fingerprint!=assignment.job_fingerprint or result.generation!=assignment.generation:
            card.telemetry.stale_results+=1;self.stale_result_count+=1
            self.complete_assignment(assignment_id);return False,"stale"
        card.telemetry.raw_results+=1
        if result.timed_out or not result.healthy:
            kind=FailureKind.TIMEOUT_THRESHOLD if result.timed_out else FailureKind.TRANSPORT_FAILURE
            self.handle_failure(card.logical_id,kind,"backend timeout/unhealthy result")
            self.complete_assignment(assignment_id);return False,"backend-unhealthy"
        if not result.raw_result_identity:
            card.telemetry.bad_results+=1;self.handle_failure(card.logical_id,FailureKind.WRONG_RAW_RESULT,"empty raw result")
            self.complete_assignment(assignment_id);return False,"bad-raw"
        if not raw_canonical_match(result):
            card.telemetry.bad_results+=1
            kind=FailureKind.WRONG_RAW_RESULT if result.raw_result_identity!=result.canonical_result_identity else FailureKind.WRONG_CANONICAL_RESULT
            sig=hashlib.sha256(f"{result.raw_result_identity}|{result.canonical_result_identity}".encode()).hexdigest()
            self.bad_result_signatures[sig].add(card.logical_id)
            self.handle_failure(card.logical_id,kind,"raw/canonical result mismatch",signature=sig)
            self.complete_assignment(assignment_id);return False,"raw-canonical-mismatch"
        if result.correctness is not True:
            card.telemetry.bad_results+=1;self.handle_failure(card.logical_id,FailureKind.CPU_MISMATCH,"backend correctness is not true")
            self.complete_assignment(assignment_id);return False,"incorrect"
        try:verified=bool(reference.verify({"fingerprint":assignment.job_fingerprint,"generation":assignment.generation},result))
        except Exception:verified=False
        if not verified:
            card.telemetry.bad_results+=1;self.handle_failure(card.logical_id,FailureKind.CPU_MISMATCH,"reference verification failed")
            self.complete_assignment(assignment_id);return False,"cpu-mismatch"
        card.telemetry.jobs_completed+=1;card.telemetry.verified_results+=1;card.consecutive_failures=0
        card.last_result_time=self.clock() if now is None else now;card.telemetry.last_result_time=card.last_result_time
        card.telemetry.result_times.append(card.last_result_time);card.telemetry.add_latency(result.elapsed_us)
        card.performance=self._performance_for_card(card)
        self.stage_successful_transactions+=1;self.stage_successful_by_card[card.logical_id]+=1;self.complete_assignment(assignment_id)
        if result.timings_us:
            known={k:result.timings_us[k] for k in TIMING_FIELDS if k in result.timings_us}
            if known:self.record_timing(card.logical_id,known)
        return True,"verified"

    def handle_failure(self,card_id,kind:FailureKind|str,reason="",*,signature=None,adapter=None):
        if adapter is None:adapter=self.lifecycle_adapter
        card=self.cards[card_id];kind=FailureKind(kind);card.error_count+=1;card.consecutive_failures+=1
        card.errors.append({"kind":kind.value,"reason":str(reason)[:256],"timestamp_utc":datetime.now(timezone.utc).isoformat()})
        card.errors=card.errors[-64:];self.recent_failures.append({"card":card_id,"kind":kind.value,"reason":str(reason)[:128]})
        if kind in (FailureKind.TIMEOUT_THRESHOLD,):card.telemetry.timeouts+=1
        if kind in (FailureKind.TRANSPORT_FAILURE,FailureKind.SHARED_TRANSPORT_CORRUPTION):card.telemetry.transport_errors+=1
        if card_id in self.stage_cohort:
            self.stage_timeouts+=int(kind==FailureKind.TIMEOUT_THRESHOLD)
            self.stage_transport_errors+=int(kind in (FailureKind.TRANSPORT_FAILURE,FailureKind.SHARED_TRANSPORT_CORRUPTION))
        self.stage_bad_results+=int(kind in (FailureKind.WRONG_RAW_RESULT,FailureKind.WRONG_CANONICAL_RESULT,FailureKind.CPU_MISMATCH))
        stage_abort=ROLLBACK_TRIGGERS[kind]["abort_stage"]
        if signature and len(self.bad_result_signatures[signature])>=2:stage_abort=True
        if card.consecutive_failures>=self.quarantine_threshold:card.quarantined=True
        if ROLLBACK_TRIGGERS[kind]["rollback_card"]:self.rollback_card(card_id,reason or kind.value,adapter=adapter,quarantine=card.quarantined)
        if stage_abort:self.abort_stage(f"{kind.value}: {reason}",adapter=adapter)

    def rollback_card(self,card_id,reason="",*,adapter:MockFleetHardwareAdapter|None=None,quarantine=False):
        card=self.cards[card_id]
        if card.state==CardState.DISABLED:return
        self._cancel_card_work(card_id)
        if card.state!=CardState.ROLLING_BACK:
            if CardState.ROLLING_BACK not in TRANSITIONS[card.state]:
                if card.state==CardState.UNQUALIFIED:card.quarantined=True;card.rollback_state="not-applicable";return
                card.state=CardState.FAILED
                self._transition(card,CardState.ROLLING_BACK)
            else:self._transition(card,CardState.ROLLING_BACK)
        card.rollback_state="in-progress";card.telemetry.rollback_count+=1
        if adapter is not None:
            if not getattr(adapter,"offline_mock",False):raise FleetError("real hardware rollback is disabled in this build")
            try:
                adapter.rollback_xbt(card,card.rollback_image_sha256 or "")
                adapter.restore_production(card);adapter.release_card(card)
            except Exception as exc:
                card.rollback_state="failed";self._transition(card,CardState.FAILED);card.health="unhealthy"
                self.stage_aborted=True;self.stage_abort_reason=f"rollback failure for {card_id}: {exc}"
                raise
        self._transition(card,CardState.RESTORED);card.backend_state="restored";card.health="degraded"
        card.current_job_fingerprint=None
        if quarantine:
            card.quarantined=True;self._transition(card,CardState.QUARANTINED)
        else:card.quarantined=False

    def abort_stage(self,reason,*,adapter=None):
        if adapter is None:adapter=self.lifecycle_adapter
        self.stage_aborted=True;self.stage_abort_reason=str(reason)
        # Stage-wide failures roll back only cards participating in this stage cohort.
        for card_id in sorted(self.stage_cohort):
            card=self.cards[card_id]
            if card.state==CardState.ACTIVE:self.rollback_card(card_id,reason,adapter=adapter,quarantine=True)

    def disable_card(self,card_id):
        card=self.cards[card_id];self._cancel_card_work(card_id)
        if card.state==CardState.ACTIVE:self._transition(card,CardState.DISABLED)
        elif card.state!=CardState.DISABLED:
            if CardState.DISABLED in TRANSITIONS[card.state]:self._transition(card,CardState.DISABLED)
            else:card.state=CardState.DISABLED
        card.enabled=False;card.health="disabled";card.backend_state="disabled"

    def enable_card(self,card_id):
        card=self.cards[card_id];card.enabled=True
        q=self._validate_card_qualification(card)
        if not q or not card.rollback_image_sha256 or not self._binding_is_unique(card):
            card.qualified=False;card.state=CardState.UNQUALIFIED;card.health="unqualified"
            raise QualificationGateError("card enable requires current qualification, unique binding, and rollback image")
        card.qualified=True;card.qualification_sha256=q.qualification_sha256
        if card.state==CardState.QUARANTINED:
            raise FleetError("quarantined cards require bounded begin_rejoin/finish_rejoin")
        card.quarantined=False;card.consecutive_failures=0
        if card.state in (CardState.DISABLED,CardState.RESTORED,CardState.QUARANTINED,CardState.UNKNOWN,CardState.UNQUALIFIED):
            self._transition(card,CardState.READY)

    def begin_rejoin(self,card_id):
        card=self.cards[card_id]
        if not card.quarantined or card.telemetry.rejoin_attempts>=self.max_rejoin_attempts:
            raise FleetError("card is not quarantined or rejoin attempt limit reached")
        self.qualification_gate_rejoin(card_id);card.telemetry.rejoin_attempts+=1
        self._transition(card,CardState.HEALTHCHECK)
        return {"card":card_id,"steps":["health_check","qualification_revalidation","limited_canary"],"hardware_access":"mock-only"}

    def qualification_gate_rejoin(self,card):
        card_id=card
        target=self.cards[card_id]
        q=self._validate_card_qualification(target)
        if not q or not self._binding_is_unique(target) or not target.rollback_image_sha256:
            raise QualificationGateError("rejoin qualification/identity gate failed")

    def finish_rejoin(self,card_id,*,healthy:bool,canary_verified:bool):
        card=self.cards[card_id]
        if card.state!=CardState.HEALTHCHECK:raise InvalidFleetTransition("rejoin health check was not started")
        if healthy and canary_verified:
            card.quarantined=False;card.consecutive_failures=0;self._transition(card,CardState.ACTIVE)
            return True
        card.quarantined=True;self._transition(card,CardState.QUARANTINED);return False

    def _cancel_card_work(self,card_id):
        for aid,a in list(self.assignments.items()):
            if a.card_id==card_id and a.state=="queued":
                self.assignments[aid]=WorkAssignment(**{**asdict(a),"state":"cancelled"})
                self.outstanding_by_card[card_id]=max(0,self.outstanding_by_card[card_id]-1)
                self.scheduler_queue_depth=max(0,self.scheduler_queue_depth-1)

    def _performance_for_card(self,card):
        times=card.telemetry.latency_summary();throughput=card.telemetry.jobs_per_second(self.clock())
        vals={f:None for f in TIMING_FIELDS}
        # Use only observed timing components from recorded result objects; missing means UNKNOWN.
        vals.update(card.performance.get("timings_us",{}))
        return {"jobs_per_second":throughput,"effective_pearlhash_rate":None,
            "timings_us":vals,"latency":times,"performance_qualification":"measured-result-samples-only" if card.telemetry.latencies_us else "UNKNOWN"}

    def record_timing(self,card_id,timings_us:dict[str,float|None|str]):
        if set(timings_us)-set(TIMING_FIELDS):raise ValueError("unknown FK timing field")
        clean={f:None for f in TIMING_FIELDS}
        for key,value in timings_us.items():
            if value=="UNKNOWN":clean[key]=None
            elif value is None:clean[key]=None
            elif isinstance(value,(int,float)) and not isinstance(value,bool) and math.isfinite(value) and value>=0:clean[key]=float(value)
            else:raise ValueError(f"invalid timing {key}")
        self.cards[card_id].performance["timings_us"]=clean
        self.cards[card_id].performance=self._performance_for_card(self.cards[card_id])

    def health_score(self,card_id):
        c=self.cards[card_id];n=c.telemetry.jobs_assigned
        if n==0:
            return {"score":None,"formula":"UNKNOWN until at least one assigned job",
                "weights":{"bad_result":self.health_weights.bad_result,"timeout":self.health_weights.timeout,
                    "transport_error":self.health_weights.transport_error,"restart":self.health_weights.restart},
                "denominator_jobs_assigned":0}
        penalty=(self.health_weights.bad_result*c.telemetry.bad_results/n+
            self.health_weights.timeout*c.telemetry.timeouts/n+
            self.health_weights.transport_error*c.telemetry.transport_errors/n+
            self.health_weights.restart*c.telemetry.restart_count/n)
        score=max(0.0,100.0*(1.0-min(1.0,penalty/100.0)))
        return {"score":score,"formula":"100 * (1 - min(1, weighted failure penalty / 100))",
            "weights":{"bad_result":self.health_weights.bad_result,"timeout":self.health_weights.timeout,
                "transport_error":self.health_weights.transport_error,"restart":self.health_weights.restart},
            "denominator_jobs_assigned":n}

    def _performance_summary(self):
        cards=list(self.cards.values());rates=[c.performance.get("jobs_per_second") for c in cards]
        rates=[r for r in rates if isinstance(r,(int,float)) and math.isfinite(r)]
        return {"measured_aggregate_jobs_per_second":sum(rates) if rates else None,
            "effective_pearlhash_rate":"UNKNOWN","timing_percentages":"UNKNOWN until measured timing samples are complete"}

    def status(self):
        rows=[]
        for c in sorted(self.cards.values(),key=lambda c:c.logical_id):
            rows.append({"logical_id":c.logical_id,"physical_binding_fingerprint":hashlib.sha256(c.physical_binding_id.encode()).hexdigest()[:16] if c.physical_binding_id else None,
                "state":c.state.value,"qualified":c.qualified,"backend":c.backend_state,"health":c.health,
                "job_fingerprint":c.current_job_fingerprint,"last_result_time":c.last_result_time,
                "error_count":c.error_count,"restart_count":c.telemetry.restart_count,"rollback_count":c.telemetry.rollback_count,
                "telemetry":self.card_telemetry(c.logical_id),"health_score":self.health_score(c.logical_id),
                "rollback_state":c.rollback_state,"quarantined":c.quarantined})
        active=sum(c.state==CardState.ACTIVE for c in self.cards.values());qualified=sum(c.qualified for c in self.cards.values())
        completed=sum(c.telemetry.jobs_completed for c in self.cards.values());verified=sum(c.telemetry.verified_results for c in self.cards.values())
        bad=sum(c.telemetry.bad_results for c in self.cards.values())
        return {"schema":"sidecar-fk-fleet-status-v1","rollout_stage":self.stage.value,
            "stage_aborted":self.stage_aborted,"stage_abort_reason":"details-redacted" if self.stage_abort_reason else None,
            "fleet":{"card_count":len(self.cards),"active_fk_count":active,"qualified_fk_count":qualified,
                "completed_jobs":completed,"verified_results":verified,"bad_results":bad,
                "verification_success_rate":verified/(verified+bad) if verified+bad else None,
                "failure_rate":bad/(verified+bad) if verified+bad else None,
                "scheduler_queue_depth":self.scheduler_queue_depth,"stale_result_count":self.stale_result_count,
                "accidental_duplicate_work_count":self.accidental_duplicate_work_count,
                "unqualified_activation_count":self.unqualified_activation_count,
                "wrong_image_activation_count":self.wrong_image_activation_count},
            "scheduler":{"state":"ABORTED" if self.stage_aborted else "READY" if active else "IDLE",
                "policies":["round_robin","least_busy","measured_throughput_weighted"]},
            "performance":self._performance_summary(),"recent_failures":[{"card":r["card"],"kind":r["kind"]} for r in self.recent_failures],
            "cards":rows,"hardware_access":"none","qualification_loaded":bool(self.qualification)}

    def card_telemetry(self,card_id):
        c=self.cards[card_id];t=c.telemetry
        return {"jobs_assigned":t.jobs_assigned,"jobs_completed":t.jobs_completed,"raw_results":t.raw_results,
            "verified_results":t.verified_results,"bad_results":t.bad_results,"timeouts":t.timeouts,
            "transport_errors":t.transport_errors,"stale_results":t.stale_results,
            "average_latency_us":t.latency_summary()["average_us"],"p50_latency_us":t.latency_summary()["p50_us"],
            "p95_latency_us":t.latency_summary()["p95_us"],"throughput_jobs_per_second":t.jobs_per_second(self.clock()),
            "uptime_seconds":max(0,self.clock()-t.started_at) if t.started_at is not None else None,
            "restart_count":t.restart_count,"rollback_count":t.rollback_count}

    def persist_state(self,path:str|Path):
        cards=[]
        for c in sorted(self.cards.values(),key=lambda c:c.logical_id):
            cards.append({"logical_id":c.logical_id,"state":c.state.value,"qualified":c.qualified,
                "bitstream_sha256":c.expected_bitstream_sha256,"runner_sha256":c.expected_runner_sha256 or self.expected_runner_sha256,
                "physical_binding_fingerprint":hashlib.sha256(c.physical_binding_id.encode()).hexdigest() if c.physical_binding_id else None,
                "rollback_image_sha256":c.rollback_image_sha256,"enabled":c.enabled,"error_count":c.error_count,
                "restart_count":c.telemetry.restart_count,"rollback_count":c.telemetry.rollback_count,
                "health":c.health,"rollback_state":c.rollback_state})
        obj={"schema":"sidecar-fk-fleet-state-v1","rollout_stage":self.stage.value,
            "stage_aborted":self.stage_aborted,"cards":cards,"current_generation":self.current_generation,
            "current_job_fingerprint":self.current_job_fingerprint}
        atomic_write_json(path,obj);return obj

    def restore_state(self,path:str|Path):
        obj=json.loads(Path(path).read_text(encoding="utf-8"))
        if obj.get("schema")!="sidecar-fk-fleet-state-v1" or set(obj)!={"schema","rollout_stage","stage_aborted","cards","current_generation","current_job_fingerprint"}:
            raise ValueError("unsupported or unsafe fleet state file")
        rows={r["logical_id"]:r for r in obj["cards"]}
        for logical_id,card in self.cards.items():
            row=rows.get(logical_id)
            if not row:continue
            # Never restore an ACTIVE assertion from disk. Require qualification and health checks again.
            persisted_enabled=row.get("enabled",card.enabled)
            if not isinstance(persisted_enabled,bool):raise ValueError("invalid persisted card enabled state")
            card.enabled=card.enabled and persisted_enabled
            card.error_count=int(row.get("error_count",0));card.telemetry.restart_count=int(row.get("restart_count",0))
            card.telemetry.rollback_count=int(row.get("rollback_count",0));card.rollback_state=row.get("rollback_state","unknown")
            card.state=CardState.DISABLED if not card.enabled else CardState.UNKNOWN
            card.health="verification-required";card.backend_state="unknown"
        # Restarted processes restart rollout evaluation at the one-card canary.
        self.stage=RolloutStage.CANARY_1;self.stage_aborted=bool(obj["stage_aborted"])
        self.stage_started_at=self.clock();self.stage_started_verified=0
        self.current_generation=None;self.current_job_fingerprint=None;self.assignments.clear();self.work_ids.clear()
        self.outstanding_by_card.clear();self.scheduler_queue_depth=0;self.requires_revalidation=True
        self._refresh_qualification()
        for card in self.cards.values():
            if card.enabled:card.state=CardState.UNKNOWN;card.health="verification-required"
        return self.status()

    def revalidate_after_restart(self,card_id):
        card=self.cards[card_id]
        if card.state!=CardState.UNKNOWN:raise FleetError("card is not in ambiguous restart state")
        self.qualification_gate(card_id);self._transition(card,CardState.READY);card.health="ready"
        return True


def atomic_write_json(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(prefix=path.name+".",dir=path.parent,text=True)
    try:
        with os.fdopen(fd,"w",encoding="utf-8") as f:
            json.dump(value,f,sort_keys=True,indent=2);f.write("\n");f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
    finally:
        try:os.unlink(tmp)
        except FileNotFoundError:pass


def load_cards_config(path):
    return FleetController.from_config(path)
