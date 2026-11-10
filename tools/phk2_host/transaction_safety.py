"""Offline durable identity, exactly-once transaction and recovery journal.

This module is policy/model code only. It contains no endpoint discovery or I/O
transport implementation. Endpoint labels are transient observations; they are
never accepted as durable card identity.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any


class Refusal(RuntimeError):
    pass


def _sha(value: str) -> bool:
    return len(value) == 64 and all(c in "0123456789abcdef" for c in value)


@dataclass(frozen=True)
class CardIdentity:
    logical_name: str
    fpga_family: str
    board_id: str
    carrier_id: str
    transport_id: str
    jtag_id: str
    protocol_id: str
    loaded_image_id: str
    image_sha256: str
    session_id: str
    # A locator may change when enumeration order or the connection changes.
    # It is recorded for diagnostics but deliberately excluded from durable_key.
    endpoint_locator: str = "mock-endpoint"

    def validate(self) -> None:
        if any(not isinstance(v, str) or not v.strip() for v in asdict(self).values()):
            raise Refusal("identity fields must be non-empty strings")
        if not _sha(self.image_sha256):
            raise Refusal("immutable image identity must be SHA256")

    def durable_key(self) -> tuple[str, ...]:
        """Physical identity only; excludes transient endpoint and session IDs."""
        return (self.logical_name, self.fpga_family, self.board_id, self.carrier_id,
                self.transport_id, self.jtag_id)

    def image_key(self) -> tuple[str, str, str]:
        return self.protocol_id, self.loaded_image_id, self.image_sha256

    def same_card(self, observed: "CardIdentity") -> bool:
        self.validate(); observed.validate()
        return self.durable_key() == observed.durable_key()

    def verify_reconnect(self, observed: "CardIdentity") -> None:
        if not self.same_card(observed):
            raise Refusal("durable card identity changed across reconnect")
        if self.image_key() != observed.image_key():
            raise Refusal("protocol or loaded image identity changed")
        if self.session_id == observed.session_id:
            raise Refusal("session identity reused after reconnect")


class State(str, Enum):
    PRECHECK="PRECHECK"; IDENTIFY="IDENTIFY"; OPEN="OPEN"; HELLO="HELLO"
    READY="READY"; WORK_SENT="WORK_SENT"; RESULT_PENDING="RESULT_PENDING"
    RESULT_RECEIVED="RESULT_RECEIVED"; CLOSE="CLOSE"; ABORTING="ABORTING"
    DISCONNECTED="DISCONNECTED"; RECOVERING="RECOVERING"
    ROLLBACK_REQUIRED="ROLLBACK_REQUIRED"; ROLLBACK_COMPLETE="ROLLBACK_COMPLETE"
    QUARANTINED="QUARANTINED"; FAILED_CLOSED="FAILED_CLOSED"


# Only explicitly listed edges are legal. Ambiguous failures cannot return READY.
EDGES: dict[State, set[State]] = {
    State.PRECHECK:{State.IDENTIFY,State.FAILED_CLOSED},
    State.IDENTIFY:{State.OPEN,State.FAILED_CLOSED,State.QUARANTINED},
    State.OPEN:{State.HELLO,State.DISCONNECTED,State.ABORTING,State.FAILED_CLOSED},
    State.HELLO:{State.READY,State.DISCONNECTED,State.ABORTING,State.FAILED_CLOSED},
    State.READY:{State.WORK_SENT,State.CLOSE,State.DISCONNECTED,State.ABORTING,State.FAILED_CLOSED},
    State.WORK_SENT:{State.RESULT_PENDING,State.DISCONNECTED,State.ABORTING,State.QUARANTINED,State.FAILED_CLOSED},
    State.RESULT_PENDING:{State.RESULT_RECEIVED,State.DISCONNECTED,State.ABORTING,State.QUARANTINED,State.FAILED_CLOSED},
    State.RESULT_RECEIVED:{State.CLOSE,State.QUARANTINED,State.FAILED_CLOSED},
    State.CLOSE:{State.ROLLBACK_REQUIRED,State.QUARANTINED,State.FAILED_CLOSED},
    State.ABORTING:{State.DISCONNECTED,State.ROLLBACK_REQUIRED,State.QUARANTINED,State.FAILED_CLOSED},
    State.DISCONNECTED:{State.RECOVERING,State.ROLLBACK_REQUIRED,State.QUARANTINED,State.FAILED_CLOSED},
    State.RECOVERING:{State.IDENTIFY,State.ROLLBACK_REQUIRED,State.QUARANTINED,State.FAILED_CLOSED},
    State.ROLLBACK_REQUIRED:{State.ROLLBACK_COMPLETE,State.QUARANTINED,State.FAILED_CLOSED},
    State.ROLLBACK_COMPLETE:{State.CLOSE,State.FAILED_CLOSED},
    State.QUARANTINED:{State.FAILED_CLOSED}, State.FAILED_CLOSED:set(),
}


def legal_transition(source: State, target: State) -> bool:
    return target in EDGES[source]


class Disposition(str, Enum):
    NOT_STARTED="NOT_STARTED"; DEFINITELY_NOT_SENT="DEFINITELY_NOT_SENT"
    MAY_HAVE_BEEN_SENT="MAY_HAVE_BEEN_SENT"; DEFINITELY_SENT="DEFINITELY_SENT"
    RESULT_VERIFIED="RESULT_VERIFIED"; ABORTED="ABORTED"; QUARANTINED="QUARANTINED"


@dataclass
class Transaction:
    evidence_id: str
    transaction_id: str
    work_id: str
    session_id: str
    image_sha256: str
    request_sha256: str
    state: str = "NOT_STARTED"
    response_sha256: str | None = None
    accepted_result_ids: list[str] | None = None


class EvidenceJournal:
    """Append-only fsynced JSONL hash chain with crash-recoverable disposition."""
    def __init__(self, path: Path):
        self.path=path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash="0"*64
        if path.exists():
            for row in self.rows(): self._last_hash=row["record_sha256"]

    def append(self, event: str, *, timestamp_ns: int | None = None, **fields: Any) -> dict:
        body={"event":event,"timestamp_ns":timestamp_ns or time.time_ns(),**fields,
              "previous_sha256":self._last_hash}
        digest=hashlib.sha256(json.dumps(body,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()).hexdigest()
        row={**body,"record_sha256":digest}
        with self.path.open("ab") as f:
            f.write((json.dumps(row,sort_keys=True,separators=(",",":"))+"\n").encode())
            f.flush();os.fsync(f.fileno())
        try:
            fd=os.open(self.path.parent,os.O_RDONLY);os.fsync(fd);os.close(fd)
        except OSError: pass
        self._last_hash=digest
        return row

    def rows(self) -> list[dict]:
        out=[]; previous="0"*64
        if not self.path.exists(): return out
        with self.path.open("rb") as f:
            for n,line in enumerate(f,1):
                row=json.loads(line)
                digest=row.pop("record_sha256")
                if row.get("previous_sha256") != previous:
                    raise Refusal(f"journal chain broken at line {n}")
                actual=hashlib.sha256(json.dumps(row,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()).hexdigest()
                if actual != digest: raise Refusal(f"journal record altered at line {n}")
                row["record_sha256"]=digest;out.append(row);previous=digest
        return out

    def reconcile(self, transaction_id: str) -> Disposition:
        events=[r for r in self.rows() if r.get("transaction_id")==transaction_id]
        if not events: return Disposition.NOT_STARTED
        names=[r["event"] for r in events]
        if "quarantined" in names: return Disposition.QUARANTINED
        if "result_verified" in names: return Disposition.RESULT_VERIFIED
        if "aborted" in names: return Disposition.ABORTED
        if "result_received" in names: return Disposition.DEFINITELY_SENT
        if "work_acknowledged" in names: return Disposition.DEFINITELY_SENT
        if "work_send_begin" in names: return Disposition.MAY_HAVE_BEEN_SENT
        if "definitely_not_sent" in names: return Disposition.DEFINITELY_NOT_SENT
        return Disposition.NOT_STARTED


class ExactlyOnceLedger:
    """Mock transaction ledger; never converts uncertain delivery into success."""
    def __init__(self, journal: EvidenceJournal, image_sha256: str):
        self.journal=journal;self.image_sha256=image_sha256
        self.work_ids:set[str]=set();self.session_ids:set[str]=set();self.results:set[str]=set()
        # Recover uniqueness fences from the append-only journal after restart.
        for row in journal.rows():
            if row.get("event")=="transaction_created":
                if row.get("work_id"): self.work_ids.add(row["work_id"])
                if row.get("session_id"): self.session_ids.add(row["session_id"])
            if row.get("event")=="result_received" and row.get("result_id"):
                self.results.add(row["result_id"])

    def begin(self, identity: CardIdentity, request: bytes, *, work_id: str | None=None) -> Transaction:
        identity.validate()
        if identity.image_sha256 != self.image_sha256: raise Refusal("wrong loaded image")
        if identity.session_id in self.session_ids: raise Refusal("session ID reuse")
        work_id=work_id or str(uuid.uuid4())
        if work_id in self.work_ids: raise Refusal("work ID reuse")
        self.session_ids.add(identity.session_id);self.work_ids.add(work_id)
        txn=Transaction(str(uuid.uuid4()),str(uuid.uuid4()),work_id,identity.session_id,
                        identity.image_sha256,hashlib.sha256(request).hexdigest(),accepted_result_ids=[])
        self.journal.append("transaction_created",transaction_id=txn.transaction_id,evidence_id=txn.evidence_id,
            work_id=txn.work_id,session_id=txn.session_id,image_sha256=txn.image_sha256,
            request_sha256=txn.request_sha256,authorization_state="mock-authorized",expected_identity=asdict(identity),observed_identity=asdict(identity))
        return txn

    def mark_send_begin(self, txn: Transaction) -> None:
        txn.state="MAY_HAVE_BEEN_SENT";self.journal.append("work_send_begin",transaction_id=txn.transaction_id,work_id=txn.work_id,session_id=txn.session_id,request_sha256=txn.request_sha256)

    def mark_definitely_not_sent(self, txn: Transaction) -> None:
        if txn.state != "NOT_STARTED": raise Refusal("cannot assert unsent after send began")
        txn.state="DEFINITELY_NOT_SENT";self.journal.append("definitely_not_sent",transaction_id=txn.transaction_id,work_id=txn.work_id)

    def acknowledge(self, txn: Transaction) -> None:
        if txn.state != "MAY_HAVE_BEEN_SENT": raise Refusal("ack without ambiguous send")
        txn.state="DEFINITELY_SENT";self.journal.append("work_acknowledged",transaction_id=txn.transaction_id,work_id=txn.work_id,session_id=txn.session_id,image_sha256=txn.image_sha256)

    def accept_result(self, txn: Transaction, result_id: str, response: bytes, *, session_id: str, image_sha256: str) -> None:
        if txn.state not in {"DEFINITELY_SENT","MAY_HAVE_BEEN_SENT"}: raise Refusal("result before work send")
        if (session_id,image_sha256)!=(txn.session_id,txn.image_sha256): raise Refusal("result session/image mismatch")
        if result_id in self.results: raise Refusal("duplicate result")
        self.results.add(result_id);txn.accepted_result_ids=(txn.accepted_result_ids or [])+[result_id]
        txn.response_sha256=hashlib.sha256(response).hexdigest();txn.state="RESULT_RECEIVED"
        self.journal.append("result_received",transaction_id=txn.transaction_id,work_id=txn.work_id,result_id=result_id,
            session_id=session_id,image_sha256=image_sha256,response_sha256=txn.response_sha256)

    def verify_result(self, txn: Transaction, result_id: str, verified: bool) -> None:
        if txn.state!="RESULT_RECEIVED" or result_id not in (txn.accepted_result_ids or []): raise Refusal("unbound result verification")
        if not verified:
            txn.state="QUARANTINED";self.journal.append("quarantined",transaction_id=txn.transaction_id,reason="result verification failed");return
        txn.state="RESULT_VERIFIED";self.journal.append("result_verified",transaction_id=txn.transaction_id,result_id=result_id,response_sha256=txn.response_sha256)

