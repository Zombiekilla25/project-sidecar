from __future__ import annotations
from dataclasses import dataclass, field
import hashlib, json, time

@dataclass(frozen=True)
class MiningJob:
    job_id: str
    sequence: int
    header: bytes
    target: int
    height: int | None = None
    cert_version: int | None = None
    difficulty: float | None = None
    received_at: float = field(default_factory=time.time)
    clean: bool = False
    @classmethod
    def from_notify(cls, p: dict, sequence: int, difficulty=None):
        if not isinstance(p, dict): raise ValueError("notify params must be object")
        try:
            job_id, header, target = p["job_id"], bytes.fromhex(p["header"]), int(p["target"], 16)
        except (KeyError, TypeError, ValueError) as e: raise ValueError("notify requires job_id, hex header, hex target") from e
        if not isinstance(job_id, str) or not job_id or len(header) != 76 or not 0 < target < 1 << 256:
            raise ValueError("invalid PRL job fields (expected 76-byte header and uint256 target)")
        return cls(job_id, sequence, header, target, p.get("height"), p.get("cert_version"), difficulty, time.time(), bool(p.get("clean", False)))
    def canonical(self):
        return json.dumps({"job_id":self.job_id,"sequence":self.sequence,"header":self.header.hex(),"target":f"{self.target:064x}","height":self.height,"cert_version":self.cert_version,"difficulty":self.difficulty,"clean":self.clean}, sort_keys=True, separators=(",",":"))
    @property
    def fingerprint(self): return hashlib.sha256(self.canonical().encode()).hexdigest()

@dataclass(frozen=True)
class Share:
    job_id: str
    job_fingerprint: str
    proof: dict
    result_hash: int
    submit_params: dict

@dataclass(frozen=True)
class Candidate:
    job_id: str
    job_fingerprint: str
    proof: dict
    result_hash: int
    submit_params: dict
