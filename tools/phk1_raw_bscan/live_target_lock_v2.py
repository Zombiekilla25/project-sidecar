#!/usr/bin/env python3
"""Live-path v2 lock adapter. Only reads supplied evidence/files; never opens devices."""
from __future__ import annotations
import argparse
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import tempfile

from target_lock_v2 import (build_lock, validate_lock,
                            LockValidationError)

PART = "xcvu33p-fsvh2104-2-e"
PHK_SHA = "47a392b76ebdfdd9edbfc5270f21b48fb6d1acb73e45a7425811865a196d76f8"
PHK_SIZE = 28329335
XBT_SHA = "f9812864d13a6963700f60709507ff85ee660fb77e846e51be533b2d479502df"


class V2LockError(RuntimeError):
    pass


def sha_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def physical_from_identity_lock(lock: dict, *, now: datetime | None = None) -> tuple[dict, dict]:
    if lock.get("status") != "PASS" or lock.get("match_count") != 1 or lock.get("peer_distinct") is not True:
        raise V2LockError("fresh physical identity source did not bind one target and distinct peer")
    try:
        captured = datetime.fromisoformat(lock["captured_utc"].replace("Z", "+00:00"))
        age = ((now or datetime.now(timezone.utc)) - captured.astimezone(timezone.utc)).total_seconds()
    except (KeyError, ValueError, TypeError, AttributeError) as exc:
        raise V2LockError("physical identity source timestamp is missing or malformed") from exc
    if age < 0 or age > 600:
        raise V2LockError("physical identity source is future-dated or stale")
    out = []
    for role in ("target", "peer"):
        x = lock.get(role)
        if not isinstance(x, dict):
            raise V2LockError(f"{role} identity missing")
        p = {"usb_path": x.get("usb_path"), "ftdi_serial": x.get("ftdi_serial"),
             "vid": str(x.get("vid", "")).lower(), "pid": str(x.get("pid", "")).lower(),
             "interface": x.get("interface"), "idcode": str(x.get("idcode", "")).lower().removeprefix("0x"),
             "dna": x.get("dna"), "bridge_lane": x.get("bridge_endpoint"),
             "workload_binding": x.get("miner_binding")}
        if any(not isinstance(v, str) or not v for v in p.values()):
            raise V2LockError(f"{role} physical identity incomplete")
        out.append(p)
    if out[0]["dna"] == out[1]["dna"] or out[0]["ftdi_serial"] == out[1]["ftdi_serial"]:
        raise V2LockError("target and peer are not distinct")
    return out[0], out[1]


def _json(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise V2LockError(f"cannot read JSON evidence {path}: {exc}") from exc


def verify_bundle(candidate_path: Path, candidate_manifest_path: Path,
                  qualification_path: Path, rollback_path: Path,
                  rollback_binding_path: Path) -> tuple[dict, dict, dict, str, str]:
    candidate_manifest = _json(candidate_manifest_path)
    qualification = _json(qualification_path)
    rollback_binding = _json(rollback_binding_path)
    candidate_sha = sha_file(candidate_path)
    rollback_sha = sha_file(rollback_path)
    if candidate_sha != PHK_SHA or candidate_path.stat().st_size != PHK_SIZE:
        raise V2LockError("candidate file SHA/size does not match the pinned patched PHK1 image")
    if candidate_manifest.get("candidate_id") != "PHK1_USER1_TCK_READCLK_RESPONSE_VALID_REFILL_20261103":
        raise V2LockError("candidate manifest identity mismatch")
    if (qualification.get("bitstream_sha256") != PHK_SHA or
        qualification.get("bitstream_size") != PHK_SIZE or
        qualification.get("target_part") != PART or
        qualification.get("physical_protocol_qualified") is not False or
        qualification.get("hello_vendor_replay") != "PASS" or
        qualification.get("vector001_vendor_replay") != "PASS" or
        "PASS" not in str(qualification.get("cpu_crosscheck", "")) or
        qualification.get("cdc") != "PASS" or qualification.get("drc") != "PASS" or
        qualification.get("timing_met") is not True):
        raise V2LockError("offline qualification manifest does not bind the patched image")
    if candidate_manifest.get("vector001_vendor_replay_pass") is not True or candidate_manifest.get("cpu_crosscheck") is not True:
        raise V2LockError("candidate manifest lacks the required offline functional qualification")
    if rollback_binding.get("sha256") != XBT_SHA or rollback_binding.get("rollback_image_unchanged") is not True:
        raise V2LockError("authoritative rollback binding is not the known-good XBT")
    if rollback_sha != XBT_SHA:
        raise V2LockError("rollback file SHA does not match the known-good XBT")
    candidate = {"role":"CANDIDATE_IMAGE_TO_PROGRAM", "image_id":candidate_manifest.get("candidate_id"),
        "sha256":candidate_sha,"size":candidate_path.stat().st_size,"target_part":PART,"path":str(candidate_path.resolve())}
    rollback = {"role":"ROLLBACK_IMAGE","image_id":rollback_binding.get("image_id"),
        "sha256":rollback_sha,"size":rollback_path.stat().st_size,"target_part":PART,"path":str(rollback_path.resolve())}
    return candidate_manifest, qualification, rollback_binding, sha_file(candidate_manifest_path), sha_file(qualification_path)


def _current(kind: str, candidate: dict, rollback: dict) -> dict:
    if kind == "xbt":
        src = rollback
    elif kind == "phk1":
        src = candidate
    else:
        raise V2LockError("current image kind must be xbt or phk1")
    return {"role":"CURRENT_LOADED_IMAGE", "image_id":src["image_id"], "sha256":src["sha256"],
            "size":src["size"], "target_part":PART, "path":src["path"]}


def create_v2_lock(*, identity_lock_path: Path, candidate_path: Path,
                   candidate_manifest_path: Path, qualification_path: Path,
                   rollback_path: Path, rollback_binding_path: Path,
                   current_kind: str, current_log_path: Path,
                   maintenance_generation: str, output_path: Path,
                   now: datetime | None = None) -> dict:
    identity_lock = _json(identity_lock_path)
    target, peer = physical_from_identity_lock(identity_lock)
    cm, qm, rb, candidate_manifest_sha, qualification_sha = verify_bundle(
        candidate_path, candidate_manifest_path, qualification_path, rollback_path, rollback_binding_path)
    candidate = {"role":"CANDIDATE_IMAGE_TO_PROGRAM", "image_id":cm["candidate_id"], "sha256":PHK_SHA,
        "size":PHK_SIZE,"target_part":PART,"path":str(candidate_path.resolve())}
    rollback = {"role":"ROLLBACK_IMAGE", "image_id":rb["image_id"], "sha256":XBT_SHA,
        "size":rollback_path.stat().st_size,"target_part":PART,"path":str(rollback_path.resolve())}
    current = _current(current_kind, candidate, rollback)
    log = current_log_path.read_text(errors="replace")
    if "Bitstream Loaded" not in log or f"Using Bitstream {current['path']}" not in log:
        raise V2LockError("current-image log does not prove the expected current image was loaded")
    if f"DNA: {target['dna']}" not in log or f"IDCODE({target['idcode']})" not in log:
        raise V2LockError("current-image log does not bind physical target IDCODE/DNA")
    timestamp = now or datetime.now(timezone.utc)
    action = "PROGRAM_CANDIDATE" if current_kind == "xbt" else "VERIFY_CANDIDATE"
    lock = build_lock(target_identity=target, peer_identity=peer, current_image=current,
        candidate_image=candidate, rollback_image=rollback,
        created_utc=timestamp.isoformat(), expires_utc=(timestamp+timedelta(seconds=300)).isoformat(),
        maintenance_generation=maintenance_generation, candidate_manifest_sha256=candidate_manifest_sha,
        qualification_sha256=qualification_sha, current_image_evidence=f"sha256:{sha_file(current_log_path)}",
        rollback_authority=f"sha256:{sha_file(rollback_binding_path)}", intended_action=action,
        run_id=maintenance_generation)
    output_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd,tmp=tempfile.mkstemp(prefix=".target-lock-v2-",dir=output_path.parent)
    with os.fdopen(fd,"w") as f:
        json.dump(lock,f,sort_keys=True,indent=2); f.write("\n"); f.flush(); os.fsync(f.fileno())
    os.chmod(tmp,0o600); os.replace(tmp,output_path)
    return lock


def validate_v2_lock_file(*, lock_path: Path, identity_lock_path: Path,
                          candidate_path: Path, candidate_manifest_path: Path,
                          qualification_path: Path, rollback_path: Path,
                          rollback_binding_path: Path, current_kind: str, current_log_path: Path,
                          maintenance_generation: str, phase: str,
                          now: datetime | None = None,
                          nonce_ledger_path: Path | None = None) -> tuple[dict,str]:
    lock = _json(lock_path)
    identity_lock = _json(identity_lock_path)
    target, peer = physical_from_identity_lock(identity_lock)
    cm,qm,rb,msha,qsha = verify_bundle(candidate_path,candidate_manifest_path,qualification_path,rollback_path,rollback_binding_path)
    candidate={"role":"CANDIDATE_IMAGE_TO_PROGRAM","image_id":cm["candidate_id"],"sha256":PHK_SHA,
        "size":PHK_SIZE,"target_part":PART,"path":str(candidate_path.resolve())}
    rollback={"role":"ROLLBACK_IMAGE","image_id":rb["image_id"],"sha256":XBT_SHA,
        "size":rollback_path.stat().st_size,"target_part":PART,"path":str(rollback_path.resolve())}
    current=_current(current_kind,candidate,rollback)
    log=current_log_path.read_text(errors="replace")
    if "Bitstream Loaded" not in log or f"Using Bitstream {current['path']}" not in log:
        raise V2LockError("JIT current-image evidence no longer proves the expected image")
    if lock.get("current_image_evidence") != f"sha256:{sha_file(current_log_path)}":
        raise V2LockError("current-image evidence changed since lock creation")
    action = "PROGRAM_CANDIDATE" if phase == "program" else "VERIFY_CANDIDATE" if phase == "verify" else None
    if action is None:
        raise V2LockError("phase must be program or verify")
    validate_lock(lock,now=now or datetime.now(timezone.utc),expected_target=target,expected_peer=peer,
        expected_candidate=candidate,expected_rollback=rollback,expected_current_image=current,
        expected_manifest_sha256=msha,expected_qualification_sha256=qsha,
        expected_maintenance_generation=maintenance_generation,
        expected_rollback_authority=f"sha256:{sha_file(rollback_binding_path)}",intended_action=action)
    raw=lock_path.read_bytes(); lock_sha=hashlib.sha256(raw).hexdigest()
    if nonce_ledger_path is not None:
        consume_nonce(lock["authorization_nonce"],nonce_ledger_path)
    return lock,lock_sha


def consume_nonce(nonce: str, ledger_path: Path) -> None:
    ledger_path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    fd=os.open(ledger_path,os.O_RDWR|os.O_CREAT,0o600)
    with os.fdopen(fd,"r+") as f:
        fcntl.flock(f,fcntl.LOCK_EX)
        raw=f.read()
        try: data=json.loads(raw) if raw else {"nonces":[]}
        except json.JSONDecodeError as exc: raise V2LockError("nonce ledger is malformed") from exc
        nonces=data.get("nonces")
        if not isinstance(nonces,list) or nonce in nonces:
            raise V2LockError("lock nonce is malformed or replayed")
        nonces.append(nonce); f.seek(0); f.truncate()
        json.dump(data,f,sort_keys=True); f.write("\n"); f.flush(); os.fsync(f.fileno())
        fcntl.flock(f,fcntl.LOCK_UN)


def main(argv=None):
    ap=argparse.ArgumentParser()
    sub=ap.add_subparsers(dest="cmd",required=True)
    for cmd in ("create","validate"):
        p=sub.add_parser(cmd)
        p.add_argument("--identity-lock",type=Path,required=True)
        p.add_argument("--candidate",type=Path,required=True)
        p.add_argument("--candidate-manifest",type=Path,required=True)
        p.add_argument("--qualification-manifest",type=Path,required=True)
        p.add_argument("--rollback",type=Path,required=True)
        p.add_argument("--rollback-binding",type=Path,required=True)
        p.add_argument("--current-kind",choices=("xbt","phk1"),required=True)
        p.add_argument("--current-log",type=Path,required=True)
        p.add_argument("--maintenance-generation",required=True)
    ap_create = sub.choices["create"]
    ap_create.add_argument("--output",type=Path,required=True)
    ap_val = sub.choices["validate"]
    ap_val.add_argument("--lock",type=Path,required=True)
    ap_val.add_argument("--phase",choices=("program","verify"),required=True)
    ap_val.add_argument("--nonce-ledger",type=Path)
    args=ap.parse_args(argv)
    try:
        common=dict(identity_lock_path=args.identity_lock,candidate_path=args.candidate,
            candidate_manifest_path=args.candidate_manifest,qualification_path=args.qualification_manifest,
            rollback_path=args.rollback,rollback_binding_path=args.rollback_binding,
            current_kind=args.current_kind,current_log_path=args.current_log,
            maintenance_generation=args.maintenance_generation)
        if args.cmd=="create":
            lock=create_v2_lock(**common,output_path=args.output)
            print(f"V2_LOCK_CREATED=PASS ACTION={lock['intended_action']} LOCK_SHA256={lock['lock_sha256']}")
        else:
            lock, digest=validate_v2_lock_file(**common,
                lock_path=args.lock,phase=args.phase,nonce_ledger_path=args.nonce_ledger)
            print(f"V2_JIT_VALIDATION=PASS ACTION={lock['intended_action']} LOCK_SHA256={digest}")
        return 0
    except (OSError,KeyError,ValueError,V2LockError,LockValidationError) as exc:
        print(f"V2_LOCK=FAIL ERROR={exc}")
        return 1


if __name__=="__main__": raise SystemExit(main())
