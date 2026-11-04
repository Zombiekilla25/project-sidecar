#!/usr/bin/env python3
"""Resolve recovery exclusively from the v2 rollback image role."""
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path
from target_lock_v2 import canonical_sha256

PHK_SHA="47a392b76ebdfdd9edbfc5270f21b48fb6d1acb73e45a7425811865a196d76f8"
XBT_SHA="f9812864d13a6963700f60709507ff85ee660fb77e846e51be533b2d479502df"
PART="xcvu33p-fsvh2104-2-e"

class RecoveryRoleError(ValueError): pass

def file_sha(path: Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda:f.read(1024*1024),b""): h.update(block)
    return h.hexdigest()

def select_rollback(lock: dict, rollback_path: Path, rollback_binding_path: Path) -> dict:
    if lock.get("schema")!="sidecar-raw-jtag-target-lock-v2" or lock.get("schema_version")!=2:
        raise RecoveryRoleError("recovery requires v2 image-role lock; legacy image binding rejected")
    body=dict(lock); digest=body.pop("lock_sha256",None)
    if digest!=canonical_sha256(body): raise RecoveryRoleError("v2 lock integrity mismatch")
    current=lock.get("current_image",{}); candidate=lock.get("candidate_image",{}); rollback=lock.get("rollback_image",{})
    if current.get("role")!="CURRENT_LOADED_IMAGE": raise RecoveryRoleError("current image role missing")
    if candidate.get("role")!="CANDIDATE_IMAGE_TO_PROGRAM" or candidate.get("sha256")!=PHK_SHA:
        raise RecoveryRoleError("patched candidate role mismatch")
    if rollback.get("role")!="ROLLBACK_IMAGE" or rollback.get("sha256")!=XBT_SHA:
        raise RecoveryRoleError("known-good XBT rollback role mismatch")
    if rollback.get("target_part")!=PART or candidate.get("target_part")!=PART:
        raise RecoveryRoleError("candidate/rollback part mismatch")
    if current.get("sha256") not in (XBT_SHA,PHK_SHA):
        raise RecoveryRoleError("current image is neither baseline nor candidate")
    if lock.get("peer_exclusion",{}).get("peer_program_allowed") is not False or lock.get("max_programmed_device_count")!=1:
        raise RecoveryRoleError("peer/single-card protection missing")
    if lock.get("rollback_authority")!="sha256:"+file_sha(rollback_binding_path):
        raise RecoveryRoleError("rollback authority binding changed")
    if rollback.get("path")!=str(rollback_path.resolve()) or file_sha(rollback_path)!=XBT_SHA:
        raise RecoveryRoleError("rollback image path/hash changed")
    if lock.get("intended_action") not in ("PROGRAM_CANDIDATE","VERIFY_CANDIDATE"):
        raise RecoveryRoleError("lock action not allowed for recovery")
    return {"status":"PASS","selected_role":"ROLLBACK_IMAGE","image_id":rollback["image_id"],
            "sha256":rollback["sha256"],"path":rollback["path"],
            "current_image_sha256":current["sha256"],"candidate_image_sha256":candidate["sha256"]}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--lock",type=Path,required=True); ap.add_argument("--rollback",type=Path,required=True); ap.add_argument("--rollback-binding",type=Path,required=True); a=ap.parse_args()
    try:
        result=select_rollback(json.loads(a.lock.read_text()),a.rollback,a.rollback_binding)
        print(json.dumps(result,sort_keys=True)); return 0
    except (OSError,json.JSONDecodeError,KeyError,RecoveryRoleError) as exc:
        print(f"RECOVERY_V2_ROLES=FAIL ERROR={exc}"); return 1
if __name__=="__main__": raise SystemExit(main())
