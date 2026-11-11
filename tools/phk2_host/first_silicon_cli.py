"""Default-offline first-silicon command. A live adapter is not shipped here."""
from __future__ import annotations
import argparse,calendar,hashlib,json,sys,time
from pathlib import Path
from first_silicon_harness import EvidenceBundle,EvidenceEmulator,FirstSiliconSession
from oracle import predict
from runtime import Descriptor,fixture_path,sha

ROOT=Path(__file__).resolve().parents[2]
AUTH_SCHEMA="PHK2-FIRST-SILICON-AUTH-v1"
# Deliberately fixed false in this host-only worktree. No routed/bitstream-
# qualified PHK2 physical image or response endpoint is available here.
PHYSICAL_QUALIFICATION_AVAILABLE=False

def fail(message):
    print(json.dumps({"classification":"PRECHECK_REFUSAL","live_action_performed":False,"reason":message},indent=2));return 3

def validate_live_authorization(path,bitstream_sha,target_lock_sha,descriptor_sha):
    obj=json.loads(Path(path).read_text())
    required={"schema":AUTH_SCHEMA,"single_use":True,"one_card_authorized":True,"candidate_image_qualified":True,"wire_contract_qualified":True,"bitstream_sha256":bitstream_sha,"target_lock_sha256":target_lock_sha,"descriptor_sha256":descriptor_sha,"max_program_attempts":1,"max_hello_attempts":1,"max_transactions":1,"peer_program_allowed":False}
    for key,value in required.items():
        if obj.get(key)!=value:raise ValueError(f"authorization field {key} does not match required value")
    expires=obj.get("expires_utc")
    if not expires:raise ValueError("authorization expiry is required")
    parsed=time.strptime(expires,"%Y-%m-%dT%H:%M:%SZ")
    if calendar.timegm(parsed) < time.time():raise ValueError("authorization expired")
    return obj

def recover(plugin,bundle):
    raise RuntimeError("live recovery hooks are disabled in this host-only worktree")

def run_authorized_live(plugin,bitstream,bit_sha,lock_path,lock_sha,desc,raw_desc,auth_path,evidence_dir):
    raise RuntimeError("legacy live programming/transact path is disabled; use no physical executor from this worktree")

def main(argv=None):
    ap=argparse.ArgumentParser(prog="phk2-first-silicon",description="Offline by default; no physical transport ships in this worktree")
    ap.add_argument("--bitstream",type=Path);ap.add_argument("--bitstream-sha");ap.add_argument("--target-lock",type=Path);ap.add_argument("--descriptor",type=Path);ap.add_argument("--evidence-dir",type=Path)
    ap.add_argument("--live",action="store_true",help="requires a one-use authorization file; never implied")
    ap.add_argument("--authorization",type=Path)
    ap.add_argument("--dry-run",action="store_true",help="explicit offline mock; this is the default")
    a=ap.parse_args(argv)
    if a.live:
        return fail("live physical execution is disabled; no executor is installed in this host-only worktree")
    desc_path=a.descriptor or (fixture_path()/"descriptor.bin")
    try:
        raw=desc_path.read_bytes();desc=Descriptor.decode(raw)
    except Exception as exc:return fail(f"descriptor precheck failed: {exc}")
    desc_sha=sha(raw)
    if a.authorization:return fail("authorization file supplied without explicit --live")
    bit_sha=None
    if a.bitstream:
        try:bit_sha=hashlib.sha256(a.bitstream.read_bytes()).hexdigest()
        except OSError as exc:return fail(f"cannot read candidate bitstream: {exc}")
        if a.bitstream_sha and bit_sha.lower()!=a.bitstream_sha.lower():return fail("candidate SHA mismatch")
    lock_sha=None
    if a.target_lock:
        try:lock_sha=sha(a.target_lock.read_bytes())
        except OSError as exc:return fail(f"target-lock reference unavailable: {exc}")
    evidence_root=a.evidence_dir or Path("/tmp")/f"phk2-host-dryrun-{desc_sha[:12]}-{time.time_ns()}"
    answer=predict(desc,0,64 if desc==Descriptor.decode((fixture_path()/"descriptor.bin").read_bytes()) else 1)
    metadata={"mode":"OFFLINE_DRY_RUN","candidate_bitstream_sha256":bit_sha,"target_lock_sha256":lock_sha,"descriptor_sha256":desc_sha,"host_executable_sha256":None,"host_cli_source_sha256":sha(Path(__file__).read_bytes()),"host_harness_source_sha256":sha(Path(__file__).with_name('first_silicon_harness.py').read_bytes()),"protocol_source_sha256":sha(Path(__file__).with_name('board_protocol.py').read_bytes()),"transport_reference_source_sha256":sha(Path(__file__).with_name('board_transport.py').read_bytes()),"hardware_access":0}
    try:
        bundle=EvidenceBundle(evidence_root,metadata);device=EvidenceEmulator(bundle);count=64 if answer.get("checks",{}).get("batch64_operand_hashes_exact") is not None else 1
        session=FirstSiliconSession(device,bundle);result=session.run(desc,answer,0,count,1)
    except FileExistsError:return fail("evidence directory already exists; attempt directories are immutable and never reused")
    except Exception as exc:return fail(f"offline dry-run failed: {type(exc).__name__}: {exc}")
    print(json.dumps({"classification":result["classification"],"mode":"OFFLINE_DRY_RUN","hardware_access":0,"program_attempts":result["counters"]["program_attempts"],"hello_attempts":result["counters"]["hello_attempts"],"transaction_count":result["counters"]["transaction_count"],"result_count":result["result_count"],"raw_result_exact":result["raw_result_exact"],"canonical_result_exact":result["canonical_result_exact"],"cpu_crosscheck":result["cpu_crosscheck"],"evidence_dir":str(evidence_root)},indent=2))
    return 0 if result["classification"]=="PASS" else 1
if __name__=="__main__":raise SystemExit(main())
