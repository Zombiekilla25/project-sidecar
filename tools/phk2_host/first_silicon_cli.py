"""Default-offline first-silicon command. A live adapter is not shipped here."""
from __future__ import annotations
import argparse,calendar,hashlib,importlib,importlib.util,json,os,sys,time
from pathlib import Path
from board_transport import HostTransportAdapter,SoftwareTransportEmulator
from first_silicon_harness import EvidenceBundle,EvidenceEmulator,EvidenceTransportProxy,FirstSiliconSession,ProgramBudget
from oracle import predict
from runtime import Descriptor,fixture_descriptor,fixture_path,sha

ROOT=Path(__file__).resolve().parents[2]
AUTH_SCHEMA="PHK2-FIRST-SILICON-AUTH-v1"

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
    hooks=plugin.recovery_hooks(bundle);record={"mode":"AUTHORIZED_LIVE_HOOKS","steps":[]}
    for name,method in (("restore_xbt",hooks.restore_xbt),("restore_shared_bridge",hooks.restore_shared_bridge),("restore_miner_workloads",hooks.restore_miner_workloads),("semantic_workload_continuity",hooks.check_semantic_workload_continuity)):
        outcome=method();record["steps"].append({"name":name,"outcome":outcome})
        if isinstance(outcome,dict) and outcome.get("pass") is False:raise RuntimeError(f"recovery hook failed: {name}")
    return record

def run_authorized_live(plugin,bitstream,bit_sha,lock_path,lock_sha,desc,raw_desc,auth_path,evidence_dir):
    metadata={"mode":"AUTHORIZED_LIVE","candidate_bitstream_sha256":bit_sha,"target_lock_sha256":lock_sha,"authorization_sha256":sha(auth_path.read_bytes()),"descriptor_sha256":sha(raw_desc),"host_executable_sha256":None,"host_cli_source_sha256":sha(Path(__file__).read_bytes()),"host_harness_source_sha256":sha(Path(__file__).with_name('first_silicon_harness.py').read_bytes()),"protocol_source_sha256":sha(Path(__file__).with_name('board_protocol.py').read_bytes()),"transport_reference_source_sha256":sha(Path(__file__).with_name('board_transport.py').read_bytes()),"physical_protocol_qualified_before_attempt":False,"hardware_access":"authorized by supplied one-use file"}
    bundle=EvidenceBundle(evidence_dir,metadata);bundle.write_bytes("raw_input.bin",raw_desc);result=None;budget=ProgramBudget()
    try:
        jit=plugin.validate_preprogram(bitstream,lock_path,bundle)
        if not isinstance(jit,dict) or jit.get("pass") is not True or jit.get("peer_program_allowed") is not False:raise RuntimeError("JIT target/peer validation failed closed")
        pinfo=budget.program_target_once(plugin.program_once,bitstream,lock_path,bundle)
        if not isinstance(pinfo,dict) or pinfo.get("programmed_device_count")!=1 or pinfo.get("peer_program_count")!=0 or pinfo.get("peer_bytes_sent",0)!=0:raise RuntimeError("programmer violated one-target/zero-peer contract")
        inner=plugin.open_transport(lock_path,bundle);recorder=EvidenceTransportProxy(inner,bundle)
        answer=predict(desc,0,64 if desc==fixture_descriptor() else 1);count=64 if desc==fixture_descriptor() else 1
        session=FirstSiliconSession(recorder,bundle);result=session.run(desc,answer,0,count,1)
        result["counters"]["program_attempts"]=budget.target_program_count
        result["counters"]["target_program_count"]=pinfo["programmed_device_count"]
        result["counters"]["peer_program_count"]=pinfo["peer_program_count"]
        result["counters"]["target_bytes_sent"]=int(pinfo.get("target_bytes_sent",0))
        result["counters"]["peer_bytes_sent"]=int(pinfo.get("peer_bytes_sent",0))
        # Session fsyncs PRE_RECOVERY evidence before these hooks run.
        recovery=recover(plugin,bundle);bundle.write_json("recovery_result.json",recovery)
        result["recovery"]=recovery
        if result["classification"]!="PASS":return result
        result["physical_qualification"]="NOT_SET_BY_HOST_HARNESS"
        return result
    except Exception as exc:
        program_attempted=budget.target_program_count>0
        classification="TRANSPORT_FAILURE" if program_attempted else "PRECHECK_REFUSAL"
        bundle.append("error_transcript.jsonl",{"phase":"AUTHORIZED_LIVE","type":type(exc).__name__,"message":str(exc),"classification":classification})
        bundle.before_recovery(classification,{"program_attempted":program_attempted,"program_attempt_count":budget.target_program_count})
        recovery={"state":"NOT_REQUIRED","reason":"target was not mutated"}
        if program_attempted:
            try:recovery=recover(plugin,bundle);bundle.write_json("recovery_result.json",recovery)
            except Exception as rex:classification="RECOVERY_FAILURE";recovery={"state":"FAIL","error":str(rex)};bundle.write_json("recovery_result.json",recovery)
        bundle.write_json("recovery_result.json",recovery)
        bundle.finalize({"classification":classification,"program_attempt_count":budget.target_program_count,"error":str(exc)}, {"measurement_class":"NOT_MEASURED"},recovery)
        return {"classification":classification,"error":str(exc),"program_attempts":budget.target_program_count,"recovery":recovery}

def main(argv=None):
    ap=argparse.ArgumentParser(prog="phk2-first-silicon",description="Offline by default; no physical transport ships in this worktree")
    ap.add_argument("--bitstream",type=Path);ap.add_argument("--bitstream-sha");ap.add_argument("--target-lock",type=Path);ap.add_argument("--descriptor",type=Path);ap.add_argument("--evidence-dir",type=Path)
    ap.add_argument("--live",action="store_true",help="requires a one-use authorization file; never implied")
    ap.add_argument("--authorization",type=Path)
    ap.add_argument("--dry-run",action="store_true",help="explicit offline mock; this is the default")
    a=ap.parse_args(argv)
    desc_path=a.descriptor or (fixture_path()/"descriptor.bin")
    try:
        raw=desc_path.read_bytes();desc=Descriptor.decode(raw)
    except Exception as exc:return fail(f"descriptor precheck failed: {exc}")
    desc_sha=sha(raw)
    if a.live:
        if not all((a.authorization,a.bitstream,a.bitstream_sha,a.target_lock,a.evidence_dir)):return fail("--live requires --authorization, --bitstream, --bitstream-sha, --target-lock, --descriptor and --evidence-dir")
        try:
            actual=hashlib.sha256(a.bitstream.read_bytes()).hexdigest()
            if actual.lower()!=a.bitstream_sha.lower():return fail("bitstream SHA-256 mismatch")
            lock_sha=sha(a.target_lock.read_bytes())
            validate_live_authorization(a.authorization,actual,lock_sha,desc_sha)
        except Exception as exc:return fail(f"live authorization/precheck refused: {exc}")
        # Import is deliberately deferred until every explicit gate passes.
        # This worktree has no physical adapter today; do not substitute the mock.
        if importlib.util.find_spec("phk2_first_silicon_live_adapter") is None:return fail("PHK2 physical programmer/transactor adapter is not installed; no hardware opened")
        try:
            # Consume the explicit authorization file atomically before any
            # plugin import can have side effects. A reused pathname fails.
            consumed=a.authorization.with_name(a.authorization.name+".consumed")
            if consumed.exists():return fail("authorization was already consumed")
            os.replace(a.authorization,consumed)
            plugin=importlib.import_module("phk2_first_silicon_live_adapter")
            result=run_authorized_live(plugin,a.bitstream,actual,a.target_lock,lock_sha,desc,raw,consumed,a.evidence_dir)
            print(json.dumps(result,indent=2));return 0 if result.get("classification")=="PASS" else 1
        except Exception as exc:return fail(f"live execution refused/failed before safe completion: {type(exc).__name__}: {exc}")
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
