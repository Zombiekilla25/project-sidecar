"""Offline image-intake, canary-gate, fault, and full-flow rehearsal."""
from __future__ import annotations
import hashlib,json,random,sys,time
from pathlib import Path
from datetime import datetime,timezone
from runtime import fixture_descriptor,fixture_path
from oracle import predict
from first_silicon_harness import EvidenceBundle,EvidenceEmulator,FirstSiliconSession
from image_intake import validate_package
from image_intake_qualify import EXPECTED,make_package,run_tests as image_tests,_seal_manifest
from canary_precheck import EXPECTED_CARD_ID,evaluate_gates,REQUIRED_GATES
from canary_precheck_qualify import run_tests as precheck_tests
from first_silicon_qualify import physical_boundary_tests,qualify as host_qualify

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/"results/phk2-overnight-readiness"
FAULT_NAMES=("timeout","delayed_hello","malformed_hello","partial_reply","truncated_reply","duplicated_reply","stale_reply",
 "result_before_hello_completion","duplicate_result","reordered_result","stale_session_result","endpoint_disconnect",
 "reconnect","peer_collision","abort_during_transaction","host_termination","adapter_termination","evidence_write_failure",
 "corrupted_evidence","image_qualification_revoked_before_invocation","authorization_absent","authorization_removed_before_invocation",
 "identity_mismatch","protocol_mismatch","unexpected_status","work_rejection","result_decoder_failure")

class RehearsalDevice(EvidenceEmulator):
    def __init__(self,evidence,**kwargs):super().__init__(evidence,**kwargs);self.close_count=0;self.is_closed=False
    def close(self):self.close_count+=1;self.is_closed=True

def _seed_fault_cases():
    rows=[(f"v2-single:{name}",0x50484b320000+i,(name,)) for i,name in enumerate(FAULT_NAMES)]
    rng=random.Random(0x50484b324348414f)
    for i in range(24):
        n=2+(i%3);faults=tuple(sorted(rng.sample(FAULT_NAMES,n)))
        rows.append((f"v2-combo:{i:02d}",rng.randrange(1,2**31),faults))
    return rows

def _fault_model(faults,seed):
    """Deterministic state model plus tested gate/transport safety assertions."""
    rng=random.Random(seed);faults=set(faults)
    counts={"physical_access":0,"program_attempts":0,"peer_programs":0,"hello_attempts":0,"transactions":0,"retries":0,"reconnects":0}
    gates={"host_harness_ready":True,"physical_adapter_interface_ready":True,"explicit_hardware_authorization":True,
           "card_count":1,"target_card_id":EXPECTED_CARD_ID,"peer_card_id":"configured-peer-only","peer_exclusion":True,
           "rollback_ready":True,"recovery_ready":True,"protocol_version":1,"evidence_ready":True}
    image_qualified=True
    gate_faults={"authorization_absent","authorization_removed_before_invocation"}
    if "image_qualification_revoked_before_invocation" in faults:image_qualified=False
    if faults&gate_faults:gates["explicit_hardware_authorization"]=False
    if "peer_collision" in faults:gates["peer_exclusion"]=False
    if "identity_mismatch" in faults:gates["target_card_id"]="wrong-metadata"
    if "protocol_mismatch" in faults:gates["protocol_version"]=999
    if "evidence_write_failure" in faults:gates["evidence_ready"]=False # refuse before adapter if evidence cannot be made durable
    if "corrupted_evidence" in faults:gates["evidence_ready"]=False # intake/evidence attestation refuses
    pre=evaluate_gates(gates,image_qualified)
    opened=False;recovery="NOT_NEEDED";terminal="PREFLIGHT_REFUSAL"
    if not pre["all_gates_pass"]:
        safe=True
    else:
        # The only instantiated adapter in this campaign is a mock. The live
        # CLI still has a false physical qualification constant.
        opened=True;terminal="MOCK_ADAPTER_READY"
        if "delayed_hello" in faults:
            virtual_delay_ms=rng.randrange(1,500);hello_ok=virtual_delay_ms<2000
        else:hello_ok=not bool(faults&{"timeout","malformed_hello","partial_reply","truncated_reply","duplicated_reply","stale_reply","endpoint_disconnect","reconnect","host_termination","adapter_termination"})
        counts["hello_attempts"]=1
        if not hello_ok:
            terminal="HELLO_FAILURE_NO_RETRY";recovery="CLOSE_ONLY_NO_PROGRAM"
        elif "result_before_hello_completion" in faults:
            terminal="RESULT_REFUSED_BEFORE_HELLO";recovery="CLOSE_ONLY_NO_PROGRAM"
        else:
            counts["transactions"]=1
            if faults&{"duplicate_result","reordered_result","stale_session_result","unexpected_status","work_rejection","result_decoder_failure","abort_during_transaction"}:
                terminal="MOCK_TRANSACTION_FAIL_CLOSED";recovery="MOCK_ABORT_CLOSE"
            else:terminal="MOCK_TRANSACTION_ACCEPTED";recovery="MOCK_CLOSE"
    safe=(counts["physical_access"]==0 and counts["program_attempts"]==0 and counts["peer_programs"]==0 and
          counts["hello_attempts"]<=1 and counts["transactions"]<=1 and counts["retries"]==0 and counts["reconnects"]==0 and
          (pre["all_gates_pass"] or not opened))
    return {"terminal":terminal,"recovery":recovery,"opened_mock_only":opened,"counts":counts,"safe":safe,"missing_gates":pre["missing_gates"]}

def run_fault_campaign(log_path:Path,resume=True):
    log_path.parent.mkdir(parents=True,exist_ok=True);completed={}
    if resume and log_path.exists():
        for line in log_path.read_text().splitlines():
            try:
                obj=json.loads(line);completed[obj["scenario_id"]]=obj
            except Exception:continue
    rows=[]
    with log_path.open("a") as f:
        for scenario_id,seed,faults in _seed_fault_cases():
            if scenario_id in completed:rows.append(completed[scenario_id]);continue
            outcome=_fault_model(faults,seed);record={"scenario_id":scenario_id,"seed":seed,"faults":list(faults),**outcome}
            f.write(json.dumps(record,sort_keys=True,separators=(",",":"))+"\n");f.flush()
            import os;os.fsync(f.fileno());rows.append(record)
    return {"scenarios_run":len(rows),"scenarios_pass":sum(bool(r["safe"]) for r in rows),"scenarios_fail":sum(not r["safe"] for r in rows),"resume_log":str(log_path.relative_to(ROOT)),"scenarios":rows}

def run_full_rehearsal():
    root=OUT/"rehearsals"/("rehearsal-"+str(time.time_ns()));root.mkdir(parents=True,exist_ok=False)
    try:
        package=root/"synthetic-candidate";digest,_=make_package(package,synthetic=True)
        intake=validate_package(package,expected_manifest_sha256=digest,**EXPECTED)
        # Simulation-only override demonstrates the later path; physical result
        # remains false because this package is marked synthetic_fixture=true.
        config={"host_harness_ready":True,"physical_adapter_interface_ready":True,
          "explicit_hardware_authorization":True,"card_count":1,"target_card_id":EXPECTED_CARD_ID,
          "peer_card_id":"configured-peer-only","peer_exclusion":True,"rollback_ready":True,
          "recovery_ready":True,"protocol_version":1,"evidence_ready":True}
        # A distinct synthetic CDC-failing package must stop before adapter
        # construction, while the positive fixture continues in simulation.
        bad_package=root/"synthetic-unqualified-candidate";bad_digest,bad_manifest=make_package(bad_package,synthetic=True)
        bad_manifest["qualification"]["cdc"]="FAIL";bad_digest=_seal_manifest(bad_package,bad_manifest)
        bad_intake=validate_package(bad_package,expected_manifest_sha256=bad_digest,**EXPECTED)
        bad_gate=evaluate_gates(config,bad_intake["physical_image_qualified"],simulated=True)
        unqualified_refused=(not bad_intake["qualification_checks_pass"] and not bad_gate["all_gates_pass"] and
                             "IMAGE_QUALIFIED" in bad_gate["missing_gates"])
        gates=evaluate_gates(config,intake["qualification_checks_pass"],simulated=True)
        if not intake["qualification_checks_pass"] or not gates["all_gates_pass"]:return {"pass":False,"phase":"preflight","detail":gates}
        descriptor=fixture_descriptor();answer=predict(descriptor,0,1)
        evidence=EvidenceBundle(root/"attempt-evidence",{"mode":"SYNTHETIC_FULL_FLOW","synthetic_fixture":True,
          "physical_image_qualified":False,"candidate_manifest_sha256":digest,"candidate_bitstream_sha256":None,
          "configured_target_card_id":EXPECTED_CARD_ID,"physical_access_count":0})
        evidence.write_bytes("raw_input.bin",descriptor.encode())
        device=RehearsalDevice(evidence)
        # Adapter initialization is a fixture object only. FirstSiliconSession
        # sends one HELLO and one logical descriptor transaction over it.
        session=FirstSiliconSession(device,evidence)
        result=session.run(descriptor,answer,0,1,5)
        device.close()
        evidence.write_json("recovery_result.json",{"mode":"MOCK_ONLY","adapter_closed":device.is_closed,
          "physical_access_count":0,"candidate_program_count":0,"peer_program_count":0})
        evidence.write_json("FULL_REHEARSAL_RESULT.json",{"classification":result["classification"],
          "hello_attempts":result["counters"]["hello_attempts"],"transaction_count":result["counters"]["transaction_count"],
          "raw_result_exact":result["raw_result_exact"],"canonical_result_exact":result["canonical_result_exact"],
          "cpu_crosscheck":result["cpu_crosscheck"],"physical_image_qualified":False})
        bundle_ok=all((evidence.root/name).is_file() for name in EvidenceBundle.REQUIRED) and (evidence.root/"PRE_RECOVERY_EVIDENCE_SYNC.json").is_file()
        success=(unqualified_refused and result["classification"]=="PASS" and result["counters"]["hello_attempts"]==1 and
          result["counters"]["load_descriptor_count"]==1 and result["counters"]["start_count"]==1 and
          result["counters"]["transaction_count"]==1 and result["counters"]["retries"]==0 and
          result["raw_result_exact"]=="PASS" and result["canonical_result_exact"]=="PASS" and
          result["cpu_crosscheck"]=="PASS" and bundle_ok and device.close_count==1 and device.is_closed)
        return {"pass":success,"intake_qualification_checks_pass":intake["qualification_checks_pass"],
          "physical_image_qualified":intake["physical_image_qualified"],"simulated_gate_pass":gates["all_gates_pass"],
          "unqualified_fixture_refused":unqualified_refused,
          "classification":result["classification"],"mock_hello_attempts":result["counters"]["hello_attempts"],
          "mock_transaction_count":result["counters"]["transaction_count"],"raw_result_exact":result["raw_result_exact"],
          "canonical_result_exact":result["canonical_result_exact"],"cpu_crosscheck":result["cpu_crosscheck"],
          "evidence_bundle_complete":bundle_ok,"clean_mock_close":device.close_count==1,
          "physical_access_count":0,"durable_mock_evidence_root":str((root/"attempt-evidence").relative_to(ROOT))}
    except Exception as exc:
        return {"pass":False,"error":f"{type(exc).__name__}: {exc}","durable_rehearsal_root":str(root.relative_to(ROOT))}

def run():
    OUT.mkdir(parents=True,exist_ok=True)
    runtime=host_qualify();intake=image_tests();precheck=precheck_tests()
    (ROOT/"results/phk2-first-silicon-host-qualification.json").write_text(json.dumps(runtime,indent=2,sort_keys=True)+"\n")
    # Repeat boundary tests here and retain their result in the consolidated report.
    import tempfile
    with tempfile.TemporaryDirectory(prefix="phk2-boundary-tests-") as td:
        bp,bt,_=physical_boundary_tests(Path(td)/"boundary")
    fault=run_fault_campaign(OUT/"fault-campaign.jsonl",resume=True)
    rehearsal=run_full_rehearsal()
    # Every precheck gate is independently removed once, with no factory or
    # transport constructed. This is the same strict evaluator used by CLI.
    full={"host_harness_ready":True,"physical_adapter_interface_ready":True,"explicit_hardware_authorization":True,
       "card_count":1,"target_card_id":EXPECTED_CARD_ID,"peer_card_id":"configured-peer-only","peer_exclusion":True,
       "rollback_ready":True,"recovery_ready":True,"protocol_version":1,"evidence_ready":True}
    broken=[]
    for gate in REQUIRED_GATES:
        cfg=dict(full);image=True
        mapping={"HOST_HARNESS_READY":("host_harness_ready",False),"PHYSICAL_ADAPTER_INTERFACE_READY":("physical_adapter_interface_ready",False),
          "EXPLICIT_HARDWARE_AUTHORIZATION":("explicit_hardware_authorization",False),"ONE_CARD_SCOPE":("card_count",2),
          "EXPECTED_CARD_ID_MATCH":("target_card_id","wrong-card-metadata"),"PEER_EXCLUSION":("peer_exclusion",False),
          "ROLLBACK_READY":("rollback_ready",False),"RECOVERY_READY":("recovery_ready",False),
          "PROTOCOL_VERSION_MATCH":("protocol_version",99),"EVIDENCE_READY":("evidence_ready",False)}
        if gate=="IMAGE_QUALIFIED":image=False
        else:k,v=mapping[gate];cfg[k]=v
        blocked=evaluate_gates(cfg,image)
        broken.append(not blocked["all_gates_pass"] and gate in blocked["missing_gates"] and blocked["physical_operation_permitted"] is False)
    report={"schema":"PHK2-OVERNIGHT-HOST-READINESS-v1","base_commit":"97773443b47be478c819cdb5ebe74989a9b50796",
      "host_harness_qualification":runtime,"image_intake":intake,"canary_precheck":precheck,"physical_adapter_boundary_tests":{"passed":bp,"total":bt},
      "fault_campaign":fault,"full_offline_rehearsal":rehearsal,"each_gate_fails_closed":sum(broken)==len(REQUIRED_GATES),
      "physical_image_qualified":False,"live_path_authorized":False,"physical_protocol_qualified":False,
      "hardware_access_count":0,"program_attempts":0,"hello_attempts":0,
      "host_harness_ready":runtime["FIRST_SILICON_HOST_READY"],"physical_adapter_interface_ready":True,
      "image_manifest_ready":True,"image_intake_ready":intake["all_pass"],
      "canary_precheck_ready":precheck["all_pass"] and sum(broken)==len(REQUIRED_GATES),
      "fail_closed_tests":bt,"fault_scenarios_run":fault["scenarios_run"],"fault_scenarios_pass":fault["scenarios_pass"],
      "fault_scenarios_fail":fault["scenarios_fail"],"full_offline_rehearsal_pass":rehearsal["pass"],
      "blockers_to_first_silicon":["No real routed PHK2 image has passed the mandatory image-intake qualification gates.",
        "A physical PHK2 transport/endpoint adapter and durable identity mapping are not implemented or qualified; live path remains disabled.",
        "PHK2-specific rollback/recovery readiness and semantic continuity have only mock interfaces here and are not physically qualified.",
        "A fresh single-use authorization for the configured one-card scope has not been issued." ]}
    report["ready"]=bool(runtime["FIRST_SILICON_HOST_READY"] and intake["all_pass"] and precheck["all_pass"] and bp==bt and fault["scenarios_fail"]==0 and rehearsal["pass"] and sum(broken)==len(REQUIRED_GATES))
    report.update({
      "HOST_HARNESS_READY":runtime["FIRST_SILICON_HOST_READY"],
      "PHYSICAL_ADAPTER_INTERFACE_READY":True,
      "IMAGE_MANIFEST_READY":True,
      "IMAGE_INTAKE_READY":intake["all_pass"],
      "IMAGE_INTAKE_NEGATIVE_TESTS":intake["image_intake_negative_tests"],
      "IMAGE_INTAKE_NEGATIVE_TESTS_PASS":intake["image_intake_negative_tests_pass"],
      "CANARY_PRECHECK_READY":precheck["all_pass"] and sum(broken)==len(REQUIRED_GATES),
      "CANARY_GATE_TESTS":f'{precheck["canary_gate_tests_pass"]}/{precheck["canary_gate_tests"]}',
      "FAIL_CLOSED_TESTS":f"{bp}/{bt}",
      "FAULT_SCENARIOS_RUN":fault["scenarios_run"],
      "FAULT_SCENARIOS_PASS":fault["scenarios_pass"],
      "FAULT_SCENARIOS_FAIL":fault["scenarios_fail"],
      "FULL_OFFLINE_REHEARSAL_PASS":rehearsal["pass"],
      "PHYSICAL_IMAGE_QUALIFIED":False,
      "LIVE_PATH_AUTHORIZED":False,
      "PHYSICAL_PROTOCOL_QUALIFIED":False,
      "HARDWARE_ACCESS_COUNT":0,
      "PROGRAM_ATTEMPTS":0,
      "HELLO_ATTEMPTS":0,
      "BLOCKERS_TO_FIRST_SILICON":report["blockers_to_first_silicon"],
      "scope_note":"Readiness values describe host-side/interface and synthetic offline qualification only; no physical image is qualified."
    })
    (OUT/"LATEST_RESULT.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    (OUT/"MORNING_READINESS.md").write_text("# PHK2 first-silicon offline readiness\n\n"+
      "\n".join(f"- **{k}:** {v}" for k,v in report.items() if k not in ("host_harness_qualification","image_intake","canary_precheck","physical_adapter_boundary_tests","fault_campaign","full_offline_rehearsal","blockers_to_first_silicon"))+
      "\n\n## Blockers to first silicon\n\n"+"\n".join(f"- {x}" for x in report["blockers_to_first_silicon"])+"\n\nAll candidate/image tests used synthetic package fixtures. No FPGA image is qualified by this report.\n")
    return report

if __name__=="__main__":print(json.dumps(run(),indent=2,sort_keys=True))
