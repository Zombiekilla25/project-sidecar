"""Offline one-card gate tests; identity is metadata and no discovery is used."""
from __future__ import annotations
import contextlib,copy,io,json,tempfile
from pathlib import Path
from canary_precheck import EXPECTED_CARD_ID,EXPECTED_PROTOCOL_VERSION,REQUIRED_GATES,evaluate_gates,validate_authorization_record,main as precheck_main

def run_tests():
    base={"host_harness_ready":True,"physical_adapter_interface_ready":True,
          "explicit_hardware_authorization":True,"card_count":1,"target_card_id":EXPECTED_CARD_ID,
          "peer_card_id":"configured-peer-metadata","peer_exclusion":True,"rollback_ready":True,
          "recovery_ready":True,"protocol_version":EXPECTED_PROTOCOL_VERSION,"evidence_ready":True,
          "candidate_image_sha256":"a"*64,"manifest_sha256":"b"*64}
    cases=[];passed=0
    # The all-true model is permitted for rehearsal only; live remains disabled.
    all_ok=evaluate_gates(base,True,simulated=True)
    ok=all_ok["all_gates_pass"] and all_ok["physical_operation_permitted"] is False
    cases.append({"case":"all_gates_present_simulated","pass":ok});passed+=int(ok)
    config_key={"HOST_HARNESS_READY":"host_harness_ready",
     "PHYSICAL_ADAPTER_INTERFACE_READY":"physical_adapter_interface_ready",
     "EXPLICIT_HARDWARE_AUTHORIZATION":"explicit_hardware_authorization",
     "ONE_CARD_SCOPE":"card_count","EXPECTED_CARD_ID_MATCH":"target_card_id",
     "PEER_EXCLUSION":"peer_exclusion","ROLLBACK_READY":"rollback_ready",
     "RECOVERY_READY":"recovery_ready","PROTOCOL_VERSION_MATCH":"protocol_version",
     "EVIDENCE_READY":"evidence_ready"}
    for gate in REQUIRED_GATES:
        cfg=copy.deepcopy(base);image=True
        if gate=="IMAGE_QUALIFIED":image=False
        elif gate=="ONE_CARD_SCOPE":cfg["card_count"]=2
        elif gate=="EXPECTED_CARD_ID_MATCH":cfg["target_card_id"]="wrong-card-metadata"
        elif gate=="PROTOCOL_VERSION_MATCH":cfg["protocol_version"]=999
        else:
            key=config_key[gate]
            if key=="target_card_id":cfg[key]="wrong-card-metadata"
            elif key=="card_count":cfg[key]=2
            else:cfg[key]=False
        report=evaluate_gates(cfg,image)
        ok=(not report["all_gates_pass"] and gate in report["missing_gates"] and report["physical_operation_permitted"] is False)
        cases.append({"case":f"missing_or_wrong_{gate}","pass":ok,"missing_gates":report["missing_gates"]});passed+=int(ok)
    auth={"schema":"PHK2-ONE-CARD-AUTH-v1","one_card_scope":True,"target_card_id":EXPECTED_CARD_ID,
          "single_use":True,"candidate_image_sha256":"a"*64,"manifest_sha256":"b"*64,
          "peer_excluded":True,"rollback_ready":True,"recovery_ready":True,"evidence_ready":True,
          "protocol_version":1,"expires_utc":"2099-01-01T00:00:00Z"}
    auth_cases=[
      ("authorization_valid",auth,True),
      ("authorization_absent",None,False),
      ("authorization_removed",None,False),
      ("authorization_wrong_image",{**auth,"candidate_image_sha256":"f"*64},False),
      ("authorization_wrong_target",{**auth,"target_card_id":"wrong-card"},False),
      ("authorization_expired",{**auth,"expires_utc":"2000-01-01T00:00:00Z"},False),
    ]
    for name,value,want in auth_cases:
        result=validate_authorization_record(value,base,now_epoch=1_900_000_000)
        ok=result is want;cases.append({"case":name,"pass":ok});passed+=int(ok)
    output=io.StringIO()
    with contextlib.redirect_stdout(output):rc=precheck_main([])
    dry=json.loads(output.getvalue());ok=rc==3 and dry["mode"]=="DRY_RUN" and not dry["physical_operation_permitted"] and dry["hardware_access_count"]==dry["program_attempts"]==dry["hello_attempts"]==0
    cases.append({"case":"default_command_is_dry_run","pass":ok});passed+=int(ok)
    output=io.StringIO()
    with contextlib.redirect_stdout(output):rc=precheck_main(["--live"])
    live=json.loads(output.getvalue());ok=rc==3 and live["mode"]=="REFUSED_LIVE" and not live["physical_operation_permitted"] and "LIVE_PATH_DISABLED" in live["missing_gates"] and live["hardware_access_count"]==live["program_attempts"]==live["hello_attempts"]==0
    cases.append({"case":"live_invocation_refused","pass":ok});passed+=int(ok)
    return {"canary_gate_tests":len(cases),"canary_gate_tests_pass":passed,
            "gate_names":list(REQUIRED_GATES),"expected_card_id_configured":EXPECTED_CARD_ID,
            "physical_operation_permitted":False,"all_pass":passed==len(cases),"cases":cases}

if __name__=="__main__":print(json.dumps(run_tests(),indent=2))
