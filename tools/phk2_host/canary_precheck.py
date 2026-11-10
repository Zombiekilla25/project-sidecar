"""Default-dry-run one-card precheck; never enumerates or opens hardware."""
from __future__ import annotations
import argparse,json,time,calendar
from pathlib import Path

EXPECTED_CARD_ID="FK0957"  # configured metadata only; never discovered here
EXPECTED_PROTOCOL_VERSION=1
LIVE_CANARY_ENABLED=False
REQUIRED_GATES=("IMAGE_QUALIFIED","HOST_HARNESS_READY","PHYSICAL_ADAPTER_INTERFACE_READY",
                "EXPLICIT_HARDWARE_AUTHORIZATION","ONE_CARD_SCOPE","EXPECTED_CARD_ID_MATCH",
                "PEER_EXCLUSION","ROLLBACK_READY","RECOVERY_READY","PROTOCOL_VERSION_MATCH","EVIDENCE_READY")

def evaluate_gates(config:dict, image_qualified:bool, *, expected_card_id=EXPECTED_CARD_ID,
                   expected_protocol=EXPECTED_PROTOCOL_VERSION, simulated=False)->dict:
    gates={
      "IMAGE_QUALIFIED": image_qualified is True,
      "HOST_HARNESS_READY": config.get("host_harness_ready") is True,
      "PHYSICAL_ADAPTER_INTERFACE_READY": config.get("physical_adapter_interface_ready") is True,
      "EXPLICIT_HARDWARE_AUTHORIZATION": config.get("explicit_hardware_authorization") is True,
      "ONE_CARD_SCOPE": config.get("card_count")==1 and config.get("target_card_id")==expected_card_id,
      "EXPECTED_CARD_ID_MATCH": config.get("target_card_id")==expected_card_id,
      "PEER_EXCLUSION": config.get("peer_exclusion") is True and config.get("peer_card_id")!=expected_card_id,
      "ROLLBACK_READY": config.get("rollback_ready") is True,
      "RECOVERY_READY": config.get("recovery_ready") is True,
      "PROTOCOL_VERSION_MATCH": config.get("protocol_version")==expected_protocol,
      "EVIDENCE_READY": config.get("evidence_ready") is True,
    }
    missing=[key for key in REQUIRED_GATES if not gates[key]]
    return {"gates":gates,"missing_gates":missing,"all_gates_pass":not missing,
            "mode":"SIMULATED" if simulated else "PHYSICAL_METADATA",
            "target_card_id_configured":config.get("target_card_id"),
            "peer_card_id_configured":config.get("peer_card_id"),
            "physical_operation_permitted":False}

def validate_authorization_record(auth:dict|None, config:dict, *, now_epoch=None)->bool:
    if not isinstance(auth,dict):return False
    try:
        expires=time.strptime(auth.get("expires_utc",""),"%Y-%m-%dT%H:%M:%SZ")
        return (auth.get("schema")=="PHK2-ONE-CARD-AUTH-v1" and
                auth.get("one_card_scope") is True and auth.get("target_card_id")==EXPECTED_CARD_ID and
                auth.get("single_use") is True and
                auth.get("candidate_image_sha256")==config.get("candidate_image_sha256") and
                auth.get("manifest_sha256")==config.get("manifest_sha256") and
                auth.get("peer_excluded") is True and auth.get("rollback_ready") is True and
                auth.get("recovery_ready") is True and auth.get("evidence_ready") is True and auth.get("protocol_version")==EXPECTED_PROTOCOL_VERSION and
                calendar.timegm(expires)>=(now_epoch if now_epoch is not None else time.time()))
    except Exception:return False

def main(argv=None)->int:
    ap=argparse.ArgumentParser(description="Offline by default; configured-card metadata only")
    ap.add_argument("--gates",type=Path)
    ap.add_argument("--image-intake-result",type=Path)
    ap.add_argument("--authorization",type=Path)
    ap.add_argument("--live",action="store_true",help="still refused until physical image/adapter qualification is installed")
    ap.add_argument("--dry-run",action="store_true",help="default; evaluates metadata without endpoint discovery")
    a=ap.parse_args(argv)
    try:config=json.loads(a.gates.read_text()) if a.gates else {}
    except Exception as exc:
        print(json.dumps({"physical_operation_permitted":False,"all_gates_pass":False,"missing_gates":list(REQUIRED_GATES),"reason":f"gate metadata unreadable: {exc}"},indent=2));return 2
    image_qualified=False
    if a.image_intake_result:
        try:
            intake=json.loads(a.image_intake_result.read_text())
            image_qualified=(intake.get("physical_image_qualified") is True and
                             intake.get("manifest_sha256")==config.get("manifest_sha256") and
                             intake.get("bitstream_sha256")==config.get("candidate_image_sha256"))
        except Exception:image_qualified=False
    authorization_valid=False
    if a.authorization:
        try:
            auth=json.loads(a.authorization.read_text())
            authorization_valid=validate_authorization_record(auth,config)
        except Exception:authorization_valid=False
    config=dict(config);config["explicit_hardware_authorization"]=authorization_valid
    report=evaluate_gates(config,image_qualified)
    report.update({"mode":"REFUSED_LIVE" if a.live else "DRY_RUN","hardware_access_count":0,
                   "program_attempts":0,"hello_attempts":0})
    if a.live:
        report["physical_operation_permitted"]=False
        report["refusal"]="LIVE_CANARY_DISABLED: no physically qualified PHK2 image or physical adapter is installed"
        report["missing_gates"]=list(dict.fromkeys(report["missing_gates"]+["LIVE_PATH_DISABLED"]))
        report["all_gates_pass"]=False
    print(json.dumps(report,indent=2,sort_keys=True))
    return 3 if a.live or report["missing_gates"] else 0

if __name__=="__main__":raise SystemExit(main())
