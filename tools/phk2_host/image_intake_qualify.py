"""Synthetic-only image-intake positive/negative package tests."""
from __future__ import annotations
import contextlib,copy,hashlib,io,json,shutil,tempfile
from datetime import datetime,timezone
from pathlib import Path
from image_intake import sha256_bytes,sha256_file,tree_digest,validate_package,main as intake_main

SOURCE_COMMIT="a"*40; QUALIFICATION_COMMIT="b"*40; HARNESS_SHA="c"*64
BOARD_COMPAT="PHK2-FK33-PROFILE3-BOARD-v1"; FPGA_PART="xcvu33p-fsvh2104-2-e"; PROTOCOL_VERSION=1
EXPECTED={"expected_source_commit":SOURCE_COMMIT,"expected_qualification_commit":QUALIFICATION_COMMIT,
 "expected_qualification_harness_sha256":HARNESS_SHA,"expected_board_compatibility_id":BOARD_COMPAT,
 "expected_fpga_part":FPGA_PART,"expected_protocol_version":PROTOCOL_VERSION,"max_age_seconds":86400}
REPORTS=("synthesis","implementation","route","drc","cdc","clock-interaction","hold-timing","gray-pointer-cdc","reset-cdc","independent-qualification")

def _sha(path):return sha256_file(path)
def _seal_manifest(root,manifest):
 raw=(json.dumps(manifest,sort_keys=True,separators=(",",":"))+"\n").encode()
 (root/"manifest.json").write_bytes(raw);digest=sha256_bytes(raw);(root/"manifest.sha256").write_text(digest+"\n");return digest
def _artifact(root,path):
 p=root/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(("SYNTHETIC FIXTURE ONLY "+path+"\n").encode())
 return {"path":path,"sha256":_sha(p)}

def make_package(root,*,synthetic=True):
 root.mkdir(parents=True)
 src=root/"source_snapshot";src.mkdir();(src/"phk2_top.sv").write_text("// synthetic RTL-source fixture\nmodule phk2_top; endmodule\n")
 tree_hash=tree_digest(src)
 constraints=[_artifact(root,"constraints/top.xdc")]
 synthesis=_artifact(root,"artifacts/synthesis.dcp.fixture")
 routed=_artifact(root,"artifacts/routed.dcp.fixture")
 bitstream=_artifact(root,"artifacts/candidate.bit.fixture")
 evdir=root/"evidence";evdir.mkdir()
 entries={}
 for name in REPORTS:
  rel=f"reports/{name}.json";p=evdir/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps({"fixture":True,"report":name},sort_keys=True)+"\n");entries[rel]=_sha(p)
 ev_raw=(json.dumps({"files":entries},sort_keys=True,separators=(",",":"))+"\n").encode()
 (evdir/"evidence-manifest.json").write_bytes(ev_raw)
 manifest={"schema":"PHK2-PHYSICAL-IMAGE-MANIFEST-v1","synthetic_fixture":synthetic,
  "source":{"commit_sha":SOURCE_COMMIT,"tree_path":"source_snapshot","tree_sha256":tree_hash},
  "design":{"rtl_top":"phk2_top","fpga_part":FPGA_PART,"vivado_version":"2026.1-fixture","target_clock_mhz":175},
  "artifacts":{"constraints":constraints,"synthesis_checkpoint":synthesis,"routed_checkpoint":routed,"bitstream":bitstream,"debug_probe_ltx":None},
  "protocol":{"protocol_version":PROTOCOL_VERSION,"descriptor_version":1},
  "compatibility":{"board_adapter_compatibility_id":BOARD_COMPAT},
  "qualification":{"synthesis":"PASS","implementation":"PASS","route":"PASS","drc":"PASS","cdc":"PASS","clock_interaction":"PASS","hold_timing":"PASS"},
  "metrics":{"wns_ns":0.01,"tns_ns":0.0,"unsafe_cdc_count":0,"unconstrained_endpoint_count":0},
  "cdc":{"gray_pointer_qualification":"PASS","reset_qualification":"PASS"},
  "independent_qualification":{"result":"PASS","commit_sha":QUALIFICATION_COMMIT,"harness_sha256":HARNESS_SHA},
  "created_utc":datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),
  "evidence":{"directory":"evidence","manifest_path":"evidence/evidence-manifest.json","manifest_sha256":sha256_bytes(ev_raw)}}
 return _seal_manifest(root,manifest),manifest

def run_tests()->dict:
 passed=0;rows=[]
 with tempfile.TemporaryDirectory(prefix="phk2-image-intake-") as temp:
  base=Path(temp)/"qualified-synthetic-fixture";base_sha,base_manifest=make_package(base,synthetic=True)
  good=validate_package(base,expected_manifest_sha256=base_sha,**EXPECTED)
  passed+=int(good["qualification_checks_pass"] and not good["physical_image_qualified"] and good["synthetic_fixture"] is True)
  rows.append({"case":"all_gates_pass_synthetic_never_physical","pass":bool(good["qualification_checks_pass"] and not good["physical_image_qualified"])})
  capture=io.StringIO()
  args=[str(base),"--expected-manifest-sha256",base_sha,"--expected-source-commit",EXPECTED["expected_source_commit"],
   "--expected-qualification-commit",EXPECTED["expected_qualification_commit"],"--expected-qualification-harness-sha256",EXPECTED["expected_qualification_harness_sha256"],
   "--expected-board-compatibility-id",EXPECTED["expected_board_compatibility_id"],"--expected-fpga-part",EXPECTED["expected_fpga_part"],
   "--expected-protocol-version",str(EXPECTED["expected_protocol_version"])]
  with contextlib.redirect_stdout(capture):cli_rc=intake_main(args)
  cli_result=json.loads(capture.getvalue());synthetic_cli_pass=(cli_rc==1 and cli_result["qualification_checks_pass"] and cli_result["physical_image_qualified"] is False)
  cases=[]
  def case(name, mutate, expected_fragment, reseal=True):
   nonlocal passed
   dst=Path(temp)/name;shutil.copytree(base,dst);m=json.loads((dst/"manifest.json").read_text());mutate(dst,m)
   current=base_sha
   if reseal:current=_seal_manifest(dst,m)
   res=validate_package(dst,expected_manifest_sha256=current,**EXPECTED)
   ok=(not res["physical_image_qualified"] and any(expected_fragment in reason for reason in res["reasons"]))
   cases.append({"case":name,"pass":ok,"reasons":res["reasons"][:3]});passed+=int(ok)
  case("missing_source_commit",lambda p,m:m["source"].pop("commit_sha"),"source.commit_sha")
  case("wrong_source_commit",lambda p,m:m["source"].update(commit_sha="d"*40),"source commit differs")
  case("tree_hash_mismatch",lambda p,m:(p/"source_snapshot/phk2_top.sv").write_text("// changed\n"),"source tree hash mismatch",False)
  case("bitstream_hash_mismatch",lambda p,m:(p/m["artifacts"]["bitstream"]["path"]).write_bytes(b"changed"),"artifact hash mismatch",False)
  case("checkpoint_hash_mismatch",lambda p,m:(p/m["artifacts"]["synthesis_checkpoint"]["path"]).write_bytes(b"changed"),"artifact hash mismatch",False)
  case("wrong_fpga_part",lambda p,m:m["design"].update(fpga_part="xc-other"),"wrong FPGA part")
  case("wrong_protocol",lambda p,m:m["protocol"].update(protocol_version=99),"wrong protocol version")
  def remove_cdc_report(p,m):
   evp=p/m["evidence"]["manifest_path"];ev=json.loads(evp.read_text());ev["files"].pop("reports/cdc.json");raw=(json.dumps(ev,sort_keys=True,separators=(",",":"))+"\n").encode();evp.write_bytes(raw);m["evidence"]["manifest_sha256"]=sha256_bytes(raw)
  case("missing_cdc_report",remove_cdc_report,"required qualification report missing: reports/cdc.json")
  case("cdc_fail",lambda p,m:m["qualification"].update(cdc="FAIL"),"qualification status is not PASS: CDC")
  case("unknown_status_never_passes",lambda p,m:m["qualification"].update(route="UNKNOWN"),"qualification status is not PASS: route")
  case("unsafe_cdc_nonzero",lambda p,m:m["metrics"].update(unsafe_cdc_count=1),"unsafe CDC count must be zero")
  case("clock_interaction_fail",lambda p,m:m["qualification"].update(clock_interaction="FAIL"),"clock interaction")
  case("timing_fail",lambda p,m:m["metrics"].update(wns_ns=-0.01),"timing WNS is negative")
  case("drc_fail",lambda p,m:m["qualification"].update(drc="FAIL"),"DRC")
  case("unconstrained_endpoints",lambda p,m:m["metrics"].update(unconstrained_endpoint_count=1),"unconstrained endpoint count")
  def remove_independent_report(p,m):
   evp=p/m["evidence"]["manifest_path"];ev=json.loads(evp.read_text());ev["files"].pop("reports/independent-qualification.json");raw=(json.dumps(ev,sort_keys=True,separators=(",",":"))+"\n").encode();evp.write_bytes(raw);m["evidence"]["manifest_sha256"]=sha256_bytes(raw)
  case("missing_independent_qualification",remove_independent_report,"required qualification report missing: reports/independent-qualification.json")
  case("qualification_commit_mismatch",lambda p,m:m["independent_qualification"].update(commit_sha="e"*40),"qualification commit differs")
  case("evidence_altered_after_manifest",lambda p,m:(p/"evidence/reports/cdc.json").write_text("tampered\n"),"evidence file missing/altered",False)
  case("incomplete_manifest",lambda p,m:m.pop("metrics"),"manifest field missing: metrics")
  case("stale_manifest",lambda p,m:m.update(created_utc="2020-01-01T00:00:00Z"),"manifest is stale")
  case("wrong_board_compatibility",lambda p,m:m["compatibility"].update(board_adapter_compatibility_id="wrong-board"),"wrong board/adapter compatibility ID")
  # A changed manifest with a refreshed package sidecar still fails the external trust digest.
  dst=Path(temp)/"altered_manifest_external_anchor";shutil.copytree(base,dst);m=json.loads((dst/"manifest.json").read_text());m["design"]["rtl_top"]="tampered_top";new_digest=_seal_manifest(dst,m)
  res=validate_package(dst,expected_manifest_sha256=base_sha,**EXPECTED)
  ok=not res["physical_image_qualified"] and any("external expected manifest SHA" in x for x in res["reasons"])
  cases.append({"case":"manifest_changed_after_creation","pass":ok,"reasons":res["reasons"][:3]});passed+=int(ok)
  rows.extend(cases)
  total=len(rows)
  return {"image_intake_negative_tests":total-1,"image_intake_negative_tests_pass":sum(1 for x in rows[1:] if x["pass"]),"positive_synthetic_gate_checks_pass":rows[0]["pass"],"synthetic_cli_never_qualifies":synthetic_cli_pass,"physical_image_qualified":False,"cases":rows,"all_pass":passed==total and synthetic_cli_pass}

if __name__=="__main__":print(json.dumps(run_tests(),indent=2))
