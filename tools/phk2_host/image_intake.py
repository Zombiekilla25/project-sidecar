"""Strict offline validation of PHK2 image qualification packages.

This tool only hashes local files and validates claims against caller-supplied
trust anchors. It never opens a device or treats synthetic fixtures as physical
qualification.
"""
from __future__ import annotations
import argparse, hashlib, json, re
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

SCHEMA="PHK2-PHYSICAL-IMAGE-MANIFEST-v1"
SHA256_RE=re.compile(r"^[0-9a-f]{64}$")
SHA1_RE=re.compile(r"^[0-9a-f]{40}$")
STATUS_FIELDS={"synthesis":"qualification.synthesis","implementation":"qualification.implementation","route":"qualification.route","DRC":"qualification.drc","CDC":"qualification.cdc","clock interaction":"qualification.clock_interaction","hold timing":"qualification.hold_timing","Gray-pointer CDC":"cdc.gray_pointer_qualification","reset CDC":"cdc.reset_qualification","independent qualification":"independent_qualification.result"}
REQUIRED_TOP=("schema","synthetic_fixture","source","design","artifacts","protocol","compatibility","qualification","metrics","cdc","independent_qualification","created_utc","evidence")
REQUIRED_NESTED={
    "source":("commit_sha","tree_path","tree_sha256"),
    "design":("rtl_top","fpga_part","vivado_version","target_clock_mhz"),
    "artifacts":("constraints","synthesis_checkpoint","routed_checkpoint","bitstream","debug_probe_ltx"),
    "protocol":("protocol_version","descriptor_version"),
    "compatibility":("board_adapter_compatibility_id",),
    "qualification":("synthesis","implementation","route","drc","cdc","clock_interaction","hold_timing"),
    "metrics":("wns_ns","tns_ns","unsafe_cdc_count","unconstrained_endpoint_count"),
    "cdc":("gray_pointer_qualification","reset_qualification"),
    "independent_qualification":("result","commit_sha","harness_sha256"),
    "evidence":("directory","manifest_path","manifest_sha256"),
}
REQUIRED_EVIDENCE_FILES=("reports/synthesis.json","reports/implementation.json","reports/route.json","reports/drc.json","reports/cdc.json","reports/clock-interaction.json","reports/hold-timing.json","reports/gray-pointer-cdc.json","reports/reset-cdc.json","reports/independent-qualification.json")

def sha256_bytes(data:bytes)->str:return hashlib.sha256(data).hexdigest()
def sha256_file(path:Path)->str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda:f.read(1024*1024),b""):h.update(block)
    return h.hexdigest()

def _safe_path(root:Path,relative:str)->Path:
    p=PurePosixPath(relative)
    if p.is_absolute() or not p.parts or any(x in ("..","") for x in p.parts):raise ValueError(f"unsafe relative path: {relative!r}")
    root=root.resolve();candidate=root
    for part in p.parts:
        candidate=candidate/part
        if candidate.is_symlink():raise ValueError(f"symlink not allowed in package path: {relative!r}")
    out=candidate.resolve()
    if root.resolve() not in out.parents:raise ValueError(f"path escapes package: {relative!r}")
    return out

def tree_digest(root:Path)->str:
    """Stable SHA-256 over relative POSIX paths and each regular file digest."""
    root=root.resolve()
    if not root.is_dir():raise ValueError("source tree is not a directory")
    rows=[]
    for p in sorted(root.rglob("*")):
        if p.is_symlink():raise ValueError(f"source tree contains symlink: {p.relative_to(root)}")
        if p.is_file():rows.append((p.relative_to(root).as_posix(),sha256_file(p)))
    if not rows:raise ValueError("source tree is empty")
    payload="".join(f"{name}\0{digest}\n" for name,digest in rows).encode()
    return sha256_bytes(payload)

def _get(obj:dict,dotted:str):
    cur=obj
    for key in dotted.split("."):
        if not isinstance(cur,dict) or key not in cur:raise KeyError(dotted)
        cur=cur[key]
    return cur

def validate_package(package:Path, *, expected_manifest_sha256:str|None,
                     expected_source_commit:str, expected_qualification_commit:str,
                     expected_qualification_harness_sha256:str,
                     expected_board_compatibility_id:str, expected_fpga_part:str,
                     expected_protocol_version:int, max_age_seconds:int=30*86400,
                     now:datetime|None=None)->dict:
    """Return an auditable true/false result; missing evidence always fails."""
    reasons=[]; checks=[]; package=package.resolve(); manifest_path=package/"manifest.json"
    def check(name, condition, reason):
        checks.append({"check":name,"pass":bool(condition)})
        if not condition:reasons.append(reason)
    if not manifest_path.is_file():
        return {"physical_image_qualified":False,"qualification_checks_pass":False,"reasons":["manifest.json missing"],"checks":[{"check":"manifest_present","pass":False}]}
    raw=manifest_path.read_bytes(); digest=sha256_bytes(raw)
    sidecar=package/"manifest.sha256"
    sidecar_digest=sidecar.read_text().strip().split()[0] if sidecar.is_file() and sidecar.read_text().strip() else None
    check("manifest_sha256_sidecar",sidecar_digest==digest,"manifest digest sidecar missing or mismatched")
    check("external_manifest_trust_anchor",bool(expected_manifest_sha256) and digest==expected_manifest_sha256,"external expected manifest SHA missing or mismatched")
    try:m=json.loads(raw)
    except Exception as exc:return {"physical_image_qualified":False,"qualification_checks_pass":False,"reasons":reasons+[f"manifest JSON invalid: {exc}"],"checks":checks}
    for field in REQUIRED_TOP:check(f"manifest_field:{field}",field in m,f"manifest field missing: {field}")
    if any(not c["pass"] for c in checks):return {"physical_image_qualified":False,"qualification_checks_pass":False,"manifest_sha256":digest,"reasons":reasons,"checks":checks}
    nested_ok=True
    for parent,fields in REQUIRED_NESTED.items():
        value=m.get(parent)
        for field in fields:
            ok=isinstance(value,dict) and field in value
            checks.append({"check":f"manifest_field:{parent}.{field}","pass":ok})
            if not ok:reasons.append(f"manifest field missing: {parent}.{field}");nested_ok=False
    if not nested_ok:return {"physical_image_qualified":False,"qualification_checks_pass":False,"manifest_sha256":digest,"reasons":reasons,"checks":checks}
    container_types={"source":dict,"design":dict,"artifacts":dict,"protocol":dict,"compatibility":dict,
                     "qualification":dict,"metrics":dict,"cdc":dict,"independent_qualification":dict,"evidence":dict}
    containers_ok=True
    for key,expected_type in container_types.items():
        ok=isinstance(m.get(key),expected_type);checks.append({"check":f"manifest_type:{key}","pass":ok})
        if not ok:reasons.append(f"manifest section has wrong type: {key}");containers_ok=False
    if isinstance(m.get("artifacts"),dict) and not isinstance(m["artifacts"].get("constraints"),list):
        checks.append({"check":"manifest_type:artifacts.constraints","pass":False});reasons.append("constraints must be a list");containers_ok=False
    if not containers_ok:return {"physical_image_qualified":False,"qualification_checks_pass":False,"manifest_sha256":digest,"reasons":reasons,"checks":checks}
    check("schema",m.get("schema")==SCHEMA,"unsupported manifest schema")
    check("synthetic_fixture_field",isinstance(m.get("synthetic_fixture"),bool),"synthetic_fixture must be explicit boolean")
    src=m["source"]; design=m["design"]; arts=m["artifacts"]; protocol=m["protocol"]; metrics=m["metrics"]
    check("source_commit_shape",bool(SHA1_RE.fullmatch(str(src.get("commit_sha","")))),"source commit missing or malformed")
    check("source_commit_match",src.get("commit_sha")==expected_source_commit,"source commit differs from trusted expected commit")
    try:actual_tree=tree_digest(_safe_path(package,src.get("tree_path","")))
    except Exception as exc:actual_tree=None;reasons.append(f"source tree cannot be verified: {exc}")
    check("source_tree_hash",actual_tree==src.get("tree_sha256") and bool(SHA256_RE.fullmatch(str(src.get("tree_sha256","")))),"source tree hash mismatch")
    check("rtl_top_present",bool(design.get("rtl_top")),"RTL top missing")
    check("fpga_part",design.get("fpga_part")==expected_fpga_part,"wrong FPGA part")
    check("vivado_version",bool(design.get("vivado_version")),"Vivado version missing")
    check("target_clock",type(design.get("target_clock_mhz")) in (int,float) and design.get("target_clock_mhz",0)>0,"target clock missing/invalid")
    check("protocol_version",type(protocol.get("protocol_version")) is int and protocol.get("protocol_version")==expected_protocol_version,"wrong protocol version")
    check("descriptor_version",type(protocol.get("descriptor_version")) is int and protocol.get("descriptor_version",0)>0,"descriptor version missing/invalid")
    check("board_adapter_compatibility",m["compatibility"].get("board_adapter_compatibility_id")==expected_board_compatibility_id,"wrong board/adapter compatibility ID")
    artifact_records=[*arts.get("constraints",[]),arts.get("synthesis_checkpoint"),arts.get("routed_checkpoint"),arts.get("bitstream")]
    if arts.get("debug_probe_ltx") is not None:artifact_records.append(arts.get("debug_probe_ltx"))
    check("constraint_hashes",bool(arts.get("constraints")) and all(isinstance(x,dict) and x.get("path") and x.get("sha256") for x in arts.get("constraints",[])),"constraint/XDC hash list missing/incomplete")
    for i,record in enumerate(artifact_records):
        valid=False
        try:
            if isinstance(record,dict) and SHA256_RE.fullmatch(str(record.get("sha256",""))):
                p=_safe_path(package,record["path"]);valid=p.is_file() and sha256_file(p)==record["sha256"]
        except Exception as exc:reasons.append(f"artifact {i} invalid: {exc}")
        check(f"artifact_hash:{i}",valid,f"artifact hash mismatch/missing: index {i}")
    # Qualification statuses are exact enumerated PASS values; UNKNOWN/NOT_RUN never pass.
    for label,path in STATUS_FIELDS.items():
        try:value=_get(m,path)
        except KeyError:value=None
        check(f"status:{label}",value=="PASS",f"qualification status is not PASS: {label}={value!r}")
    check("wns_nonnegative",type(metrics.get("wns_ns")) in (int,float) and metrics.get("wns_ns",-1)>=0,"timing WNS is negative or missing")
    check("tns_zero",type(metrics.get("tns_ns")) in (int,float) and metrics.get("tns_ns",1)==0,"timing TNS must be exactly zero")
    check("unsafe_cdc_zero",type(metrics.get("unsafe_cdc_count")) is int and metrics.get("unsafe_cdc_count")==0,"unsafe CDC count must be zero")
    check("unconstrained_endpoints_zero",type(metrics.get("unconstrained_endpoint_count")) is int and metrics.get("unconstrained_endpoint_count")==0,"unconstrained endpoint count must be zero")
    iq=m["independent_qualification"]
    check("qualification_commit_shape",bool(SHA1_RE.fullmatch(str(iq.get("commit_sha","")))),"qualification commit missing/malformed")
    check("qualification_commit_match",iq.get("commit_sha")==expected_qualification_commit,"qualification commit differs from trusted commit")
    check("qualification_harness_hash",iq.get("harness_sha256")==expected_qualification_harness_sha256 and bool(SHA256_RE.fullmatch(str(iq.get("harness_sha256","")))),"qualification harness hash missing/mismatched")
    evidence=m["evidence"]
    try:
        ev_manifest_path=_safe_path(package,evidence["manifest_path"]);ev_raw=ev_manifest_path.read_bytes();ev_digest=sha256_bytes(ev_raw)
        check("evidence_manifest_hash",ev_digest==evidence.get("manifest_sha256"),"evidence manifest hash mismatch")
        ev_obj=json.loads(ev_raw);ev_dir=_safe_path(package,evidence["directory"]);entries=ev_obj.get("files")
        check("evidence_manifest_nonempty",isinstance(entries,dict) and bool(entries),"evidence hash manifest missing/empty")
        if isinstance(entries,dict):
            for required in REQUIRED_EVIDENCE_FILES:
                check(f"evidence_required:{required}",required in entries,f"required qualification report missing: {required}")
            for rel,expected_hash in sorted(entries.items()):
                try:p=_safe_path(ev_dir,rel);ok=p.is_file() and sha256_file(p)==expected_hash
                except Exception:ok=False
                check(f"evidence_file:{rel}",ok,f"evidence file missing/altered: {rel}")
    except Exception as exc:check("evidence_manifest",False,f"evidence manifest unreadable: {exc}")
    try:
        stamp=datetime.fromisoformat(str(m["created_utc"]).replace("Z","+00:00"))
        if stamp.tzinfo is None:raise ValueError("timestamp must include timezone")
        current=now or datetime.now(timezone.utc);age=(current-stamp.astimezone(timezone.utc)).total_seconds()
        check("manifest_not_future",age>=0,"manifest timestamp is in the future")
        check("manifest_fresh",0<=age<=max_age_seconds,"manifest is stale")
    except Exception as exc:check("manifest_timestamp",False,f"manifest timestamp invalid: {exc}")
    checks_pass=all(c["pass"] for c in checks)
    physical_qualified=checks_pass and m.get("synthetic_fixture") is False
    if checks_pass and m.get("synthetic_fixture") is True:reasons.append("synthetic fixture can exercise the gate but cannot qualify a physical image")
    return {"physical_image_qualified":physical_qualified,"qualification_checks_pass":checks_pass,"synthetic_fixture":m.get("synthetic_fixture"),"manifest_sha256":digest,"bitstream_sha256":m.get("artifacts",{}).get("bitstream",{}).get("sha256"),"reasons":reasons,"checks":checks}

def main(argv=None)->int:
    ap=argparse.ArgumentParser(description="Offline fail-closed PHK2 physical image package intake")
    ap.add_argument("package",type=Path)
    ap.add_argument("--expected-manifest-sha256")
    ap.add_argument("--expected-source-commit",required=True)
    ap.add_argument("--expected-qualification-commit",required=True)
    ap.add_argument("--expected-qualification-harness-sha256",required=True)
    ap.add_argument("--expected-board-compatibility-id",required=True)
    ap.add_argument("--expected-fpga-part",required=True)
    ap.add_argument("--expected-protocol-version",type=int,required=True)
    ap.add_argument("--max-age-seconds",type=int,default=30*86400)
    a=ap.parse_args(argv)
    try:result=validate_package(a.package,expected_manifest_sha256=a.expected_manifest_sha256,expected_source_commit=a.expected_source_commit,expected_qualification_commit=a.expected_qualification_commit,expected_qualification_harness_sha256=a.expected_qualification_harness_sha256,expected_board_compatibility_id=a.expected_board_compatibility_id,expected_fpga_part=a.expected_fpga_part,expected_protocol_version=a.expected_protocol_version,max_age_seconds=a.max_age_seconds)
    except Exception as exc:result={"physical_image_qualified":False,"qualification_checks_pass":False,"reasons":[f"intake error: {type(exc).__name__}: {exc}"],"checks":[]}
    print(json.dumps(result,indent=2,sort_keys=True));return 0 if result["physical_image_qualified"] else 1

if __name__=="__main__":raise SystemExit(main())
