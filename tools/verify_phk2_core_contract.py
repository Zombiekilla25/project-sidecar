#!/usr/bin/env python3
"""Check frozen contract widths and prevent the test stub entering physical source lists."""
from __future__ import annotations
import argparse
import json
import re
import hashlib
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "handoff/phk2-core-board-contract-v1.json"
ADAPTER = ROOT / "rtl/phk2_board/phk2_core_contract_adapter.sv"
MANIFEST = ROOT / "handoff/PHK2_BOARD_CORE_SOURCES.json"

EXPECTED = {
    "clk": ("input",1), "rst": ("input",1), "reset_req": ("input",1),
    "descriptor_valid": ("input",1), "descriptor_ready": ("output",1), "descriptor_payload": ("input",896),
    "range_valid": ("input",1), "range_ready": ("output",1), "range_generation": ("input",64),
    "range_job_key": ("input",256), "range_start": ("input",32), "range_count": ("input",16), "range_id": ("input",16),
    "abort_valid": ("input",1), "abort_ready": ("output",1), "abort_generation": ("input",64),
    "abort_job_key": ("input",256), "abort_range_id": ("input",16), "abort_reason": ("input",16),
    "core_rst": ("output",1), "core_descriptor_valid": ("output",1), "core_descriptor_ready": ("input",1),
    "core_descriptor_payload": ("output",896), "core_range_valid": ("output",1), "core_range_ready": ("input",1),
    "core_range_generation": ("output",64), "core_range_job_key": ("output",256), "core_range_start": ("output",32),
    "core_range_count": ("output",16), "core_range_id": ("output",16), "core_abort_valid": ("output",1),
    "core_abort_ready": ("input",1), "core_abort_generation": ("output",64), "core_abort_job_key": ("output",256),
    "core_abort_range_id": ("output",16), "core_abort_reason": ("output",16), "core_busy": ("input",1),
    "core_result_ready": ("input",1), "core_error": ("input",1), "core_stale_job": ("input",1),
    "core_aborted": ("input",1), "core_error_code": ("input",16), "core_result_valid": ("input",1),
    "core_result_ready_i": ("output",1), "core_result_payload": ("input",896), "busy": ("output",1),
    "result_ready": ("output",1), "error": ("output",1), "stale_job": ("output",1), "aborted": ("output",1),
    "error_code": ("output",16), "result_valid": ("output",1), "result_ready_i": ("input",1),
    "result_payload": ("output",896)
}


def check() -> dict:
    contract=json.loads(CONTRACT.read_text()); rtl=ADAPTER.read_text()
    assert contract["schema"] == "PHK2-BOARD-CORE-CONTRACT-v1"
    assert contract["descriptor"]["payload_bits"] == 112*8
    assert contract["descriptor"]["fields_lsb_first"][-1]["offset"] + contract["descriptor"]["fields_lsb_first"][-1]["bits"] == 896
    assert contract["range"]["count_min"] == 1 and contract["range"]["count_max"] == 64
    assert contract["result"]["payload_bits"] == 112*8
    assert contract["status"] == {"busy":1,"result_ready":1,"error":1,"stale_job":1,"aborted":1,"error_code":16}
    ports={}
    for direction,width_hi,width_lo,name in re.findall(r"\b(input|output)\s+wire\s+(?:\[(\d+):(\d+)\]\s+)?(\w+)",rtl):
        width=(int(width_hi)-int(width_lo)+1) if width_hi else 1
        ports[name]=(direction,width)
    if ports != EXPECTED:
        missing=sorted(set(EXPECTED)-set(ports)); extra=sorted(set(ports)-set(EXPECTED))
        wrong={k:(EXPECTED[k],ports.get(k)) for k in EXPECTED.keys()&ports.keys() if EXPECTED[k]!=ports[k]}
        raise ValueError(f"RTL interface mismatch missing={missing} extra={extra} wrong={wrong}")
    manifest=json.loads(MANIFEST.read_text())
    stub=set(manifest["test_only_stub"])
    assert "rtl/phk2_board/phk2_core_stub.sv" in stub
    physical_files=set(manifest["board_transport_rtl"]+manifest["core_contract_adapter_rtl"]+manifest["real_core_rtl_candidate"]["files"])
    if physical_files & stub:
        raise ValueError("test stub appears in physical synthesis source list")
    for rec in manifest.get("source_records", []):
        if "repository" in rec:
            raw=subprocess.check_output(["git","-C",rec["repository"],"show",f"{rec['commit']}:{rec['path']}"])
        else:
            raw=(ROOT/rec["path"]).read_bytes()
        actual=hashlib.sha256(raw).hexdigest()
        if actual != rec["sha256"]:
            raise ValueError(f"source manifest SHA mismatch for {rec['path']}: {actual}")
    return {"INTERFACE_WIDTH_ASSERTIONS":"PASS","STUB_PHYSICAL_BUILD_GUARD":"PASS","BOARD_CORE_SOURCE_MANIFEST":"PASS","port_count":len(ports),"source_record_count":len(manifest.get("source_records",[]))}


def main() -> int:
    ap=argparse.ArgumentParser(); ap.add_argument("--physical-sources",nargs="*"); args=ap.parse_args()
    try:
        result=check()
        if args.physical_sources:
            forbidden={"phk2_core_stub.sv"}
            bad=[p for p in args.physical_sources if Path(p).name in forbidden]
            if bad: raise ValueError(f"test stub forbidden for physical build: {bad}")
        print(json.dumps(result,sort_keys=True)); return 0
    except (AssertionError,ValueError,KeyError,json.JSONDecodeError) as e:
        print(json.dumps({"status":"FAIL","reason":str(e)},sort_keys=True)); return 1


if __name__ == "__main__": raise SystemExit(main())
