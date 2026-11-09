"""Exercise the future import gate using an explicitly synthetic mock bundle."""
from __future__ import annotations
import hashlib, json, subprocess, sys, tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
TOOL=ROOT/"tools/qualify_phk2_core_binding.py"
ADAPTER=ROOT/"rtl/phk2_board/phk2_core_contract_adapter.sv"
COMMIT="1"*40

def main() -> int:
    with tempfile.TemporaryDirectory(prefix="phk2-tool-fixture-") as td:
        root=Path(td); (root/"rtl").mkdir(); (root/"tests").mkdir()
        (root/"rtl/phk2_core_contract_adapter.sv").write_bytes(ADAPTER.read_bytes())
        (root/"rtl/mock_timing_core.sv").write_text("module mock_timing_core(input wire clk); endmodule\n")
        (root/"tests/tb_timing_core_binding.sv").write_text(
            "module tb_timing_core_binding; mock_timing_core c(); initial begin $display(\"TIMING_CORE_BINDING_TESTS=PASS\"); $finish; end endmodule\n")
        sources=[]
        for rel in ("rtl/phk2_core_contract_adapter.sv","rtl/mock_timing_core.sv"):
            sources.append({"path":rel,"sha256":hashlib.sha256((root/rel).read_bytes()).hexdigest()})
        manifest={"contract":"PHK2-BOARD-CORE-CONTRACT-v1","commit":COMMIT,
          "sources":sources,"core_module":"mock_timing_core",
          "binding_testbench":"tests/tb_timing_core_binding.sv",
          "timing_qualification":{"status":"PASS","commit":COMMIT,
            "target_part":"xcvu33p-fsvh2104-2-e","wns_ns":0.1}}
        (root/"source_manifest.json").write_text(json.dumps(manifest))
        cp=subprocess.run([sys.executable,str(TOOL),str(root),"--expected-commit",COMMIT],text=True,capture_output=True)
        if cp.returncode or '"status": "PASS"' not in cp.stdout:
            raise SystemExit(f"mock positive gate failed: {cp.stdout}{cp.stderr}")
        cp=subprocess.run([sys.executable,str(TOOL),str(root),"--expected-commit","2"*40],text=True,capture_output=True)
        if cp.returncode==0 or "commit mismatch" not in cp.stdout:
            raise SystemExit("wrong candidate commit was not rejected")
        manifest["sources"][0]["sha256"]="0"*64
        (root/"source_manifest.json").write_text(json.dumps(manifest))
        cp=subprocess.run([sys.executable,str(TOOL),str(root),"--expected-commit",COMMIT],text=True,capture_output=True)
        if cp.returncode==0 or "source SHA mismatch" not in cp.stdout:
            raise SystemExit("source hash mismatch was not rejected")
        manifest["sources"][0]["sha256"]=hashlib.sha256((root/"rtl/phk2_core_contract_adapter.sv").read_bytes()).hexdigest()
        stub=b"module phk2_core_stub; endmodule\n"
        (root/"rtl/phk2_core_stub.sv").write_bytes(stub)
        sources.append({"path":"rtl/phk2_core_stub.sv","sha256":hashlib.sha256(stub).hexdigest()})
        manifest["sources"]=sources; (root/"source_manifest.json").write_text(json.dumps(manifest))
        cp=subprocess.run([sys.executable,str(TOOL),str(root),"--expected-commit",COMMIT],text=True,capture_output=True)
        if cp.returncode==0 or "test-only stub is forbidden" not in cp.stdout:
            raise SystemExit("stub-containing candidate was not rejected")
    print("CORE_BINDING_IMPORT_GATE_TESTS=4/4")
    return 0

if __name__=="__main__": raise SystemExit(main())
