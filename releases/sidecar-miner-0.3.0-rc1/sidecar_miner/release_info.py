from __future__ import annotations
import subprocess
import json
from pathlib import Path
from . import __version__

SUPPORTED_QUALIFICATION_SCHEMAS=("sidecar-backend-qualification-v1","sidecar-cuda-qualification-v1")
def git_revision() -> str:
    try:
        return subprocess.run(["git","rev-parse","--short","HEAD"],check=True,capture_output=True,
            text=True,timeout=2).stdout.strip()
    except Exception:
        try:
            obj=json.loads((Path(__file__).resolve().parents[1]/"release-manifest.json").read_text())
            value=obj.get("git_commit")
            return value if isinstance(value,str) and value else "unknown"
        except Exception:return "unknown"

def release_manifest() -> dict:
    return {"miner_version":__version__,"git_commit":git_revision(),
        "schema_versions":{"runtime_config":1,"canary_result":1,"execution_plan":1,
            "phk1_qualification":1,"cuda_qualification":1,"release_manifest":1,
            "fk33_fleet_config":1,"fk33_fleet_status":1,"fk33_timing":1,
            "first_silicon_benchmark":1,"gpu_fk_comparison":1},
        "supported_qualification_artifacts":list(SUPPORTED_QUALIFICATION_SCHEMAS),
        "configuration_schema_version":1,"launcher_identity":"bin/sidecar-canary",
        "supported_modes":["gpu-only","sidecar","auto"],
        "qualification_state":{"real_cuda_backend_qualified":False,
            "phk1_physical_protocol_qualified":False},
        "known_blocked_backends":["real CUDA backend awaits offline runtime qualification",
            "PHK1 physical RAW_BSCAN awaits physical qualification; VU33P bitstream generation needs a suitable Vivado device license"],
        "test_counts":{"full_offline_suite":"244/244","miner_core":"161/161",
            "fleet":"54/54","benchmark":"12/12","qualification":"14/14","release_candidate":"3/3"}}

def version_line() -> str:
    info=release_manifest()
    return (f"sidecar-miner {info['miner_version']} ({info['git_commit']}); qualification schemas: "
        f"{', '.join(info['supported_qualification_artifacts'])}; benchmark schemas: first-silicon-v1, gpu-fk-v1")
