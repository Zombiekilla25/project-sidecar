#!/usr/bin/env python3
"""Reproduce the b821/4463 integration campaign's legacy-route false accept.

Usage: python3 tests/reference/repro_fk0957_candidate_4463_campaign_false_accept.py CANDIDATE_ROOT
This auditor-owned fixture is read-only with respect to CANDIDATE_ROOT.
Exit 0 means the defect reproduced; exit 1 means behavior changed or the
candidate fixture is unavailable.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

EXPECTED_CANDIDATE = "4463a4b6c826cc3211f75aef83ed4089e85488b7"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("candidate module unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: repro_fk0957_candidate_4463_campaign_false_accept.py CANDIDATE_ROOT")
        return 2
    root = Path(sys.argv[1]).resolve(strict=True)
    tools = root / "tools/phk2_host"
    sys.path.insert(0, str(tools))
    campaign = load("audit_campaign_4463", tools / "run_fk0957_integration_scenario_campaign.py")
    compat = sys.modules.get("fk0957_release_candidate_compatibility")
    if compat is None:
        compat = load("fk0957_release_candidate_compatibility", tools / "fk0957_release_candidate_compatibility.py")
    head, manifest, profile, controller, permit, handoff, fault = campaign.candidate_fixture(
        6, b"campaign-case-6-minimal")
    result = compat.audit_candidate(reviewed_head=head, release_manifest=manifest,
        profile=profile, controller=controller, permit_fields=permit,
        handoff_fields=handoff, authenticated_manifest_verified=True)
    reproduced = (fault == 6 and
        controller["operation_entrypoint"] == "phk2_fk0957_remote_orchestrator.py" and
        result["checks"]["controller_live_path_uses_candidate_rgb_cli"] is True and
        result["compatible"] is True)
    print({"candidate_expected_at_review": EXPECTED_CANDIDATE,
           "fault": fault,
           "controller_entrypoint": controller["operation_entrypoint"],
           "live_route_check_default": result["checks"]["controller_live_path_uses_candidate_rgb_cli"],
           "compatible": result["compatible"],
           "false_accept_reproduced": reproduced})
    return 0 if reproduced else 1


if __name__ == "__main__":
    raise SystemExit(main())
