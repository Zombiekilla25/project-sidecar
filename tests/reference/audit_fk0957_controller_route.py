#!/usr/bin/env python3
"""Independently inspect FK0957 controller routing from an immutable checkout.

Does not trust campaign booleans. Derives the public --live gate and the actual
argv producer consumed by the internal one-shot runner from controller AST.
Also reproduces the old fault-6 fixture mismatch and compares the checker's
call-presence heuristic to simple argv data flow.
"""
from __future__ import annotations

import argparse
import ast
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

EXPECTED = {
    "9ce7bb2435c2a942f7baf6c1668e09a081597c82",
    "3e31c44ccd1454b59f49f4d01279e2cdfd53ab81",
}


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("candidate module unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Call):
        return node.func.id if isinstance(node.func, ast.Name) else None
    return None


def route_facts(source: str) -> dict:
    tree = ast.parse(source)
    functions = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    live = functions.get("_live")
    main = functions.get("main")
    assigned_argv = None
    runner_consumes_argv = False
    call_names = []
    if live is not None:
        for node in ast.walk(live):
            if isinstance(node, ast.Call):
                name = call_name(node)
                if name:
                    call_names.append(name)
                if (name == "run_operation_once" and node.args and
                        isinstance(node.args[0], ast.Name) and node.args[0].id == "argv"):
                    runner_consumes_argv = True
            if isinstance(node, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id == "argv" for t in node.targets):
                assigned_argv = call_name(node.value)
    live_gate_returns_before_precheck = False
    if main is not None:
        for node in ast.walk(main):
            if not isinstance(node, ast.If) or ast.dump(node.test) != ast.dump(
                    ast.Attribute(value=ast.Name(id="args", ctx=ast.Load()), attr="live", ctx=ast.Load())):
                continue
            gate_calls = {call_name(n) for n in ast.walk(node)}
            live_gate_returns_before_precheck = (
                any(isinstance(n, ast.Return) for n in ast.walk(node)) and
                "_precheck" not in gate_calls and "_live" not in gate_calls)
            break
    if assigned_argv == "build_candidate_rgb_cli_argv" and runner_consumes_argv:
        internal_route = "CANDIDATE_RGB_CLI"
    elif assigned_argv == "build_operation_argv" and runner_consumes_argv:
        internal_route = "LEGACY_ORCHESTRATOR"
    else:
        internal_route = "UNRESOLVED_OR_ALTERNATE"
    return {
        "internal_argv_producer": assigned_argv,
        "runner_consumes_assigned_argv": runner_consumes_argv,
        "internal_route": internal_route,
        "candidate_builder_calls_present": "build_candidate_rgb_cli_argv" in call_names,
        "public_live_gate_returns_before_precheck": live_gate_returns_before_precheck,
    }


def checker_presence_heuristic(source: str) -> bool:
    tree = ast.parse(source)
    live = next((n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_live"), None)
    return live is not None and any(
        isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and
        n.func.id == "build_candidate_rgb_cli_argv" for n in ast.walk(live))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate_root", type=Path)
    args = parser.parse_args()
    root = args.candidate_root.resolve(strict=True)
    head = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], check=True,
                          text=True, stdout=subprocess.PIPE).stdout.strip()
    if head not in EXPECTED:
        raise SystemExit("candidate HEAD is not one of the exact audited revisions")
    sys.dont_write_bytecode = True
    tools = root / "tools/phk2_host"
    sys.path.insert(0, str(tools))
    source = (tools / "fk0957_maintenance_controller.py").read_text(encoding="utf-8")
    facts = route_facts(source)
    # The checked-in scenario fixture mutates the legacy entrypoint at case 6,
    # but its direct audit_candidate call omits the live-route fact and inherits
    # the API's True default. Compare that result with source-derived routing.
    campaign = load("audit_campaign_route", tools / "run_fk0957_integration_scenario_campaign.py")
    checker = sys.modules.get("fk0957_release_candidate_compatibility") or load(
        "fk0957_release_candidate_compatibility", tools / "fk0957_release_candidate_compatibility.py")
    seed = b"independent-route-case-6"
    candidate_head, manifest, profile, controller, permit, handoff, fault = campaign.candidate_fixture(6, seed)
    unchecked = checker.audit_candidate(reviewed_head=candidate_head, release_manifest=manifest,
        profile=profile, controller=controller, permit_fields=permit, handoff_fields=handoff,
        authenticated_manifest_verified=True)
    observed_uses_rgb = facts["internal_route"] == "CANDIDATE_RGB_CLI"
    checked = checker.audit_candidate(reviewed_head=candidate_head, release_manifest=manifest,
        profile=profile, controller=controller, permit_fields=permit, handoff_fields=handoff,
        authenticated_manifest_verified=True, controller_live_uses_candidate_cli=observed_uses_rgb)
    # Mutate only a disposable source string: add a dead call to the candidate
    # helper while retaining legacy argv production/consumption. A presence-only
    # checker accepts the mutation; data-flow-derived route does not.
    mutated = source.replace("    argv = build_operation_argv(signing_key, expected_hostname, output, operation_pid_path)\n",
        "    build_candidate_rgb_cli_argv(None, None, None, expected_cli_sha256='0' * 64)\n"
        "    argv = build_operation_argv(signing_key, expected_hostname, output, operation_pid_path)\n", 1)
    mutation_facts = route_facts(mutated)
    result = {
        "candidate_head": head,
        "controller_source_route": facts,
        "legacy_fixture_fault": fault,
        "fixture_controller_entrypoint": controller.get("operation_entrypoint"),
        "fixture_default_check_compatible": unchecked["compatible"],
        "fixture_source_derived_check_compatible": checked["compatible"],
        "dead_candidate_helper_mutation": mutation_facts,
        "presence_only_checker_false_positive": (
            checker_presence_heuristic(mutated) and mutation_facts["internal_route"] == "LEGACY_ORCHESTRATOR"),
        "fixture_false_accept_reproduced": fault == 6 and unchecked["compatible"] and not checked["compatible"],
        "hardware_access": False,
        "network_access": False,
    }
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if (result["fixture_false_accept_reproduced"] and
                  facts["public_live_gate_returns_before_precheck"] and
                  result["presence_only_checker_false_positive"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
