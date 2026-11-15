#!/usr/bin/env python3
"""Source-derived FK0957 entrypoint audit; never trusts campaign booleans.

This audit inspects only disposable source checkouts. It parses the controller
and orchestrator AST, follows the argv producer into the one-shot runner, and
checks whether public/import-level guards precede side-effect-capable calls.
No candidate route is invoked with a real runner or external service.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import subprocess


def fn_map(source: str) -> dict[str, ast.FunctionDef]:
    tree = ast.parse(source)
    return {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def name_of_call(node: ast.AST) -> str | None:
    if not isinstance(node, ast.Call):
        return None
    return node.func.id if isinstance(node.func, ast.Name) else None


def calls(fn: ast.FunctionDef) -> list[str]:
    return [name for node in ast.walk(fn) if (name := name_of_call(node))]


def controller_facts(path: Path) -> dict:
    source = path.read_text()
    fns = fn_map(source)
    live = fns.get("_live")
    main = fns.get("main")
    if live is None or main is None:
        return {"present": False}
    assignments = [n for n in ast.walk(live) if isinstance(n, ast.Assign) and
                   any(isinstance(t, ast.Name) and t.id == "argv" for t in n.targets)]
    producer = name_of_call(assignments[0].value) if assignments else None
    runner_uses_argv = any(name_of_call(n) == "run_operation_once" and n.args and
                           isinstance(n.args[0], ast.Name) and n.args[0].id == "argv"
                           for n in ast.walk(live))
    live_calls = calls(live)
    first_live_statement_calls = calls(live.body[0]) if live.body else []
    public_live_refusal = False
    public_live_first_guarded = False
    guardian_calls = []
    for node in ast.walk(main):
        if not isinstance(node, ast.If):
            continue
        test = ast.dump(node.test)
        if "args" in test and "live" in test:
            branch_calls = {name_of_call(n) for n in ast.walk(node)}
            public_live_refusal = ("_live" not in branch_calls and "_precheck" not in branch_calls and
                                   any(isinstance(n, ast.Return) for n in ast.walk(node)))
            public_live_first_guarded = ("require_pre_release_authorization_api" in branch_calls or
                                         "require_authenticated_pre_release_api" in branch_calls)
        if "_guardian" in test:
            guardian_calls.extend(name for name in (name_of_call(n) for n in ast.walk(node)) if name)
    route = "LEGACY_ORCHESTRATOR" if producer == "build_operation_argv" and runner_uses_argv else (
        "CANDIDATE_RGB_CLI" if producer == "build_candidate_rgb_cli_argv" and runner_uses_argv else
        "UNRESOLVED")
    legacy_line = "    argv = build_operation_argv(signing_key, expected_hostname, output, operation_pid_path)\n"
    injected = source.replace(legacy_line,
        "    build_candidate_rgb_cli_argv(None, None, None, expected_cli_sha256='0' * 64)\n" + legacy_line, 1)
    mutated = fn_map(injected).get("_live")
    mutation_calls = calls(mutated) if mutated else []
    mutation_assignments = [n for n in ast.walk(mutated) if isinstance(n, ast.Assign) and
                            any(isinstance(t, ast.Name) and t.id == "argv" for t in n.targets)] if mutated else []
    mutation_producer = name_of_call(mutation_assignments[0].value) if mutation_assignments else None
    mutation_route = "LEGACY_ORCHESTRATOR" if mutation_producer == "build_operation_argv" and any(
        name_of_call(n) == "run_operation_once" and n.args and isinstance(n.args[0], ast.Name) and
        n.args[0].id == "argv" for n in ast.walk(mutated)) else "UNRESOLVED"
    return {
        "present": True,
        "_live_argv_producer": producer,
        "_live_runner_consumes_argv": runner_uses_argv,
        "_live_route": route,
        "dead_candidate_helper_does_not_change_route": (
            "build_candidate_rgb_cli_argv" in mutation_calls and mutation_route == "LEGACY_ORCHESTRATOR"),
        "_live_first_statement_calls": first_live_statement_calls,
        "_live_has_pre_release_guard": bool(live_calls and live_calls[0] in {
            "require_pre_release_authorization_api", "require_authenticated_pre_release_api"}),
        "public_live_refuses_before_precheck": public_live_refusal,
        "public_live_calls_unconditional_guard": public_live_first_guarded,
        "hidden_guardian_branch_calls": guardian_calls,
        "guardian_cli_refuses_without_call": "guardian_main" not in guardian_calls,
    }


def orchestrator_facts(path: Path) -> dict:
    fns = fn_map(path.read_text())
    main, api, helper = (fns.get("main"), fns.get("acquire_and_sign"),
                         fns.get("_acquire_and_sign_for_test"))
    if main is None or api is None:
        return {"present": False}
    main_calls, api_calls = calls(main), calls(api)
    helper_calls = calls(helper) if helper else []
    helper_runner_default_real = False
    if helper:
        pairs = list(zip(helper.args.args[-len(helper.args.defaults):], helper.args.defaults))
        pairs += list(zip(helper.args.kwonlyargs, helper.args.kw_defaults))
        for arg, default in pairs:
            if arg.arg == "runner" and isinstance(default, ast.Attribute) and \
                    isinstance(default.value, ast.Name) and default.value.id == "subprocess" and default.attr == "run":
                helper_runner_default_real = True
    return {
        "legacy_main_calls_acquire_and_sign": "acquire_and_sign" in main_calls,
        "public_api_has_pre_release_guard_first": bool(api_calls and api_calls[0] in {
            "require_authenticated_pre_release_api", "require_pre_release_authorization_api"}),
        "public_api_calls_runner_or_test_helper": any(x in api_calls for x in ("runner", "_acquire_and_sign_for_test")),
        "unguarded_test_helper_present": helper is not None and
            not (helper_calls and helper_calls[0] in {"require_authenticated_pre_release_api",
                                                       "require_pre_release_authorization_api"}),
        "test_helper_default_is_real_subprocess": helper_runner_default_real,
        "test_helper_calls_runner": "runner" in helper_calls,
        "test_helper_reaches_signing": bool(helper and any(isinstance(n, ast.Attribute) and n.attr == "sign"
                                                             for n in ast.walk(helper))),
    }


def guardian_facts(path: Path) -> dict:
    fns = fn_map(path.read_text())
    fn = fns.get("guardian_main")
    if fn is None:
        return {"present": False}
    body_calls = calls(fn)
    # guardian_main's --self-sha256 is caller supplied and compared to the
    # current module, rather than to an immutable trusted runner identity.
    caller_hash_argument = any(isinstance(n, ast.Compare) and any(
        isinstance(c, ast.Name) and c.id == "args" for c in ast.walk(n)) for n in ast.walk(fn))
    return {"present": True, "calls_guardian_worker": "_guardian_main" in body_calls,
            "accepts_caller_supplied_self_hash": caller_hash_argument,
            "direct_import_guard": bool(body_calls and body_calls[0] in {
                "require_pre_release_authorization_api", "require_authenticated_pre_release_api"})}


def audit(root: Path) -> dict:
    root = root.resolve(strict=True)
    tools = root / "tools/phk2_host"
    controller = controller_facts(tools / "fk0957_maintenance_controller.py")
    orchestrator = orchestrator_facts(tools / "phk2_fk0957_remote_orchestrator.py")
    guardian = guardian_facts(tools / "fk0957_maintenance_controller.py")
    return {"root": str(root),
            "head": subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], check=True,
                                   text=True, stdout=subprocess.PIPE).stdout.strip(),
            "controller": controller, "orchestrator": orchestrator, "guardian": guardian,
            "source_derived": True, "external_execution": False}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("candidate_root", type=Path)
    args = p.parse_args()
    result = audit(args.candidate_root)
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
