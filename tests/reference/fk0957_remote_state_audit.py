#!/usr/bin/env python3
"""Offline audit of RGB's remote-process-state classification."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


def run(candidate: Path) -> dict:
    sys.path.insert(0, str(candidate / "tools/phk2_host"))
    import phk2_fk0957_remote_orchestrator as ssh_policy
    import phk2_fk0957_topology_rgb_orchestrator as rgb

    host = {"algorithm": "ssh-ed25519", "fingerprint": "SHA256:" + "A" * 43}
    refusal = rgb.endpoint.canonical({
        "schema": "fk0957-remote-acquisition-v1", "status": "REFUSED",
        "phase": "DEVICE_OPEN", "code": "DEVICE_OPEN_FAILED",
    })
    observations = {}
    for status in (2, 255, 1):
        def runner(*_args, **_kwargs):
            return SimpleNamespace(returncode=status, stdout=refusal, stderr=b"hidden")

        with mock.patch.object(ssh_policy, "_read_pinned_source",
                               return_value=(b"pin", host, (1, 2))), \
             mock.patch.object(ssh_policy, "_validated_local_ssh_auth_sock",
                               return_value=("/agent", (3, 4))), \
             mock.patch.object(ssh_policy, "_probe_local_ssh_agent"), \
             mock.patch.object(ssh_policy, "_revalidate_local_ssh_auth_sock"), \
             mock.patch.object(ssh_policy, "_validate_private_pin"):
            try:
                rgb._pinned_ssh(b"request", runner=runner)
            except rgb.Refusal as exc:
                observations[str(status)] = {
                    "state": exc.remote_state,
                    "message": str(exc),
                    "stderr_leaked": "hidden" in str(exc),
                }
    return {
        "candidate_head": __import__("subprocess").check_output(
            ["git", "-C", str(candidate), "rev-parse", "HEAD"], text=True).strip(),
        "remote_refusal_exit_2": observations.get("2"),
        "ssh_transport_exit_255_with_refusal_bytes": observations.get("255"),
        "other_nonzero_exit_1_with_refusal_bytes": observations.get("1"),
        "expected_for_255": "REMOTE_STATE_UNKNOWN",
        "classification_bug": observations.get("255", {}).get("state") != "REMOTE_STATE_UNKNOWN",
        "hardware_access": False,
        "ssh_access": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run(args.candidate.resolve())
    encoded = json.dumps(result, sort_keys=True, indent=2) + "\n"
    if args.output:
        args.output.write_text(encoded)
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
