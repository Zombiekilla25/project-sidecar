#!/usr/bin/env python3
"""Offline attack for caller-overridden source prehash in FK0957 transport."""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest import mock


def run(candidate: Path) -> dict:
    original_cwd = Path.cwd()
    os.chdir(candidate)
    host = candidate / "tools/phk2_host"
    sys.path.insert(0, str(host))
    import test_phk2_fk0957_remote_topology_endpoint as endpoint_fixtures
    import test_phk2_fk0957_topology_transport as transport_fixtures
    import phk2_fk0957_remote_topology_endpoint as endpoint
    import phk2_fk0957_topology_transport as transport

    transport_case = transport_fixtures.TopologyTransportTests()
    transport_case.setUp()
    endpoint_case = endpoint_fixtures.RemoteTopologyEndpointTests()
    endpoint_case.setUp()
    try:
        # Build an actual descriptor signed under the temporary test signer,
        # then bind fresh temporary release/handoff signatures to its digest.
        permit = transport_case.permit()
        endpoint_case.descriptor = transport_case.raw
        endpoint_case.descriptor_sha = transport_case.digest
        endpoint_case.handoff["permit_sha256"] = transport_case.digest
        endpoint_case.handoff_sha = __import__("hashlib").sha256(
            endpoint.canonical(endpoint_case.handoff)).hexdigest()
        endpoint_case.authorization["permit_sha256"] = transport_case.digest
        endpoint_case.authorization["handoff_sha256"] = endpoint_case.handoff_sha
        endpoint_case.request.update({
            "descriptor_evidence_b64": base64.b64encode(transport_case.raw).decode("ascii"),
            "descriptor_evidence_sha256": transport_case.digest,
            "handoff": endpoint_case._sign(endpoint_case.handoff, endpoint_case.handoff_key,
                                            "FK0957_MAINTENANCE_AUTHORITY"),
            "release_authorization": endpoint_case._sign(
                endpoint_case.authorization, endpoint_case.release_key,
                "FK0957_RELEASE_AUTHORITY"),
        })
        request_raw = endpoint_case.request_bytes()

        temp = tempfile.TemporaryDirectory(prefix="fk0957-prehash-audit-")
        ledger = Path(temp.name) / "ledger"
        ledger.mkdir(mode=0o700)
        backend = transport_case.backend()
        outcome = "RETURNED"
        with mock.patch.object(endpoint, "_load_trust_config",
                               return_value=endpoint_case.issuers), \
             mock.patch.object(endpoint, "CONSUMED_AUTHORIZATION_DIR", ledger), \
             mock.patch.object(transport, "_NativeLibFtdi", return_value=backend):
            try:
                transport._run_consumed_permit(
                    permit, source_sha256_before="0" * 64, request_raw=request_raw)
            except transport.Refusal:
                outcome = "REFUSED_AFTER_POST_IO_SOURCE_HASH_MISMATCH"
        result = {
            "candidate_head": __import__("subprocess").check_output(
                ["git", "-C", str(candidate), "rev-parse", "HEAD"], text=True).strip(),
            "request_signatures": "temporary Ed25519 release/handoff keys verified by production validator",
            "runtime_manifest": "real source/native manifest validation passed",
            "caller_source_sha256": "0" * 64,
            "fake_backend_open_count": backend.open_count,
            "fake_backend_close_count": backend.close_count,
            "authorization_consumed": (ledger / (endpoint_case.auth_id + ".consumed")).exists(),
            "result": outcome,
            "hardware_backend_used": False,
        }
        temp.cleanup()
        return result
    finally:
        endpoint_case.doCleanups()
        transport_case.doCleanups()
        os.chdir(original_cwd)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate", type=Path)
    args = parser.parse_args()
    print(json.dumps(run(args.candidate.resolve()), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
