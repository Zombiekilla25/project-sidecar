#!/usr/bin/env python3
"""Offline fake-transport attacks against FK0957 internal transport gates."""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock


def run(candidate: Path) -> dict:
    original_cwd = Path.cwd()
    candidate = candidate.resolve()
    sys.path.insert(0, str(candidate / "tools/phk2_host"))
    sys.path.insert(0, str(candidate / "tests"))
    import test_phk2_fk0957_remote_topology_endpoint as endpoint_fixtures
    import test_phk2_fk0957_topology_transport as transport_fixtures
    import phk2_fk0957_remote_topology_endpoint as endpoint
    import phk2_fk0957_topology_discovery as topology
    import phk2_fk0957_topology_transport as transport

    os_chdir = __import__("os").chdir
    os_chdir(candidate)
    transport_case = transport_fixtures.TopologyTransportTests()
    endpoint_cases = []
    try:
        transport_case.setUp()
        outputs = {}
        for attack in ("unsigned_descriptor", "caller_source_hash"):
            request_case = endpoint_fixtures.RemoteTopologyEndpointTests()
            request_case.setUp()
            endpoint_cases.append(request_case)
            now = datetime.now(timezone.utc)
            token = object()
            identity = topology.DescriptorIdentity(
                "FK0957", "153300000957A", "153300000957", "1-9.3",
                "0403", "6010", "Xilinx", "SQRL FK", "A")
            permit = topology.DiscoveryPermit(
                request_case.descriptor_sha, identity, "4" * 64,
                now.isoformat(), (now + timedelta(seconds=120)).isoformat(),
                transport.identity_gate.TRUSTED_SIGNER_FINGERPRINT_SHA256, token)
            with topology._PERMIT_LOCK:
                topology._ACTIVE[token] = (
                    permit.descriptor_evidence_sha256, permit.identity, permit.nonce,
                    permit.issued_at, permit.expires_at, permit.trusted_signer_fingerprint)
            backend = transport_case.backend()
            temp = tempfile.TemporaryDirectory(prefix="fk0957-auth-attack-")
            ledger = Path(temp.name) / "ledger"
            ledger.mkdir(mode=0o700)
            with mock.patch.object(endpoint, "_load_trust_config",
                                   return_value=request_case.issuers), \
                 mock.patch.object(endpoint, "CONSUMED_AUTHORIZATION_DIR", ledger), \
                 mock.patch.object(transport, "_NativeLibFtdi", return_value=backend):
                if attack == "unsigned_descriptor":
                    with transport._REMOTE_AUTH_LOCK:
                        transport._REMOTE_AUTHORIZED_PERMITS[token] = request_case.request_bytes()
                    result = transport.run_fk0957_topology_discovery(permit)
                    outputs[attack] = {
                        "request_signatures_valid": True,
                        "descriptor_evidence_signature_valid": False,
                        "runtime_manifest_validated": True,
                        "fake_backend_open_count": backend.open_count,
                        "fake_backend_close_count": backend.close_count,
                        "observation_returned": result.descriptor_evidence_sha256 == request_case.descriptor_sha,
                        "permit_consumed": token in topology._CONSUMED,
                        "hardware_backend_used": False,
                    }
                else:
                    outcome = "RETURNED"
                    try:
                        transport._run_consumed_permit(
                            permit, source_sha256_before="0" * 64,
                            request_raw=request_case.request_bytes())
                    except transport.Refusal:
                        outcome = "REFUSED_AFTER_POST_IO_SOURCE_HASH_MISMATCH"
                    outputs[attack] = {
                        "request_signatures_valid": True,
                        "descriptor_evidence_signature_valid": False,
                        "runtime_manifest_validated": True,
                        "caller_source_sha256": "0" * 64,
                        "fake_backend_open_count": backend.open_count,
                        "fake_backend_close_count": backend.close_count,
                        "result": outcome,
                        "authorization_consumed": (ledger / (request_case.auth_id + ".consumed")).exists(),
                        "hardware_backend_used": False,
                    }
            temp.cleanup()
        outputs["candidate_head"] = __import__("subprocess").check_output(
            ["git", "-C", str(candidate), "rev-parse", "HEAD"], text=True).strip()
        return outputs
    finally:
        for item in endpoint_cases:
            item.doCleanups()
        transport_case.doCleanups()
        os_chdir(original_cwd)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate", type=Path)
    args = parser.parse_args()
    print(json.dumps(run(args.candidate), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
