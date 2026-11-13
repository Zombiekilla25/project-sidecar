#!/usr/bin/env python3
"""Offline test for endpoint/transport permit identity continuity.

Uses the production endpoint and transport with only the native adapter
replaced by the candidate's existing fake backend fixture. No USB is opened.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from unittest import mock


def run(candidate: Path) -> dict:
    candidate = candidate.resolve()
    sys.path.insert(0, str(candidate / "tools/phk2_host"))
    import test_phk2_fk0957_topology_transport as transport_fixtures
    import test_phk2_fk0957_remote_topology_endpoint as endpoint_fixtures
    import phk2_fk0957_remote_topology_endpoint as endpoint
    import phk2_fk0957_topology_transport as transport

    original_cwd = Path.cwd()
    __import__("os").chdir(candidate)
    transport_case = transport_fixtures.TopologyTransportTests()
    request_case = endpoint_fixtures.RemoteTopologyEndpointTests()
    try:
        transport_case.setUp()
        request_case.setUp()
        request_case.descriptor = transport_case.raw
        request_case.descriptor_sha = transport_case.digest
        request_case.handoff["permit_sha256"] = transport_case.digest
        request_case.handoff_sha = hashlib.sha256(
            endpoint.canonical(request_case.handoff)).hexdigest()
        request_case.authorization["permit_sha256"] = transport_case.digest
        request_case.authorization["handoff_sha256"] = request_case.handoff_sha
        request_case.request.update({
            "descriptor_evidence_b64": base64.b64encode(
                transport_case.raw).decode("ascii"),
            "descriptor_evidence_sha256": transport_case.digest,
            "handoff": request_case._sign(
                request_case.handoff, request_case.handoff_key,
                "FK0957_MAINTENANCE_AUTHORITY"),
            "release_authorization": request_case._sign(
                request_case.authorization, request_case.release_key,
                "FK0957_RELEASE_AUTHORITY"),
        })
        backend = transport_case.backend()
        ledger_tmp = tempfile.TemporaryDirectory(prefix="fk0957-permit-continuity-")
        ledger = Path(ledger_tmp.name) / "consumed"
        ledger.mkdir(mode=0o700)
        observed: dict[str, object] = {}
        real_validate = transport.validate_transport_observation

        def capture_permits(permit, result):
            observed["endpoint_permit_nonce"] = permit.nonce
            observed["result_permit_nonce"] = result.permit_nonce
            return real_validate(permit, result)

        with mock.patch.object(endpoint, "_load_trust_config",
                               return_value=request_case.issuers), \
             mock.patch.object(endpoint, "CONSUMED_AUTHORIZATION_DIR", ledger), \
             mock.patch.object(transport, "_NativeLibFtdi", return_value=backend), \
             mock.patch.object(transport, "validate_transport_observation",
                               side_effect=capture_permits):
            try:
                endpoint.execute_request(request_case.request_bytes())
                observed["endpoint_status"] = "ACQUIRED"
            except (endpoint.Refusal, transport.Refusal) as exc:
                observed["endpoint_status"] = "REFUSED"
                envelope = getattr(exc, "envelope", None)
                observed["failure_phase"] = getattr(envelope, "phase", "unknown")
                observed["failure_code"] = getattr(envelope, "code", "unknown")

        observed.update({
            "candidate_head": __import__("subprocess").check_output(
                ["git", "-C", str(candidate), "rev-parse", "HEAD"], text=True).strip(),
            "fake_backend_open_count": backend.open_count,
            "fake_backend_close_count": backend.close_count,
            "authorization_consumed":
                (ledger / (request_case.auth_id + ".consumed")).is_file(),
            "hardware_backend_used": False,
        })
        ledger_tmp.cleanup()
        return observed
    finally:
        request_case.doCleanups()
        transport_case.doCleanups()
        __import__("os").chdir(original_cwd)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate", type=Path)
    args = parser.parse_args()
    print(json.dumps(run(args.candidate), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
