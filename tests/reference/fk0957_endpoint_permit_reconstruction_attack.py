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
    import phk2_fk0957_topology_discovery as topology
    import phk2_fk0957_topology_transport as transport

    original_cwd = Path.cwd()
    __import__("os").chdir(candidate)
    outcomes = {}
    for scenario, capability in (("without_supervisor", False),
                                 ("supervisor_authorized", True)):
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
            with mock.patch.object(endpoint, "_load_trust_config",
                                   return_value=request_case.issuers), \
                 mock.patch.object(endpoint, "CONSUMED_AUTHORIZATION_DIR", ledger):
                context, auth_bytes, auth_id = endpoint._validate_request(
                    request_case.request_bytes(), request_case.issuers)
                if capability:
                    # Model the supervisor's durable consume before child launch.
                    endpoint._consume_authorization(auth_id, auth_bytes)

            def capture_permits(permit, result):
                observed["endpoint_permit_nonce"] = permit.nonce
                observed["result_permit_nonce"] = result.permit_nonce
                with topology._PERMIT_LOCK:
                    observed["endpoint_permit_active"] = permit._token in topology._ACTIVE
                    observed["endpoint_permit_consumed"] = permit._token in topology._CONSUMED
                    matching = [
                        (token, row) for token, row in topology._ACTIVE.items()
                        if row[0] == result.descriptor_evidence_sha256 and
                        row[2] == result.permit_nonce
                    ]
                    observed["matching_nonce_active_permits"] = len(matching)
                    observed["matching_nonce_consumed_permits"] = sum(
                        token in topology._CONSUMED for token, _row in matching)
                return real_validate(permit, result)

            with mock.patch.object(endpoint, "_load_trust_config",
                                   return_value=request_case.issuers), \
                 mock.patch.object(endpoint, "CONSUMED_AUTHORIZATION_DIR", ledger), \
                 mock.patch.object(endpoint, "supervisor_capability_valid",
                                   return_value=capability), \
                 mock.patch.object(transport, "_NativeLibFtdi", return_value=backend), \
                 mock.patch.object(transport, "validate_transport_observation",
                                   side_effect=capture_permits):
                try:
                    acquired_raw = endpoint.execute_request(request_case.request_bytes())
                    observed["endpoint_status"] = "ACQUIRED"
                    acquired = json.loads(acquired_raw)
                    observed["result_authorization_id"] = acquired.get("authorization_id")
                    observed["result_operation_id"] = acquired.get("operation_id")
                    observed["result_descriptor_sha256"] = acquired.get(
                        "descriptor_evidence_sha256")
                    observed["result_permit_nonce"] = acquired.get("permit_nonce")
                    observed["end_to_end_identity_equal"] = (
                        acquired.get("authorization_id") == request_case.auth_id and
                        acquired.get("operation_id") == request_case.operation and
                        acquired.get("descriptor_evidence_sha256") == transport_case.digest and
                        acquired.get("permit_nonce") == request_case.nonce)
                except (endpoint.Refusal, transport.Refusal) as exc:
                    observed["endpoint_status"] = "REFUSED"
                    envelope = getattr(exc, "envelope", None)
                    observed["failure_phase"] = getattr(envelope, "phase", "unknown")
                    observed["failure_code"] = getattr(envelope, "code", "unknown")

            observed.update({
                "fake_backend_open_count": backend.open_count,
                "fake_backend_close_count": backend.close_count,
                "authorization_consumed": capability or
                    (ledger / (request_case.auth_id + ".consumed")).is_file(),
                "hardware_backend_used": False,
            })
            outcomes[scenario] = observed
            ledger_tmp.cleanup()
        finally:
            request_case.doCleanups()
            transport_case.doCleanups()
    outcomes["candidate_head"] = __import__("subprocess").check_output(
        ["git", "-C", str(candidate), "rev-parse", "HEAD"], text=True).strip()
    __import__("os").chdir(original_cwd)
    return outcomes


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate", type=Path)
    args = parser.parse_args()
    print(json.dumps(run(args.candidate), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
