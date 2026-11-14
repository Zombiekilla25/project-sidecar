from __future__ import annotations

from pathlib import Path
import io
import hashlib
import json
import tempfile
import unittest
from unittest import mock

import phk2_fk0957_topology_rgb_cli as cli


def stage_operation(progress, signed, supervisor_state="EXITED_SUCCESS", code=0):
    context = {"operation_id": "a" * 32, "authorization_id": "b" * 64}
    progress.bind(context)
    progress.authorization_consumed(context)
    progress.supervisor_terminal(context["operation_id"], context["authorization_id"],
                                 supervisor_state, code)
    if supervisor_state == "EXITED_SUCCESS":
        progress.remote_result_validated()
        progress.locally_signed(context["operation_id"], context["authorization_id"],
                                hashlib.sha256(cli.canonical_json.canonical(signed)).hexdigest())


class RGBCLIEndToEndTests(unittest.TestCase):
    def test_remote_unsigned_path_validates_signs_then_atomically_publishes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = root / "request.json"
            output = root / "evidence.json"
            request.write_bytes(b"canonical request")
            signed = {"payload": {"schema": "signed"}}
            unsigned = {"status": "ACQUIRED", "operation_id": "a" * 32,
                        "authorization_id": "b" * 64, "scan_a_raw_tdo_hex": "00",
                        "scan_b_raw_tdo_hex": "00"}
            events = []
            def acquire(raw, *, progress):
                events.append(("acquire", raw))
                stage_operation(progress, signed)
                return signed
            def verify(value):
                events.append(("verify", value))
                return unsigned
            def summary(payload, destination, digest):
                events.append(("summary", payload, destination, digest))
                return {"status": "SIGNED", "operation_id": payload["operation_id"],
                        "evidence_sha256": digest}
            def publish(destination, data, state):
                events.append(("publish", destination, data))
                state.begin("a" * 32, hashlib.sha256(data).hexdigest())
                state.prepare_commit("a" * 32, hashlib.sha256(data).hexdigest())
                destination.write_bytes(data)
                state.commit()
            with mock.patch.object(cli, "_verify_signed_remote_result", side_effect=lambda _signed: unsigned), \
                 mock.patch.object(cli.rgb, "acquire_validate_sign_once", side_effect=acquire), \
                 mock.patch.object(cli, "_verify_signed_remote_result", side_effect=verify), \
                 mock.patch.object(cli.evidence_cli, "_success_summary", side_effect=summary), \
                 mock.patch.object(cli.evidence_cli, "_publish_evidence_atomic", side_effect=publish):
                report, status, published = cli.run_once(request, output)
            self.assertEqual(status, 0)
            self.assertTrue(published)
            self.assertTrue(output.exists())
            self.assertEqual([event[0] for event in events], ["acquire", "verify", "summary", "publish"])
            self.assertEqual(events[0][1], b"canonical request")
            self.assertEqual(json.loads(report), {"status": "SIGNED", "operation_id": "a" * 32,
                                                  "evidence_sha256": hashlib.sha256(
                                                      cli.canonical_json.canonical(signed)).hexdigest(),
                                                  "supervisor_state": "EXITED_SUCCESS",
                                                  "publication_state": "PUBLISHED"})

    def test_remote_refusal_never_signs_or_publishes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request, output = root / "request.json", root / "evidence.json"
            request.write_bytes(b"canonical request")
            with mock.patch.object(cli.rgb, "acquire_validate_sign_once", side_effect=ValueError("raw secret text")) as acquire, \
                 mock.patch.object(cli.evidence_cli, "_publish_evidence_atomic") as publish:
                report, status, published = cli.run_once(request, output)
            self.assertEqual(status, 2)
            self.assertFalse(published)
            self.assertFalse(output.exists())
            self.assertEqual(json.loads(report)["code"], "REMOTE_RGB_FLOW_FAILED")
            self.assertNotIn(b"raw secret text", report)
            acquire.assert_called_once()
            publish.assert_not_called()

    def test_cli_has_no_host_or_scan_override_arguments(self):
        output = io.BytesIO()
        with mock.patch.object(cli, "run_once", return_value=(b"done\n", 0, True)) as run, \
             mock.patch.object(cli.sys, "stdout", type("Stdout", (), {"buffer": output})()):
            self.assertEqual(cli.main(["--authorization-request", "/request",
                                      "--output", "/evidence"]), 0)
        self.assertEqual(output.getvalue(), b"done\n")
        run.assert_called_once()

    def test_unsigned_publication_stage_substitution_is_rejected(self):
        progress = cli.rgb.AcquisitionProgress()
        context = {"operation_id": "a" * 32, "authorization_id": "b" * 64}
        progress.bind(context)
        progress.authorization_consumed(context)
        progress.supervisor_terminal("a" * 32, "b" * 64, "EXITED_SUCCESS", 0)
        progress.remote_result_validated()
        digest = "c" * 64
        progress.locally_signed("a" * 32, "b" * 64, digest)
        progress.publication_started("a" * 32, digest)
        report = json.loads(cli._status_report(progress, "REFUSED", "REMOTE_RGB_FLOW_FAILED"))
        self.assertTrue(cli._status_matches_operation(report, progress))
        for replacement in ("NOT_STARTED", "SIGNED_STAGED", "PUBLISHED", "caller-stage"):
            forged = dict(report, publication_state=replacement)
            self.assertFalse(cli._status_matches_operation(forged, progress))
        for replacement in ("SIGNED", "POST_SUCCESS_REPORTING_FAULT"):
            self.assertFalse(cli._status_matches_operation(dict(report, status=replacement), progress))
        self.assertFalse(cli._status_matches_operation(dict(report, code="INJECTED"), progress))
        with self.assertRaises(AttributeError):
            progress.publication_state = "NOT_STARTED"
        with self.assertRaises(Exception):
            progress.publication_started("d" * 32, digest)

    def test_supervisor_operation_id_substitution_is_rejected_before_publish(self):
        progress = cli.rgb.AcquisitionProgress()
        context = {"operation_id": "a" * 32, "authorization_id": "b" * 64}
        progress.bind(context)
        progress.authorization_consumed(context)
        with self.assertRaises(cli.rgb.Refusal):
            progress.supervisor_terminal("d" * 32, "b" * 64, "EXITED_SUCCESS", 0)
        self.assertEqual(progress.supervisor_state, "UNKNOWN")
        self.assertEqual(progress.local_state, "AUTHORIZATION_CONSUMED")

    def test_malformed_result_preserves_confirmed_supervisor_success_without_publish(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request, output = root / "request", root / "evidence"
            request.write_bytes(b"request")
            malformed_signed = {"not": "a signed result"}
            def acquire(_raw, *, progress):
                stage_operation(progress, malformed_signed)
                return malformed_signed
            with mock.patch.object(cli.rgb, "acquire_validate_sign_once", side_effect=acquire), \
                    mock.patch.object(cli.evidence_cli, "_publish_evidence_atomic") as publish:
                report, code, published = cli.run_once(request, output)
            value = json.loads(report)
            self.assertEqual((code, published), (2, False))
            self.assertEqual(value["status"], "REFUSED")
            self.assertEqual(value["supervisor_state"], "EXITED_SUCCESS")
            self.assertEqual(value["local_state"], "LOCAL_SIGNED")
            self.assertEqual(value["publication_state"], "SIGNED_STAGED")
            self.assertEqual(value["operation_id"], "a" * 32)
            self.assertFalse(output.exists())
            publish.assert_not_called()

    def test_confirmed_remote_refusal_state_survives_rgb_refusal_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request, output = root / "request", root / "evidence"
            request.write_bytes(b"request")
            def acquire(_raw, *, progress):
                context = {"operation_id": "a" * 32, "authorization_id": "b" * 64}
                progress.bind(context)
                progress.authorization_consumed(context)
                progress.supervisor_terminal("a" * 32, "b" * 64, "EXITED_REFUSAL", 2)
                raise cli.rgb.Refusal("secret diagnostic")
            with mock.patch.object(cli.rgb, "acquire_validate_sign_once", side_effect=acquire), \
                    mock.patch.object(cli.rgb.signing, "_sign_validated_remote_record") as sign, \
                    mock.patch.object(cli.evidence_cli, "_publish_evidence_atomic") as publish:
                report, code, published = cli.run_once(request, output)
            value = json.loads(report)
            self.assertEqual((code, published), (2, False))
            self.assertEqual(value["supervisor_state"], "EXITED_REFUSAL")
            self.assertEqual(value["local_state"], "SUPERVISOR_TERMINAL")
            self.assertEqual(value["publication_state"], "NOT_STARTED")
            self.assertNotIn(b"secret diagnostic", report)
            sign.assert_not_called()
            publish.assert_not_called()

    def test_post_publish_reporting_fault_retains_published_operation_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request, output = root / "request", root / "evidence"
            request.write_bytes(b"request")
            signed = {"payload": {"schema": "signed"}}
            unsigned = {"status": "ACQUIRED", "operation_id": "a" * 32,
                        "authorization_id": "b" * 64}
            def acquire(_raw, *, progress):
                stage_operation(progress, signed)
                return signed
            def summary(_payload, _destination, digest):
                return {"status": "SIGNED", "operation_id": "a" * 32,
                        "evidence_sha256": digest}
            def publish(destination, data, state):
                state.begin("a" * 32, hashlib.sha256(data).hexdigest())
                state.prepare_commit("a" * 32, hashlib.sha256(data).hexdigest())
                destination.write_bytes(data)
                state.commit()
                raise OSError("private post-publish error")
            with mock.patch.object(cli.rgb, "acquire_validate_sign_once", side_effect=acquire), \
                    mock.patch.object(cli, "_verify_signed_remote_result", return_value=unsigned), \
                    mock.patch.object(cli.evidence_cli, "_success_summary", side_effect=summary), \
                    mock.patch.object(cli.evidence_cli, "_publish_evidence_atomic", side_effect=publish):
                report, code, published = cli.run_once(request, output)
            value = json.loads(report)
            self.assertEqual((code, published), (3, True))
            self.assertEqual(value["status"], "POST_SUCCESS_REPORTING_FAULT")
            self.assertEqual(value["supervisor_state"], "EXITED_SUCCESS")
            self.assertEqual(value["publication_state"], "PUBLISHED")
            self.assertTrue(output.exists())
            self.assertNotIn(b"private post-publish error", report)

    def test_observer_fault_after_verified_link_cannot_downgrade_published_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request, output = root / "request", root / "evidence"
            request.write_bytes(b"request")
            signed = {"payload": {"schema": "signed"}}
            unsigned = {"status": "ACQUIRED", "operation_id": "a" * 32,
                        "authorization_id": "b" * 64}
            def acquire(_raw, *, progress):
                stage_operation(progress, signed)
                return signed
            def summary(_payload, _destination, digest):
                return {"status": "SIGNED", "operation_id": "a" * 32,
                        "evidence_sha256": digest}
            with mock.patch.object(cli.rgb, "acquire_validate_sign_once", side_effect=acquire), \
                    mock.patch.object(cli, "_verify_signed_remote_result", return_value=unsigned), \
                    mock.patch.object(cli.evidence_cli, "_success_summary", side_effect=summary), \
                    mock.patch.object(cli.rgb.AcquisitionProgress, "evidence_published",
                                      side_effect=RuntimeError("observer fault")):
                report, code, published = cli.run_once(request, output)
            value = json.loads(report)
            self.assertEqual((code, published), (3, True))
            self.assertEqual(value["status"], "POST_SUCCESS_REPORTING_FAULT")
            self.assertEqual(value["publication_state"], "PUBLISHED")
            self.assertEqual(value["supervisor_state"], "EXITED_SUCCESS")
            self.assertTrue(output.exists())


if __name__ == "__main__":
    unittest.main()
