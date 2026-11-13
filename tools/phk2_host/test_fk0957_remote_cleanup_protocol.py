import hashlib
import unittest
from datetime import datetime, timezone, timedelta

import fk0957_remote_cleanup_protocol as protocol


class RemoteCleanupContractTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 11, 13, 12, tzinfo=timezone.utc)
        self.expected = dict(
            operation_id="a" * 32, query_nonce="b" * 64,
            release_authorization_id="permit-7f19", release_authorization_sha256="c" * 64,
            release_manifest_sha256="d" * 64, expected_receipt_id="e" * 32,
            source_commit="1" * 40,
            release_authorization_expires_utc="2026-11-13T12:05:00Z",
            expected_host="testbench.example", expected_user="rmann", expected_uid=1000,
            expected_executable="/usr/bin/python3", expected_executable_sha256="f" * 64,
            expected_argv_sha256="2" * 64,
            expected_cwd="/run/user/1000/fk0957-op", now=self.now)

    def process(self):
        return {"pid": 4123, "start_identity": "99123", "uid": 1000,
                "executable": "/usr/bin/python3", "executable_sha256": "f" * 64,
                "argv_sha256": "2" * 64,
                "cwd": "/run/user/1000/fk0957-op",
                "operation_id_argument": self.expected["operation_id"]}

    def receipt(self, state="PREPARED", **changes):
        row = {"schema": protocol.RECEIPT_SCHEMA,
               "operation_id": self.expected["operation_id"],
               "release_authorization_id": self.expected["release_authorization_id"],
               "release_authorization_sha256": self.expected["release_authorization_sha256"],
               "target_selector": "FK0957", "usb_descriptor_serial": "153300000957",
               "adapter_serial": "153300000957A",
               "expected_executable": self.expected["expected_executable"],
               "expected_executable_sha256": self.expected["expected_executable_sha256"],
               "release_manifest_sha256": self.expected["release_manifest_sha256"],
               "source_commit": self.expected["source_commit"],
               "release_authorization_expires_utc": self.expected["release_authorization_expires_utc"],
               "remote_host": self.expected["expected_host"], "remote_user": self.expected["expected_user"],
               "receipt_id": self.expected["expected_receipt_id"],
               "created_utc": self.now.isoformat().replace("+00:00", "Z"),
               "updated_utc": self.now.isoformat().replace("+00:00", "Z"),
               "one_shot": True, "state": state,
               "process": None if state == "PREPARED" else self.process(),
               "exit_code": None}
        row.update(changes)
        return row

    def status(self, name, receipt=None, **changes):
        receipt = self.receipt() if receipt is None else receipt
        row = {"schema": protocol.STATUS_SCHEMA,
               "operation_id": self.expected["operation_id"],
               "query_nonce": self.expected["query_nonce"],
               "observed_utc": self.now.isoformat().replace("+00:00", "Z"),
               "release_authorization_id": self.expected["release_authorization_id"],
               "release_authorization_sha256": self.expected["release_authorization_sha256"],
               "target_selector": "FK0957",
               "release_manifest_sha256": self.expected["release_manifest_sha256"],
               "remote_host": self.expected["expected_host"],
               "remote_user": self.expected["expected_user"],
               "launch_closed": True,
               "status": name,
               "receipt_sha256": hashlib.sha256(protocol.canonical(receipt)).hexdigest(),
               "receipt": receipt,
               "process_identity": receipt["process"] if name in {
                   protocol.RUNNING_EXPECTED_PROCESS, protocol.EXITED_SUCCESS,
                   protocol.EXITED_REFUSAL, protocol.EXITED_FAILURE} else None}
        row.update(changes)
        return protocol.canonical(row)

    def classify(self, raw):
        return protocol.validate_status(raw, **self.expected)

    def test_restore_decision_matrix_exactly_matches_contract(self):
        terminal = (protocol.NOT_STARTED, protocol.EXITED_SUCCESS,
                    protocol.EXITED_REFUSAL, protocol.EXITED_FAILURE)
        for state in terminal:
            self.assertTrue(protocol.restore_allowed(state), state)
        for state in (protocol.RUNNING_EXPECTED_PROCESS, protocol.IDENTITY_MISMATCH,
                      protocol.STATUS_INSPECTION_FAILED, protocol.TRANSPORT_FAILED,
                      protocol.UNKNOWN, "arbitrary", [], {}, None, True):
            self.assertFalse(protocol.restore_allowed(state), state)

    def test_transport_and_status_failures_never_imply_remote_exit(self):
        response = self.status(protocol.NOT_STARTED)
        for rc in (255, 1, -1, True, None):
            state = protocol.classify_status_query(
                transport_return_code=rc, response_bytes=response,
                validator_kwargs=self.expected)
            self.assertEqual(state, protocol.TRANSPORT_FAILED)
            self.assertFalse(protocol.restore_allowed(state))
        for bad_response in (None, b"", b"not-json"):
            state = protocol.classify_status_query(
                transport_return_code=0, response_bytes=bad_response,
                validator_kwargs=self.expected)
            self.assertEqual(state, protocol.STATUS_INSPECTION_FAILED)
            self.assertFalse(protocol.restore_allowed(state))
        state = protocol.classify_status_query(
            transport_return_code=0, response_bytes=response,
            validator_kwargs={**self.expected, "query_nonce": "wrong"})
        self.assertEqual(state, protocol.STATUS_INSPECTION_FAILED)
        self.assertFalse(protocol.restore_allowed(state))
        canonical_unknown = self.status(protocol.UNKNOWN)
        state = protocol.classify_status_query(
            transport_return_code=0, response_bytes=canonical_unknown,
            validator_kwargs=self.expected)
        self.assertEqual(state, protocol.UNKNOWN)
        self.assertFalse(protocol.restore_allowed(state))

    def test_receipt_state_transitions_are_monotonic_and_terminal(self):
        allowed = (("PREPARED", "PREPARED"), ("PREPARED", "CLAIMED"),
                   ("CLAIMED", "CLAIMED"), ("CLAIMED", "RUNNING"),
                   ("RUNNING", "RUNNING"), ("RUNNING", "EXITED_SUCCESS"),
                   ("RUNNING", "EXITED_REFUSAL"), ("RUNNING", "EXITED_FAILURE"),
                   ("EXITED_SUCCESS", "EXITED_SUCCESS"),
                   ("EXITED_REFUSAL", "EXITED_REFUSAL"),
                   ("EXITED_FAILURE", "EXITED_FAILURE"))
        denied = (("PREPARED", "EXITED_SUCCESS"), ("RUNNING", "PREPARED"),
                  ("EXITED_SUCCESS", "RUNNING"), ("EXITED_REFUSAL", "EXITED_SUCCESS"),
                  ("EXITED_FAILURE", "PREPARED"), ("UNKNOWN", "RUNNING"),
                  ("CLAIMED", "PREPARED"))
        for pair in allowed: self.assertTrue(protocol.receipt_transition_allowed(*pair))
        for pair in denied: self.assertFalse(protocol.receipt_transition_allowed(*pair))
        self.assertTrue(protocol.one_shot_claim_allowed("PREPARED", claimed=False))
        self.assertFalse(protocol.one_shot_claim_allowed("PREPARED", claimed=True))
        for state in ("CLAIMED", "RUNNING", "EXITED_SUCCESS", "EXITED_REFUSAL", "EXITED_FAILURE", "UNKNOWN"):
            self.assertFalse(protocol.one_shot_claim_allowed(state, claimed=False))

    def test_not_started_requires_fresh_exact_prepared_receipt(self):
        self.assertEqual(self.classify(self.status(protocol.NOT_STARTED)), protocol.NOT_STARTED)
        self.assertEqual(self.classify(self.status(protocol.NOT_STARTED, self.receipt("CLAIMED"))),
                         protocol.UNKNOWN)
        changed = self.receipt(process=self.process())
        self.assertEqual(self.classify(self.status(protocol.NOT_STARTED, changed)), protocol.UNKNOWN)
        stale = self.receipt(created_utc=(self.now - timedelta(seconds=121)).isoformat(),
                             updated_utc=(self.now - timedelta(seconds=121)).isoformat())
        self.assertEqual(self.classify(self.status(protocol.NOT_STARTED, stale)), protocol.UNKNOWN)

    def test_running_and_terminal_states_bind_full_process_identity(self):
        running = self.receipt("RUNNING")
        self.assertEqual(self.classify(self.status(protocol.RUNNING_EXPECTED_PROCESS, running)),
                         protocol.RUNNING_EXPECTED_PROCESS)
        for state, receipt_state, code in ((protocol.EXITED_SUCCESS, "EXITED_SUCCESS", 0),
                            (protocol.EXITED_REFUSAL, "EXITED_REFUSAL", 2),
                            (protocol.EXITED_FAILURE, "EXITED_FAILURE", 70)):
            receipt = self.receipt(receipt_state, exit_code=code)
            self.assertEqual(self.classify(self.status(state, receipt)), state)

    def test_ssh_loss_before_exec_vs_after_exec_and_surviving_child(self):
        # A fresh PREPARED receipt proves launch was not claimed; no receipt or
        # a still-running child after transport loss never permits restoration.
        self.assertTrue(protocol.restore_allowed(self.classify(self.status(protocol.NOT_STARTED))))
        self.assertFalse(protocol.restore_allowed(self.classify(None)))
        running = self.receipt("RUNNING")
        self.assertEqual(self.classify(self.status(protocol.RUNNING_EXPECTED_PROCESS, running)),
                         protocol.RUNNING_EXPECTED_PROCESS)
        self.assertFalse(protocol.restore_allowed(protocol.RUNNING_EXPECTED_PROCESS))
        open_lease = self.status(protocol.NOT_STARTED, launch_closed=False)
        self.assertEqual(self.classify(open_lease), protocol.UNKNOWN)
        self.assertFalse(protocol.restore_allowed(self.classify(open_lease)))

    def test_pid_reuse_and_same_pid_different_process_identity_are_nonrestorable(self):
        running = self.receipt("RUNNING")
        cases = [self.process() | {"pid": 4124},
                 self.process() | {"executable": "/tmp/evil"},
                 self.process() | {"start_identity": "99124"},
                 self.process() | {"executable_sha256": "0" * 64},
                 self.process() | {"argv_sha256": "3" * 64},
                 self.process() | {"cwd": "/tmp"},
                 self.process() | {"uid": 0},
                 self.process() | {"operation_id_argument": "9" * 32}]
        for actual in cases:
            with self.subTest(actual=actual):
                raw = self.status(protocol.RUNNING_EXPECTED_PROCESS, running,
                                  process_identity=actual)
                result = self.classify(raw)
                self.assertEqual(result, protocol.IDENTITY_MISMATCH)
                self.assertFalse(protocol.restore_allowed(result))

    def test_wrong_operation_permit_manifest_target_host_or_user_is_unknown(self):
        receipt = self.receipt()
        cases = [self.status(protocol.NOT_STARTED, receipt, operation_id="9" * 32),
                 self.status(protocol.NOT_STARTED, receipt, release_authorization_id="other"),
                 self.status(protocol.NOT_STARTED, receipt, release_authorization_sha256="0" * 64),
                 self.status(protocol.NOT_STARTED, receipt, release_manifest_sha256="0" * 64),
                 self.status(protocol.NOT_STARTED, receipt | {"source_commit": "9" * 40}),
                 self.status(protocol.NOT_STARTED, receipt, target_selector="FK0711"),
                 self.status(protocol.NOT_STARTED, receipt, remote_host="evil.example"),
                 self.status(protocol.NOT_STARTED, receipt, remote_user="other"),
                 self.status(protocol.NOT_STARTED, receipt, query_nonce="0" * 64)]
        for raw in cases:
            self.assertEqual(self.classify(raw), protocol.UNKNOWN)

    def test_stale_authorization_and_stale_or_future_status_are_unknown(self):
        receipt = self.receipt(release_authorization_id="expired")
        self.assertEqual(self.classify(self.status(protocol.NOT_STARTED, receipt)), protocol.UNKNOWN)
        expired_before_claim = self.receipt(release_authorization_expires_utc=
                                            (self.now - timedelta(seconds=1)).isoformat())
        self.assertEqual(self.classify(self.status(protocol.NOT_STARTED, expired_before_claim)), protocol.UNKNOWN)
        changed_expiry = self.receipt(release_authorization_expires_utc="2026-11-13T12:06:00Z")
        self.assertEqual(self.classify(self.status(protocol.NOT_STARTED, changed_expiry)), protocol.UNKNOWN)
        old = self.now - timedelta(seconds=11)
        self.assertEqual(self.classify(self.status(protocol.NOT_STARTED, observed_utc=old.isoformat())),
                         protocol.UNKNOWN)
        future = self.now + timedelta(seconds=1)
        self.assertEqual(self.classify(self.status(protocol.NOT_STARTED, observed_utc=future.isoformat())),
                         protocol.UNKNOWN)

    def test_receipt_replacement_symlink_parent_replacement_and_replay_refuse(self):
        original = self.receipt()
        replaced = original | {"receipt_id": "9" * 32}
        self.assertEqual(self.classify(self.status(protocol.NOT_STARTED, replaced)), protocol.UNKNOWN)
        # Unrecognized storage attestation fields cannot be silently ignored.
        self.assertEqual(self.classify(self.status(protocol.NOT_STARTED, original,
                                                   receipt_symlink=True)), protocol.UNKNOWN)
        self.assertEqual(self.classify(self.status(protocol.NOT_STARTED, original,
                                                   parent_identity_changed=True)), protocol.UNKNOWN)
        self.assertEqual(self.classify(self.status(protocol.NOT_STARTED, original,
                                                   query_nonce="0" * 64)), protocol.UNKNOWN)

    def test_status_unavailable_malformed_duplicate_noncanonical_and_tampered(self):
        good = self.status(protocol.NOT_STARTED)
        for raw in (None, b"", b"{", good.replace(
                    b'"status":"' + protocol.NOT_STARTED.encode() + b'"', b'"status":"BOGUS"'),
                    good.replace(b'\n', b' \n'),
                    good[:-2] + b',"operation_id":"' + self.expected["operation_id"].encode() + b'"}\n',
                    self.status(protocol.NOT_STARTED, receipt_sha256="0" * 64)):
            self.assertEqual(self.classify(raw), protocol.UNKNOWN)

    def test_receipt_state_machine_and_exit_class_are_strict(self):
        for bad in (self.receipt("RUNNING", exit_code=0),
                    self.receipt(protocol.EXITED_SUCCESS, exit_code=1),
                    self.receipt(protocol.EXITED_REFUSAL, exit_code=0),
                    self.receipt("PREPARED", one_shot=False)):
            raw = self.status(protocol.NOT_STARTED, bad)
            self.assertEqual(self.classify(raw), protocol.UNKNOWN)

    def test_terminal_receipt_stale_at_query_is_unknown(self):
        old = self.now - timedelta(seconds=121)
        receipt = self.receipt(protocol.EXITED_SUCCESS, exit_code=0,
                               created_utc=old.isoformat(), updated_utc=old.isoformat(),
                               release_authorization_expires_utc=(old + timedelta(minutes=5)).isoformat())
        self.assertEqual(self.classify(self.status(protocol.EXITED_SUCCESS, receipt)), protocol.UNKNOWN)

    def test_remote_receipt_storage_rejects_symlink_hardlink_and_unsafe_parents(self):
        safe = [(0, 0o755, True, False), (1000, 0o700, True, False)]
        base = dict(expected_uid=1000, file_uid=1000, file_mode=0o600,
                    file_nlink=1, file_regular=True, file_symlink=False, parents=safe)
        self.assertTrue(protocol.receipt_storage_safe(**base))
        attacks = [base | {"file_symlink": True}, base | {"file_nlink": 2},
                   base | {"file_regular": False},
                   base | {"parents": [(0, 0o777, True, False), safe[-1]]},
                   base | {"parents": [(0, 0o755, True, True), safe[-1]]},
                   base | {"parents": [safe[0], (1001, 0o700, True, False)]},
                   base | {"parents": [safe[0], (1000, 0o750, True, False)]}]
        for attack in attacks:
            self.assertFalse(protocol.receipt_storage_safe(**attack))

    def test_receipt_parent_and_file_inode_replacement_refuse(self):
        stable = dict(parent_before=(8, 100), parent_after=(8, 100),
                      file_before=(8, 202, 1024, 456, 457),
                      file_after=(8, 202, 1024, 456, 457))
        self.assertTrue(protocol.receipt_path_identity_stable(**stable))
        self.assertFalse(protocol.receipt_path_identity_stable(**(stable | {"parent_after": (8, 101)})))
        self.assertFalse(protocol.receipt_path_identity_stable(**(stable | {"file_after": (8, 203, 1024, 456, 457)})))
        self.assertFalse(protocol.receipt_path_identity_stable(**(stable | {"file_after": (8, 202, 2048, 457, 458)})))


if __name__ == "__main__":
    unittest.main()
