from __future__ import annotations

import json
import os
import socket
import base64
import hashlib
import tempfile
import unittest
from unittest import mock

import fk0957_supervisor as supervisor
import fk0957_supervisor_client as client
import phk2_fk0957_remote_topology_endpoint as endpoint


class SupervisorProtocolTests(unittest.TestCase):
    def test_restart_converts_unowned_inflight_state_to_unknown_only(self):
        running = {"schema": supervisor.RESPONSE_SCHEMA,
                   "operation_id": "a" * 32, "state": "RUNNING"}
        recovered = supervisor.recover_after_supervisor_restart(
            running, active_in_this_process=False)
        self.assertEqual(recovered["state"], "UNKNOWN")
        self.assertEqual(recovered["reason"], "SUPERVISOR_RESTART_UNCERTAIN")
        self.assertIs(supervisor.recover_after_supervisor_restart(
            running, active_in_this_process=True), running)
        terminal = {"state": "EXITED_SUCCESS"}
        self.assertIs(supervisor.recover_after_supervisor_restart(
            terminal, active_in_this_process=False), terminal)

    def test_exact_child_identity_is_post_exec_pinned_python_not_launcher_argv(self):
        executable_bytes = b"reviewed-python-executable"
        executable_sha = hashlib.sha256(executable_bytes).hexdigest()
        rest = ["S", str(os.getpid()), *(["0"] * 17), "12345"]
        raw_stat = f"321 (python3.12) " + " ".join(rest)
        argv = b"\0".join((supervisor.PYTHON_EXECUTABLE.encode(), b"-I", b"-S",
                             b"/proc/self/fd/7", supervisor.ENDPOINT_MODE.encode())) + b"\0"
        with mock.patch.object(supervisor, "PYTHON_EXECUTABLE_SHA256", executable_sha):
            result = supervisor._identity_from_snapshot(
                321, "a" * 32, "b" * 64, raw_stat,
                supervisor.PYTHON_EXECUTABLE, executable_bytes, argv, "c" * 64)
            self.assertEqual(result["launcher"], supervisor.LAUNCHER)
            self.assertEqual(result["executable"], supervisor.PYTHON_EXECUTABLE)
            self.assertEqual(result["executable_sha256"], executable_sha)
            wrong_argv = b"\0".join((supervisor.LAUNCHER.encode(),
                                      supervisor.ENDPOINT_MODE.encode())) + b"\0"
            with self.assertRaises(OSError):
                supervisor._identity_from_snapshot(
                    321, "a" * 32, "b" * 64, raw_stat,
                    supervisor.PYTHON_EXECUTABLE, executable_bytes, wrong_argv, "c" * 64)

    def test_ipc_schema_has_no_caller_asserted_process_state(self):
        self.assertEqual(tuple(__import__("inspect").signature(supervisor.serve_one).parameters),
                         ("client",))
        request = {"schema": supervisor.REQUEST_SCHEMA, "command": "run",
                   "operation_id": "a" * 32, "request_b64": "e30="}
        self.assertEqual(set(request), supervisor.RUN_KEYS)
        for forged in ("launch_closed", "process_exited", "terminal_state",
                       "device_opened", "permit_consumed", "source_trusted"):
            value = dict(request, **{forged: True})
            with self.assertRaises(ValueError):
                supervisor.validate_request(value)

    def test_ipc_json_requires_canonical_no_duplicate_fields(self):
        with self.assertRaises(ValueError):
            supervisor.parse_message(b'{"command":"run","command":"status"}\n')
        with self.assertRaises(ValueError):
            supervisor.parse_message(b'{ "schema": "fk0957-supervisor-ipc-v1" }\n')

    def test_state_machine_is_monotonic_and_terminal_states_are_immutable(self):
        chain = ["REGISTERED", "LAUNCHING", "RUNNING", "EXITED_SUCCESS"]
        for before, after in zip(chain, chain[1:]):
            self.assertTrue(supervisor.transition_allowed(before, after))
        for terminal in supervisor.TERMINAL:
            for next_state in supervisor.ALLOWED_TRANSITIONS:
                self.assertFalse(supervisor.transition_allowed(terminal, next_state))
            self.assertFalse(supervisor.transition_allowed(terminal, terminal))
        self.assertFalse(supervisor.transition_allowed("RUNNING", "REGISTERED"))
        self.assertFalse(supervisor.transition_allowed("RUNNING", "EXITED_SUCCESSFUL"))

    def test_direct_python_process_cannot_fabricate_supervisor_peer_credential(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            if os.geteuid() != 0:
                self.assertFalse(endpoint.supervisor_capability_valid(left.fileno()))
        finally:
            left.close()
            right.close()

    def test_path_connected_supervisor_ipc_is_not_child_capability(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "supervisor.sock")
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(path)
            server.listen(1)
            client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client_socket.connect(path)
            accepted, _ = server.accept()
            try:
                self.assertEqual(client_socket.getpeername(), path)
                self.assertFalse(endpoint.supervisor_capability_valid(client_socket.fileno()))
            finally:
                client_socket.close()
                accepted.close()
                server.close()

    def test_unapproved_ipc_principal_is_rejected_before_read(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            with mock.patch.object(supervisor.os, "geteuid", return_value=0), \
                    mock.patch.object(supervisor, "_service_accounts",
                                      return_value=(os.getuid() + 10_000, 20_000, 30_000)):
                with self.assertRaises(PermissionError):
                    supervisor.serve_one(left)
        finally:
            left.close()
            right.close()

    def test_terminal_state_is_not_claimed_from_timeout_or_ssh_code(self):
        # The daemon's terminal rows are generated only after Popen.wait().
        with open(supervisor.__file__, encoding="utf-8") as handle:
            source = handle.read()
        self.assertIn("exit_code = child.wait()", source)
        self.assertNotIn('request.get("launch_closed")', source)
        self.assertNotIn('request.get("exit_code")', source)

    def test_rgb_remote_command_routes_through_supervisor_client(self):
        import phk2_fk0957_topology_rgb_orchestrator as rgb
        self.assertEqual(rgb.REMOTE_ENDPOINT_COMMAND,
                         "/usr/local/bin/fk0957-safe-launcher --supervisor-client run")

    def test_supervisor_client_refuses_unknown_and_nonterminal_states(self):
        request = {"operation_id": "a" * 32}
        raw = endpoint.canonical(request)
        refused = {"schema": supervisor.RESPONSE_SCHEMA,
                   "operation_id": "a" * 32, "state": "UNKNOWN"}
        with mock.patch.object(client, "request_supervisor", return_value=refused):
            with self.assertRaises(ValueError):
                client.run_once(raw)

    def test_supervisor_client_requires_reaped_exit_and_matching_code(self):
        raw = endpoint.canonical({"operation_id": "a" * 32,
                                  "release_authorization": {"payload": {"authorization_id": "b" * 64}}})
        response = {
            "schema": supervisor.RESPONSE_SCHEMA, "operation_id": "a" * 32,
            "authorization_id": "b" * 64, "authorization_sha256": "c" * 64,
            "handoff_sha256": "d" * 64, "manifest_sha256": "e" * 64,
            "production_head": "f" * 40, "transaction_profile_sha256": "9" * 64,
            "target": "FK0957", "one_shot": True, "registered_ns": 100,
            "state": "EXITED_SUCCESS", "exit_code": 0, "reaped_ns": 200,
            "process": {"pid": 100, "start_identity": "12345", "parent_pid": 50,
                        "operation_id": "a" * 32, "authorization_id": "b" * 64,
                        "launcher": supervisor.LAUNCHER, "launcher_sha256": "1" * 64,
                        "executable": supervisor.PYTHON_EXECUTABLE,
                        "executable_sha256": supervisor.PYTHON_EXECUTABLE_SHA256,
                        "argv_sha256": "2" * 64},
            "result_b64": base64.b64encode(b'{"ok":true}\n').decode(),
        }
        with mock.patch.object(client, "request_supervisor", return_value=response):
            result, status = client.run_once(raw)
        self.assertEqual((result, status), (b'{"ok":true}\n', 0))
        response["exit_code"] = 2
        with mock.patch.object(client, "request_supervisor", return_value=response):
            with self.assertRaises(ValueError):
                client.run_once(raw)

    def test_supervisor_failure_does_not_emit_valid_refusal_or_confirm_exit(self):
        import io
        output = io.BytesIO()
        with mock.patch.object(client, "run_once", side_effect=OSError("secret path")), \
             mock.patch.object(client.sys, "stdout", type("Stdout", (), {"buffer": output})()):
            status = client.main(["run"])
        self.assertEqual(status, 3)
        envelope = supervisor.parse_message(output.getvalue())
        self.assertEqual(envelope["state"], "UNKNOWN")
        self.assertNotIn("secret", output.getvalue().decode())


if __name__ == "__main__":
    unittest.main()
