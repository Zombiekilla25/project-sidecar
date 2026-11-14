#!/usr/bin/python3
"""Unprivileged narrow client for the protected FK0957 supervisor socket."""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import socket
import sys
from typing import Any

import phk2_fk0957_remote_topology_endpoint as endpoint
import fk0957_supervisor as supervisor_protocol

SOCKET_PATH = supervisor_protocol.SOCKET_PATH
MAX_RESPONSE = supervisor_protocol.MAX_MESSAGE
OP_ID = re.compile(r"[0-9a-f]{32}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
CLIENT_RESULT_SCHEMA = "fk0957-supervisor-client-result-v1"


def _recv_all(sock: socket.socket) -> bytes:
    data = bytearray()
    while len(data) <= MAX_RESPONSE:
        block = sock.recv(min(65536, MAX_RESPONSE + 1 - len(data)))
        if not block:
            break
        data.extend(block)
    if not data or len(data) > MAX_RESPONSE:
        raise ValueError("supervisor response size invalid")
    return bytes(data)


def request_supervisor(message: dict[str, Any], *, socket_path: str = SOCKET_PATH) -> dict[str, Any]:
    raw = supervisor_protocol.canonical(message)
    if len(raw) > supervisor_protocol.MAX_MESSAGE:
        raise ValueError("supervisor request oversized")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(930)
        client.connect(socket_path)
        client.sendall(raw)
        client.shutdown(socket.SHUT_WR)
        response_raw = _recv_all(client)
    response = supervisor_protocol.parse_message(response_raw)
    if response.get("schema") != supervisor_protocol.RESPONSE_SCHEMA:
        raise ValueError("supervisor response schema rejected")
    return response


def _run_once_detailed(request_raw: bytes) -> dict[str, Any]:
    request = endpoint._parse_canonical(request_raw, endpoint.MAX_REQUEST_BYTES)
    operation_id = request.get("operation_id")
    if type(operation_id) is not str or not OP_ID.fullmatch(operation_id):
        raise ValueError("operation ID invalid")
    response = request_supervisor({
        "schema": supervisor_protocol.REQUEST_SCHEMA,
        "command": "run", "operation_id": operation_id,
        "request_b64": base64.b64encode(request_raw).decode("ascii"),
    })
    expected_fields = {"schema", "operation_id", "authorization_id", "authorization_sha256",
                       "handoff_sha256", "manifest_sha256", "production_head",
                       "transaction_profile_sha256", "target", "one_shot", "registered_ns",
                       "state", "process", "exit_code", "reaped_ns", "result_b64"}
    process_fields = {"pid", "start_identity", "parent_pid", "operation_id",
                      "authorization_id", "launcher", "launcher_sha256", "executable",
                      "executable_sha256", "argv_sha256"}
    process = response.get("process")
    if (set(response) != expected_fields or response.get("operation_id") != operation_id or
            response.get("authorization_id") != request.get("release_authorization", {}).get("payload", {}).get("authorization_id") or
            response.get("target") != "FK0957" or response.get("one_shot") is not True or
            type(response.get("registered_ns")) is not int or response["registered_ns"] <= 0 or
            type(response.get("reaped_ns")) is not int or response["reaped_ns"] < response["registered_ns"] or
            not HEX64.fullmatch(str(response.get("authorization_sha256", ""))) or
            not HEX64.fullmatch(str(response.get("handoff_sha256", ""))) or
            not HEX64.fullmatch(str(response.get("manifest_sha256", ""))) or
            not HEX64.fullmatch(str(response.get("transaction_profile_sha256", ""))) or
            not HEX40.fullmatch(str(response.get("production_head", ""))) or
            type(process) is not dict or set(process) != process_fields or
            type(process.get("pid")) is not int or process["pid"] <= 1 or
            type(process.get("parent_pid")) is not int or process["parent_pid"] <= 1 or
            type(process.get("start_identity")) is not str or
            not re.fullmatch(r"[1-9][0-9]{0,19}", process["start_identity"]) or
            process.get("operation_id") != operation_id or
            process.get("authorization_id") != response.get("authorization_id") or
            process.get("launcher") != supervisor_protocol.LAUNCHER or
            type(process.get("launcher_sha256")) is not str or
            not HEX64.fullmatch(process["launcher_sha256"]) or
            process.get("executable") != supervisor_protocol.PYTHON_EXECUTABLE or
            process.get("executable_sha256") != supervisor_protocol.PYTHON_EXECUTABLE_SHA256 or
            type(process.get("argv_sha256")) is not str or
            not HEX64.fullmatch(process["argv_sha256"]) or
            type(response.get("state")) is not str or
            response.get("state") not in {
            "EXITED_SUCCESS", "EXITED_REFUSAL", "EXITED_FAILURE"}):
        raise ValueError("supervisor did not confirm a terminal child state")
    code = response.get("exit_code")
    if type(code) is not int or not -255 <= code <= 255:
        raise ValueError("supervisor exit code invalid")
    try:
        result = base64.b64decode(response["result_b64"], validate=True)
    except (KeyError, ValueError, TypeError):
        raise ValueError("supervisor result encoding invalid") from None
    if not result or len(result) > endpoint.MAX_RECORD_BYTES:
        raise ValueError("supervisor result size invalid")
    if ((response["state"] == "EXITED_SUCCESS" and code != 0) or
            (response["state"] == "EXITED_REFUSAL" and code != 2) or
            (response["state"] == "EXITED_FAILURE" and code in (0, 2))):
        raise ValueError("supervisor state and exit code conflict")
    return {
        "schema": CLIENT_RESULT_SCHEMA,
        "operation_id": response["operation_id"],
        "authorization_id": response["authorization_id"],
        "authorization_sha256": response["authorization_sha256"],
        "handoff_sha256": response["handoff_sha256"],
        "manifest_sha256": response["manifest_sha256"],
        "production_head": response["production_head"],
        "transaction_profile_sha256": response["transaction_profile_sha256"],
        "target": response["target"], "one_shot": response["one_shot"],
        "registered_ns": response["registered_ns"], "state": response["state"],
        "process": response["process"], "exit_code": code,
        "reaped_ns": response["reaped_ns"],
        "result_sha256": hashlib.sha256(result).hexdigest(),
        "result_b64": base64.b64encode(result).decode("ascii"),
    }


def run_once(request_raw: bytes) -> tuple[bytes, int]:
    """Compatibility helper; production CLI emits the complete bound contract."""
    detailed = _run_once_detailed(request_raw)
    return base64.b64decode(detailed["result_b64"], validate=True), detailed["exit_code"]


def _status_projection(operation_id: str, response: Any) -> dict[str, Any]:
    """Return a bounded maintenance view; only exact reaped children restore."""
    unknown = {"schema": "fk0957-maintenance-status-v1",
               "operation_id": operation_id, "state": "UNKNOWN",
               "terminal": False, "restore_eligible": False}
    if type(response) is not dict or response.get("operation_id") != operation_id:
        return unknown
    state = response.get("state")
    if type(state) is not str:
        return unknown
    if state in {"REGISTERED", "LAUNCHING", "RUNNING"}:
        # These states are useful for diagnosis, but never permit restoration.
        allowed = {
            "REGISTERED": {"schema", "operation_id", "authorization_id", "authorization_sha256",
                            "handoff_sha256", "manifest_sha256", "production_head",
                            "transaction_profile_sha256", "target", "one_shot", "registered_ns", "state"},
            "LAUNCHING": {"schema", "operation_id", "authorization_id", "authorization_sha256",
                           "handoff_sha256", "manifest_sha256", "production_head",
                           "transaction_profile_sha256", "target", "one_shot", "registered_ns",
                           "state", "launch_ns"},
            "RUNNING": {"schema", "operation_id", "authorization_id", "authorization_sha256",
                        "handoff_sha256", "manifest_sha256", "production_head",
                        "transaction_profile_sha256", "target", "one_shot", "registered_ns",
                        "state", "process"},
        }[state]
        if set(response) != allowed or not _status_identity_valid(response, operation_id):
            return unknown
        if state == "LAUNCHING" and (type(response.get("launch_ns")) is not int or
                                      response["launch_ns"] < response["registered_ns"]):
            return unknown
        if state == "RUNNING" and not _status_process_valid(response.get("process"), operation_id,
                                                             response.get("authorization_id")):
            return unknown
        return {"schema": "fk0957-maintenance-status-v1", "operation_id": operation_id,
                "state": state, "terminal": False, "restore_eligible": False,
                **({"child_identity": response["process"]} if state == "RUNNING" else {})}
    if state not in {"EXITED_SUCCESS", "EXITED_REFUSAL", "EXITED_FAILURE"}:
        return unknown
    required = {"schema", "operation_id", "authorization_id", "authorization_sha256",
                "handoff_sha256", "manifest_sha256", "production_head",
                "transaction_profile_sha256", "target", "one_shot", "registered_ns",
                "state", "process", "exit_code", "reaped_ns", "result_b64"}
    if set(response) != required or not _status_identity_valid(response, operation_id):
        return unknown
    if not _status_process_valid(response.get("process"), operation_id,
                                 response.get("authorization_id")):
        return unknown
    code, registered, reaped = (response.get("exit_code"), response.get("registered_ns"),
                                 response.get("reaped_ns"))
    if (type(code) is not int or not -255 <= code <= 255 or
            type(registered) is not int or registered <= 0 or
            type(reaped) is not int or reaped < registered or
            (state == "EXITED_SUCCESS" and code != 0) or
            (state == "EXITED_REFUSAL" and code != 2) or
            (state == "EXITED_FAILURE" and code in (0, 2))):
        return unknown
    encoded = response.get("result_b64")
    if type(encoded) is not str or len(encoded) > endpoint.MAX_RECORD_BYTES * 2:
        return unknown
    try:
        result = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        return unknown
    if not result or len(result) > endpoint.MAX_RECORD_BYTES:
        return unknown
    # Keep the supervisor's bound identities visible to the controller, while
    # computing restore eligibility here from the complete validated proof.
    return {"schema": "fk0957-maintenance-status-v1", "operation_id": operation_id,
            "state": state, "terminal": True, "restore_eligible": True,
            "authorization_id": response["authorization_id"],
            "authorization_sha256": response["authorization_sha256"],
            "handoff_sha256": response["handoff_sha256"],
            "manifest_sha256": response["manifest_sha256"],
            "production_head": response["production_head"],
            "transaction_profile_sha256": response["transaction_profile_sha256"],
            "target": response["target"], "one_shot": True,
            "registered_ns": registered, "reaped_ns": reaped, "exit_code": code,
            "result_b64": encoded, "child_identity": response["process"]}


def _status_identity_valid(response: dict[str, Any], operation_id: str) -> bool:
    return (response.get("schema") == supervisor_protocol.RESPONSE_SCHEMA and
            response.get("operation_id") == operation_id and
            type(response.get("authorization_id")) is str and
            HEX64.fullmatch(response["authorization_id"]) is not None and
            all(type(response.get(name)) is str and HEX64.fullmatch(response[name]) is not None
                for name in ("authorization_sha256", "handoff_sha256", "manifest_sha256",
                             "transaction_profile_sha256")) and
            type(response.get("production_head")) is str and
            HEX40.fullmatch(response["production_head"]) is not None and
            response.get("target") == "FK0957" and response.get("one_shot") is True and
            type(response.get("registered_ns")) is int and response["registered_ns"] > 0)


def _status_process_valid(process: Any, operation_id: str, authorization_id: Any) -> bool:
    fields = {"pid", "start_identity", "parent_pid", "operation_id", "authorization_id",
              "launcher", "launcher_sha256", "executable", "executable_sha256", "argv_sha256"}
    return (type(process) is dict and set(process) == fields and
            type(process.get("pid")) is int and process["pid"] > 1 and
            type(process.get("parent_pid")) is int and process["parent_pid"] > 1 and
            type(process.get("start_identity")) is str and
            re.fullmatch(r"[1-9][0-9]{0,19}", process["start_identity"]) is not None and
            process.get("operation_id") == operation_id and
            process.get("authorization_id") == authorization_id and
            process.get("launcher") == supervisor_protocol.LAUNCHER and
            process.get("executable") == supervisor_protocol.PYTHON_EXECUTABLE and
            process.get("executable_sha256") == supervisor_protocol.PYTHON_EXECUTABLE_SHA256 and
            all(type(process.get(name)) is str and HEX64.fullmatch(process[name]) is not None
                for name in ("launcher_sha256", "argv_sha256")))


def query_status(operation_id: str) -> dict[str, Any]:
    if type(operation_id) is not str or not OP_ID.fullmatch(operation_id):
        raise ValueError("operation ID invalid")
    try:
        response = request_supervisor({"schema": supervisor_protocol.REQUEST_SCHEMA,
                                       "command": "status", "operation_id": operation_id})
    except BaseException:
        return _status_projection(operation_id, None)
    return _status_projection(operation_id, response)


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        if args == ["run"]:
            request_raw = sys.stdin.buffer.read(endpoint.MAX_REQUEST_BYTES + 1)
            if len(request_raw) > endpoint.MAX_REQUEST_BYTES:
                raise ValueError("request oversized")
            result = _run_once_detailed(request_raw)
            code = result["exit_code"]
            sys.stdout.buffer.write(supervisor_protocol.canonical(result))
            sys.stdout.buffer.flush()
            return code
        if len(args) == 2 and args[0] == "status":
            status = query_status(args[1])
            sys.stdout.buffer.write(supervisor_protocol.canonical(status))
            return 0
        raise ValueError("unsupported supervisor client command")
    except BaseException:
        # Never turn an unavailable/unknown supervisor state into a valid
        # remote refusal: the RGB side must not infer child exit from it.
        sys.stdout.buffer.write(supervisor_protocol.canonical({
            "schema": CLIENT_RESULT_SCHEMA,
            "state": "UNKNOWN", "code": "SUPERVISOR_UNAVAILABLE"}))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
