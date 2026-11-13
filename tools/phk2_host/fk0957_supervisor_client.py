#!/usr/bin/python3
"""Unprivileged narrow client for the protected FK0957 supervisor socket."""
from __future__ import annotations

import base64
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


def run_once(request_raw: bytes) -> tuple[bytes, int]:
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
                      "authorization_id", "executable", "executable_sha256", "argv_sha256"}
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
            not re.fullmatch(r"[1-9][0-9]{0,19}", str(process.get("start_identity", ""))) or
            process.get("operation_id") != operation_id or
            process.get("authorization_id") != response.get("authorization_id") or
            process.get("executable") != "/usr/local/bin/fk0957-safe-launcher" or
            not HEX64.fullmatch(str(process.get("executable_sha256", ""))) or
            not HEX64.fullmatch(str(process.get("argv_sha256", ""))) or
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
    return result, code


def query_status(operation_id: str) -> dict[str, Any]:
    if type(operation_id) is not str or not OP_ID.fullmatch(operation_id):
        raise ValueError("operation ID invalid")
    response = request_supervisor({"schema": supervisor_protocol.REQUEST_SCHEMA,
                                   "command": "status", "operation_id": operation_id})
    if response.get("operation_id") != operation_id:
        raise ValueError("operation status binding rejected")
    return response


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        if args == ["run"]:
            request_raw = sys.stdin.buffer.read(endpoint.MAX_REQUEST_BYTES + 1)
            if len(request_raw) > endpoint.MAX_REQUEST_BYTES:
                raise ValueError("request oversized")
            result, code = run_once(request_raw)
            sys.stdout.buffer.write(result)
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
            "schema": supervisor_protocol.RESPONSE_SCHEMA,
            "state": "UNKNOWN", "code": "SUPERVISOR_UNAVAILABLE"}))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
