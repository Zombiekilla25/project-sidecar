"""RGB-side pinned-SSH orchestration and validation for unsigned FK0957 reads."""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from typing import Any

import phk2_fk0957_remote_orchestrator as ssh_policy
import phk2_fk0957_idcode_gate as identity_gate
import phk2_fk0957_topology_discovery as topology
import phk2_fk0957_topology_signing as signing
import phk2_fk0957_topology_transport as transport
import phk2_fk0957_remote_topology_endpoint as endpoint
import fk0957_supervisor as supervisor_protocol

KNOWN_HOSTS_PATH = Path("/home/rmann/.local/share/sidecar/ssh/fk0957-testbench-known_hosts")
REMOTE_ENDPOINT_COMMAND = "/usr/local/bin/fk0957-safe-launcher --supervisor-client run"
REMOTE_STATUS_COMMAND = "/usr/local/bin/fk0957-safe-launcher --supervisor-client status"
LOCAL_CONSUMED_AUTH_DIR = Path("/home/rmann/.local/share/sidecar/fk0957/consumed-authorizations")
SSH_TIMEOUT_SECONDS = 150
MAX_RESPONSE_BYTES = endpoint.MAX_RECORD_BYTES
HEX64 = re.compile(r"[0-9a-f]{64}\Z")

UNSIGNED_FIELDS = {
    "schema", "status", "operation_id", "authorization_id", "authorization_sha256",
    "handoff_sha256", "manifest_sha256", "production_head", "transaction_profile_sha256",
    "card_id", "adapter_serial", "usb_descriptor_serial", "physical_interface",
    "descriptor_evidence_sha256", "permit_nonce", "trusted_signer_fingerprint",
    "observation_timestamp", "transport_source_sha256", "worktree_clean",
    "runtime_library_provenance", "scan_a_transaction_sha256", "scan_a_tck_count",
    "scan_a_raw_tdo_hex", "scan_b_transaction_sha256", "scan_b_tck_count",
    "scan_b_raw_tdo_hex", "total_tck_count", "matched_device_count",
    "opened_device_count", "second_device_opened", "aggregate_dr_length",
    "observed_taps_tdo_to_tdi", "raw_tdo_scan_a_bits_lsb_first",
    "raw_tdo_scan_b_bits_lsb_first", "write_count", "reset_count", "program_count",
    "jtag_operation_count", "topology_discovery_only", "idcode_qualification_pass",
    "fpga_dna_observed", "loaded_image_identity_observed", "bitstream_identity_observed",
}


class Refusal(ValueError):
    def __init__(self, message: str, *, remote_state: str = "REMOTE_STATE_UNKNOWN"):
        super().__init__(message)
        self.remote_state = remote_state


def _parse_response(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_RESPONSE_BYTES:
        raise Refusal("remote unsigned result missing or oversized")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=endpoint._unique_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("constant")))
    except (UnicodeError, ValueError, json.JSONDecodeError):
        raise Refusal("remote unsigned result is malformed") from None
    if type(value) is not dict or endpoint.canonical(value) != raw:
        raise Refusal("remote unsigned result is not canonical")
    if value.get("status") == "REFUSED":
        # Preserve only a fixed refusal code/phase, never remote exception text.
        code, phase = value.get("code"), value.get("phase")
        if type(code) is str and re.fullmatch(r"[A-Z0-9_]{1,64}", code) and \
                type(phase) is str and re.fullmatch(r"[A-Z0-9_]{1,64}", phase):
            raise Refusal("remote refusal " + phase + "/" + code)
        raise Refusal("remote endpoint refused with malformed envelope")
    if set(value) != UNSIGNED_FIELDS:
        raise Refusal("remote unsigned result schema mismatch")
    return value


def _validated_local_context(request_raw: bytes) -> dict[str, Any]:
    issuers = endpoint._load_trust_config()
    context, _, _ = endpoint._validate_request(request_raw, issuers)
    # This local authorization ledger prevents an unsigned response replay from
    # being signed twice, independently of the testbench's own ledger.
    return context


def _consume_local_auth(context: dict[str, Any]) -> None:
    root = LOCAL_CONSUMED_AUTH_DIR
    try:
        parent_fd, name = endpoint._open_absolute_parent(root)
        root_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
                          dir_fd=parent_fd)
    except (OSError, endpoint.Refusal):
        raise Refusal("local authorization ledger unavailable") from None
    try:
        info = os.fstat(root_fd)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or
                stat.S_IMODE(info.st_mode) != 0o700):
            raise Refusal("local authorization ledger unsafe")
        name = context["authorization_id"] + ".signed"
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                         0o600, dir_fd=root_fd)
        except FileExistsError:
            raise Refusal("local authorization replay") from None
        try:
            body = (context["authorization_sha256"] + "\n").encode("ascii")
            offset = 0
            while offset < len(body):
                offset += os.write(fd, body[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(root_fd)
    finally:
        os.close(root_fd)
        os.close(parent_fd)


def _pinned_ssh(request_raw: bytes, *, runner=None) -> tuple[bytes, dict[str, Any]]:
    runner = subprocess.run if runner is None else runner
    known_hosts, host_identity, source_identity = ssh_policy._read_pinned_source(KNOWN_HOSTS_PATH)
    known_hosts_sha = hashlib.sha256(known_hosts).hexdigest()
    agent_path, agent_identity = ssh_policy._validated_local_ssh_auth_sock()
    ssh_policy._probe_local_ssh_agent(agent_path)
    safe_env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C",
                "SSH_AUTH_SOCK": agent_path}
    with tempfile.TemporaryDirectory(prefix="fk0957-known-hosts-", dir="/tmp") as raw_dir:
        pin_dir = Path(raw_dir)
        pin_fd, pin_dir_identity = ssh_policy._open_private_pin_dir(pin_dir)
        try:
            pin_file_identity = ssh_policy._write_private_pin(pin_fd, known_hosts)
        finally:
            os.close(pin_fd)
        pin_path = pin_dir / "known_hosts"
        ssh_policy._validate_private_pin(pin_path, known_hosts, host_identity,
                                         pin_dir_identity, pin_file_identity)
        cmd = [ssh_policy.SSH_BINARY, "-F", "/dev/null", "-T",
               "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
               "-o", f"UserKnownHostsFile={pin_path}",
               "-o", "GlobalKnownHostsFile=/dev/null", "-o", "CheckHostIP=yes",
               "-o", "UpdateHostKeys=no", "-o", "KnownHostsCommand=none",
               "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes",
               "-o", "PermitLocalCommand=no", ssh_policy._AUTHORIZED_SSH_DESTINATION,
               REMOTE_ENDPOINT_COMMAND]
        current, current_identity, current_inode = ssh_policy._read_pinned_source(KNOWN_HOSTS_PATH)
        if (current != known_hosts or current_identity != host_identity or
                current_inode != source_identity or hashlib.sha256(current).hexdigest() != known_hosts_sha):
            raise Refusal("pinned host identity changed before SSH")
        ssh_policy._validate_private_pin(pin_path, known_hosts, host_identity,
                                         pin_dir_identity, pin_file_identity)
        ssh_policy._revalidate_local_ssh_auth_sock(agent_path, agent_identity)
        try:
            result = runner(cmd, input=request_raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            check=False, timeout=SSH_TIMEOUT_SECONDS, env=safe_env)
        except subprocess.TimeoutExpired:
            result = None
        except OSError:
            raise Refusal("SSH process did not start; remote acquisition was not invoked",
                          remote_state="REMOTE_PROCESS_CONFIRMED_EXITED") from None
        code = 255 if result is None else getattr(result, "returncode", 255)
        if result is None or code == 255:
            try:
                request_value = endpoint._parse_canonical(request_raw, endpoint.MAX_REQUEST_BYTES)
                operation_id = request_value.get("operation_id")
                if type(operation_id) is not str or not re.fullmatch(r"[0-9a-f]{32}", operation_id):
                    raise ValueError("operation id invalid")
                status_cmd = [*cmd[:-1], f"{REMOTE_STATUS_COMMAND} {operation_id}"]
                current, current_identity, current_inode = ssh_policy._read_pinned_source(KNOWN_HOSTS_PATH)
                if (current != known_hosts or current_identity != host_identity or
                        current_inode != source_identity):
                    raise ValueError("host pin changed")
                ssh_policy._validate_private_pin(pin_path, known_hosts, host_identity,
                                                 pin_dir_identity, pin_file_identity)
                ssh_policy._revalidate_local_ssh_auth_sock(agent_path, agent_identity)
                status_result = runner(status_cmd, input=b"", stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, check=False,
                                       timeout=SSH_TIMEOUT_SECONDS, env=safe_env)
                if getattr(status_result, "returncode", 255) != 0:
                    raise ValueError("status query unavailable")
                status_raw = getattr(status_result, "stdout", b"")
                if isinstance(status_raw, str):
                    status_raw = status_raw.encode("utf-8", "strict")
                status = endpoint._parse_canonical(status_raw, 1024 * 1024)
                status_fields = {"schema", "operation_id", "authorization_id", "authorization_sha256",
                                 "handoff_sha256", "manifest_sha256", "production_head",
                                 "transaction_profile_sha256", "target", "one_shot", "registered_ns",
                                 "state", "process", "exit_code", "reaped_ns", "result_b64"}
                auth_payload = request_value.get("release_authorization", {}).get("payload", {})
                handoff_payload = request_value.get("handoff", {}).get("payload", {})
                manifest_payload = request_value.get("runtime_manifest", {}).get("payload", {})
                auth_id = auth_payload.get("authorization_id")
                auth_sha = hashlib.sha256(endpoint.canonical(auth_payload)).hexdigest()
                handoff_sha = hashlib.sha256(endpoint.canonical(handoff_payload)).hexdigest()
                manifest_sha = hashlib.sha256(endpoint.canonical(manifest_payload)).hexdigest()
                if (set(status) != status_fields or
                        status.get("schema") != "fk0957-supervisor-status-v1" or
                        status.get("operation_id") != operation_id or
                        status.get("authorization_id") != auth_id or
                        status.get("authorization_sha256") != auth_sha or
                        status.get("handoff_sha256") != handoff_sha or
                        status.get("manifest_sha256") != manifest_sha or
                        status.get("production_head") != manifest_payload.get("production_head") or
                        status.get("transaction_profile_sha256") != manifest_payload.get("transaction_profile_sha256") or
                        status.get("target") != "FK0957" or status.get("one_shot") is not True):
                    raise ValueError("status binding mismatch")
                if status.get("state") not in {"EXITED_SUCCESS", "EXITED_REFUSAL", "EXITED_FAILURE"}:
                    raise ValueError("status is not terminal")
                terminal_code = status.get("exit_code")
                if (type(terminal_code) is not int or not -255 <= terminal_code <= 255 or
                        (status["state"] == "EXITED_SUCCESS" and terminal_code != 0) or
                        (status["state"] == "EXITED_REFUSAL" and terminal_code != 2) or
                        (status["state"] == "EXITED_FAILURE" and terminal_code in (0, 2))):
                    raise ValueError("terminal process state contradicts exit status")
                child_identity = status.get("process")
                if (type(child_identity) is not dict or child_identity.get("operation_id") != operation_id or
                        child_identity.get("authorization_id") != auth_id or
                        type(child_identity.get("pid")) is not int or child_identity["pid"] <= 1 or
                        type(child_identity.get("parent_pid")) is not int or child_identity["parent_pid"] <= 1 or
                        not re.fullmatch(r"[1-9][0-9]{0,19}", str(child_identity.get("start_identity", ""))) or
                        child_identity.get("launcher") != supervisor_protocol.LAUNCHER or
                        not re.fullmatch(r"[0-9a-f]{64}", str(child_identity.get("launcher_sha256", ""))) or
                        child_identity.get("executable") != supervisor_protocol.PYTHON_EXECUTABLE or
                        child_identity.get("executable_sha256") != supervisor_protocol.PYTHON_EXECUTABLE_SHA256 or
                        not re.fullmatch(r"[0-9a-f]{64}", str(child_identity.get("argv_sha256", "")))):
                    raise ValueError("child identity binding invalid")
                if (type(status.get("registered_ns")) is not int or status["registered_ns"] <= 0 or
                        type(status.get("reaped_ns")) is not int or status["reaped_ns"] <= 0 or
                        status["reaped_ns"] < status["registered_ns"]):
                    raise ValueError("reap proof absent")
                stdout = base64.b64decode(status.get("result_b64", ""), validate=True)
                if not stdout or len(stdout) > MAX_RESPONSE_BYTES:
                    raise ValueError("recovered result absent or oversized")
                code = terminal_code
            except BaseException:
                raise Refusal("remote process state unknown after SSH loss; do not restore ownership",
                              remote_state="REMOTE_STATE_UNKNOWN") from None
        else:
            stdout = getattr(result, "stdout", b"")
            if isinstance(stdout, str):
                stdout = stdout.encode("utf-8", "replace")
    if len(stdout) > MAX_RESPONSE_BYTES:
        raise Refusal("remote result exceeded its size bound")
    if code != 0:
        # A bounded refusal envelope may be returned with the endpoint's
        # documented nonzero status. Never expose stderr or arbitrary output.
        # OpenSSH uses 255 for transport/authentication failure. Bytes may have
        # arrived before the channel failed, so even a valid refusal envelope
        # cannot prove that the remote process has exited.
        if code != 255:
            try:
                _parse_response(stdout)
            except Refusal as exc:
                if str(exc).startswith("remote refusal "):
                    raise Refusal(str(exc), remote_state="REMOTE_PROCESS_CONFIRMED_EXITED") from None
        raise Refusal("SSH or remote acquisition failed; remote process cleanup must be confirmed separately",
                      remote_state="REMOTE_STATE_UNKNOWN")
    provenance = {
        "ssh_destination": ssh_policy._AUTHORIZED_SSH_DESTINATION,
        "ssh_host_key_algorithm": host_identity["algorithm"],
        "ssh_host_key_sha256": host_identity["fingerprint"],
        "pinned_known_hosts_sha256": known_hosts_sha,
        "local_agent_available_to_ssh_client": True,
        "remote_agent_forwarding": False,
        "remote_process_state": "REMOTE_PROCESS_CONFIRMED_EXITED",
    }
    return stdout, provenance


def _validate_unsigned_record(raw: bytes, request_context: dict[str, Any]) -> dict[str, Any]:
    record = _parse_response(raw)
    exact = {
        "schema": "fk0957-unsigned-topology-acquisition-v1", "status": "ACQUIRED",
        "operation_id": request_context["operation_id"],
        "authorization_id": request_context["authorization_id"],
        "authorization_sha256": request_context["authorization_sha256"],
        "handoff_sha256": request_context["handoff_sha256"],
        "manifest_sha256": request_context["manifest_sha256"],
        "production_head": request_context["production_head"],
        "transaction_profile_sha256": request_context["transaction_profile_sha256"],
        "card_id": transport.CARD_ID, "adapter_serial": transport.ADAPTER_SERIAL,
        "usb_descriptor_serial": transport.USB_DESCRIPTOR_SERIAL, "physical_interface": "A",
        "descriptor_evidence_sha256": request_context["descriptor_sha256"],
        "trusted_signer_fingerprint": identity_gate.TRUSTED_SIGNER_FINGERPRINT_SHA256,
        "scan_a_tck_count": 591, "scan_b_tck_count": 586, "total_tck_count": 1177,
        "matched_device_count": 1, "opened_device_count": 1, "second_device_opened": False,
        "write_count": 0, "reset_count": 0, "program_count": 0, "jtag_operation_count": 1,
        "topology_discovery_only": True, "idcode_qualification_pass": False,
        "fpga_dna_observed": False, "loaded_image_identity_observed": False,
        "bitstream_identity_observed": False, "worktree_clean": True,
    }
    for field, expected in exact.items():
        if record.get(field) != expected or type(record.get(field)) is not type(expected):
            raise Refusal("remote unsigned result binding mismatch: " + field)
    if record.get("permit_nonce") != request_context["permit_nonce"]:
        raise Refusal("remote permit nonce does not match signed authorization")
    plan = topology.build_plan()
    if (record["scan_a_transaction_sha256"] != topology.scan_transaction_sha256(plan.scan_a_commands) or
            record["scan_b_transaction_sha256"] != topology.scan_transaction_sha256(plan.scan_b_commands)):
        raise Refusal("remote topology transaction hash mismatch")
    if type(record["observation_timestamp"]) is not str:
        raise Refusal("remote observation timestamp malformed")
    try:
        observed = datetime.fromisoformat(record["observation_timestamp"])
        auth_end = datetime.fromisoformat(request_context["expires_at"])
    except (ValueError, KeyError):
        raise Refusal("remote observation timestamp invalid") from None
    now = datetime.now(timezone.utc)
    if observed.tzinfo is None or auth_end.tzinfo is None or abs((now - observed.astimezone(timezone.utc)).total_seconds()) > 180 or observed.astimezone(timezone.utc) >= auth_end.astimezone(timezone.utc):
        raise Refusal("remote unsigned result stale or outside authorization window")
    if record["transport_source_sha256"] != transport.transport_source_sha256():
        raise Refusal("remote physical source provenance mismatch")
    expected_runtime = [
        {"logical_name": pin.name, "approved_path": str(pin.path), "expected_sha256": pin.sha256,
         "expected_build_id": pin.build_id, "soname": pin.soname,
         "loaded_object_realpath": str(pin.path)}
        for pin in transport.LIBRARY_PINS]
    if record["runtime_library_provenance"] != expected_runtime:
        raise Refusal("remote native runtime pin report mismatch")
    if (type(record["scan_a_raw_tdo_hex"]) is not str or
            type(record["scan_b_raw_tdo_hex"]) is not str or
            not re.fullmatch(r"[0-9a-f]+", record["scan_a_raw_tdo_hex"]) or
            not re.fullmatch(r"[0-9a-f]+", record["scan_b_raw_tdo_hex"])):
        raise Refusal("remote raw TDO encoding invalid")
    try:
        raw_a, raw_b = bytes.fromhex(record["scan_a_raw_tdo_hex"]), bytes.fromhex(record["scan_b_raw_tdo_hex"])
    except (TypeError, ValueError):
        raise Refusal("remote raw TDO encoding invalid") from None
    try:
        bits_a = topology.raw_tdo_bits(raw_a[:-1], raw_a[-1:])
        bits_b = topology.raw_tdo_bits(raw_b[:-1], raw_b[-1:])
        parsed = topology.parse_raw_tdo(bits_a, bits_b, plan.tdi_scans[0], plan.tdi_scans[1])
    except BaseException:
        raise Refusal("remote raw TDO validation failed") from None
    if parsed.status != "PARSED_RESET_DEFAULT_DR":
        raise Refusal("remote topology response is ambiguous")
    if (record["aggregate_dr_length"] != parsed.aggregate_dr_length or
            record["observed_taps_tdo_to_tdi"] != list(parsed.taps_tdo_to_tdi or ()) or
            record["raw_tdo_scan_a_bits_lsb_first"] != parsed.raw_tdo_scan_a_bits or
            record["raw_tdo_scan_b_bits_lsb_first"] != parsed.raw_tdo_scan_b_bits):
        raise Refusal("remote topology parse does not match raw captures")
    return record


def acquire_validate_sign_once(request_raw: bytes) -> dict[str, Any]:
    """One pinned SSH transaction; validate every byte before local signing."""
    context = _validated_local_context(request_raw)
    _consume_local_auth(context)
    unsigned_raw, ssh_provenance = _pinned_ssh(request_raw)
    record = _validate_unsigned_record(unsigned_raw, context)
    return signing._sign_validated_remote_record(record, ssh_provenance)
