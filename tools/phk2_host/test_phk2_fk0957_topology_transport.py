from __future__ import annotations

from datetime import datetime, timedelta, timezone
import ctypes
from dataclasses import replace
import hashlib
import inspect
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import phk2_fk0957_topology_discovery as topology
import phk2_fk0957_topology_transport as transport

DESCRIPTOR = Path("/home/rmann/.local/share/sidecar/fk0957-descriptor-identity-20261112.json")


def pack_raw(bits: str) -> tuple[bytes, bytes]:
    packed = bytearray((len(bits) + 7) // 8)
    for i, bit in enumerate(bits):
        packed[i // 8] |= int(bit) << (i % 8)
    return bytes(packed[:-1]), bytes(((packed[-1] & 1) << 7,))


def response_for(pattern: tuple[int, ...]) -> tuple[bytes, bytes]:
    # Synthetic single IDCODE reset capture, followed by the actual shifted TDI.
    idcode = 0x04B69093
    captured = "".join(str((idcode >> i) & 1) for i in range(32))
    bits = captured + "".join(map(str, pattern[:len(pattern) - 32]))
    return pack_raw(bits)


class FakeBackend:
    def __init__(self, candidates=None, *, failure=None, short_read=False,
                 oversized_read=False, close_failure=False):
        self.candidates = candidates
        self.failure = failure
        self.short_read = short_read
        self.oversized_read = oversized_read
        self.close_failure = close_failure
        self.events = []
        self.writes = []
        self.reads = []
        self.read_index = 0
        self.reads = []
        self.open_count = 0
        self.close_count = 0
        self._runtime = {}
        for pin in transport.LIBRARY_PINS:
            fingerprint = transport._stat_fingerprint(pin.path.stat())
            self._runtime[pin.name] = transport._LoadedLibrary(
                pin, None, -1, fingerprint, fingerprint, str(pin.path))
        self.candidate = topology.Candidate(
            topology.DescriptorIdentity("FK0957", "153300000957A", "153300000957",
                "1-9.3", "0403", "6010", "Xilinx", "SQRL FK", "A"), object())

    def _fail(self, phase):
        if self.failure == phase:
            raise OSError("synthetic transport failure with secret=NEVER-LEAK")

    def enumerate_candidates(self):
        self.events.append("enumerate")
        self._fail("enumerate")
        return (self.candidate,) if self.candidates is None else tuple(self.candidates)

    def open_exact(self, candidate):
        self.events.append("open")
        self._fail("open")
        if candidate is not self.candidate:
            raise AssertionError("opened an unselected candidate")
        self.open_count += 1

    def initialize_mpsse(self):
        self.events.append("initialize")
        self._fail("initialize")
        self.write_exact(topology.MPSSE_SYNC)
        if self.read_exact(2) != topology.MPSSE_SYNC_REPLY:
            raise AssertionError("MPSSE sync fake mismatch")
        self.write_exact(topology.MPSSE_SETUP)

    def write_exact(self, data):
        self.writes.append(bytes(data))
        self.events.append("write")
        # Sync and setup are followed by SCAN A then SCAN B writes.
        if self.failure == "scan_a" and len(self.writes) == 6:
            self._fail("scan_a")
        if self.failure == "between_scans" and len(self.writes) == 7:
            self._fail("between_scans")
        if self.failure == "scan_b" and len(self.writes) == 9:
            self._fail("scan_b")

    def read_exact(self, size):
        self.events.append("read")
        self.reads.append(size)
        self._fail("read")
        if size == 2:  # MPSSE sync only
            return topology.MPSSE_SYNC_REPLY
        responses = (response_for(topology.tdi_pattern()), response_for(topology.tdi_pattern_b()))
        value = responses[self.read_index // 2][0 if self.read_index % 2 == 0 else 1]
        self.read_index += 1
        if self.short_read:
            return value[:-1]
        if self.oversized_read:
            return value + b"x"
        return value

    def close_checked(self):
        self.events.append("close")
        self.close_count += 1
        if self.close_failure:
            raise OSError("synthetic close failure")


class TopologyTransportTests(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self.signing_key = Ed25519PrivateKey.generate()
        der = self.signing_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.fingerprint = hashlib.sha256(der).hexdigest()
        import base64
        self._pins = [
            mock.patch.object(transport.identity_gate, "TRUSTED_SIGNER_PUBLIC_DER_B64",
                             base64.b64encode(der).decode()),
            mock.patch.object(transport.identity_gate, "TRUSTED_SIGNER_FINGERPRINT_SHA256", self.fingerprint),
            mock.patch.object(transport.identity_gate, "_trusted_signer", return_value=self.signing_key.public_key()),
        ]
        for patcher in self._pins:
            patcher.start()
            self.addCleanup(patcher.stop)
        original = __import__("json").loads(DESCRIPTOR.read_bytes())
        payload = original["payload"]
        unsigned = payload["unsigned_evidence"]
        unsigned["acquisition_timestamp"] = datetime.now(timezone.utc).isoformat()
        provenance = payload["provenance"]
        provenance["acquisition_timestamp"] = unsigned["acquisition_timestamp"]
        provenance["raw_unsigned_sha256"] = transport.orchestrator.sha(
            transport.orchestrator.canonical(unsigned) + b"\n")
        encoded = transport.orchestrator.canonical(payload)
        self.raw = transport.orchestrator.canonical({
            "payload": payload,
            "payload_sha256": hashlib.sha256(encoded).hexdigest(),
            "signature_algorithm": "Ed25519",
            "signature_hex": self.signing_key.sign(encoded).hex(),
        })
        self.digest = hashlib.sha256(self.raw).hexdigest()

    def permit(self):
        return topology.issue_permit(self.raw, self.digest)

    def backend(self, **kwargs):
        return FakeBackend(**kwargs)

    def native_backend(self, count=1):
        backend = object.__new__(transport._NativeLibFtdi)
        backend._ctx = ctypes.c_void_p(0x77)
        backend._opened = False
        backend._closed = False
        first = transport._FtdiDeviceList()
        first.dev = ctypes.c_void_p(0x1234)
        second = transport._FtdiDeviceList()
        second.dev = ctypes.c_void_p(0x5678)
        first.next = ctypes.pointer(second) if count > 1 else transport._FtdiDeviceListPtr()
        self.native_nodes = (first, second)
        backend._list = transport._FtdiDeviceListPtr()
        backend._selected_dev = None
        backend._candidate = None

        def find_all(ctx, output, vid, pid):
            ctypes.cast(output, ctypes.POINTER(transport._FtdiDeviceListPtr))[0] = ctypes.pointer(first)
            return count

        def get_descriptor(dev, output):
            descriptor = ctypes.cast(output, ctypes.POINTER(transport._UsbDeviceDescriptor)).contents
            descriptor.idVendor = transport.FTDI_VID
            descriptor.idProduct = transport.FTDI_PID
            return 0

        def get_ports(dev, output, maximum):
            output[0], output[1] = 9, 3
            return 2

        backend._ftdi = SimpleNamespace(
            ftdi_usb_find_all=mock.Mock(side_effect=find_all),
            ftdi_list_free=mock.Mock(),
            ftdi_set_interface=mock.Mock(return_value=0),
            ftdi_usb_open_dev=mock.Mock(return_value=0),
        )
        backend._usb = SimpleNamespace(
            libusb_get_device_descriptor=mock.Mock(side_effect=get_descriptor),
            libusb_get_bus_number=mock.Mock(return_value=1),
            libusb_get_port_numbers=mock.Mock(side_effect=get_ports),
        )
        return backend

    def run_fake(self, backend=None):
        b = backend or self.backend()
        result = transport._run_with_backend(self.permit(), b)
        return b, result

    def test_public_api_is_one_permit_and_no_generic_scan_surface(self):
        self.assertEqual(tuple(inspect.signature(transport.run_fk0957_topology_discovery).parameters),
                         ("authorized_permit",))
        for forbidden in ("shift_ir", "shift_dr", "execute_scan", "generic_mpsse", "sign_remote"):
            self.assertFalse(hasattr(transport, forbidden))

    def test_golden_transactions_counts_bytes_reads_and_close(self):
        backend, result = self.run_fake()
        plan = topology.build_plan()
        self.assertEqual((plan.scan_a_tck_count, plan.scan_b_tck_count, plan.tck_count), (591, 586, 1177))
        self.assertEqual(transport.GOLDEN_SCAN_A_SHA256, topology.scan_transaction_sha256(plan.scan_a_commands))
        self.assertEqual(transport.GOLDEN_SCAN_B_SHA256, topology.scan_transaction_sha256(plan.scan_b_commands))
        self.assertEqual(tuple(backend.writes), tuple(c.write for c in plan.commands))
        self.assertEqual(backend.reads, [2, 72, 1, 72, 1])
        self.assertEqual(backend.read_index, 4)
        self.assertEqual(len(result.scan_a_raw_tdo), 73)
        self.assertEqual(len(result.scan_b_raw_tdo), 73)
        self.assertEqual(result.scan_a_transaction_sha256, transport.GOLDEN_SCAN_A_SHA256)
        self.assertEqual(result.scan_b_transaction_sha256, transport.GOLDEN_SCAN_B_SHA256)
        self.assertEqual((backend.open_count, backend.close_count), (1, 1))
        self.assertEqual(backend.events[-1], "close")

    def test_exact_candidate_binding_happens_before_open(self):
        backend = self.backend()
        original = backend.open_exact
        def check(candidate):
            self.assertEqual(candidate.identity.usb_descriptor_serial, "153300000957")
            self.assertEqual(candidate.identity.interface, "A")
            original(candidate)
        backend.open_exact = check
        permit = self.permit()
        result = transport._run_with_backend(permit, backend)
        self.assertEqual(backend.events.index("enumerate") < backend.events.index("open"), True)
        self.assertEqual(result.usb_descriptor_serial, "153300000957")

    def test_native_enumerator_resolves_sysfs_identity_before_exact_pointer_open(self):
        native = self.native_backend(1)
        expected_identity = self.backend().candidate.identity
        with mock.patch.object(transport, "_identity_from_sysfs", return_value=expected_identity) as sysfs:
            rows = native.enumerate_candidates()
        sysfs.assert_called_once_with("1-9.3", mock.ANY)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].identity, expected_identity)
        native.open_exact(rows[0])
        native._ftdi.ftdi_set_interface.assert_called_once_with(native._ctx, transport.FTDI_INTERFACE_A)
        native._ftdi.ftdi_usb_open_dev.assert_called_once_with(native._ctx, 0x1234)
        self.assertTrue(native._ftdi.ftdi_set_interface.called)
        self.assertTrue(native._ftdi.ftdi_usb_open_dev.called)
        self.assertFalse(hasattr(native._ftdi, "ftdi_usb_get_strings"))

    def test_native_enumerator_zero_or_multiple_candidates_never_opens(self):
        for count in (0, 2):
            native = self.native_backend(count)
            with self.subTest(count=count), mock.patch.object(transport, "_identity_from_sysfs") as sysfs:
                with self.assertRaises(transport.Refusal):
                    native.enumerate_candidates()
                sysfs.assert_not_called()
                native._ftdi.ftdi_usb_open_dev.assert_not_called()

    def test_zero_duplicate_wrong_and_peer_candidates_fail_before_open(self):
        good = self.backend().candidate
        bad_identity = topology.DescriptorIdentity("FK0957", "153300000957A", "153300000958",
            "1-9.3", "0403", "6010", "Xilinx", "SQRL FK", "A")
        bad = topology.Candidate(bad_identity, object())
        for candidates in ((), (good, good), (bad,), (good, bad)):
            backend = self.backend(candidates=candidates)
            with self.subTest(count=len(candidates)), self.assertRaises(transport.Refusal):
                transport._run_with_backend(self.permit(), backend)
            self.assertEqual(backend.open_count, 0)
            self.assertEqual(backend.close_count, 1)

    def test_wrong_vid_pid_interface_and_adapter_mapping_refuse_preopen(self):
        base = self.backend().candidate
        for field, value in (("vid", "0404"), ("pid", "6011"), ("interface", "B"),
                             ("adapter_serial", "wrong"), ("usb_descriptor_serial", "153300000957A")):
            ident = base.identity.__class__(**{**base.identity.__dict__, field: value})
            backend = self.backend(candidates=(topology.Candidate(ident, object()),))
            with self.subTest(field=field), self.assertRaises(transport.Refusal):
                transport._run_with_backend(self.permit(), backend)
            self.assertEqual(backend.open_count, 0)

    def test_plan_mutation_and_environment_substitution_fail_before_enumeration(self):
        backend = self.backend()
        plan = topology.build_plan()
        altered = topology.DiscoveryPlan(**{**plan.__dict__, "tck_count": 1178})
        with mock.patch.object(topology, "build_plan", return_value=altered):
            with self.assertRaises(transport.Refusal):
                transport._run_with_backend(self.permit(), backend)
        self.assertNotIn("enumerate", backend.events)
        command = plan.scan_a_commands[2]
        changed_command = topology.Command(command.write, 71, command.tck_count,
                                           command.label, command.scan)
        changed_a = plan.scan_a_commands[:2] + (changed_command,) + plan.scan_a_commands[3:]
        changed_commands = tuple(changed_command if c is command else c for c in plan.commands)
        altered_reads = topology.DiscoveryPlan(**{
            **plan.__dict__, "commands": changed_commands, "scan_a_commands": changed_a})
        with mock.patch.object(topology, "build_plan", return_value=altered_reads):
            with self.assertRaises(transport.Refusal):
                transport._run_with_backend(self.permit(), self.backend())
        with mock.patch.dict(os.environ, {"FTDI_SERIAL": "attacker", "FTDI_INTERFACE": "B",
                                          "PHK2_TMS": "arbitrary", "PHK2_DR_LENGTH": "1"}):
            backend, result = self.run_fake()
        self.assertEqual(result.usb_descriptor_serial, "153300000957")

    def test_short_reads_and_transport_failures_close_and_consume_permit(self):
        phases = ("enumerate", "open", "initialize", "scan_a", "between_scans", "scan_b", "read")
        for phase in phases:
            backend = self.backend(failure=phase)
            permit = self.permit()
            with self.subTest(phase=phase), self.assertRaises(transport.Refusal):
                transport._run_with_backend(permit, backend)
            self.assertEqual(backend.close_count, 1)
            with self.assertRaises(topology.Refusal):
                transport._run_with_backend(permit, self.backend())
        backend = self.backend(short_read=True)
        with self.assertRaises(transport.Refusal):
            transport._run_with_backend(self.permit(), backend)
        self.assertEqual(backend.close_count, 1)
        backend = self.backend(oversized_read=True)
        with self.assertRaises(transport.Refusal):
            transport._run_with_backend(self.permit(), backend)
        self.assertEqual(backend.close_count, 1)

    def test_close_failure_and_observation_tampering_refuse(self):
        backend = self.backend(close_failure=True)
        with self.assertRaises(transport.Refusal):
            transport._run_with_backend(self.permit(), backend)
        backend, result = self.run_fake()
        altered = transport.TransportObservation(**{**result.__dict__, "scan_a_tck_count": 590})
        with self.assertRaises(transport.Refusal):
            transport.validate_transport_observation(self.permit(), altered)
        altered_tdo = transport.TransportObservation(**{
            **result.__dict__, "scan_a_raw_tdo": result.scan_a_raw_tdo[::-1]})
        with self.assertRaises(transport.Refusal):
            transport.validate_transport_observation(self.permit(), altered_tdo)
        caller_fabricated = transport.TransportObservation(**{
            **result.__dict__, "_proof": object()})
        with self.assertRaises(transport.Refusal):
            transport.validate_transport_observation(self.permit(), caller_fabricated)

    def test_post_transport_permit_field_replacement_refuses_before_signing(self):
        permit = self.permit()
        result = transport._run_with_backend(permit, self.backend())
        extended = replace(permit, expires_at=(datetime.now(timezone.utc) +
                                                timedelta(days=30)).isoformat())
        with self.assertRaises(transport.Refusal):
            transport.validate_transport_observation(extended, result)
        changed_nonce = replace(permit, nonce="f" * 64)
        with self.assertRaises(transport.Refusal):
            transport.validate_transport_observation(changed_nonce, result)

    def test_native_exact_io_loops_partial_and_refuses_nonprogress_or_overcount(self):
        native = object.__new__(transport._NativeLibFtdi)
        native._opened = True
        native._ctx = ctypes.c_void_p(0x77)
        sent = bytearray()

        def partial_write(ctx, buf, size):
            count = min(2, size)
            sent.extend(bytes(buf[:count]))
            return count

        native._ftdi = SimpleNamespace(ftdi_write_data=mock.Mock(side_effect=partial_write))
        native.write_exact(b"abcdef")
        self.assertEqual(bytes(sent), b"abcdef")
        self.assertEqual(native._ftdi.ftdi_write_data.call_count, 3)

        for bad_count in (0, -1, 7):
            native._ftdi.ftdi_write_data = mock.Mock(return_value=bad_count)
            with self.subTest(write_result=bad_count), self.assertRaises(transport.Refusal):
                native.write_exact(b"abcdef")

        payload = iter((b"ab", b"cd", b"ef"))

        def partial_read(ctx, buf, size):
            chunk = next(payload)
            count = min(len(chunk), size)
            for index, value in enumerate(chunk[:count]):
                buf[index] = value
            return count

        native._ftdi = SimpleNamespace(ftdi_read_data=mock.Mock(side_effect=partial_read))
        self.assertEqual(native.read_exact(6), b"abcdef")
        self.assertEqual(native._ftdi.ftdi_read_data.call_count, 3)
        for bad_count in (0, -1, 7):
            native._ftdi.ftdi_read_data = mock.Mock(return_value=bad_count)
            with self.subTest(read_result=bad_count), self.assertRaises(transport.Refusal):
                native.read_exact(6)

    def test_local_record_builder_signs_only_after_valid_transport(self):
        from cryptography.hazmat.primitives import serialization
        key = self.signing_key
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
        permit = self.permit()
        result = transport._run_with_backend(permit, self.backend())
        with tempfile.TemporaryDirectory() as directory:
            key_path = Path(directory) / "key.pem"
            key_path.write_bytes(pem)
            key_path.chmod(0o600)
            with mock.patch.object(transport, "LOCAL_SIGNING_KEY_PATH", key_path):
                envelope = transport.sign_local_discovery_record(permit, result)
                self.assertEqual(envelope["signer_fingerprint"], self.fingerprint)
                encoded_record = transport.orchestrator.canonical(envelope["payload"])
                self.assertEqual(hashlib.sha256(encoded_record).hexdigest(), envelope["payload_sha256"])
                key.public_key().verify(bytes.fromhex(envelope["signature_hex"]), encoded_record)
                record = envelope["payload"]
                self.assertTrue(record["topology_discovery_only"])
                self.assertFalse(record["idcode_qualification_pass"])
                self.assertFalse(record["fpga_dna_observed"])
                self.assertFalse(record["loaded_image_identity_observed"])
                self.assertFalse(record["bitstream_identity_observed"])


if __name__ == "__main__":
    unittest.main()
