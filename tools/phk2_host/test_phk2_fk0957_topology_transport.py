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
        if self.failure == "scan_a_read" and self.read_index < 2:
            raise OSError("secret=DO_NOT_REPORT path=/private/raw")
        if self.failure == "scan_b_read" and self.read_index >= 2:
            raise OSError("secret=DO_NOT_REPORT path=/private/raw")
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

    def native_backend(self, count=1, *, ports=None, vidpids=None):
        backend = object.__new__(transport._NativeLibFtdi)
        backend._ctx = ctypes.c_void_p(0x77)
        backend._opened = False
        backend._closed = False
        nodes = [transport._FtdiDeviceList() for _ in range(count)]
        devices = [0x1234 + index for index in range(count)]
        for index, node in enumerate(nodes):
            node.dev = ctypes.c_void_p(devices[index])
            node.next = ctypes.pointer(nodes[index + 1]) if index + 1 < count else transport._FtdiDeviceListPtr()
        self.native_nodes = tuple(nodes)
        port_rows = ports or [(9, 3 + index) for index in range(count)]
        id_rows = vidpids or [(transport.FTDI_VID, transport.FTDI_PID)] * count
        by_dev = dict(zip(devices, zip(port_rows, id_rows)))
        backend._list = transport._FtdiDeviceListPtr()
        backend._selected_dev = None
        backend._candidate = None
        backend._eligible_candidates = ()

        def find_all(ctx, output, vid, pid):
            ctypes.cast(output, ctypes.POINTER(transport._FtdiDeviceListPtr))[0] = (
                ctypes.pointer(nodes[0]) if nodes else transport._FtdiDeviceListPtr())
            return count

        def get_descriptor(dev, output):
            descriptor = ctypes.cast(output, ctypes.POINTER(transport._UsbDeviceDescriptor)).contents
            _ports, (descriptor.idVendor, descriptor.idProduct) = by_dev[int(dev)]
            return 0

        def get_ports(dev, output, maximum):
            port_row, _ids = by_dev[int(dev)]
            for index, value in enumerate(port_row):
                output[index] = value
            return len(port_row)

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

    def native_rows_for_serials(self, serials, *, ports=None, vidpids=None, permit=None,
                                interfaces=None):
        permit = permit or self.permit()
        ports = ports or [(9, 3 + index) for index in range(len(serials))]
        serial_by_path = {"1-" + ".".join(map(str, port)): serial
                          for port, serial in zip(ports, serials)}
        native = self.native_backend(len(serials), ports=ports, vidpids=vidpids)

        def identity_for(path, _descriptor):
            serial = serial_by_path[path]
            if path == permit.identity.usb_path and serial == "153300000957":
                identity = permit.identity
            else:
                identity = topology.DescriptorIdentity(
                    "FK0957", "153300000957A", serial, path, "0403", "6010",
                    "Xilinx", "SQRL FK", "A")
            if interfaces and path in interfaces:
                identity = topology.DescriptorIdentity(**{
                    **identity.__dict__, "interface": interfaces[path]})
            return identity

        with mock.patch.object(transport, "_serial_for_candidate",
                               side_effect=lambda path, _descriptor: serial_by_path.get(path)), \
             mock.patch.object(transport, "_identity_from_sysfs", side_effect=identity_for):
            rows = native.enumerate_candidates()
        return permit, native, rows

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
        with mock.patch.object(transport, "_serial_for_candidate",
                               return_value="153300000957") as serial, \
             mock.patch.object(transport, "_identity_from_sysfs",
                               return_value=expected_identity) as sysfs:
            rows = native.enumerate_candidates()
        serial.assert_called_once_with("1-9.3", mock.ANY)
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
            with self.subTest(count=count):
                with mock.patch.object(transport, "_serial_for_candidate",
                                       return_value="153300000957") as serial, \
                     mock.patch.object(transport, "_identity_from_sysfs",
                                       return_value=self.backend().candidate.identity) as sysfs:
                    rows = native.enumerate_candidates()
                self.assertEqual(len(rows), count)
                if count != 1:
                    with self.assertRaises((transport.Refusal, topology.Refusal)):
                        topology.validate_candidates(self.permit(), rows)
                if count == 0:
                    serial.assert_not_called()
                    sysfs.assert_not_called()
                native._ftdi.ftdi_usb_open_dev.assert_not_called()

    def test_native_enumeration_filters_peer_serial_before_multiplicity(self):
        target = "153300000957"
        peer = "153300000958"
        scenarios = (
            ((target,), ((9, 3),), ((transport.FTDI_VID, transport.FTDI_PID),), True),
            ((target, peer), ((9, 3), (9, 4)), None, True),
            ((peer, target), ((9, 4), (9, 3)), None, True),
            ((peer, "153300000959", target), ((9, 4), (9, 5), (9, 3)), None, True),
            ((peer,), ((9, 4),), None, False),
            ((target, target), ((9, 3), (9, 6)), None, False),
            ((target,), ((9, 3),), ((transport.FTDI_VID, transport.FTDI_PID + 1),), False),
            (("x" + target, target + "A", target + "0"),
             ((9, 4), (9, 5), (9, 6)), None, False),
            ((None, peer), ((9, 7), (9, 4)), None, False),
        )
        for serials, ports, vidpids, should_select in scenarios:
            permit = self.permit()
            _permit, native, rows = self.native_rows_for_serials(
                serials, ports=ports, vidpids=vidpids, permit=permit)
            with self.subTest(serials=serials, ports=ports):
                if should_select:
                    selected = topology.validate_candidates(permit, rows)
                    self.assertEqual(selected.identity, permit.identity)
                    exact_index = serials.index(target)
                    self.assertEqual(int(selected.handle_token), 0x1234 + exact_index)
                    native.open_exact(selected)
                    native._ftdi.ftdi_set_interface.assert_called_once_with(
                        native._ctx, transport.FTDI_INTERFACE_A)
                    native._ftdi.ftdi_usb_open_dev.assert_called_once_with(
                        native._ctx, 0x1234 + exact_index)
                else:
                    with self.assertRaises((transport.Refusal, topology.Refusal)):
                        topology.validate_candidates(permit, rows)
                    self.assertEqual(native._ftdi.ftdi_usb_open_dev.call_count, 0)

    def test_exact_serial_wrong_interface_refuses_and_peer_is_ineligible_to_open(self):
        permit = self.permit()
        _permit, native, rows = self.native_rows_for_serials(
            ("153300000957",), ports=((9, 3),), permit=permit,
            interfaces={"1-9.3": "B"})
        with self.assertRaises((transport.Refusal, topology.Refusal)):
            topology.validate_candidates(permit, rows)
        native._ftdi.ftdi_usb_open_dev.assert_not_called()

        permit = self.permit()
        _permit, native, rows = self.native_rows_for_serials(
            ("153300000958", "153300000957"), ports=((9, 4), (9, 3)), permit=permit)
        selected = topology.validate_candidates(permit, rows)
        peer_candidate = topology.Candidate(
            topology.DescriptorIdentity("FK0957", "153300000957A", "153300000958",
                "1-9.4", "0403", "6010", "Xilinx", "SQRL FK", "A"), 0x1234)
        with self.assertRaises(transport.Refusal):
            native.open_exact(peer_candidate)
        self.assertEqual(int(selected.handle_token), 0x1235)
        native._ftdi.ftdi_usb_open_dev.assert_not_called()

    def test_serial_sysfs_filter_preserves_exact_value_and_rejects_malformed_values(self):
        descriptor = transport._UsbDeviceDescriptor()
        descriptor.idVendor = transport.FTDI_VID
        descriptor.idProduct = transport.FTDI_PID
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sysfs = root / "1-9.3"
            sysfs.mkdir()
            (sysfs / "idVendor").write_text("0403\n")
            (sysfs / "idProduct").write_text("6010\n")
            with mock.patch.object(transport, "SYSFS_USB_ROOT", root):
                for raw, expected in (("153300000957\n", "153300000957"),
                                      (" 153300000957\n", " 153300000957"),
                                      ("153300000957 \n", "153300000957 "),
                                      ("153300000957A\n", "153300000957A"),
                                      ("1533000009570\n", "1533000009570"),
                                      ("\xff\n", None), ("\n", None),
                                      ("153300000957\x00\n", None)):
                    (sysfs / "serial").write_bytes(raw.encode("latin-1"))
                    actual = transport._serial_for_candidate("1-9.3", descriptor)
                    self.assertEqual(actual, expected)
                self.assertEqual(transport._serial_for_candidate("1-9.3", descriptor), None)

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
            with self.assertRaises(transport.Refusal) as replay:
                transport._run_with_backend(permit, self.backend())
            self.assertEqual(json.loads(replay.exception.canonical_envelope())["permit_consumed"], 1)
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

        trace = transport._AttemptTrace()
        trace.phase = "SCAN_A_WRITE"
        native._trace = trace
        native._ftdi = SimpleNamespace(ftdi_write_data=mock.Mock(side_effect=(5, 0)))
        with self.assertRaises(transport.Refusal):
            native.write_exact(bytes.fromhex("39 03 00 11 22 33 44"))
        self.assertEqual(trace.scan_a_tck_emitted, 16)
        self.assertEqual(trace.refuse().envelope.scan_a_tck_emitted, 16)

    def test_refusal_envelope_is_canonical_bounded_and_phase_specific(self):
        cases = (
            ((), "DEVICE_SELECTION", "NO_TARGET_CANDIDATE"),
            ((self.backend().candidate, self.backend().candidate),
             "DEVICE_SELECTION", "MULTIPLE_TARGET_CANDIDATES"),
        )
        for candidates, phase, code in cases:
            permit = self.permit()
            backend = self.backend(candidates=candidates)
            with self.subTest(code=code), self.assertRaises(transport.Refusal) as caught:
                transport._run_with_backend(permit, backend)
            refusal = caught.exception
            envelope = json.loads(refusal.canonical_envelope())
            self.assertEqual(set(envelope), {
                "status", "phase", "code", "evidence_path", "signature_verified",
                "return_code", "target_candidates", "device_opened", "scan_a_started",
                "scan_a_tck_emitted", "scan_b_started", "scan_b_tck_emitted",
                "transport_closed", "permit_consumed",
            })
            self.assertEqual(envelope["status"], "REFUSED")
            self.assertEqual(envelope["evidence_path"], "none")
            self.assertIs(envelope["signature_verified"], False)
            self.assertEqual((envelope["phase"], envelope["code"]), (phase, code))
            self.assertEqual(envelope["permit_consumed"], 1)
            self.assertNotIn("reason", envelope)
            self.assertNotIn("path", envelope)
            self.assertNotIn("stderr", envelope)
            self.assertNotIn("secret", refusal.canonical_envelope().decode())
            self.assertEqual(backend.open_count, 0)

        phases = (
            ("open", "DEVICE_OPEN", "DEVICE_OPEN_FAILED"),
            ("initialize", "MPSSE_INIT", "MPSSE_INIT_FAILED"),
            ("scan_a", "SCAN_A_WRITE", "SCAN_A_WRITE_FAILED"),
            ("scan_a_read", "SCAN_A_READ", "SCAN_A_READ_FAILED"),
            ("scan_b", "SCAN_B_WRITE", "SCAN_B_WRITE_FAILED"),
            ("scan_b_read", "SCAN_B_READ", "SCAN_B_READ_FAILED"),
            ("close", "TRANSPORT_CLOSE", "TRANSPORT_CLOSE_FAILED"),
        )
        for failure, phase, code in phases:
            permit = self.permit()
            backend = self.backend(failure=None if failure == "close" else failure,
                                   close_failure=failure == "close")
            with self.subTest(failure=failure), self.assertRaises(transport.Refusal) as caught:
                transport._run_with_backend(permit, backend)
            envelope = json.loads(caught.exception.canonical_envelope())
            self.assertEqual((envelope["phase"], envelope["code"]), (phase, code))
            self.assertNotIn("secret", caught.exception.canonical_envelope().decode())
            with self.assertRaises(transport.Refusal) as replay:
                transport._run_with_backend(permit, self.backend())
            self.assertEqual(json.loads(replay.exception.canonical_envelope())["permit_consumed"], 1)

    def test_permit_library_descriptor_and_local_validation_refusals_are_bounded(self):
        with self.assertRaises(transport.Refusal) as invalid:
            transport.run_fk0957_topology_discovery(object())
        env = json.loads(invalid.exception.canonical_envelope())
        self.assertEqual((env["phase"], env["code"]), ("PERMIT_VALIDATION", "PERMIT_INVALID"))
        self.assertEqual(env["permit_consumed"], "unknown")

        with self.assertRaises(transport.Refusal) as stale:
            transport.issue_fk0957_topology_permit(b"not descriptor", "0" * 64)
        env = json.loads(stale.exception.canonical_envelope())
        self.assertEqual((env["phase"], env["code"]), ("PERMIT_VALIDATION", "DESCRIPTOR_STALE"))
        self.assertEqual(env["permit_consumed"], 0)

        permit = self.permit()
        with mock.patch.object(transport, "transport_source_sha256",
                               side_effect=transport.Refusal("secret path /private/native.so")):
            with self.assertRaises(transport.Refusal) as library:
                transport.run_fk0957_topology_discovery(permit)
        env = json.loads(library.exception.canonical_envelope())
        self.assertEqual((env["phase"], env["code"]),
                         ("LIBRARY_PROVENANCE", "LIBRARY_PIN_MISMATCH"))
        self.assertEqual(env["permit_consumed"], 1)
        self.assertNotIn("private", library.exception.canonical_envelope().decode())

        permit = self.permit()
        result = transport._run_with_backend(permit, self.backend())
        with mock.patch.object(transport.topology, "parse_raw_tdo",
                               side_effect=topology.Refusal("secret stderr /unsafe/path")):
            with self.assertRaises(transport.Refusal) as validation:
                transport.validate_transport_observation(permit, result)
        env = json.loads(validation.exception.canonical_envelope())
        self.assertEqual((env["phase"], env["code"]),
                         ("LOCAL_VALIDATION", "LOCAL_VALIDATION_FAILED"))
        self.assertNotIn("unsafe", validation.exception.canonical_envelope().decode())

        permit = self.permit()
        result = transport._run_with_backend(permit, self.backend())
        with mock.patch.object(transport, "_read_local_private_key",
                               side_effect=transport.Refusal("secret key /private/key.pem")):
            with self.assertRaises(transport.Refusal) as signing:
                transport.sign_local_discovery_record(permit, result)
        env = json.loads(signing.exception.canonical_envelope())
        self.assertEqual((env["phase"], env["code"]),
                         ("LOCAL_SIGNING", "LOCAL_SIGNING_FAILED"))
        self.assertNotIn("private", signing.exception.canonical_envelope().decode())
        self.assertNotIn("signature_hex", env)

    def test_one_shot_workflow_orders_validate_before_local_sign_and_never_retries(self):
        events = []
        permit = object()
        result = object()
        with mock.patch.object(transport, "issue_fk0957_topology_permit",
                               side_effect=lambda *_a, **_k: events.append("permit") or permit), \
             mock.patch.object(transport, "run_fk0957_topology_discovery",
                               side_effect=lambda _p: events.append("acquire") or result) as acquire, \
             mock.patch.object(transport, "validate_transport_observation",
                               side_effect=lambda *_a: events.append("validate")), \
             mock.patch.object(transport, "sign_local_discovery_record",
                               side_effect=lambda *_a: events.append("sign") or {"signed": True}):
            envelope = transport.perform_fk0957_topology_discovery_once(b"descriptor", "a" * 64)
        self.assertEqual(events, ["permit", "acquire", "validate", "sign"])
        self.assertEqual(acquire.call_count, 1)
        self.assertEqual(envelope, {"signed": True})

        events.clear()
        failure = transport.Refusal("untrusted secret text")
        with mock.patch.object(transport, "issue_fk0957_topology_permit",
                               return_value=permit), \
             mock.patch.object(transport, "run_fk0957_topology_discovery",
                               side_effect=failure) as acquire, \
             mock.patch.object(transport, "validate_transport_observation") as validate, \
             mock.patch.object(transport, "sign_local_discovery_record") as sign:
            with self.assertRaises(transport.Refusal) as caught:
                transport.perform_fk0957_topology_discovery_once(b"descriptor", "a" * 64)
        self.assertEqual(acquire.call_count, 1)
        validate.assert_not_called()
        sign.assert_not_called()
        self.assertEqual(json.loads(caught.exception.canonical_envelope())["status"], "REFUSED")

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
