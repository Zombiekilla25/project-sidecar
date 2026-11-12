from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
import hashlib
import inspect
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import phk2_fk0957_idcode_gate as identity_gate
import phk2_fk0957_topology_discovery as topo

DESCRIPTOR = Path("/home/rmann/.local/share/sidecar/fk0957-descriptor-identity-20261112.json")


def pack_lsb(bits):
    out = bytearray((len(bits) + 7) // 8)
    for index, bit in enumerate(bits):
        out[index // 8] |= int(bit) << (index % 8)
    return bytes(out)


def capture_bits(devices, pattern):
    """TDO-nearest first; synthetic reset-default IDCODE/BYPASS contents."""
    captured = []
    for kind, value in devices:
        if kind == "BYPASS":
            captured.append(0)
        else:
            captured.extend((value >> bit) & 1 for bit in range(32))
    if not captured or len(captured) > topo.MAX_DEFAULT_DR_BITS:
        raise ValueError("fixture outside bounded census")
    full = captured + list(pattern[:topo.CAPTURE_BITS - len(captured)])
    return "".join(map(str, full))


def fixture_scans(devices):
    return (capture_bits(devices, topo.tdi_pattern()),
            capture_bits(devices, topo.tdi_pattern_b()))


class FakeTransport:
    def __init__(self, rows, result=None, error=None):
        self.rows = tuple(rows)
        self.result = result
        self.error = error
        self.open_count = 0
        self.close_count = 0
        self.plan = None

    def enumerate_candidates(self):
        return self.rows

    def open_exact(self, handle):
        self.open_count += 1
        owner = self
        class Opened:
            def execute_fixed_plan(self, plan):
                owner.plan = plan
                if owner.error:
                    raise owner.error
                bits_a, bits_b = owner.result
                return (pack_lsb(bits_a[:-1]), bytes(((int(bits_a[-1]) << 7,))),
                        pack_lsb(bits_b[:-1]), bytes(((int(bits_b[-1]) << 7,))))
            def close(self):
                owner.close_count += 1
        return Opened()


class TopologyDiscoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = DESCRIPTOR.read_bytes()
        cls.digest = hashlib.sha256(cls.raw).hexdigest()
        cls.document = json.loads(cls.raw)
        stamp = identity_gate._timestamp(cls.document["payload"]["unsigned_evidence"]["acquisition_timestamp"])
        cls.clock = mock.patch.object(identity_gate, "datetime", type("Clock", (), {
            "now": staticmethod(lambda tz=None: stamp + timedelta(seconds=1)),
            "fromisoformat": staticmethod(__import__("datetime").datetime.fromisoformat)}))

    def setUp(self):
        self.clock_ctx = self.clock
        self.clock_ctx.start()
        self.addCleanup(self.clock_ctx.stop)
        self.permit = topo.issue_permit(self.raw, self.digest)
        self.identity = self.permit.identity
        self.candidate = topo.Candidate(self.identity, object())

    def fresh_permit(self):
        self.permit = topo.issue_permit(self.raw, self.digest)
        self.identity = self.permit.identity
        self.candidate = topo.Candidate(self.identity, object())

    def run_devices(self, devices):
        if self.permit._token in topo._CONSUMED:
            self.fresh_permit()
        result = fixture_scans(devices)
        transport = FakeTransport((self.candidate,), result)
        parsed, raw_pair = topo._run_mock_transport(self.permit, transport)
        self.assertEqual(transport.open_count, 1)
        self.assertEqual(transport.close_count, 1)
        return parsed, raw_pair, transport

    def test_literal_mpsse_plan_and_fixed_bounds(self):
        plan = topo.build_plan()
        self.assertEqual(topo.MPSSE_SETUP, bytes.fromhex("97 8a 86 2b 01 85 80 08 0b"))
        self.assertEqual(plan.tck_count, 1177)
        self.assertEqual(plan.scan_a_tck_count, 591)
        self.assertEqual(plan.scan_b_tck_count, 586)
        self.assertEqual(len(plan.tdi_bits), 1177)
        self.assertEqual(len(plan.tms_bits), 1177)
        self.assertEqual([c.write[0] for c in plan.commands if c.tck_count],
                         [0x4B, 0x4B, 0x39, 0x6B, 0x4B, 0x4B, 0x39, 0x6B, 0x4B])
        self.assertEqual(topo.CAPTURE_BITS, 577)
        self.assertEqual(len(plan.tdi_scans[0]), 577)
        self.assertEqual(len(plan.tdi_scans[1]), 577)
        self.assertEqual(plan.scan_a_commands[0].write, bytes.fromhex("4b 06 5f"))
        self.assertEqual(plan.scan_a_commands[1].write, bytes.fromhex("4b 01 00"))
        self.assertEqual(plan.scan_b_commands[0].write, bytes.fromhex("4b 03 02"))
        self.assertEqual(plan.scan_a_commands[2].write[:3], bytes.fromhex("39 47 00"))
        self.assertEqual(plan.scan_b_commands[1].write[:3], bytes.fromhex("39 47 00"))
        self.assertEqual(topo.scan_transaction_sha256(plan.scan_a_commands),
                         "81f0fb9eefad365e50d8cdbe855274bdf408104158ac193a50798e0aaba778f2")
        pattern = topo.tdi_pattern()
        windows = [tuple(pattern[i:i + topo.DEBRUIJN_ORDER]) for i in range(topo.MAX_DEFAULT_DR_BITS)]
        self.assertEqual(len(windows), len(set(windows)))
        self.assertFalse(hasattr(topo, "shift_ir"))
        self.assertFalse(hasattr(topo, "shift_dr"))
        self.assertEqual(inspect.signature(topo.build_plan).parameters, {})

    def test_one_idcode_tap_observation_does_not_compare_to_expected(self):
        parsed, raw_pair, _ = self.run_devices((("IDCODE", 0x04B69093),))
        self.assertEqual(parsed.status, "PARSED_RESET_DEFAULT_DR")
        self.assertEqual(parsed.aggregate_dr_length, 32)
        self.assertEqual(parsed.taps_tdo_to_tdi[0]["idcode"], "0x04b69093")
        self.assertEqual((parsed.raw_tdo_scan_a_bits, parsed.raw_tdo_scan_b_bits), raw_pair)

    def test_two_valid_idcode_taps_preserve_order(self):
        parsed, _, _ = self.run_devices((("IDCODE", 0x04B69093), ("IDCODE", 0x0362D093)))
        self.assertEqual(parsed.aggregate_dr_length, 64)
        self.assertEqual([row["idcode"] for row in parsed.taps_tdo_to_tdi],
                         ["0x04b69093", "0x0362d093"])

    def test_idcode_plus_bypass_and_leading_trailing_bypass(self):
        parsed, _, _ = self.run_devices((("IDCODE", 0x04B69093), ("BYPASS", 0)))
        self.assertEqual([row["kind"] for row in parsed.taps_tdo_to_tdi], ["IDCODE", "BYPASS"])
        parsed, _, _ = self.run_devices((("BYPASS", 0), ("IDCODE", 0x04B69093), ("BYPASS", 0)))
        self.assertEqual([row["kind"] for row in parsed.taps_tdo_to_tdi], ["BYPASS", "IDCODE", "BYPASS"])

    def test_all_zero_and_all_one_scans_are_inconclusive(self):
        tdi_a, tdi_b = topo.tdi_pattern(), topo.tdi_pattern_b()
        for value in ("0", "1"):
            with self.subTest(value=value):
                parsed = topo.parse_raw_tdo(value * topo.CAPTURE_BITS, value * topo.CAPTURE_BITS,
                                            tdi_a, tdi_b)
                self.assertNotEqual(parsed.status, "PARSED_RESET_DEFAULT_DR")

    def test_short_extra_reversed_edge_and_bad_idcode_marker(self):
        with self.assertRaises(topo.Refusal):
            topo.raw_tdo_bits(bytes(71), b"\0")
        with self.assertRaises(topo.Refusal):
            topo.raw_tdo_bits(bytes(73), b"\0")
        valid_a, valid_b = fixture_scans((("IDCODE", 0x04B69093),))
        self.assertNotEqual(topo.parse_raw_tdo(valid_a[::-1], valid_b[::-1],
                                               topo.tdi_pattern(), topo.tdi_pattern_b()).status,
                            "PARSED_RESET_DEFAULT_DR")
        wrong_phase_a = valid_a[1:] + "0"
        wrong_phase_b = valid_b[1:] + "0"
        self.assertNotEqual(topo.parse_raw_tdo(wrong_phase_a, wrong_phase_b,
                                               topo.tdi_pattern(), topo.tdi_pattern_b()).status,
                            "PARSED_RESET_DEFAULT_DR")
        with self.assertRaisesRegex(topo.Refusal, "capture convention"):
            topo.parse_raw_tdo(valid_a, valid_b, topo.tdi_pattern(), topo.tdi_pattern_b(),
                               sample_edge="FALLING")
        malformed_a, malformed_b = fixture_scans((("IDCODE", 0x04B69092),))
        self.assertNotEqual(topo.parse_raw_tdo(malformed_a, malformed_b,
                                               topo.tdi_pattern(), topo.tdi_pattern_b()).status,
                            "PARSED_RESET_DEFAULT_DR")

    def test_multiple_candidates_refuse_before_open(self):
        other = topo.Candidate(self.identity, object())
        transport = FakeTransport((self.candidate, other), fixture_scans((("IDCODE", 0x04B69093),)))
        with self.assertRaisesRegex(topo.Refusal, "multiple FTDI candidates"):
            topo._run_mock_transport(self.permit, transport)
        self.assertEqual(transport.open_count, 0)

    def test_descriptor_mismatch_and_second_device_substitution_refuse_before_open(self):
        wrong = replace(self.identity, usb_descriptor_serial="153300000957A")
        transport = FakeTransport((topo.Candidate(wrong, object()),), fixture_scans((("IDCODE", 0x04B69093),)))
        with self.assertRaisesRegex(topo.Refusal, "differs"):
            topo._run_mock_transport(self.permit, transport)
        self.assertEqual(transport.open_count, 0)

    def test_caller_cannot_alter_permit_nonce_or_expiry(self):
        altered = replace(self.permit, nonce="f" * 64)
        transport = FakeTransport((self.candidate,), fixture_scans((("IDCODE", 0x04B69093),)))
        with self.assertRaisesRegex(topo.Refusal, "altered topology permit"):
            topo._run_mock_transport(altered, transport)
        self.assertEqual(transport.open_count, 0)

    def test_permit_replay_and_transport_failure_consume_permit(self):
        transport = FakeTransport((self.candidate,), fixture_scans((("IDCODE", 0x04B69093),)), RuntimeError("fixture"))
        with self.assertRaisesRegex(RuntimeError, "fixture"):
            topo._run_mock_transport(self.permit, transport)
        self.assertEqual(transport.close_count, 1)
        with self.assertRaisesRegex(topo.Refusal, "replayed"):
            topo._run_mock_transport(self.permit, transport)

    def test_expired_permit_is_consumed_before_transport(self):
        expired = __import__("datetime").datetime.fromisoformat(self.permit.expires_at) + timedelta(seconds=1)
        transport = FakeTransport((self.candidate,), fixture_scans((("IDCODE", 0x04B69093),)))
        with self.assertRaisesRegex(topo.Refusal, "expired"):
            topo._consume(self.permit, now=expired)
        self.assertEqual(transport.open_count, 0)
        with self.assertRaisesRegex(topo.Refusal, "replayed"):
            topo._run_mock_transport(self.permit, transport)

    def test_partial_operation_closes_and_cannot_replay(self):
        transport = FakeTransport((self.candidate,), fixture_scans((("IDCODE", 0x04B69093),)))
        opened = transport.open_exact
        def partial(handle):
            instance = opened(handle)
            instance.execute_fixed_plan = lambda plan: (b"\0", b"", b"\0", b"")
            return instance
        transport.open_exact = partial
        with self.assertRaises(topo.Refusal):
            topo._run_mock_transport(self.permit, transport)
        self.assertEqual(transport.close_count, 1)
        with self.assertRaisesRegex(topo.Refusal, "replayed"):
            topo._run_mock_transport(self.permit, transport)

    def test_arbitrary_scan_and_ir_injection_unavailable(self):
        self.assertEqual(inspect.signature(topo.build_plan).parameters, {})
        self.assertNotIn("now", inspect.signature(topo.issue_permit).parameters)
        self.assertFalse(hasattr(topo, "shift_ir"))
        self.assertFalse(hasattr(topo, "shift_dr"))
        self.assertFalse(hasattr(topo, "execute_scan"))

    def test_record_binds_raw_scans_and_explicit_nonclaims_once(self):
        transport = FakeTransport((self.candidate,), fixture_scans((("IDCODE", 0x04B69093),)))
        parsed, _ = topo._run_mock_transport(self.permit, transport)
        record = topo.build_observation(self.permit, parsed, tck_count=topo.build_plan().tck_count)
        self.assertEqual(record["descriptor_evidence_sha256"], self.digest)
        self.assertEqual(record["permit_nonce"], self.permit.nonce)
        self.assertEqual(record["observed_tdo_scan_a_bits_lsb_first"], parsed.raw_tdo_scan_a_bits)
        self.assertEqual(record["observed_tdo_scan_b_bits_lsb_first"], parsed.raw_tdo_scan_b_bits)
        self.assertEqual(record["tck_count"], 1177)
        self.assertEqual(record["scan_count"], 2)
        self.assertEqual(record["tap_state_reset_clocks"], 10)
        self.assertEqual(record["jtag_operation_count"], 1)
        self.assertIsNone(record["transport_source_sha256"])
        self.assertFalse(record["transport_adapter_integrated"])
        self.assertTrue(record["topology_discovery_only"])
        self.assertFalse(record["idcode_qualification_pass"])
        self.assertFalse(record["fpga_dna_observed"])
        self.assertFalse(record["loaded_image_identity_observed"])
        self.assertFalse(record["bitstream_identity_observed"])
        with self.assertRaisesRegex(topo.Refusal, "already emitted"):
            topo.build_observation(self.permit, parsed, tck_count=topo.build_plan().tck_count)

    def test_production_entrypoint_stays_disabled_without_reviewed_adapter(self):
        with self.assertRaisesRegex(topo.Refusal, "adapter is not implemented"):
            topo.discover_fk0957_topology(self.raw, self.digest)


if __name__ == "__main__":
    unittest.main()
