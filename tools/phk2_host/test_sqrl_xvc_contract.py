"""Offline regression for the statically reviewed SQRL XVC settck handler."""
from __future__ import annotations

import unittest

from sqrl_xvc_contract import (
    NOMINAL_MPSSE_BASE_HZ,
    REVIEWED_ELF_BUILD_ID,
    REVIEWED_ELF_SHA256,
    XvcProtocolError,
    model_reviewed_settck,
    reviewed_binary_nominal_tck_hz,
)


class ReviewedSqrlXvcTests(unittest.TestCase):
    def test_reviewed_elf_identity_is_pinned(self):
        self.assertEqual(len(REVIEWED_ELF_SHA256), 64)
        self.assertEqual(len(REVIEWED_ELF_BUILD_ID), 40)

    def test_settck_wire_shape_and_echo(self):
        period = (1000).to_bytes(4, "little")
        result = model_reviewed_settck(b"settck:" + period)
        self.assertEqual(result.response, period)
        self.assertEqual(result.requested_period_ns, 1000)

    def test_zero_u32_is_echoed_without_validation(self):
        result = model_reviewed_settck(b"settck:" + bytes(4))
        self.assertEqual(result.response, bytes(4))
        self.assertEqual(result.requested_period_ns, 0)

    def test_max_u32_is_echoed_without_clamp(self):
        value = (2**32 - 1).to_bytes(4, "little")
        result = model_reviewed_settck(b"settck:" + value)
        self.assertEqual(result.response, value)
        self.assertEqual(result.requested_period_ns, 2**32 - 1)

    def test_wrong_command_refused_by_offline_fixture(self):
        with self.assertRaises(XvcProtocolError):
            model_reviewed_settck(b"getinfo" + bytes(4))

    def test_short_or_long_request_refused_by_offline_fixture(self):
        for request in (b"settck:", b"settck:" + bytes(3), b"settck:" + bytes(5)):
            with self.subTest(request=request), self.assertRaises(XvcProtocolError):
                model_reviewed_settck(request)

    def test_settck_echo_does_not_change_effective_clock(self):
        for period_ns in (1, 1000, 10_000, 2**32 - 1):
            model_reviewed_settck(b"settck:" + period_ns.to_bytes(4, "little"))
            self.assertEqual(reviewed_binary_nominal_tck_hz(), NOMINAL_MPSSE_BASE_HZ)

    def test_generic_and_jcc4p_clock_branches_select_divisor_zero(self):
        self.assertEqual(reviewed_binary_nominal_tck_hz(), 30_000_000)
        self.assertEqual(reviewed_binary_nominal_tck_hz(jcc4p_descriptor=True), 30_000_000)


if __name__ == "__main__":
    unittest.main()
