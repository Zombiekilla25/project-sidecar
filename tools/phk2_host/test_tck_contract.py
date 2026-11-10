"""Synthetic tests for the future proof-backed PHK2 TCK gate."""
from __future__ import annotations
import unittest
from tck_contract import TckContractRefusal, TckObservation, TckPolicy, validate_tck

SYNTHETIC_MAX = 1_000_000  # Test boundary only; NOT a PHK2 limit.
POLICY = TckPolicy(True, SYNTHETIC_MAX, "fixture-transport", "a" * 64)

def obs(rate, *, actual=None, verified=True, transport="fixture-transport"):
    return TckObservation(rate, rate if actual is None else actual, verified, transport)

class TckContractTests(unittest.TestCase):
    def test_below_max(self): self.assertEqual(validate_tck(POLICY, obs(SYNTHETIC_MAX-1)), SYNTHETIC_MAX-1)
    def test_at_max(self): self.assertEqual(validate_tck(POLICY, obs(SYNTHETIC_MAX)), SYNTHETIC_MAX)
    def test_above_max(self):
        with self.assertRaises(TckContractRefusal): validate_tck(POLICY, obs(SYNTHETIC_MAX+1))
    def test_unknown_rate(self):
        with self.assertRaises(TckContractRefusal): validate_tck(POLICY, obs(None, actual=None))
    def test_client_change_after_authorization(self):
        with self.assertRaises(TckContractRefusal): validate_tck(POLICY, obs(500_000), authorized_hz=400_000)
    def test_reconnect_changed_rate(self):
        with self.assertRaises(TckContractRefusal): validate_tck(POLICY, obs(500_000), prior_session_hz=400_000, reconnect=True)
    def test_reconnect_same_rate(self): self.assertEqual(validate_tck(POLICY, obs(400_000), prior_session_hz=400_000, reconnect=True), 400_000)
    def test_unproven_phk2_policy_refuses(self):
        unknown = TckPolicy(False, None, None, None)
        with self.assertRaises(TckContractRefusal): validate_tck(unknown, obs(100_000))
    def test_failed_verification(self):
        with self.assertRaises(TckContractRefusal): validate_tck(POLICY, obs(500_000, actual=499_999, verified=False))
    def test_wrong_transport_refuses(self):
        with self.assertRaises(TckContractRefusal): validate_tck(POLICY, obs(500_000, transport="other"))

if __name__ == '__main__': unittest.main()
