import unittest
from sidecar_miner.target import target_to_compact,compact_target,effective_share_target,compare_result,U256_MAX
class PrlTargetTests(unittest.TestCase):
    def test_easy_and_hard_targets(self):
        easy=(0xffff<<240); hard=(0x7fff<<200)
        self.assertGreater(easy,hard); self.assertGreater(effective_share_target(easy,128),effective_share_target(hard,128))
    def test_compact_conversion_never_weakens_target(self):
        for t in (1,255,256,(0xffff<<240),(1<<255)-1): self.assertLessEqual(compact_target(target_to_compact(t)),t)
    def test_boundary_equality_one_above_one_below(self):
        t=100; self.assertTrue(compare_result(t,t)); self.assertFalse(compare_result(t+1,t)); self.assertTrue(compare_result(t-1,t))
    def test_adjustment_factor_saturates_as_consensus(self): self.assertEqual(effective_share_target(U256_MAX,1024),U256_MAX)
    def test_invalid_targets_and_factors_fail_closed(self):
        for t in (0,-1,1<<256):
            with self.subTest(t=t),self.assertRaises(ValueError): target_to_compact(t)
        for factor in (0,-1,True):
            with self.subTest(factor=factor),self.assertRaises(ValueError): effective_share_target(1,factor)
