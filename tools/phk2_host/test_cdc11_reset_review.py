"""Synthetic report-model tests for the read-only CDC-11 intake reviewer."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from cdc11_reset_review import Refusal, compare_routed, review_report


class Cdc11ResetReviewDryRun(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="phk2-cdc11-review-")
        self.root = Path(self.temp.name)
        (self.root / "src").mkdir()
        (self.root / "reports").mkdir()
        (self.root / "src" / "top.sv").write_text("// synthetic source snapshot\n")
        self.source_file_hash = self.digest(self.root / "src" / "top.sv")
        self._file("source.tar", b"synthetic source archive")
        self.report_refs = {}
        for name in ("mapped.dcp", "cdc.rpt", "cdc_all.rpt", "timing.rpt", "recovery.rpt", "exceptions.rpt", "clocks.rpt", "reset_cells.rpt"):
            self._file("reports/" + name, ("synthetic " + name).encode())
        self.report_refs = {
            "mapped_checkpoint": self.ref("reports/mapped.dcp", "SYNTH_MAPPED"),
            "cdc_default_report": self.ref("reports/cdc.rpt"),
            "cdc_all_checks_report": self.ref("reports/cdc_all.rpt"),
            "timing_summary_report": self.ref("reports/timing.rpt"),
            "recovery_removal_report": self.ref("reports/recovery.rpt"),
            "exceptions_report": self.ref("reports/exceptions.rpt"),
            "clock_inventory_report": self.ref("reports/clocks.rpt"),
            "reset_cell_inventory_report": self.ref("reports/reset_cells.rpt"),
        }
        self.data = self._evidence()
        self.path = self.root / "review.json"
        self.save()

    def tearDown(self):
        self.temp.cleanup()

    def digest(self, path):
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()

    def _file(self, rel, blob):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(blob)
        return path

    def ref(self, rel, stage=None):
        path = self.root / rel
        result = {"path": rel, "sha256": self.digest(path)}
        if stage:
            result["stage"] = stage
            result["source_commit"] = "a" * 40
        return result

    def clock(self, i):
        return {"clock_object": f"jtag_user{i}_tck", "clock_root": f"BSCANE2/TCK_ROOT_{i}",
                "period_ps": 33333.333, "generated_clock_relationship": f"async_external_tck_{i}",
                "physical_clock_source": f"JTAG_TCK_PORT_{i}", "logical_domain": f"user{i}_domain"}

    def _evidence(self):
        archive_hash = self.digest(self.root / "source.tar")
        chains = []
        rows = []
        for i in range(1, 4):
            chain_id = f"rst_sync_user{i}"
            consumers = [f"u_user{i}/logic_a", f"u_user{i}/logic_b"]
            chains.append({"chain_id": chain_id, "source_reset": "core_rst", "rule": "CDC-9", "stage_cells": [f"u_user{i}/rst_sync[0]", f"u_user{i}/rst_sync[1]"],
                           "ASYNC_REG": True, "sync_stages": 2, "destination_clock": self.clock(i),
                           "ASYNC_ASSERT": True, "SYNC_DEASSERT": True,
                           "ONE_RELEASE_SYNCHRONIZER_PER_DOMAIN": True,
                           "ALL_SAME_DOMAIN_CONSUMERS_SHARE_RELEASE": True,
                           "RESET_DEASSERT_WHILE_CLOCK_STOPPED_SAFE": True,
                           "DOMAIN_REMAINS_IN_RESET_UNTIL_SYNC_EDGES": True,
                           "downstream_consumers": consumers,
                           "consumer_release_chain_ids": {consumer: chain_id for consumer in consumers}})
            rows.append({"ROW_ID": f"CDC11-{i}", "RULE": "CDC-11", "SOURCE_RESET": "core_rst",
                         "SOURCE_CELL": f"u_reset/reset_ff[{i}]", "DESTINATION_SYNC_STAGE": f"u_user{i}/rst_sync[0]",
                         "DESTINATION_HIERARCHY": f"u_user{i}", "CDC9_CHAIN": chain_id,
                         "ASYNC_REG": True, "SYNC_STAGES": 2, "DOMAIN_ID": f"user{i}_domain",
                         "destination_clock": self.clock(i), "endpoint_rules": ["CDC-11", "CDC-9"]})
        return {"schema": "PHK2-VIVADO-CDC11-RESET-REVIEW-v1", "synthetic_fixture": False,
                "source": {"SOURCE_COMMIT": "a" * 40, "SOURCE_TREE_HASH": archive_hash,
                           "SOURCE_TREE_ARCHIVE": {"path": "source.tar", "sha256": archive_hash},
                           "SOURCE_FILES": {"src/top.sv": self.source_file_hash}},
                **self.report_refs, "cdc_methodology": {"all_checks_per_endpoint": True, "cdc_default_report_generated": True},
                "reported_counts": {"CDC11_COUNT": 3, "CDC9_COUNT": 3}, "cdc11_rows": rows,
                "cdc9_reset_chains": chains,
                "recovery_removal": {"analysis_present": True, "pass": True, "false_path_hiding": False},
                "gray_constraints": {"max_delay": [{"active": True, "value_ns": 3.0 + i} for i in range(4)],
                                     "bus_skew": [{"active": True, "value_ns": 2.0} for _ in range(4)]}}

    def save(self):
        self.path.write_text(json.dumps(self.data, sort_keys=True))

    def test_three_distinct_domains_are_structurally_safe_not_waived(self):
        result = review_report(self.path)
        self.assertEqual(result["CDC11_ROWS"], 3)
        self.assertEqual(result["CDC9_RESET_CHAINS"], 3)
        self.assertEqual(result["DESTINATION_DOMAINS"], 3)
        self.assertEqual(result["SAME_DOMAIN_DUPLICATE_RELEASE_CHAINS"], 0)
        self.assertTrue(result["CDC11_STRUCTURALLY_SAFE"])
        self.assertTrue(all(x["both_11_and_9"] for x in result["endpoint_rule_precedence"]))

    def test_three_chains_in_one_domain_are_unsafe(self):
        for i in range(1, 4):
            clock = self.clock(1)
            self.data["cdc9_reset_chains"][i - 1]["destination_clock"] = clock
            self.data["cdc11_rows"][i - 1]["destination_clock"] = clock
            self.data["cdc11_rows"][i - 1]["DOMAIN_ID"] = "user1_domain"
        self.save()
        result = review_report(self.path)
        self.assertEqual(result["DESTINATION_DOMAINS"], 1)
        self.assertEqual(result["SAME_DOMAIN_DUPLICATE_RELEASE_CHAINS"], 2)
        self.assertTrue(result["CDC11_REAL_UNSAFE"])
        self.assertTrue(result["RTL_FIX_REQUIRED"])

    def test_stop_clock_deassertion_not_safe_refuses(self):
        self.data["cdc9_reset_chains"][0]["DOMAIN_REMAINS_IN_RESET_UNTIL_SYNC_EDGES"] = False
        self.save()
        with self.assertRaisesRegex(Refusal, "DOMAIN_REMAINS_IN_RESET"):
            review_report(self.path)

    def test_missing_recovery_analysis_is_indeterminate(self):
        self.data["recovery_removal"] = {"analysis_present": False, "pass": False, "false_path_hiding": False}
        self.save()
        result = review_report(self.path)
        self.assertIsNone(result["RECOVERY_REMOVAL_PASS"])

    def test_false_path_hiding_fails_recovery_removal(self):
        self.data["recovery_removal"]["false_path_hiding"] = True
        self.save()
        result = review_report(self.path)
        self.assertFalse(result["RECOVERY_REMOVAL_PASS"])

    def test_missing_all_checks_per_endpoint_refuses(self):
        self.data["cdc_methodology"]["all_checks_per_endpoint"] = False
        self.save()
        with self.assertRaisesRegex(Refusal, "all_checks_per_endpoint"):
            review_report(self.path)

    def test_count_mismatch_refuses(self):
        self.data["reported_counts"]["CDC11_COUNT"] = 2
        self.save()
        with self.assertRaisesRegex(Refusal, "counts differ"):
            review_report(self.path)

    def test_missing_gray_constraint_refuses(self):
        self.data["gray_constraints"]["bus_skew"].pop()
        self.save()
        with self.assertRaisesRegex(Refusal, "four Gray"):
            review_report(self.path)

    def test_changed_source_file_refuses(self):
        (self.root / "src/top.sv").write_text("changed source")
        with self.assertRaisesRegex(Refusal, "immutable source file.*hash mismatch"):
            review_report(self.path)

    def test_postroute_must_preserve_topology_and_recovery(self):
        mapped = review_report(self.path)
        route_data = dict(self.data)
        route_data["mapped_checkpoint"] = self.ref("reports/mapped.dcp", "ROUTED")
        route_data["mapped_checkpoint"]["source_commit"] = "a" * 40
        route_data["mapped_checkpoint"]["stage"] = "ROUTED"
        route_path = self.root / "routed-review.json"
        route_path.write_text(json.dumps(route_data))
        routed = review_report(route_path)
        result = compare_routed(mapped, routed)
        self.assertTrue(result["CDC11_POST_ROUTE_ACCEPTANCE_PASS"])
        self.assertTrue(result["ASYNC_REG_PROPERTIES_PRESERVED"])


if __name__ == "__main__":
    unittest.main()
