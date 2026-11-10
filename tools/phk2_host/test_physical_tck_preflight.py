"""Synthetic-only dry runs for PHK2 physical TCK preflight gates."""
from __future__ import annotations

from dataclasses import replace
import fcntl
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from physical_tck_preflight import (
    PINNED_REVIEWED_BRIDGE_SHA256,
    PINNED_REVIEWED_BUILD_ID,
    ExclusiveTestLock,
    ProcessRecord,
    Refusal,
    RuntimeSnapshot,
    SocketRecord,
    evaluate_runtime,
    validate_bridge_policy,
    validate_qualification_manifest,
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class PhysicalTckPreflightDryRun(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory(prefix="phk2-tck-preflight-")
        self.root = Path(self.tmpdir.name)
        self.target = {
            "path": str(self.root / "target-lock.json"),
            "sha256": "a" * 64,
            "adapter": {"usb_path": "synthetic/1-2", "ftdi_serial": "SYNTHETIC123",
                        "vid": "0403", "pid": "6010", "interface": "A"},
            "target": {"board_id": "SYNTHETIC-PHK2", "target_part": "xcvu33p-fsvh2104-2-e",
                       "idcode": "00000000", "current_image_sha256": "b" * 64,
                       "expected_chain_topology": "one VU33P IDCODE TAP"},
            "xvc": {"host": "127.0.0.1", "port": 2542},
        }
        self.config_path = self.root / "sqrl-xvc.service"
        self.config_path.write_text(
            "[Service]\nExecStart=/opt/sqrl/sqrl_bridge_rawjtag_coe -s ,SYNTHETIC123 -j 2542\n"
        )
        self.policy = {
            "policy_path": str(self.root / "bridge-policy.json"),
            "BRIDGE_PATH": "/opt/sqrl/sqrl_bridge_rawjtag_coe",
            "BRIDGE_SHA256": PINNED_REVIEWED_BRIDGE_SHA256,
            "BUILD_ID": PINNED_REVIEWED_BUILD_ID,
            "SERVICE_UNIT": "sqrl-xvc.service",
            "SERVICE_CONFIG_PATH": str(self.config_path),
            "SERVICE_CONFIG_HASH": digest(self.config_path.read_bytes()),
            "XVC_PORT": 2542,
            "FTDI_SERIAL": "SYNTHETIC123",
            "ARGV_CONTAINS": ["-j", "2542", "-s", ",SYNTHETIC123"],
            "target_part": "xcvu33p-fsvh2104-2-e",
        }
        self.server = ProcessRecord(
            4242,
            ("/opt/sqrl/sqrl_bridge_rawjtag_coe", "-s", ",SYNTHETIC123", "-j", "2542"),
            "/opt/sqrl/sqrl_bridge_rawjtag_coe",
            PINNED_REVIEWED_BRIDGE_SHA256,
            PINNED_REVIEWED_BUILD_ID,
            "0::/system.slice/sqrl-xvc.service",
        )
        self.snapshot = RuntimeSnapshot(
            (self.server,),
            (SocketRecord("LISTEN", "0.0.0.0:2542", "*:0", (4242,)),),
            (),
        )
        self.manifest_path = self._make_manifest()

    def tearDown(self):
        self.tmpdir.cleanup()

    def _write_artifact(self, name: str, data: bytes) -> dict:
        path = self.root / name
        path.write_bytes(data)
        return {"path": name, "sha256": digest(data)}

    def _make_manifest(self) -> Path:
        source = self._write_artifact("source.tar", b"synthetic source archive")
        routed = self._write_artifact("routed.dcp", b"synthetic routed checkpoint")
        constraints_data = b'{"model":"synthetic constraints"}\n'
        constraints = self._write_artifact("constraints.json", constraints_data)
        timing = self._write_artifact("timing.rpt", b"synthetic routed TCK analysis envelope\n")
        promotion_path = self.root / "promotion.json"
        promotion_link = {
            "SOURCE_COMMIT": "c" * 40,
            "SOURCE_TREE_HASH": source["sha256"],
            "ROUTED_DCP_HASH": routed["sha256"],
            "CONSTRAINT_MODEL_HASH": constraints["sha256"],
            "TARGET_PART": "xcvu33p-fsvh2104-2-e",
        }
        promotion_path.write_text(json.dumps({"status": "PASS", **promotion_link}, sort_keys=True))
        promotion = {
            "status": "COMPLETE", "result": "PASS", "approval_id": "SYNTHETIC-PROMOTION-1",
            **promotion_link,
            "evidence": {"path": "promotion.json", "sha256": digest(promotion_path.read_bytes())},
        }
        manifest = {
            "schema": "PHK2-QUALIFICATION-MANIFEST-v1",
            "SOURCE_COMMIT": "c" * 40,
            "SOURCE_TREE_HASH": source["sha256"],
            "SOURCE_TREE_ARCHIVE": source,
            "ROUTED_DCP_HASH": routed["sha256"],
            "ROUTED_DCP": routed,
            "CONSTRAINT_MODEL": {"name": "synthetic-xdc", **constraints},
            "TARGET_PART": "xcvu33p-fsvh2104-2-e",
            "TCK_ANALYSIS_ENVELOPE": {
                "qualified": True, "minimum_tck_hz": 1_000_000, "maximum_tck_hz": 50_000_000,
                "minimum_high_ns": 8, "minimum_low_ns": 8,
                "minimum_duty_cycle_percent": 40, "maximum_duty_cycle_percent": 60,
                "maximum_period_jitter_p2p_ns": 1, "maximum_period_jitter_rms_ns": 0.25,
                "timing_report": timing,
            },
            "QUALIFICATION_STATUS": "QUALIFIED",
            "INDEPENDENT_PROMOTION": promotion,
        }
        path = self.root / "qualification.json"
        path.write_text(json.dumps(manifest, indent=2))
        return path

    def test_correct_process_and_qualified_package_pass(self):
        validated = validate_qualification_manifest(self.manifest_path)
        policy = dict(self.policy)
        policy["SERVICE_CONFIG_HASH"] = digest(self.config_path.read_bytes())
        checked_policy = validate_bridge_policy(self._write_policy(policy), self.target)
        result = evaluate_runtime(checked_policy, self.target, self.snapshot)
        self.assertEqual(validated["QUALIFICATION_STATUS"], "QUALIFIED")
        self.assertTrue(result["ready"])
        self.assertEqual(result["BRIDGE_SHA256"], PINNED_REVIEWED_BRIDGE_SHA256)

    def _write_policy(self, policy: dict) -> Path:
        path = self.root / "bridge-policy.json"
        path.write_text(json.dumps({
            "schema": "PHK2-SQRL-XVC-BRIDGE-POLICY-v1",
            "BRIDGE_PATH": policy["BRIDGE_PATH"], "BRIDGE_SHA256": policy["BRIDGE_SHA256"],
            "BUILD_ID": policy["BUILD_ID"], "SERVICE_UNIT": policy["SERVICE_UNIT"],
            "SERVICE_CONFIG_PATH": policy["SERVICE_CONFIG_PATH"],
            "SERVICE_CONFIG_HASH": policy["SERVICE_CONFIG_HASH"],
            "SERVICE_EXEC_TOKENS": ["/opt/sqrl/sqrl_bridge_rawjtag_coe", "-s", ",SYNTHETIC123", "-j", "2542"],
            "XVC_PORT": policy["XVC_PORT"], "FTDI_SERIAL": policy["FTDI_SERIAL"],
            "ARGV_CONTAINS": policy["ARGV_CONTAINS"], "TARGET_PART": policy["target_part"],
        }, indent=2))
        return path

    def test_wrong_binary_refuses(self):
        wrong = replace(self.server, sha256="d" * 64)
        with self.assertRaisesRegex(Refusal, "differs from statically reviewed"):
            evaluate_runtime(self.policy, self.target, replace(self.snapshot, processes=(wrong,)))

    def test_wrong_service_config_refuses(self):
        self.config_path.write_text("[Service]\nExecStart=/opt/other/server\n")
        policy_path = self._write_policy(self.policy)
        # A changed file is rejected by its pinned hash before process checks.
        with self.assertRaisesRegex(Refusal, "SERVICE_CONFIG_HASH"):
            validate_bridge_policy(policy_path, self.target)

    def test_duplicate_server_refuses(self):
        duplicate = replace(self.server, pid=4243, cgroup="0::/system.slice/duplicate.service")
        with self.assertRaisesRegex(Refusal, "missing or duplicated"):
            evaluate_runtime(self.policy, self.target, replace(self.snapshot, processes=(self.server, duplicate)))

    def test_active_client_connection_refuses(self):
        active = SocketRecord("ESTAB", "192.0.2.10:43000", "192.0.2.20:2542", (4242,))
        with self.assertRaisesRegex(Refusal, "existing XVC client"):
            evaluate_runtime(self.policy, self.target, replace(self.snapshot, established=(active,)))

    def test_competing_local_jtag_client_refuses(self):
        client = ProcessRecord(5252, ("python", "other_jtag_client.py"), "/usr/bin/python3",
                               "e" * 64, "f" * 40, "0::/user.slice/other.scope")
        with self.assertRaisesRegex(Refusal, "competing"):
            evaluate_runtime(self.policy, self.target, replace(self.snapshot, processes=(self.server, client)))

    def test_stale_lock_reclaimed_by_flock_not_pid_guess(self):
        path = self.root / "locks" / "adapter.lock"
        path.parent.mkdir()
        path.parent.chmod(0o700)
        path.write_text(json.dumps({"schema": "PHK2-PHYSICAL-TCK-OS-LOCK-v1",
                                   "state": "held", "lock_key": "a" * 64,
                                   "pid": 987654321, "created_utc": "2000-01-01T00:00:00Z"}))
        with ExclusiveTestLock(path, "a" * 64) as lock:
            self.assertTrue(lock.stale_metadata_replaced)
            metadata = json.loads(path.read_text())
            self.assertEqual(metadata["state"], "held")
            self.assertNotEqual(metadata["pid"], 987654321)
        self.assertEqual(json.loads(path.read_text())["state"], "released")

    def test_live_foreign_lock_refuses_even_with_stale_looking_pid(self):
        path = self.root / "locks" / "adapter.lock"
        path.parent.mkdir()
        path.parent.chmod(0o700)
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(Refusal, "live foreign lock"):
                ExclusiveTestLock(path, "a" * 64).acquire()
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def test_missing_qualification_manifest_refuses(self):
        with self.assertRaisesRegex(Refusal, "qualification manifest is unavailable"):
            validate_qualification_manifest(self.root / "absent.json")

    def _mutate_manifest(self, mutate):
        data = json.loads(self.manifest_path.read_text())
        mutate(data)
        self.manifest_path.write_text(json.dumps(data, indent=2))

    def test_wrong_routed_hash_refuses(self):
        self._mutate_manifest(lambda d: d.update(ROUTED_DCP_HASH="0" * 64))
        with self.assertRaisesRegex(Refusal, "ROUTED_DCP_HASH"):
            validate_qualification_manifest(self.manifest_path)

    def test_unqualified_route_refuses(self):
        self._mutate_manifest(lambda d: d.update(QUALIFICATION_STATUS="ROUTE_FAILED"))
        with self.assertRaisesRegex(Refusal, "not QUALIFIED"):
            validate_qualification_manifest(self.manifest_path)

    def test_missing_tck_envelope_refuses(self):
        self._mutate_manifest(lambda d: d.pop("TCK_ANALYSIS_ENVELOPE"))
        with self.assertRaisesRegex(Refusal, "TCK_ANALYSIS_ENVELOPE is absent"):
            validate_qualification_manifest(self.manifest_path)

    def test_incomplete_independent_promotion_refuses(self):
        self._mutate_manifest(lambda d: d["INDEPENDENT_PROMOTION"].update(status="PENDING"))
        with self.assertRaisesRegex(Refusal, "promotion is incomplete"):
            validate_qualification_manifest(self.manifest_path)


if __name__ == "__main__":
    unittest.main()
