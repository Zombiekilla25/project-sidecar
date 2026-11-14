from __future__ import annotations

import contextlib
import io
import json
import tempfile
from pathlib import Path
import unittest

import install_fk0957_supervisor as package
import fk0957_supervisor as supervisor
from phk2_fk0957_remote_topology_endpoint import REMOTE_SOURCE_PATHS


class SupervisorPackageTests(unittest.TestCase):
    def test_service_supervisor_and_rgb_status_use_one_launcher_path(self):
        self.assertEqual(supervisor.LAUNCHER, "/usr/local/bin/fk0957-safe-launcher")
        unit = package.UNIT.read_text(encoding="utf-8")
        self.assertIn(f"ExecStart={supervisor.LAUNCHER} --supervisor", unit)

    def test_installed_remote_source_closure_covers_endpoint_manifest(self):
        installed = set(package.INSTALLS)
        for relative in REMOTE_SOURCE_PATHS:
            self.assertIn(f"/usr/local/lib/sidecar/fk0957/{relative}", installed)
            self.assertTrue((package.ROOT / relative).is_file(), relative)

    def test_dry_run_verifies_source_and_does_not_install(self):
        package.verify_source_package()
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(package.main([]), 0)
        self.assertIn("INSTALL=DRY_RUN_ONLY", output.getvalue())
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(package.main(["--apply"]), 2)
        self.assertIn("deliberately not implemented", output.getvalue())
        self.assertEqual(package.INSTALLS["/usr/local/bin/fk0957-safe-launcher"],
                         ("root", "root", 0o755))

    def test_disposable_filesystem_root_install_rehearsal(self):
        with tempfile.TemporaryDirectory(prefix="fk0957-package-stage-") as raw:
            root = Path(raw) / "rootfs"
            package.stage_package(root)
            self.assertEqual(package.verify_staged_package(root), [])
            launcher = root / "usr/local/bin/fk0957-safe-launcher"
            self.assertTrue(launcher.is_file())
            config = root / "etc/sidecar/fk0957/remote-trust.json"
            self.assertEqual(config.read_bytes(),
                             (package.ROOT / "ops/phk2/FK0957_REMOTE_TRUST_TEMPLATE.json").read_bytes())
            self.assertEqual(config.stat().st_mode & 0o777, 0o400)
            ownership = json.loads((root / "etc/sidecar/fk0957/deployment-ownership.json").read_bytes())
            self.assertEqual(ownership, package.ownership_payload())
            self.assertEqual(ownership["service"], {
                "name": "fk0957-supervisor.service", "uid": 0, "user": "root",
                "gid": 970, "group": "sidecar-acquire"})
            rows = {row["path"]: row for row in ownership["paths"]}
            for protected in ("/var/lib/sidecar/fk0957/supervisor",
                              "/var/lib/sidecar/fk0957/consumed-release-authorizations"):
                self.assertEqual((rows[protected]["owner_uid"], rows[protected]["mode"]),
                                 (0, "0700"))
            self.assertFalse(ownership["authority_policy"]["ordinary_client_may_write_state"])
            self.assertFalse(ownership["authority_policy"]["ordinary_client_may_write_ledger"])
            self.assertFalse(ownership["authority_policy"]["protected_state_acl_write_grants"])
            self.assertEqual((rows["/run/sidecar/fk0957-supervisor.sock"]["group_gid"],
                              rows["/run/sidecar/fk0957-supervisor.sock"]["mode"]), (970, "0660"))
            for key_slot in ("release-issuer.pub", "handoff-issuer.pub"):
                slot = root / "etc/sidecar/fk0957" / key_slot
                self.assertTrue(slot.is_file())
                self.assertEqual(slot.read_bytes(), b"")
                self.assertEqual(slot.stat().st_mode & 0o777, 0o400)
            unit = root / "etc/systemd/system/fk0957-supervisor.service"
            self.assertIn(b"Restart=no", unit.read_bytes())


if __name__ == "__main__":
    unittest.main()
