from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools" / "phk2_host"


class SafeLauncherTests(unittest.TestCase):
    def test_launcher_build_requires_absolute_installed_bootstrap_path(self):
        with tempfile.TemporaryDirectory(prefix="fk0957-launcher-path-test-") as raw:
            output = Path(raw) / "launcher"
            for bootstrap in (
                "relative/bootstrap.py",
                "/usr/local/lib/sidecar/../unsafe.py",
            ):
                run = subprocess.run([
                    "/usr/bin/python3", str(TOOLS / "build_fk0957_safe_launcher.py"),
                    "--output", str(output), "--bootstrap-path", bootstrap,
                ], check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                   env={"PATH": "/usr/bin:/bin", "LANG": "C"})
                self.assertNotEqual(run.returncode, 0)
                self.assertFalse(output.exists())

    def test_prestart_runtime_hash_and_build_id_mismatches_refuse_before_python(self):
        source = (TOOLS / "fk0957_safe_launcher.c").read_text()
        python_hash = "e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f"
        loader_build_id = "231ab65dd867a89dce29cb958fd5ca50abb1aa34"
        expected = '{"status":"REFUSED","phase":"PRESTART_VALIDATION","code":"NATIVE_RUNTIME_PIN_MISMATCH"}\n'
        with tempfile.TemporaryDirectory(prefix="fk0957-prestart-pin-test-") as raw:
            root = Path(raw)
            for label, changed in (
                ("hash", source.replace(python_hash, "0" + python_hash[1:], 1)),
                ("build-id", source.replace(loader_build_id, "0" + loader_build_id[1:], 1)),
            ):
                with self.subTest(label=label):
                    variant = root / f"launcher-{label}.c"
                    output = root / f"launcher-{label}"
                    variant.write_text(changed)
                    subprocess.run([
                        "/usr/bin/cc", "-static", "-O2", "-Wall", "-Wextra",
                        "-fstack-protector-strong", "-D_FORTIFY_SOURCE=3",
                        "-Wno-deprecated-declarations", str(variant), "-o", str(output), "-lcrypto",
                    ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       env={"PATH": "/usr/bin:/bin", "LANG": "C"})
                    run = subprocess.run([str(output), "--launcher-self-test"], check=False,
                                         text=True, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, timeout=10,
                                         env={"PATH": "/bad/path", "LD_PRELOAD": "/bad/preload"})
                    self.assertEqual(run.returncode, 126)
                    self.assertEqual(run.stdout, expected)
                    self.assertEqual(run.stderr, "")

    def test_static_launcher_blocks_hostile_python_and_loader_environment(self):
        with tempfile.TemporaryDirectory(prefix="fk0957-launcher-test-") as raw:
            root = Path(raw)
            output = root / "launcher"
            bootstrap = root / "installed" / "fk0957_safe_bootstrap.py"
            bootstrap.parent.mkdir(mode=0o700)
            bootstrap.write_bytes((TOOLS / "fk0957_safe_bootstrap.py").read_bytes())
            subprocess.run([
                "/usr/bin/python3", str(TOOLS / "build_fk0957_safe_launcher.py"),
                "--output", str(output), "--bootstrap-path", str(bootstrap),
            ], check=True, env={"PATH": "/usr/bin:/bin", "LANG": "C"})
            program_headers = subprocess.run(
                ["/usr/bin/readelf", "-l", str(output)], check=True,
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env={"PATH": "/usr/bin:/bin", "LANG": "C"}).stdout
            self.assertNotIn("INTERP", program_headers)

            hostile = root / "hostile"
            hostile.mkdir()
            marker = root / "startup-ran"
            (hostile / "sitecustomize.py").write_text(
                f"from pathlib import Path; Path({str(marker)!r}).write_text('site')\n")
            (hostile / "usercustomize.py").write_text(
                f"from pathlib import Path; Path({str(marker)!r}).write_text('user')\n")
            preload_source = root / "preload.c"
            preload_source.write_text(
                "#include <fcntl.h>\n#include <unistd.h>\n"
                f"__attribute__((constructor)) static void init(void) {{ int f=open({json.dumps(str(marker))},O_WRONLY|O_CREAT,0600); if(f>=0){{write(f,\"ld\",2);close(f);}} }}\n")
            preload = root / "preload.so"
            subprocess.run(["/usr/bin/cc", "-shared", "-fPIC", str(preload_source),
                            "-o", str(preload)], check=True,
                           env={"PATH": "/usr/bin:/bin", "LANG": "C"})
            substitute = root / "substitute"
            substitute.mkdir()
            (substitute / "python3").write_text(
                f"#!/bin/sh\ntouch {marker}\nexit 99\n")
            (substitute / "python3").chmod(0o700)
            env = {
                "PATH": str(substitute), "PYTHONPATH": str(hostile),
                "PYTHONHOME": str(root / "bad-home"),
                "PYTHONUSERBASE": str(root / "bad-userbase"),
                "PYTHONNOUSERSITE": "0",
                "LD_PRELOAD": str(preload), "LD_LIBRARY_PATH": str(root),
            }
            run = subprocess.run([str(output), "--launcher-self-test"], check=False,
                                 text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 env=env, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)
            report = json.loads(run.stdout)
            self.assertEqual(report["isolated"], 1)
            self.assertEqual(report["no_site"], 1)
            self.assertFalse(report["sitecustomize_loaded"])
            self.assertFalse(report["usercustomize_loaded"])
            self.assertEqual(report["environment_keys"],
                             ["FK0957_TRUSTED_LAUNCHER", "LANG", "PATH"])
            self.assertFalse(marker.exists())

    def test_direct_python_cli_fails_closed_without_running_operation(self):
        run = subprocess.run([
            "/usr/bin/python3", str(TOOLS / "phk2_fk0957_topology_live_cli.py"),
            "--descriptor-evidence", "/does/not/exist", "--output", "/does/not/exist",
        ], check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
           env={"PATH": "/usr/bin:/bin", "LANG": "C"}, timeout=10)
        self.assertEqual(run.returncode, 2)
        value = json.loads(run.stdout)
        self.assertEqual((value["phase"], value["code"]),
                         ("PRELIVE_VALIDATION", "TRUSTED_LAUNCHER_REQUIRED"))
        self.assertEqual(run.stderr, "")


if __name__ == "__main__":
    unittest.main()
