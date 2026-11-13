#!/usr/bin/python3
"""Build the required static FK0957 environment-sanitizing launcher."""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    source_dir = Path(__file__).resolve().parent
    source = source_dir / "fk0957_safe_launcher.c"
    bootstrap = source_dir / "fk0957_safe_bootstrap.py"
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    escaped = str(bootstrap).replace("\\", "\\\\").replace('"', '\\"')
    define = '-DFK0957_BOOTSTRAP_PATH="' + escaped + '"'
    command = ["/usr/bin/cc", "-static", "-O2", "-Wall", "-Wextra",
               "-fstack-protector-strong", "-D_FORTIFY_SOURCE=3", define,
               "-Wno-deprecated-declarations", str(source), "-o", str(output), "-lcrypto"]
    subprocess.run(command, check=True, env={"PATH": "/usr/bin:/bin", "LANG": "C"})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
