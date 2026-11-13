#!/usr/bin/python3
"""Build the required static FK0957 environment-sanitizing launcher."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import subprocess

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--bootstrap-path", required=True, type=Path,
                        help="absolute installed path of the administrator-managed bootstrap")
    args = parser.parse_args()
    source_dir = Path(__file__).resolve().parent
    source = source_dir / "fk0957_safe_launcher.c"
    bootstrap = args.bootstrap_path
    if (not bootstrap.is_absolute() or ".." in bootstrap.parts
            or any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in str(bootstrap))):
        parser.error("--bootstrap-path must be an absolute path without traversal or control characters")
    try:
        bootstrap_sha256 = hashlib.sha256(bootstrap.read_bytes()).hexdigest()
    except OSError:
        parser.error("--bootstrap-path must identify the reviewed installed bootstrap bytes")
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    escaped = str(bootstrap).replace("\\", "\\\\").replace('"', '\\"')
    define = '-DFK0957_BOOTSTRAP_PATH="' + escaped + '"'
    bootstrap_define = '-DFK0957_BOOTSTRAP_SHA256="' + bootstrap_sha256 + '"'
    command = ["/usr/bin/cc", "-static", "-O2", "-Wall", "-Wextra",
               "-fstack-protector-strong", "-D_FORTIFY_SOURCE=3", define, bootstrap_define,
               "-Wno-deprecated-declarations", str(source), "-o", str(output), "-lcrypto"]
    subprocess.run(command, check=True, env={"PATH": "/usr/bin:/bin", "LANG": "C"})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
