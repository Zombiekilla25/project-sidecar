#!/usr/bin/python3
"""Build the required static FK0957 environment-sanitizing launcher."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import stat
import subprocess

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--bootstrap-path", required=True, type=Path,
                        help="absolute installed path of the administrator-managed bootstrap")
    parser.add_argument("--bootstrap-bytes", type=Path,
                        help="optional staged bootstrap bytes used only for offline packaging rehearsal")
    parser.add_argument("--manifest-path", required=True, type=Path,
                        help="absolute administrator-approved signed runtime manifest path")
    parser.add_argument("--manifest-bytes", type=Path,
                        help="optional staged manifest bytes used only for offline package rehearsal")
    parser.add_argument("--trust-config-path", required=True, type=Path,
                        help="absolute administrator-managed issuer configuration path")
    parser.add_argument("--trust-config-bytes", type=Path,
                        help="optional staged trust configuration bytes for offline rehearsal")
    args = parser.parse_args()
    source_dir = Path(__file__).resolve().parent
    source = source_dir / "fk0957_safe_launcher.c"
    bootstrap = args.bootstrap_path
    if (not bootstrap.is_absolute() or ".." in bootstrap.parts
            or any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in str(bootstrap))):
        parser.error("--bootstrap-path must be an absolute path without traversal or control characters")
    manifest = args.manifest_path
    if (not manifest.is_absolute() or ".." in manifest.parts
            or any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in str(manifest))):
        parser.error("--manifest-path must be an absolute path without traversal or control characters")
    trust_config = args.trust_config_path
    if (not trust_config.is_absolute() or ".." in trust_config.parts
            or any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in str(trust_config))):
        parser.error("--trust-config-path must be absolute and canonical")
    bootstrap_bytes = args.bootstrap_bytes or bootstrap
    try:
        info = bootstrap_bytes.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                info.st_size <= 0 or info.st_size > 1024 * 1024):
            raise OSError("unsafe bootstrap bytes")
        bootstrap_sha256 = hashlib.sha256(bootstrap_bytes.read_bytes()).hexdigest()
    except OSError:
        parser.error("--bootstrap-path must identify the reviewed installed bootstrap bytes")
    manifest_bytes = args.manifest_bytes or manifest
    try:
        info = manifest_bytes.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                info.st_size <= 0 or info.st_size > 16 * 1024 * 1024):
            raise OSError("unsafe manifest bytes")
        manifest_sha256 = hashlib.sha256(manifest_bytes.read_bytes()).hexdigest()
    except OSError:
        parser.error("--manifest-bytes must identify a bounded regular manifest file")
    trust_bytes = args.trust_config_bytes or trust_config
    try:
        info = trust_bytes.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                info.st_size <= 0 or info.st_size > 64 * 1024):
            raise OSError("unsafe trust config bytes")
        trust_sha256 = hashlib.sha256(trust_bytes.read_bytes()).hexdigest()
    except OSError:
        parser.error("--trust-config-bytes must identify a bounded regular file")
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    escaped = str(bootstrap).replace("\\", "\\\\").replace('"', '\\"')
    define = '-DFK0957_BOOTSTRAP_PATH="' + escaped + '"'
    bootstrap_define = '-DFK0957_BOOTSTRAP_SHA256="' + bootstrap_sha256 + '"'
    manifest_escaped = str(manifest).replace("\\", "\\\\").replace('"', '\\"')
    manifest_path_define = '-DFK0957_MANIFEST_PATH="' + manifest_escaped + '"'
    manifest_sha_define = '-DFK0957_MANIFEST_SHA256="' + manifest_sha256 + '"'
    trust_escaped = str(trust_config).replace("\\", "\\\\").replace('"', '\\"')
    trust_path_define = '-DFK0957_TRUST_CONFIG_PATH="' + trust_escaped + '"'
    trust_sha_define = '-DFK0957_TRUST_CONFIG_SHA256="' + trust_sha256 + '"'
    command = ["/usr/bin/cc", "-static", "-O2", "-Wall", "-Wextra",
               "-fstack-protector-strong", "-D_FORTIFY_SOURCE=3", define, bootstrap_define,
               manifest_path_define, manifest_sha_define, trust_path_define, trust_sha_define,
               "-Wno-deprecated-declarations", str(source), "-o", str(output), "-lcrypto"]
    subprocess.run(command, check=True, env={"PATH": "/usr/bin:/bin", "LANG": "C"})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
