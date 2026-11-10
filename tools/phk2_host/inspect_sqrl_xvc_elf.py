#!/usr/bin/env python3
"""Read-only static checks for the locally retained SQRL/XVC ELF.

This tool invokes file/readelf/nm/objdump/strings only. It never executes the
ELF, opens a device, enumerates USB, connects to XVC, or sends JTAG traffic.
The default input is the hash-pinned FK33 static-review copy.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

DEFAULT_ELF = Path("/home/rmann/Downloads/fk33-sqrl-bridge-static-review/sqrl_bridge_rawjtag_coe")
EXPECTED_SHA256 = "8c7230f0bf586e9297dc0e568bd19278aeeb7cff8dbb3dde150811f11393218a"


def run(*args: str) -> str:
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT).stdout


def inspect(path: Path) -> dict:
    for tool in ("file", "readelf", "nm", "objdump", "strings"):
        if shutil.which(tool) is None:
            raise RuntimeError(f"required read-only tool not found: {tool}")
    path = path.resolve(strict=True)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    file_text = run("file", str(path))
    header = run("readelf", "-h", str(path))
    dynamic = run("readelf", "-d", str(path))
    notes = run("readelf", "-n", str(path))
    sections = run("readelf", "-S", str(path))
    symbols = run("nm", "-C", str(path))
    xvc = run("objdump", "-d", "-C", "--start-address=0x282d0",
              "--stop-address=0x28e10", str(path))
    clock = run("objdump", "-d", "-C", "--start-address=0x1ed6b",
                "--stop-address=0x1ee75", str(path))
    strings_out = run("strings", "-a", str(path))

    required_symbols = ("SQCoEStartXVC", "_xvcThread", "SQRLJtagGetDeviceCount",
                        "SQRLJtagCreate", "FT_SetDivisor", "FT_SetLatencyTimer")
    for symbol in required_symbols:
        if symbol not in symbols:
            raise AssertionError(f"expected retained symbol absent: {symbol}")
    if "cmpw   $0x6567" not in xvc or "cmpw   $0x6573" not in xvc or "cmpw   $0x6873" not in xvc:
        raise AssertionError("XVC getinfo/settck/shift dispatch signatures changed")
    if "mov    $0x9,%ebx" not in xvc or "mov    -0x8b(%rbp),%eax" not in xvc:
        raise AssertionError("settck request read/value extraction changed")
    if "mov    $0x4,%edx" not in xvc or "call   49b0 <write@plt>" not in xvc:
        raise AssertionError("settck four-byte response write changed")
    # Ensure the settck handler body itself contains only socket read/write and
    # ordinary error reporting, never the MPSSE setup or divisor APIs.
    settle_lines = []
    for line in xvc.splitlines():
        match = re.match(r"\s*([0-9a-f]+):", line)
        if match and 0x28C40 <= int(match.group(1), 16) < 0x28CB4:
            settle_lines.append(line)
    settle = "\n".join(settle_lines)
    if "FT_SetDivisor" in settle or "ftdi_mpsse" in settle or "0x86" in settle:
        raise AssertionError("settck handler now appears to touch MPSSE clock state")
    if "mov    $0x1c9c380,%eax" not in clock or "div    %ecx" not in clock:
        raise AssertionError("MPSSE rate formula no longer matches expected 30 MHz base")
    if "mov    $0xffff8a97,%edx" not in clock or "movb   $0x86" not in clock:
        raise AssertionError("MPSSE setup command sequence changed")
    if "SQCoEStartXVC" not in strings_out or "xvcServer_v1.0:%lu" not in strings_out:
        raise AssertionError("expected XVC evidence strings missing")

    needed = re.findall(r"Shared library: \[(.*?)\]", dynamic)
    build_id_match = re.search(r"Build ID: ([0-9a-f]+)", notes)
    size = path.stat().st_size
    callees = sorted(set(re.findall(r"call\s+[0-9a-f]+ <([^>]+)>", settle)))
    if not callees or any(not (name.startswith("read@plt") or name.startswith("write@plt") or
                               name.startswith("perror@plt")) for name in callees):
        raise AssertionError(f"unexpected call target in settck handler: {callees}")
    return {
        "path": str(path), "size_bytes": size, "sha256": digest,
        "expected_sha256_matches": digest == EXPECTED_SHA256,
        "file": file_text.strip(),
        "machine": re.search(r"Machine:\s+(.+)", header).group(1).strip(),
        "class": re.search(r"Class:\s+(.+)", header).group(1).strip(),
        "build_id": build_id_match.group(1) if build_id_match else None,
        "stripped": ".symtab" not in sections,
        "debug_symbols_present": ".symtab" in sections,
        "dwarf_sections_present": bool(re.search(r"\.debug_(info|line)", sections)),
        "dynamic_libraries": needed,
        "static_checks": {
            "xvc_getinfo_settck_shift_dispatch_found": True,
            "settck_reads_9_bytes_after_2_byte_dispatch": True,
            "settck_copies_u32_at_request_offset_7_and_writes_4_bytes": True,
            "settck_touches_mpsse_clock_state": False,
            "settck_direct_call_targets": callees,
            "mpsse_rate_formula_30mhz_over_requested_minus_one": True,
            "mpsse_sequence_97_8a_86_divisor": True,
            "xvc_getinfo_banner_found": True
        }
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--elf", type=Path, default=DEFAULT_ELF,
                    help="retained ELF path (the file is inspected but never executed)")
    ap.add_argument("--allow-other-hash", action="store_true",
                    help="report an ELF with a different SHA-256 without failing identity check")
    args = ap.parse_args()
    result = inspect(args.elf)
    print(json.dumps(result, indent=2))
    if not result["expected_sha256_matches"] and not args.allow_other_hash:
        raise SystemExit("ELF SHA-256 differs from the pinned FK33 review artifact")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
