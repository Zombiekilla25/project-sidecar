#!/usr/bin/python3
"""Verify a canonical signed FK0957 release/runtime manifest."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
import sys

import phk2_fk0957_remote_topology_endpoint as endpoint


def verify_document(document: object, *, issuers: dict[str, bytes], now=None) -> dict:
    payload, _payload_bytes, _payload_digest = endpoint._verify_signed(
        document, expected_issuer="FK0957_RELEASE_AUTHORITY",
        public_key_raw=issuers.get("release", b""),
        payload_fields=endpoint.MANIFEST_FIELDS,
        schema="fk0957-runtime-source-manifest-v1")
    current = now or datetime.now(timezone.utc)
    issued = endpoint._parse_time(payload.get("issued_at"))
    if current < issued or (current - issued).total_seconds() > 86400:
        raise endpoint.Refusal("RUNTIME_MANIFEST_STALE")
    endpoint._verify_runtime_manifest(payload, endpoint._profile_hash())
    return payload


def verify_file(path: Path) -> dict:
    raw = endpoint._read_protected_file(path, owner=0, mode=0o400,
                                        limit=16 * 1024 * 1024,
                                        failure="RUNTIME_MANIFEST")
    document = endpoint._parse_canonical(raw, 16 * 1024 * 1024)
    issuers = endpoint._load_trust_config()
    return verify_document(document, issuers=issuers)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args(argv)
    try:
        payload = verify_file(args.manifest)
    except (endpoint.Refusal, OSError, ValueError, TypeError):
        sys.stdout.write("RUNTIME_MANIFEST=REFUSED\n")
        return 2
    sys.stdout.write("RUNTIME_MANIFEST=VERIFIED\n")
    sys.stdout.write(f"PRODUCTION_HEAD={payload['production_head']}\n")
    sys.stdout.write(f"SOURCE_COUNT={len(payload['source_hashes'])}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
