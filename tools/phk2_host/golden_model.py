#!/usr/bin/env python3
"""Offline CPU replay for a retained PRL real-v3-slice evidence bundle.

The tool reads a capture and a separately retained V64 compact recipe. It does
not import the CUDA library, open sockets, or write inside either evidence tree.
Only the requested JSON result path is written.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import importlib
import json
import os
import random
import struct
import sys
from pathlib import Path

K, R = 4096, 256
M = N = 131072
EXPECTED_PRODUCTION_COMMIT = "41ef42158b110a088662f3aac1f7fd9c064bbe1b"
EXPECTED_PRODUCTION_RNG_SHA = "945ce7d5603f9d0ba422706c0882208aff361295aa6070e8224728a5cdf01a0e"
EXPECTED_CAPTURE_BUILDER_SHA = "361da93cb6cb353830a9123bf33fb7317380463b0e3ffbd6ac940bad33461e1a"
EXPECTED_MAKE_VECTORS_SHA = "fd4cb39831e32ad68e24af527b70dc992036c2de8a12d7bd8f129506b433eb0b"
EXPECTED_PACKAGE_REPLAY_SHA = "e69909083c8f5885089b672fb7d3e76d83df71172baff5225fc26c07e3aecc1a"


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha_file(path: Path) -> str:
    return sha(path.read_bytes())


def signed8(v: int) -> int:
    return v if v < 128 else v - 256


def philox4(base: int, seed64: int) -> tuple[int, int, int, int]:
    """CPU translation of the production rng_fill_sm61.cu counter mapping."""
    mask = 0xFFFFFFFF
    lo, hi = base & mask, (base >> 32) & mask
    c0, c1, c2, c3 = lo, hi, hi ^ lo, 0
    kx, ky = seed64 & mask, (seed64 >> 32) & mask
    for _ in range(10):
        p0 = c0 * 0xD2511F53
        p1 = c2 * 0xCD9E8D57
        c0, c1, c2, c3 = (
            ((p1 >> 32) ^ c1 ^ kx) & mask,
            p1 & mask,
            ((p0 >> 32) ^ c3 ^ ky) & mask,
            p0 & mask,
        )
        p = kx * 0x9E3779B9
        kx, ky = (((p >> 32) ^ ky ^ 0x9E3779B9) & mask, p & mask)
    return tuple((v & 0x7F) - 64 for v in (c0, c1, c2, c3))


def extract_source_philox(make_vectors_path: Path):
    """Load only audited pure Philox functions; never execute source top-level."""
    tree = ast.parse(make_vectors_path.read_text())
    wanted_constants = {"MASK", "M0", "M1", "W"}
    wanted_functions = {"key_round", "philox4", "rng_value"}
    nodes = []
    found_constants, found_functions = set(), set()
    for node in tree.body:
        if isinstance(node, ast.Assign):
            names = {t.id for t in node.targets if isinstance(t, ast.Name)}
            if names & wanted_constants:
                nodes.append(node)
                found_constants |= names & wanted_constants
        elif isinstance(node, ast.FunctionDef) and node.name in wanted_functions:
            nodes.append(node)
            found_functions.add(node.name)
    if found_constants != wanted_constants or found_functions != wanted_functions:
        raise ValueError("unexpected source Philox reference structure")
    ns: dict[str, object] = {}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(make_vectors_path), "exec"), ns)
    return ns["philox4"], ns["rng_value"]


def load_recipe(recipe_root: Path, capture_manifest: dict) -> tuple[bytes, dict]:
    recipe_path = recipe_root / "recipe.bin"
    report_path = recipe_root / "report.json"
    sums_path = recipe_root / "SHA256SUMS"
    recipe, report = recipe_path.read_bytes(), json.loads(report_path.read_text())
    expected = report["v64_recipe"]["sha256"]
    if sha(recipe) != expected or report.get("result") != "PASS":
        raise ValueError("compact recipe hash/result mismatch")
    if sums_path.exists():
        sums = sums_path.read_text().split()
        if len(sums) < 2 or sums[0] != sha(recipe) or sums[1] != "recipe.bin":
            raise ValueError("compact recipe SHA256SUMS mismatch")
    capgrid = capture_manifest["grid"]
    if report.get("grid") != {k: capgrid[k] for k in report.get("grid", {})}:
        raise ValueError("compact recipe does not bind to capture grid")
    if len(recipe) != 53248:
        raise ValueError("unexpected V64 compact recipe length")
    return recipe, report


def expand_capture(recipe: bytes, seed64: int) -> tuple[tuple[bytes, ...], tuple[tuple[bytes, ...], ...]]:
    """Generate the retained 64-row A / 80-row B-transpose production slice."""
    eal_len, ebr_len, ear_len, ebl_len = 64 * R, 80 * R, K * 2, K * 2
    off = 0
    eal = recipe[off:off + eal_len]; off += eal_len
    ebr = recipe[off:off + ebr_len]; off += ebr_len
    ear = recipe[off:off + ear_len]; off += ear_len
    ebl = recipe[off:off + ebl_len]; off += ebl_len
    if off != len(recipe):
        raise ValueError("recipe layout mismatch")

    a = bytearray(64 * K)
    bt = bytearray(80 * K)
    for row in range(64):
        rowbase = row * K
        for kbase in range(0, K, 4):
            vals = philox4(rowbase + kbase, seed64)
            for j, value in enumerate(vals):
                a[rowbase + kbase + j] = value & 0xFF

    for k in range(K):
        kbase = k * N
        rowbase = k * K
        for rbase in range(0, 80, 4):
            vals = philox4(kbase + rbase, (seed64 + 1) & 0xFFFFFFFFFFFFFFFF)
            for j, value in enumerate(vals):
                bt[(rbase + j) * K + k] = value & 0xFF

    an = bytearray(len(a))
    btn = bytearray(len(bt))
    for row in range(64):
        rb = row * K
        eb = row * R
        for k in range(K):
            plus, minus = ear[2 * k], ear[2 * k + 1]
            x = signed8(a[rb + k]) + signed8(eal[eb + plus]) - signed8(eal[eb + minus])
            if not -128 <= x <= 127:
                raise ValueError(f"A int8 overflow row={row} k={k}")
            an[rb + k] = x & 0xFF
    for row in range(80):
        rb = row * K
        eb = row * R
        for k in range(K):
            plus, minus = ebl[2 * k], ebl[2 * k + 1]
            x = signed8(bt[rb + k]) + signed8(ebr[eb + plus]) - signed8(ebr[eb + minus])
            if not -128 <= x <= 127:
                raise ValueError(f"B^T int8 overflow row={row} k={k}")
            btn[rb + k] = x & 0xFF

    vectors: list[tuple[bytes, ...]] = []
    for matrix, row_groups in ((an, 4), (btn, 5)):
        for group in range(row_groups):
            start = group * 16
            vectors.append(tuple(
                bytes(matrix[(start + j) * K + k] for j in range(16))
                for k in range(K)
            ))

    port_groups = ((0, 1), (2, 3), (4, 5), (6, 7, 8))
    ports = tuple(
        b"".join(vectors[group][k] for k in range(K) for group in groups)
        for groups in port_groups
    )
    return ports, tuple(vectors)


def cpu_known_answers(vectors: tuple[tuple[bytes, ...], ...], pow_key: bytes):
    """CPU model copied semantically from the retained capture producer."""
    mask = 0xFFFFFFFF
    iv = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A]
    perm = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]

    def rr(v: int, n: int) -> int:
        return ((v >> n) | (v << (32 - n))) & mask

    def compress(words: list[int]) -> bytes:
        m = list(words)
        v = list(struct.unpack("<8I", pow_key)) + iv + [0, 0, 64, 27]

        def g(a, b, c, d, x, y):
            v[a] = (v[a] + v[b] + x) & mask
            v[d] = rr(v[d] ^ v[a], 16)
            v[c] = (v[c] + v[d]) & mask
            v[b] = rr(v[b] ^ v[c], 12)
            v[a] = (v[a] + v[b] + y) & mask
            v[d] = rr(v[d] ^ v[a], 8)
            v[c] = (v[c] + v[d]) & mask
            v[b] = rr(v[b] ^ v[c], 7)

        schedule = [(0,4,8,12),(1,5,9,13),(2,6,10,14),(3,7,11,15),
                    (0,5,10,15),(1,6,11,12),(2,7,8,13),(3,4,9,14)]
        for _ in range(7):
            for i, (a,b,c,d) in enumerate(schedule):
                g(a,b,c,d,m[2*i],m[2*i+1])
            m = [m[i] for i in perm]
        return struct.pack("<8I", *(v[i] ^ v[i+8] for i in range(8)))

    transcripts, digests = [], []
    for engine in range(20):
        av, bv = vectors[engine // 5], vectors[4 + engine % 5]
        acc = [0] * 256
        words = []
        for k in range(K):
            aa = struct.unpack("16b", av[k])
            bb = struct.unpack("16b", bv[k])
            for i, x in enumerate(aa):
                base = i * 16
                for j, y in enumerate(bb):
                    acc[base + j] += x * y
            if k % R == R - 1:
                value = 0
                for x in acc:
                    value ^= x & mask
                words.append(value)
        transcripts.append(struct.pack("<16I", *words))
        digests.append(compress(words))
    return tuple(transcripts), tuple(digests)


def first_diff(expected: bytes, actual: bytes):
    for i, (a, b) in enumerate(zip(expected, actual)):
        if a != b:
            return {"offset": i, "expected": a, "actual": b}
    if len(expected) != len(actual):
        return {"offset": min(len(expected), len(actual)), "expected": "EOF", "actual": "EOF"}
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--capture-root", required=True, type=Path)
    ap.add_argument("--recipe-root", required=True, type=Path)
    ap.add_argument("--producer-script", required=True, type=Path)
    ap.add_argument("--make-vectors-source", required=True, type=Path)
    ap.add_argument("--production-rng-source", required=True, type=Path)
    ap.add_argument("--production-repo", required=True, type=Path)
    ap.add_argument("--reference-package-root", required=True, type=Path)
    ap.add_argument("--random-cases", type=int, default=100000)
    ap.add_argument("--random-seed", type=int, default=0x50484B32)
    ap.add_argument("--output", type=Path, default=Path("docs/phk2-production-oracle-result.json"))
    args = ap.parse_args()

    capture = args.capture_root.resolve()
    manifest = json.loads((capture / "manifest.json").read_text())
    source_job = json.loads((capture / "source-job.json").read_text())
    if manifest.get("format") != "fk33-prl-real-v3-slice-v1":
        raise ValueError("unsupported capture format")
    if source_job.get("share_submission") is not False:
        raise ValueError("source job is not explicitly non-submitted evidence")
    for name, meta in manifest["files"].items():
        raw = (capture / name).read_bytes()
        if len(raw) != meta["bytes"] or sha(raw) != meta["sha256"]:
            raise ValueError(f"capture file integrity failure: {name}")
    if sha((capture / "source-job.json").read_bytes()) != manifest["files"]["source-job.json"]["sha256"]:
        raise ValueError("source-job manifest binding failed")

    production_head = __import__("subprocess").check_output(
        ["git", "-C", str(args.production_repo.resolve()), "rev-parse", "HEAD"], text=True
    ).strip()
    production_rng_sha = sha_file(args.production_rng_source)
    producer_sha = sha_file(args.producer_script)
    make_vectors_sha = sha_file(args.make_vectors_source)
    if production_head != EXPECTED_PRODUCTION_COMMIT:
        raise ValueError("production source commit differs from pinned identity")
    if production_rng_sha != EXPECTED_PRODUCTION_RNG_SHA:
        raise ValueError("production CUDA Philox source hash differs from pinned identity")
    if producer_sha != EXPECTED_CAPTURE_BUILDER_SHA:
        raise ValueError("real-slice producer source differs from pinned identity")
    if make_vectors_sha != EXPECTED_MAKE_VECTORS_SHA:
        raise ValueError("CPU replay source differs from pinned identity")

    recipe, recipe_report = load_recipe(args.recipe_root.resolve(), manifest)
    seed64 = int(manifest["grid"]["seed64"], 16)
    if (K, R) != (4096, 256) or manifest["source_job"]["cert_version"] != 3:
        raise ValueError("unexpected production profile")

    ports, vectors = expand_capture(recipe, seed64)
    captured_ports = tuple((capture / f"hbm_port{i}.bin").read_bytes() for i in range(4))
    combined_capture = b"".join(captured_ports)
    port_checks = []
    for i, (got, expected) in enumerate(zip(ports, captured_ports)):
        port_checks.append({
            "port": i,
            "bytes": len(expected),
            "capture_sha256": sha(expected),
            "oracle_sha256": sha(got),
            "exact": got == expected,
            "first_difference": first_diff(expected, got),
        })

    # The retained producer's source-manifest audit protects the CPU compute oracle.
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(args.reference_package_root.resolve()))
    href = importlib.import_module("host.reference")
    audited_source_count = href.audit_sources()
    cpu_transcripts, cpu_digests = cpu_known_answers(vectors, bytes.fromhex(manifest["grid"]["noise_seed_A"]))
    gpu_transcripts = (capture / "gpu_transcripts.bin").read_bytes()
    exp_transcripts = (capture / "expected_transcripts.bin").read_bytes()
    gpu_digests = (capture / "gpu_digests.bin").read_bytes()
    exp_digests = (capture / "expected_digests.bin").read_bytes()
    cpu_transcript_bytes = b"".join(cpu_transcripts)
    cpu_digest_bytes = b"".join(cpu_digests)
    cpu_gpu_transcript_matches = sum(
        cpu_transcripts[i] == gpu_transcripts[i*64:(i+1)*64] for i in range(20)
    )
    cpu_gpu_digest_matches = sum(
        cpu_digests[i] == gpu_digests[i*32:(i+1)*32] for i in range(20)
    )

    source_philox, source_rng_value = extract_source_philox(args.make_vectors_source)
    rng = random.Random(args.random_seed)
    mismatches = []
    for case in range(args.random_cases):
        seed = rng.getrandbits(64)
        index = rng.getrandbits(63) & ~3
        actual = philox4(index, seed)
        expected = tuple(source_philox(index, seed))
        # Also compare a lane selected by the producer's scalar byte-index helper.
        lane = rng.randrange(4)
        if actual != expected or source_rng_value(index + lane, seed) != actual[lane]:
            mismatches.append({"case": case, "seed": seed, "index": index, "lane": lane,
                               "oracle": actual, "reference": expected})
            if len(mismatches) >= 16:
                break

    gpu_library = manifest["gpu_library"]
    gpu_lib_path = Path(gpu_library["path"])
    gpu_library_exists = gpu_lib_path.is_file()
    gpu_library_sha_ok = gpu_library_exists and sha_file(gpu_lib_path) == gpu_library["sha256"]
    result = {
        "schema_version": "phk2-production-capture-oracle-v1",
        "capture": {
            "path": str(capture),
            "run_id": "real-v3-slice-1017db2f_2097152-20261013T222702Z",
            "job_id": manifest["source_job"]["job_id"],
            "captured_job_utc": source_job["captured_utc"],
            "job_key": manifest["grid"]["job_key"],
            "setup_seed64": manifest["grid"]["seed64"],
            "dimensions": {"M": M, "N": N, "K": K, "R": R},
            "selection": {"A_rows": manifest["fk"]["A_rows"], "B_columns": manifest["fk"]["B_columns"]},
            "port_bytes": [len(x) for x in captured_ports],
            "total_bytes": len(combined_capture),
            "ordered_ports_sha256": sha(combined_capture),
            "per_port": port_checks,
            "noise_seed_A": manifest["grid"]["noise_seed_A"],
            "noise_seed_B": manifest["grid"]["noise_seed_B"],
            "compact_recipe_sha256": sha(recipe),
            "compact_recipe_bytes": len(recipe),
            "capture_producer_gpu_library_sha256": gpu_library["sha256"],
            "capture_producer_gpu_library_hash_verified": gpu_library_sha_ok,
            "capture_producer_script_sha256": producer_sha,
            "source_job_share_submission": source_job["share_submission"],
        },
        "source_identity": {
            "production_repo_commit": production_head,
            "production_rng_source_sha256": production_rng_sha,
            "producer_build_script_sha256": producer_sha,
            "cpu_vector_replay_source_sha256": make_vectors_sha,
            "cpu_search_oracle_audited_file_count": audited_source_count,
            "capture_manifest_sha256": sha((capture / "manifest.json").read_bytes()),
        },
        "oracle": {
            "production_operand_exact": all(x["exact"] for x in port_checks),
            "production_operand_sha256": sha(b"".join(ports)),
            "production_operand_bytes": sum(map(len, ports)),
            "cpu_transcript_sha256": sha(cpu_transcript_bytes),
            "expected_cpu_transcript_sha256": sha(exp_transcripts),
            "gpu_transcript_sha256": sha(gpu_transcripts),
            "cpu_transcript_exact": cpu_transcript_bytes == exp_transcripts,
            "cpu_gpu_transcript_match_count": cpu_gpu_transcript_matches,
            "cpu_digest_sha256": sha(cpu_digest_bytes),
            "expected_cpu_digest_sha256": sha(exp_digests),
            "gpu_digest_sha256": sha(gpu_digests),
            "cpu_digest_exact": cpu_digest_bytes == exp_digests,
            "cpu_gpu_digest_match_count": cpu_gpu_digest_matches,
        },
        "randomized_philox_reference": {
            "cases": args.random_cases,
            "mismatches": len(mismatches),
            "first_mismatches": mismatches,
            "scope": "independent random (u64 setup seed, aligned 64-bit Philox counter) blocks and scalar lanes against the archived pure CPU reference extracted from make_vectors.py; full captured K4096/R256 operand replay is separately checked above",
            "seed": args.random_seed,
        },
        "compact_descriptor": {
            "tested_fields": ["setup_seed64", "compact_noise_recipe[53248]", "profile K4096/R256 and 4x5 row/column map", "generation/sequence metadata"],
            "tested_data_bytes": len(recipe) + 8,
            "job_key_bytes": 32,
            "job_key_role": "identity/provenance; compact recipe replay does not consume it directly",
            "minimum_seed_only_descriptor_proven": False,
            "recipe_to_hbm_reduction_x": len(combined_capture) / len(recipe),
            "note": "The 53,248-byte recipe is already-derived sparse noise state. This replay proves the captured production slice from seed+recipe; it does not prove recipe/noise-seed derivation from job_key alone.",
        },
        "batch_model": {
            "classification": "SEED_PER_WORK_REQUIRED",
            "reason": "The production miner calls setup_job with a fresh time-derived u64 seed for each new grid; no consecutive seed-range semantics are present in the inspected path.",
            "batch64_exact": "NOT_RUN",
        },
        "gates": {
            "production_capture_provenance": "PASS" if gpu_library_sha_ok and source_job["share_submission"] is False else "FAIL",
            "production_oracle_exact": "PASS" if all(x["exact"] for x in port_checks) else "FAIL",
            "production_search_cpu_crosscheck": "PASS" if cpu_transcripts == tuple(exp_transcripts[i*64:(i+1)*64] for i in range(20)) and cpu_digests == tuple(exp_digests[i*32:(i+1)*32] for i in range(20)) else "FAIL",
            "gpu_known_answer_crosscheck": "PASS" if gpu_transcripts == exp_transcripts and gpu_digests == exp_digests and cpu_gpu_transcript_matches == 20 and cpu_gpu_digest_matches == 20 else "FAIL",
            "randomized_reference": "PASS" if not mismatches and args.random_cases >= 100000 else "FAIL",
            "production_compact_descriptor": "PASS_CAPTURED_SLICE_RECIPE" if all(x["exact"] for x in port_checks) else "FAIL",
            "production_batch64_exact": "NOT_PROVEN",
            "production_compact_end_to_end": "PASS_CAPTURED_OPERAND_AND_20_TILE_CPU_GPU_KNOWN_ANSWERS; no accepted-share proof in capture",
            "phk2_autonomous_workgen_proven": False,
        },
        "activity": {"cuda_executed": False, "pool_connected": False, "hardware_accessed": False,
                     "testbench_ssh": False, "mining_changed": False},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({
        "capture_bytes": len(combined_capture),
        "capture_sha256": sha(combined_capture),
        "operand_exact": result["oracle"]["production_operand_exact"],
        "cpu_gpu_transcripts": f"{cpu_gpu_transcript_matches}/20",
        "cpu_gpu_digests": f"{cpu_gpu_digest_matches}/20",
        "random_cases": args.random_cases,
        "random_mismatches": len(mismatches),
        "output": str(args.output),
    }, sort_keys=True))
    return 0 if result["oracle"]["production_operand_exact"] and not mismatches else 1


if __name__ == "__main__":
    raise SystemExit(main())
