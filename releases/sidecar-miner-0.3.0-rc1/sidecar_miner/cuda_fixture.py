"""Validator and CPU oracle extracted from qualified PearlHash test logic.

The transcript/digest loop follows the independently checked `verify_tile`
function in the qualified upstream open-pearl-miner test_pipeline_e2e.py. It is
CPU-only and returns the raw keyed-BLAKE3 digest bytes consumed by the CUDA ABI.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

import blake3
import numpy as np

SCHEMA = "sidecar-cuda-raw-digest-v1"
TILE = 16
R = 64
ORACLE_ID = "open-pearl-miner/tests/test_pipeline_e2e.py::verify_tile"
ORACLE_SOURCE_SHA256 = "9c4d7e3eb692b75632e46b93ce6034d2e5f6c37beff250d08f95da0e57eb59d8"


@dataclass(frozen=True)
class CudaRawDigestFixture:
    manifest_path: Path
    manifest: dict
    input_bytes: bytes
    expected_bytes: bytes
    A_noised: np.ndarray
    Bt_noised: np.ndarray
    key: bytes
    target: bytes
    m: int
    n: int
    k: int
    reduction: int
    digest_count: int


def deterministic_inputs():
    """Build minimal Ampere input: 64x64 matrices, k=64, fixed signed bytes."""
    m = n = k = R
    A = np.fromfunction(lambda i, j: ((i * 7 + j * 3) % 127) - 63,
                        (m, k), dtype=int).astype(np.int8)
    B = np.fromfunction(lambda i, j: ((i * 5 + j * 11) % 127) - 63,
                        (k, n), dtype=int).astype(np.int8)
    Bt = np.ascontiguousarray(B.T)
    key = bytes((i * 17 + 3) & 0xff for i in range(32))
    target = bytes([0xff]) * 32
    return A, B, Bt, key, target


def cpu_raw_digests(A_noised, Bt_noised, key: bytes, reduction: int = R) -> bytes:
    """Verbatim transcript semantics of upstream verify_tile, all tiles row-major.

    Inputs are signed int8 A[m,k], Bt[n,k]. Each tile hashes the 16-word
    transcript serialized little-endian, using keyed BLAKE3 with `key`.
    """
    A = np.ascontiguousarray(A_noised, dtype=np.int8)
    Bt = np.ascontiguousarray(Bt_noised, dtype=np.int8)
    if A.ndim != 2 or Bt.ndim != 2 or A.shape[1] != Bt.shape[1]:
        raise ValueError("A_noised and Bt_noised must be rank-2 with matching K")
    m, k = A.shape
    n = Bt.shape[0]
    if m % TILE or n % TILE or k % reduction or len(key) != 32:
        raise ValueError("invalid CUDA raw-digest dimensions/key")
    T = k // reduction
    out = bytearray()
    for row in range(0, m, TILE):
        for col in range(0, n, TILE):
            transcript = np.zeros(16, dtype=np.uint32)
            Csum = np.zeros((TILE, TILE), dtype=np.int64)
            for t in range(T):
                p = t * reduction
                Csum = Csum + A[row:row + TILE, p:p + reduction].astype(np.int64) @ \
                    Bt[col:col + TILE, p:p + reduction].astype(np.int64).T
                cur = Csum.astype(np.int32).reshape(-1).view(np.uint32)
                h = np.bitwise_xor.reduce(cur)
                idx = t % 16
                x = transcript[idx]
                transcript[idx] = np.uint32(((int(x) << 13) | (int(x) >> 19)) & 0xffffffff) ^ h
            tb = b"".join(int(word).to_bytes(4, "little") for word in transcript)
            out.extend(blake3.blake3(tb, key=key).digest())
    return bytes(out)


def generate_fixture_files(directory: str | Path) -> Path:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    A, B, Bt, key, target = deterministic_inputs()
    input_bytes = A.tobytes(order="C") + Bt.tobytes(order="C") + key + target
    expected = cpu_raw_digests(A, Bt, key, R)
    input_name = "pearlhash-16x16-input.bin"
    expected_name = "pearlhash-16x16-expected.bin"
    (directory / input_name).write_bytes(input_bytes)
    (directory / expected_name).write_bytes(expected)
    manifest = {
        "schema": SCHEMA,
        "version": 1,
        "kind": "pearlhash-raw-keyed-blake3-digests",
        "shape": {"A_noised": [64, 64], "Bt_noised": [64, 64], "tile": [16, 16],
                  "reduction_R": R, "k": 64, "digest_count": 16},
        "input_file": input_name,
        "input_encoding": "A_noised signed-int8 C-row-major; Bt_noised signed-int8 C-row-major; key32; target32",
        "input_item_count": 8192,
        "input_sha256": hashlib.sha256(input_bytes).hexdigest(),
        "input_bytes": len(input_bytes),
        "expected_file": expected_name,
        "output_encoding": "raw BLAKE3 digest bytes per tile; 32 bytes each",
        "digest_byte_order": "BLAKE3 output byte sequence; CUDA uint32 words are little-endian on target",
        "tile_order": "row-major: tile-row outer, tile-column inner; origin (0,0) then (0,16) ...",
        "digest_count": 16,
        "digest_size_bytes": 32,
        "expected_bytes": len(expected),
        "expected_sha256": hashlib.sha256(expected).hexdigest(),
        "cpu_oracle": {"identity": ORACLE_ID, "upstream_source_sha256": ORACLE_SOURCE_SHA256,
                       "numpy_version": np.__version__, "blake3_version": getattr(blake3, "__version__", "unknown"),
                       "method": "int64 tile accumulation; int32 wrap; xor reduction; rotl32(13)-xor transcript; keyed BLAKE3"},
        "input_generator": "A[i,j]=((7*i+3*j)%127)-63; B[i,j]=((5*i+11*j)%127)-63; Bt=C-contiguous transpose(B); key[b]=(17*b+3)&255; target=0xff*32",
        "ordering_and_matrix_contract": "A[m,k], Bt[n,k], signed int8 two's-complement; digest IDs match CUDA tile_id=(row/16)*(n/16)+(column/16)",
    }
    manifest_path = directory / "pearlhash-16x16-raw-digest-v1.json"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    return manifest_path


def load_fixture(path: str | Path, *, replay: bool = True) -> CudaRawDigestFixture:
    manifest_path = Path(path)
    obj = json.loads(manifest_path.read_text())
    if obj.get("schema") != SCHEMA or obj.get("version") != 1:
        raise ValueError("unsupported CUDA fixture schema/version")
    shape = obj.get("shape")
    if not isinstance(shape, dict) or shape != {"A_noised": [64, 64], "Bt_noised": [64, 64],
            "tile": [16, 16], "reduction_R": 64, "k": 64, "digest_count": 16}:
        raise ValueError("fixture shape/count does not match one Ampere minimum grid")
    if obj.get("digest_count") != 16: raise ValueError("wrong digest item count")
    if obj.get("input_item_count") != 8192: raise ValueError("wrong signed-int8 matrix item count")
    if obj.get("input_encoding") != "A_noised signed-int8 C-row-major; Bt_noised signed-int8 C-row-major; key32; target32":
        raise ValueError("unsupported input encoding")
    if obj.get("output_encoding") != "raw BLAKE3 digest bytes per tile; 32 bytes each":
        raise ValueError("unsupported output encoding")
    if obj.get("digest_size_bytes") != 32 or obj.get("expected_bytes") != 16 * 32:
        raise ValueError("wrong digest size")
    if obj.get("digest_byte_order") != "BLAKE3 output byte sequence; CUDA uint32 words are little-endian on target":
        raise ValueError("unsupported digest byte-order marker")
    if obj.get("tile_order") != "row-major: tile-row outer, tile-column inner; origin (0,0) then (0,16) ...":
        raise ValueError("unsupported tile ordering")
    oracle = obj.get("cpu_oracle", {})
    if oracle.get("identity") != ORACLE_ID or oracle.get("upstream_source_sha256") != ORACLE_SOURCE_SHA256:
        raise ValueError("CPU oracle identity does not match qualified source")
    if obj.get("input_generator") != "A[i,j]=((7*i+3*j)%127)-63; B[i,j]=((5*i+11*j)%127)-63; Bt=C-contiguous transpose(B); key[b]=(17*b+3)&255; target=0xff*32":
        raise ValueError("unknown deterministic input generator")
    base = manifest_path.parent
    input_bytes = (base / obj["input_file"]).read_bytes()
    expected = (base / obj["expected_file"]).read_bytes()
    if len(input_bytes) != 8256: raise ValueError("truncated or malformed input fixture")
    if len(expected) != 512: raise ValueError("truncated or malformed expected output")
    if obj.get("input_bytes") != len(input_bytes) or hashlib.sha256(input_bytes).hexdigest() != obj.get("input_sha256"):
        raise ValueError("input hash/length mismatch")
    if hashlib.sha256(expected).hexdigest() != obj.get("expected_sha256"):
        raise ValueError("expected output hash mismatch")
    A = np.frombuffer(input_bytes[:4096], np.int8).reshape(64, 64).copy()
    Bt = np.frombuffer(input_bytes[4096:8192], np.int8).reshape(64, 64).copy()
    key, target = input_bytes[8192:8224], input_bytes[8224:8256]
    if replay:
        gen_A, _B, gen_Bt, gen_key, gen_target = deterministic_inputs()
        regenerated = gen_A.tobytes() + gen_Bt.tobytes() + gen_key + gen_target
        if regenerated != input_bytes: raise ValueError("deterministic input replay mismatch")
        replayed = cpu_raw_digests(A, Bt, key, R)
        if replayed != expected: raise ValueError("CPU raw-digest replay mismatch")
    return CudaRawDigestFixture(manifest_path,obj,input_bytes,expected,A,Bt,key,target,64,64,64,64,16)


def compare_digests(fixture: CudaRawDigestFixture, actual: bytes) -> bool:
    return len(actual) == fixture.digest_count * 32 and actual == fixture.expected_bytes
