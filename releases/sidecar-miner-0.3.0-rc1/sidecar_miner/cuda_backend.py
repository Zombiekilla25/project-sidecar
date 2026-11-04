"""Lazy, explicitly device-pinned adapter for the Sidecar CUDA ABI.

Importing this module never loads a shared library or initializes CUDA. Real
execution remains opt-in until the adapter is qualified against a GPU vector.
"""
from __future__ import annotations

import ctypes
import hashlib
import os
import time
from dataclasses import dataclass
from pathlib import Path

from sidecar_scheduler.contracts import BackendResult, WorkBatch

ABI_VERSION = 1
REAL_CUDA_AVAILABLE_UNQUALIFIED = "REAL_CUDA_AVAILABLE_UNQUALIFIED"


class CudaBackendError(RuntimeError):
    pass


@dataclass(frozen=True)
class CudaPowBatch:
    """Prepared PearlHash stage inputs; pointers are owned by the ABI context."""
    A: int
    Bt: int
    key: int
    target: int
    transcript: int
    digests: int
    found: int
    coord: int
    m: int
    n: int
    k: int
    rank: int
    variant: int


@dataclass(frozen=True)
class CudaPowOutput:
    digests: bytes
    found: bool
    row: int | None
    column: int | None
    digest_count: int


class CudaPearlHashBackend:
    """GpuBackend adapter for the bounded low-level PearlHash CUDA ABI.

    Device selection is required and performed by `sidecar_cuda_create`; every
    ABI operation then reselects the context's device before touching CUDA.
    `allow_unqualified` defaults false and must stay false until vector parity,
    proof construction and CPU verification have passed on target hardware.
    """
    backend_id = "cuda-pearlhash"

    def __init__(self, gpu_id: int, library_path: str | os.PathLike | None = None,
                 *, loader=None, allow_unqualified: bool = False):
        if isinstance(gpu_id, bool) or not isinstance(gpu_id, int) or gpu_id < 0:
            raise ValueError("gpu_id must be an explicit non-negative integer")
        self.gpu_id = gpu_id
        self.library_path = Path(library_path) if library_path else None
        self._loader = loader or ctypes.CDLL
        self._allow_unqualified = allow_unqualified
        self._lib = None
        self._context = ctypes.c_void_p()
        self._prepared = None
        self.healthy = True
        self.state = REAL_CUDA_AVAILABLE_UNQUALIFIED

    def initialize(self) -> None:
        if not self._allow_unqualified:
            raise CudaBackendError("real CUDA backend is disabled until hardware vector qualification")
        configured = str(self.library_path) if self.library_path else os.environ.get("SIDECAR_CUDA_LIBRARY", "")
        if not configured:
            raise CudaBackendError("SIDECAR_CUDA_LIBRARY must name the Sidecar CUDA ABI library")
        lib = self._loader(configured)
        version = lib.sidecar_cuda_abi_version
        version.restype = ctypes.c_uint
        if version() != ABI_VERSION:
            raise CudaBackendError("incompatible Sidecar CUDA ABI version")
        create = lib.sidecar_cuda_create
        create.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_int]
        create.restype = ctypes.c_int
        context = ctypes.c_void_p()
        rc = create(ctypes.byref(context), self.gpu_id)
        if rc:
            self.healthy = False
            raise CudaBackendError(f"CUDA context creation failed (status {rc})")
        self._lib, self._context = lib, context

    def _ready(self):
        if self._lib is None or not self._context.value:
            raise CudaBackendError("CUDA backend is not initialized")

    def allocate(self, nbytes: int) -> ctypes.c_void_p:
        self._ready()
        if nbytes <= 0:
            raise ValueError("allocation size must be positive")
        ptr = ctypes.c_void_p()
        fn = self._lib.sidecar_cuda_malloc
        fn.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_size_t]
        fn.restype = ctypes.c_int
        rc = fn(self._context, ctypes.byref(ptr), nbytes)
        if rc:
            self.healthy = False
            raise CudaBackendError(f"CUDA allocation failed (status {rc})")
        return ptr

    def upload(self, device_ptr: ctypes.c_void_p, data: bytes) -> None:
        self._ready()
        host = ctypes.create_string_buffer(data)
        fn = self._lib.sidecar_cuda_copy_h2d
        fn.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
        fn.restype = ctypes.c_int
        rc = fn(self._context, device_ptr, host, len(data))
        if rc:
            self.healthy = False
            raise CudaBackendError(f"CUDA input copy failed (status {rc})")

    def free(self, device_ptr: ctypes.c_void_p) -> None:
        self._ready()
        fn = self._lib.sidecar_cuda_free
        fn.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        fn.restype = ctypes.c_int
        rc = fn(self._context, device_ptr)
        if rc:
            self.healthy = False
            raise CudaBackendError(f"CUDA free failed (status {rc})")

    def prepare_job(self, job) -> None:
        self._ready()
        self._prepared = (job.fingerprint, job.generation)

    def compute_batch(self, batch: WorkBatch) -> BackendResult:
        self._ready()
        if self._prepared != (batch.job_fingerprint, batch.generation):
            raise CudaBackendError("batch does not match prepared CUDA job")
        work = batch.context
        if not isinstance(work, CudaPowBatch):
            raise CudaBackendError("batch context must carry prepared CUDA PearlHash buffers")
        started = time.perf_counter()
        fn = self._lib.sidecar_cuda_run_batch
        fn.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                       ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                       ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                       ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                       ctypes.c_void_p, ctypes.c_int]
        fn.restype = ctypes.c_int
        rc = fn(self._context, work.A, work.Bt, work.m, work.n, work.k, work.rank,
                work.key, work.target, work.transcript, work.digests,
                work.found, work.coord, work.variant)
        if rc:
            self.healthy = False
            raise CudaBackendError(f"PearlHash kernel failed (status {rc})")
        sync = self._lib.sidecar_cuda_sync
        sync.argtypes = [ctypes.c_void_p]
        sync.restype = ctypes.c_int
        rc = sync(self._context)
        if rc:
            self.healthy = False
            raise CudaBackendError(f"CUDA synchronize failed (status {rc})")
        count = (work.m // 16) * (work.n // 16)
        raw = ctypes.create_string_buffer(count * 32)
        found = ctypes.c_int32()
        coord = (ctypes.c_int32 * 2)()
        copy = self._lib.sidecar_cuda_copy_d2h
        copy.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
        copy.restype = ctypes.c_int
        for host, device, size in ((raw, work.digests, count * 32),
                                   (ctypes.byref(found), work.found, 4),
                                   (coord, work.coord, 8)):
            rc = copy(self._context, host, device, size)
            if rc:
                self.healthy = False
                raise CudaBackendError(f"CUDA result copy failed (status {rc})")
        elapsed = (time.perf_counter() - started) * 1e6
        output = CudaPowOutput(raw.raw, bool(found.value),
                               int(coord[0]) if found.value else None,
                               int(coord[1]) if found.value else None, count)
        identity = hashlib.sha256(raw.raw + bytes((bool(found.value),))).hexdigest()
        # Raw digest output is intentionally not a submit-eligible Candidate.
        # Host proof construction + CPU/reference verification is a later gate.
        return BackendResult(batch.job_fingerprint, batch.generation, batch.batch_id,
                             self.backend_id, identity, identity, None, output, elapsed,
                             self.healthy, False, "raw-result-awaits-proof-and-reference")

    def close(self) -> None:
        if self._lib is not None and self._context.value:
            fn = self._lib.sidecar_cuda_destroy
            fn.argtypes = [ctypes.c_void_p]
            fn.restype = ctypes.c_int
            rc = fn(self._context)
            if rc:
                self.healthy = False
                raise CudaBackendError(f"CUDA context destruction failed (status {rc})")
        self._context = ctypes.c_void_p()
        self._lib = None
