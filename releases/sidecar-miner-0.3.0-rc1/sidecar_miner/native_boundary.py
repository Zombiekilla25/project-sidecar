"""Lazy ctypes client for the narrow Sidecar RAW_BSCAN C ABI."""
from __future__ import annotations
import ctypes
from enum import IntEnum
from pathlib import Path

class NativeErrorCode(IntEnum):
    OK=0; TARGET_NOT_FOUND=1; TARGET_AMBIGUOUS=2; IDCODE_MISMATCH=3
    FTDI_OPEN_FAILED=4; MPSSE_SYNC_FAILED=5; TAP_FAILED=6
    INVALID_PROTOCOL=7; TRANSPORT_DISCONNECTED=8

class NativeTransportError(RuntimeError):
    def __init__(self,category: str,message: str):
        super().__init__(message);self.category=category

_ERROR_NAMES={NativeErrorCode.TARGET_NOT_FOUND:'TARGET_NOT_FOUND',
 NativeErrorCode.TARGET_AMBIGUOUS:'TARGET_AMBIGUOUS',NativeErrorCode.IDCODE_MISMATCH:'IDCODE_MISMATCH',
 NativeErrorCode.FTDI_OPEN_FAILED:'FTDI_OPEN_FAILED',NativeErrorCode.MPSSE_SYNC_FAILED:'MPSSE_SYNC_FAILED',
 NativeErrorCode.TAP_FAILED:'TAP_FAILED',NativeErrorCode.INVALID_PROTOCOL:'VECTOR_PROTOCOL_ERROR',
 NativeErrorCode.TRANSPORT_DISCONNECTED:'TRANSPORT_DISCONNECTED'}

class CtypesRawBscanBoundary:
    """The shared library is opened only by `open`, after the qualification gate."""
    def __init__(self,library_path: str | Path):
        self.library_path=Path(library_path);self.lib=None;self.context=ctypes.c_void_p();self.closed=True
    def open(self,selector,expected_idcode: int,jtag_clock_hz: int):
        try:self.lib=ctypes.CDLL(str(self.library_path))
        except OSError as exc:raise NativeTransportError('FTDI_OPEN_FAILED',f'native library load failed: {exc}') from exc
        self.lib.sidecar_raw_abi_version.restype=ctypes.c_int
        if self.lib.sidecar_raw_abi_version()!=1:raise NativeTransportError('INVALID_PROTOCOL','unsupported native RAW_BSCAN ABI')
        fn=self.lib.sidecar_raw_open;fn.restype=ctypes.c_int
        fn.argtypes=[ctypes.POINTER(ctypes.c_void_p),ctypes.c_uint16,ctypes.c_uint16,
            ctypes.c_char_p,ctypes.c_char_p,ctypes.c_char_p,ctypes.c_char_p,ctypes.c_char_p,
            ctypes.c_uint32,ctypes.c_uint32]
        rc=fn(ctypes.byref(self.context),selector.vid,selector.pid,selector.serial.encode(),
            selector.usb_path.encode(),selector.manufacturer.encode(),selector.product.encode(),
            selector.interface_name.encode(),expected_idcode,jtag_clock_hz)
        if rc: self._raise(rc)
        self.closed=False
    def user_scan(self,chain: int,payload: bytes) -> bytes:
        if self.closed or not self.lib:raise NativeTransportError('TRANSPORT_DISCONNECTED','native handle is closed')
        tx=(ctypes.c_uint8*len(payload)).from_buffer_copy(payload);rx=(ctypes.c_uint8*len(payload))();n=ctypes.c_size_t()
        fn=self.lib.sidecar_raw_user_scan;fn.restype=ctypes.c_int
        fn.argtypes=[ctypes.c_void_p,ctypes.c_uint8,ctypes.POINTER(ctypes.c_uint8),ctypes.c_size_t,
                     ctypes.POINTER(ctypes.c_uint8),ctypes.c_size_t,ctypes.POINTER(ctypes.c_size_t)]
        rc=fn(self.context,chain,tx,len(payload),rx,len(payload),ctypes.byref(n))
        if rc:self._raise(rc)
        if n.value!=len(payload):raise NativeTransportError('VECTOR_PROTOCOL_ERROR','native TDO length mismatch')
        return bytes(rx)
    def close(self):
        if self.closed:return
        try:
            fn=self.lib.sidecar_raw_close;fn.restype=ctypes.c_int;fn.argtypes=[ctypes.c_void_p]
            rc=fn(self.context)
            if rc:self._raise(rc)
        finally:self.context=ctypes.c_void_p();self.closed=True
    def _raise(self,rc):
        try:code=NativeErrorCode(rc);category=_ERROR_NAMES[code]
        except (ValueError,KeyError):category='TAP_FAILED'
        message='native RAW_BSCAN operation failed'
        try:
            self.lib.sidecar_raw_last_error.restype=ctypes.c_char_p
            raw=self.lib.sidecar_raw_last_error()
            if raw:message=raw.decode('utf-8','replace')
        except Exception:pass
        raise NativeTransportError(category,message)
