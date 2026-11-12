#!/usr/bin/env python3
"""Read-only FK0957 FTDI identity resolver.

This backend deliberately observes USB descriptors through sysfs only. It
does not open a USB handle, claim an interface, initialize MPSSE, reset the
TAP, or issue any command to the FPGA. Consequently JTAG-side identity fields
are unavailable. The exact serial-to-card association is the pinned historical
FK0957 mapping; it is not a fresh FPGA observation.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import subprocess
from typing import Mapping

from phk2_fk0957_identity_observer import (
    EXPECTED_ADAPTER_SERIAL, EXPECTED_CARD_ID, Refusal, Selection, TargetSelector,
)

BACKEND_VERSION = "1.0.0"
SUPPORTED_TARGET_SELECTOR = {
    "name": "FK0957",
    "adapter_serial": EXPECTED_ADAPTER_SERIAL,
    "card_id": EXPECTED_CARD_ID,
    "vid": "0403",
    "pid": "6010",
    "interface": "A",
    "interface_number": "00",
    "manufacturer": "Xilinx",
    "product": "SQRL FK",
}
METHOD_ACCESS = {
    "select_exact": "READ_ONLY", "open_selected": "READ_ONLY",
    "observe": "READ_ONLY", "close": "READ_ONLY",
}
SINGLE_DEVICE_SERIAL_SCOPE = True
FORBIDDEN = frozenset({
    "write", "write_exact", "register_write", "program", "reset",
    "reconfigure", "configure", "tap_update", "shift_ir", "shift_dr",
    "mpsse", "send_command", "workload_change", "service_change",
})
REFERENCE_FILES = (
    "tools/phk1_raw_bscan/usb_identity.hpp",
    "tools/phk1_raw_bscan/usb_selection.cpp",
    "tools/phk1_raw_bscan/libftdi_io.cpp",
    "tools/phk1_raw_bscan/identify_only.cpp",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _source_commit(path: Path) -> str:
    repo = Path(__file__).resolve().parents[2]
    relative = path.resolve().relative_to(repo).as_posix()
    try:
        return subprocess.run(
            ["git", "-C", str(repo), "log", "-1", "--format=%H", "--", relative],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise Refusal("backend source commit cannot be resolved") from exc


@dataclass(frozen=True)
class Device:
    vid: str
    pid: str
    serial: str
    manufacturer: str
    product: str
    usb_path: str
    interface_number: str
    interface_name: str
    sysfs_path: str

    @property
    def is_fk_family(self) -> bool:
        return (self.vid.lower() == "0403" and self.pid.lower() == "6010" and
                self.manufacturer == "Xilinx" and self.product == "SQRL FK")

    def token(self) -> str:
        return hashlib.sha256(_canonical(self.__dict__)).hexdigest()


def _canonical(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


class SysfsCatalog:
    """Read-only descriptor catalog; never opens USB devices or interfaces."""
    def __init__(self, root: Path = Path("/sys/bus/usb/devices")):
        self.root = root

    def enumerate_fk(self) -> list[Device]:
        devices: list[Device] = []
        if not self.root.is_dir():
            raise Refusal("USB descriptor catalog is unavailable")
        for node in sorted(self.root.iterdir()):
            if ":" in node.name or not node.is_dir():
                continue
            try:
                vid = (node / "idVendor").read_text().strip().lower()
                pid = (node / "idProduct").read_text().strip().lower()
                manufacturer = (node / "manufacturer").read_text().strip()
                product = (node / "product").read_text().strip()
                serial = (node / "serial").read_text().strip()
                bus = (node / "busnum").read_text().strip()
                devpath = (node / "devpath").read_text().strip()
            except OSError:
                # An unreadable potentially matching candidate makes the
                # single-device scope ambiguous; do not silently skip it.
                if node.name.startswith(("1-", "2-", "3-", "4-", "5-", "6-", "7-", "8-")):
                    raise Refusal(f"USB candidate metadata incomplete: {node.name}")
                continue
            if vid != "0403" or pid != "6010" or manufacturer != "Xilinx" or product != "SQRL FK":
                continue
            interfaces = sorted(self.root.glob(f"{node.name}:1.*"))
            for intf in interfaces:
                try:
                    number = (intf / "bInterfaceNumber").read_text().strip().lower().zfill(2)
                except OSError as exc:
                    raise Refusal(f"FTDI interface metadata incomplete: {intf.name}") from exc
                if number == "00":
                    devices.append(Device(vid, pid, serial, manufacturer, product,
                                          f"{bus}-{devpath}", number, "A", str(node.resolve())))
        return devices


class _DescriptorTransport:
    """Observer-compatible metadata view; no USB/JTAG transport is opened."""
    METHOD_ACCESS = {"observe": "READ_ONLY", "close": "READ_ONLY"}
    def __init__(self, record: Device, catalog: SysfsCatalog):
        self._record = record
        self._catalog = catalog
        self._closed = False

    def observe(self) -> Mapping[str, object]:
        if self._closed:
            raise Refusal("descriptor view is closed")
        current = self._catalog.enumerate_fk()
        if len(current) != 1 or current[0] != self._record:
            raise Refusal("FK0957 USB identity changed or became ambiguous after resolution")
        return {
            "adapter_identity": {
                "vid": self._record.vid, "pid": self._record.pid,
                "manufacturer": self._record.manufacturer,
                "product": self._record.product,
                "interface": self._record.interface_name,
                "usb_path": self._record.usb_path,
            },
            "adapter_serial": self._record.serial,
            # This is an immutable historical adapter-to-card mapping, not a
            # fresh FPGA-side read. The observer schema's card scope remains
            # exact and cannot be caller-selected.
            "card_id": EXPECTED_CARD_ID,
            "accessed_card_ids": [EXPECTED_CARD_ID],
        }

    def close(self) -> None:
        self._closed = True


class FK0957ReadOnlyBackend:
    METHOD_ACCESS = METHOD_ACCESS
    SINGLE_DEVICE_SERIAL_SCOPE = SINGLE_DEVICE_SERIAL_SCOPE

    def __init__(self, catalog: SysfsCatalog | None = None):
        self._catalog = catalog or SysfsCatalog()
        self.BACKEND_IDENTITY = self._identity()

    @staticmethod
    def _identity() -> Mapping[str, str]:
        path = Path(__file__).resolve()
        repo = path.parents[2]
        refs = {name: _sha256(repo / name) for name in REFERENCE_FILES}
        return {
            "name": "phk2_fk0957_sysfs_readonly",
            "version": BACKEND_VERSION,
            "sha256": _sha256(path),
            "source_commit": _source_commit(path),
            "source_file_hashes": json.dumps(refs, sort_keys=True, separators=(",", ":")),
            "supported_target_selector": json.dumps(SUPPORTED_TARGET_SELECTOR, sort_keys=True, separators=(",", ":")),
            "jtag_or_fpga_observation": "UNAVAILABLE_READ_ONLY_BACKEND_DOES_NOT_OPEN_TRANSPORT",
        }

    def select_exact(self, selector: TargetSelector) -> Selection:
        selector.validate()
        devices = self._catalog.enumerate_fk()
        # Refuse any peer FK adapter, even if the requested serial is present.
        # This avoids treating family enumeration as an implicit multi-target
        # permission and leaves no peer-selection ambiguity.
        if len(devices) != 1:
            raise Refusal(f"expected exactly one FK adapter in scope; found {len(devices)}")
        device = devices[0]
        expected = SUPPORTED_TARGET_SELECTOR
        if (device.serial != selector.adapter_serial or device.vid != expected["vid"] or
                device.pid != expected["pid"] or device.manufacturer != expected["manufacturer"] or
                device.product != expected["product"] or device.interface_name != "A" or
                device.interface_number != "00"):
            raise Refusal("exact FK0957 FTDI interface identity mismatch")
        # Re-resolve immediately before returning the token; transport open is
        # deliberately absent from this backend.
        confirm = self._catalog.enumerate_fk()
        if confirm != [device]:
            raise Refusal("FK0957 identity changed during pre-open resolution")
        return Selection(device.serial, EXPECTED_CARD_ID, selector.serial_suffix,
                         1, True, False, device.token())

    def open_selected(self, selection: Selection) -> _DescriptorTransport:
        current = self._catalog.enumerate_fk()
        if len(current) != 1 or current[0].token() != selection.endpoint_token:
            raise Refusal("selected FTDI/interface changed before descriptor observation")
        # No USB handle, interface claim, JTAG, or MPSSE transport is opened.
        return _DescriptorTransport(current[0], self._catalog)


def create_backend() -> FK0957ReadOnlyBackend:
    return FK0957ReadOnlyBackend()


if __name__ == "__main__":
    raise SystemExit("This backend is loaded by the identity observer; no standalone live mode exists.")
