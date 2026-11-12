#!/usr/bin/env python3
"""Read-only FK0957 FTDI identity resolver.

This backend deliberately observes USB descriptors through sysfs only. It
does not open a USB handle, claim an interface, initialize MPSSE, reset the
TAP, or issue any command to the FPGA. Consequently JTAG-side identity fields
are unavailable. USB descriptor serial and historical adapter-to-card
identity are separate; the card association is not a fresh FPGA observation.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Mapping

from phk2_fk0957_identity_observer import (
    EXPECTED_ADAPTER_SERIAL, EXPECTED_USB_SERIAL, EXPECTED_CARD_ID, Refusal, Selection, TargetSelector,
)


class BackendRefusal(Refusal):
    """A bounded refusal category for descriptor-only selection failures."""
    def __init__(self, refusal_code: str):
        self.refusal_code = refusal_code
        super().__init__(refusal_code)

BACKEND_VERSION = "1.0.0"
# Origin of the reviewed descriptor-only backend. The live evidence separately
# records the full current repository commit; sha256 below binds this exact
# backend source, including any subsequently audited fail-closed amendments.
REVIEWED_BASE_COMMIT = "e2feedcfde44563854a3cf41fe4526c231ed385b"
SUPPORTED_TARGET_SELECTOR = {
    "name": "FK0957",
    "adapter_serial": EXPECTED_ADAPTER_SERIAL,
    "expected_usb_serial": EXPECTED_USB_SERIAL,
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
REVIEWED_REFERENCE_HASHES = {
    "tools/phk1_raw_bscan/usb_identity.hpp": "916e436168d4a7cf057e1019a06f0b2207d9122246e7bae22a73121549eb2fcb",
    "tools/phk1_raw_bscan/usb_selection.cpp": "6bd03fd54b2a94d0a056c3eb155b6c50cdc65a530eae752aeb93f5fedf41df48",
    "tools/phk1_raw_bscan/libftdi_io.cpp": "4b61ff5c78f6c666e5888d56ffda885edf6923fc4d72b361b75b6e56ca949194",
    "tools/phk1_raw_bscan/identify_only.cpp": "31260a7c6a3ac437bcfc1dcd6e8914d700c74ab26600a1bdb7c2b957e9e4d117",
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@dataclass(frozen=True)
class Device:
    vid: str
    pid: str
    usb_descriptor_serial: str
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
            raise BackendRefusal("DESCRIPTOR_READ_FAILED")
        for node in sorted(self.root.iterdir()):
            if ":" in node.name or not node.is_dir():
                continue
            try:
                vid = (node / "idVendor").read_text().strip().lower()
                pid = (node / "idProduct").read_text().strip().lower()
            except OSError as exc:
                # Without VID/PID, a numeric bus-port entry could be an
                # approved peer. Keep the uniqueness check fail-closed.
                if re.match(r"^[0-9]+-", node.name):
                    raise BackendRefusal("INCOMPLETE_DESCRIPTOR_METADATA") from exc
                continue
            # VID/PID is the only eligibility check needed for unrelated USB
            # devices. Do not require FK-specific descriptors from them.
            if (vid, pid) != ("0403", "6010"):
                continue
            try:
                manufacturer = (node / "manufacturer").read_text().strip()
                product = (node / "product").read_text().strip()
                usb_descriptor_serial = (node / "serial").read_text().strip()
                bus = (node / "busnum").read_text().strip()
                devpath = (node / "devpath").read_text().strip()
            except OSError as exc:
                raise BackendRefusal("INCOMPLETE_DESCRIPTOR_METADATA") from exc
            if manufacturer != "Xilinx" or product != "SQRL FK":
                continue
            interfaces = sorted(self.root.glob(f"{node.name}:1.*"))
            if not interfaces:
                raise BackendRefusal("INCOMPLETE_DESCRIPTOR_METADATA")
            found_target_interface = False
            for intf in interfaces:
                try:
                    number = (intf / "bInterfaceNumber").read_text().strip().lower().zfill(2)
                except OSError as exc:
                    raise BackendRefusal("INCOMPLETE_DESCRIPTOR_METADATA") from exc
                if number == "00":
                    found_target_interface = True
                    devices.append(Device(vid, pid, usb_descriptor_serial, manufacturer, product,
                                          f"{bus}-{devpath}", number, "A", str(node.resolve())))
            if not found_target_interface:
                raise BackendRefusal("INCOMPLETE_DESCRIPTOR_METADATA")
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
            raise BackendRefusal("DESCRIPTOR_READ_FAILED")
        current = self._catalog.enumerate_fk()
        if not current:
            raise BackendRefusal("NO_MATCHING_TARGET")
        if len(current) > 1:
            raise BackendRefusal("MULTIPLE_MATCHING_TARGETS")
        if current[0] != self._record:
            raise BackendRefusal("DESCRIPTOR_READ_FAILED")
        return {
            "adapter_identity": {
                "vid": self._record.vid, "pid": self._record.pid,
                "manufacturer": self._record.manufacturer,
                "product": self._record.product,
                "interface": self._record.interface_name,
                "usb_path": self._record.usb_path,
            },
            # The adapter/card identity is historical configuration; sysfs
            # serial is a distinct USB descriptor identity.
            "adapter_serial": EXPECTED_ADAPTER_SERIAL,
            "usb_descriptor_serial": self._record.usb_descriptor_serial,
            # This is an immutable historical adapter-to-card mapping, not a
            # fresh FPGA-side read; the sysfs USB serial remains distinct.
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
        # Preserve the reviewed legacy-source provenance without requiring or
        # transmitting those unrelated historical implementation files.
        refs = REVIEWED_REFERENCE_HASHES
        return {
            "name": "phk2_fk0957_sysfs_readonly",
            "version": BACKEND_VERSION,
            "sha256": _sha256(path),
            "source_commit": REVIEWED_BASE_COMMIT,
            "source_file_hashes": json.dumps(refs, sort_keys=True, separators=(",", ":")),
            "supported_target_selector": json.dumps(SUPPORTED_TARGET_SELECTOR, sort_keys=True, separators=(",", ":")),
            "jtag_or_fpga_observation": "UNAVAILABLE_READ_ONLY_BACKEND_DOES_NOT_OPEN_TRANSPORT",
        }

    def select_exact(self, selector: TargetSelector) -> Selection:
        try:
            selector.validate()
        except Refusal as exc:
            raise BackendRefusal("SOURCE_PROVENANCE_MISMATCH") from exc
        devices = self._catalog.enumerate_fk()
        # Refuse any peer FK adapter, even if the requested serial is present.
        # This avoids treating family enumeration as an implicit multi-target
        # permission and leaves no peer-selection ambiguity.
        if not devices:
            raise BackendRefusal("NO_MATCHING_TARGET")
        if len(devices) > 1:
            expected_serial_count = sum(
                device.usb_descriptor_serial == selector.expected_usb_serial for device in devices)
            if expected_serial_count == 1:
                raise BackendRefusal("UNEXPECTED_PEER_DEVICE")
            raise BackendRefusal("MULTIPLE_MATCHING_TARGETS")
        device = devices[0]
        expected = SUPPORTED_TARGET_SELECTOR
        if device.usb_descriptor_serial != selector.expected_usb_serial:
            raise BackendRefusal("EXPECTED_SERIAL_NOT_FOUND")
        if (device.vid != expected["vid"] or device.pid != expected["pid"] or
                device.manufacturer != expected["manufacturer"] or device.product != expected["product"] or
                device.interface_name != "A" or device.interface_number != "00"):
            raise BackendRefusal("INCOMPLETE_DESCRIPTOR_METADATA")
        if not expected.get("card_id"):
            raise BackendRefusal("TARGET_MAPPING_MISSING")
        if expected["card_id"] != selector.card_id:
            raise BackendRefusal("TARGET_MAPPING_AMBIGUOUS")
        # Re-resolve immediately before returning the token; transport open is
        # deliberately absent from this backend.
        confirm = self._catalog.enumerate_fk()
        if not confirm:
            raise BackendRefusal("NO_MATCHING_TARGET")
        if len(confirm) > 1:
            raise BackendRefusal("UNEXPECTED_PEER_DEVICE")
        if confirm != [device]:
            raise BackendRefusal("DESCRIPTOR_READ_FAILED")
        return Selection(adapter_serial=selector.adapter_serial,
                         usb_descriptor_serial=device.usb_descriptor_serial,
                         card_id=EXPECTED_CARD_ID, serial_suffix=selector.serial_suffix,
                         matching_devices=1, serial_scoped_before_open=True,
                         requires_write=False, endpoint_token=device.token())

    def open_selected(self, selection: Selection) -> _DescriptorTransport:
        current = self._catalog.enumerate_fk()
        if not current:
            raise BackendRefusal("NO_MATCHING_TARGET")
        if len(current) > 1:
            if any(device.usb_descriptor_serial == selection.usb_descriptor_serial for device in current):
                raise BackendRefusal("UNEXPECTED_PEER_DEVICE")
            raise BackendRefusal("MULTIPLE_MATCHING_TARGETS")
        if current[0].token() != selection.endpoint_token:
            raise BackendRefusal("DESCRIPTOR_READ_FAILED")
        # No USB handle, interface claim, JTAG, or MPSSE transport is opened.
        return _DescriptorTransport(current[0], self._catalog)


def create_backend() -> FK0957ReadOnlyBackend:
    return FK0957ReadOnlyBackend()


if __name__ == "__main__":
    raise SystemExit("This backend is loaded by the identity observer; no standalone live mode exists.")
