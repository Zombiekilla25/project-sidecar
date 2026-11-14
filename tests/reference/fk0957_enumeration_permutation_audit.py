#!/usr/bin/env python3
"""Independent randomized descriptor-enumeration ordering campaign."""
from __future__ import annotations

import argparse
import ctypes
from pathlib import Path
import random
import subprocess
import sys
from types import SimpleNamespace
from unittest import mock


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidate-root", type=Path, required=True)
    ap.add_argument("--expected-commit", required=True)
    ap.add_argument("--seed", type=lambda value: int(value, 0), default=0xE0957)
    ap.add_argument("--permutations", type=int, default=1000)
    args = ap.parse_args()
    root = args.candidate_root.resolve(strict=True)
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, text=True,
                          capture_output=True, check=True, timeout=10).stdout.strip()
    if head != args.expected_commit or not 1 <= args.permutations <= 100_000:
        raise SystemExit("candidate binding or permutation limit invalid")
    sys.path.insert(0, str(root / "tools/phk2_host"))
    import phk2_fk0957_topology_discovery as topology
    import phk2_fk0957_topology_transport as transport

    expected = topology.DescriptorIdentity(
        "FK0957", "153300000957A", "153300000957", "1-9.3",
        "0403", "6010", "Xilinx", "SQRL FK", "A")
    permit = SimpleNamespace(identity=expected)
    rng = random.Random(args.seed)
    selected = refused = opened = 0

    def enumerate_case(rows):
        backend = object.__new__(transport._NativeLibFtdi)
        backend._ctx = ctypes.c_void_p(0x77)
        backend._opened = backend._closed = False
        nodes = [transport._FtdiDeviceList() for _ in rows]
        devices = [0x1200 + i for i in range(len(rows))]
        for i, node in enumerate(nodes):
            node.dev = ctypes.c_void_p(devices[i])
            node.next = (ctypes.pointer(nodes[i + 1]) if i + 1 < len(nodes)
                         else transport._FtdiDeviceListPtr())
        by_dev = {devices[i]: rows[i] for i in range(len(rows))}
        path_rows = {"1-" + ".".join(map(str, row["ports"])): row for row in rows}
        backend._list = transport._FtdiDeviceListPtr()
        backend._eligible_candidates = ()
        backend._ftdi = SimpleNamespace(
            ftdi_usb_find_all=mock.Mock(side_effect=lambda _ctx, output, _vid, _pid: (
                ctypes.cast(output, ctypes.POINTER(transport._FtdiDeviceListPtr)).__setitem__(
                    0, ctypes.pointer(nodes[0]) if nodes else transport._FtdiDeviceListPtr()) or len(nodes))),
            ftdi_list_free=mock.Mock(), ftdi_set_interface=mock.Mock(return_value=0),
            ftdi_usb_open_dev=mock.Mock(return_value=0))
        def descriptor(dev, output):
            row = by_dev[int(dev)]
            desc = ctypes.cast(output, ctypes.POINTER(transport._UsbDeviceDescriptor)).contents
            desc.idVendor, desc.idProduct = row["vid"], row["pid"]
            return 0
        def ports(dev, output, _maximum):
            values = by_dev[int(dev)]["ports"]
            for i, value in enumerate(values): output[i] = value
            return len(values)
        backend._usb = SimpleNamespace(
            libusb_get_device_descriptor=mock.Mock(side_effect=descriptor),
            libusb_get_bus_number=mock.Mock(return_value=1),
            libusb_get_port_numbers=mock.Mock(side_effect=ports))
        def identity(path, desc):
            row = path_rows[path]
            return topology.DescriptorIdentity(
                "FK0957", "153300000957A", row["serial"], path,
                f"{row['vid']:04x}", f"{row['pid']:04x}", "Xilinx", "SQRL FK",
                row.get("interface", "A"))
        with mock.patch.object(transport, "_serial_for_candidate",
                               side_effect=lambda path, _d: path_rows[path]["serial"]), \
             mock.patch.object(transport, "_identity_from_sysfs", side_effect=identity):
            candidates = backend.enumerate_candidates()
        return backend, candidates

    for _ in range(args.permutations):
        peer_count = rng.randrange(0, 7)
        rows = [{"serial": "153300000957", "ports": (9, 3),
                 "vid": transport.FTDI_VID, "pid": transport.FTDI_PID}]
        for i in range(peer_count):
            rows.append({"serial": "153300000958" + str(i), "ports": (9, 4 + i),
                         "vid": transport.FTDI_VID, "pid": transport.FTDI_PID})
        rng.shuffle(rows)
        backend, candidates = enumerate_case(rows)
        try:
            got = topology.validate_candidates(permit, candidates)
            assert got.identity == expected and len(candidates) == 1
            selected += 1
        except (topology.Refusal, transport.Refusal):
            refused += 1
            raise AssertionError("enumeration order or peer count changed exact selection")
        assert backend._ftdi.ftdi_usb_open_dev.call_count == 0
        assert backend._ftdi.ftdi_set_interface.call_count == 0
        opened += backend._ftdi.ftdi_usb_open_dev.call_count

    # Exact-identity duplicates and wrong-interface candidates must refuse pre-open.
    duplicate = [
        {"serial": "153300000957", "ports": (9, 3), "vid": transport.FTDI_VID,
         "pid": transport.FTDI_PID},
        {"serial": "153300000957", "ports": (9, 9), "vid": transport.FTDI_VID,
         "pid": transport.FTDI_PID},
    ]
    backend, candidates = enumerate_case(duplicate)
    try: topology.validate_candidates(permit, candidates)
    except (topology.Refusal, transport.Refusal): refused += 1
    else: raise AssertionError("duplicate exact target did not refuse")
    assert backend._ftdi.ftdi_usb_open_dev.call_count == 0
    wrong_if = [{"serial": "153300000957", "ports": (9, 3), "vid": transport.FTDI_VID,
                 "pid": transport.FTDI_PID, "interface": "B"}]
    backend, candidates = enumerate_case(wrong_if)
    try: topology.validate_candidates(permit, candidates)
    except (topology.Refusal, transport.Refusal): refused += 1
    else: raise AssertionError("wrong interface did not refuse")
    assert backend._ftdi.ftdi_usb_open_dev.call_count == 0
    print(f"CANDIDATE_COMMIT={head}")
    print(f"SEED={args.seed}")
    print(f"PERMUTATIONS={args.permutations}")
    print(f"EXACT_TARGETS_SELECTED={selected}")
    print(f"EXPECTED_REFUSALS={refused}")
    print(f"DEVICE_OPENS={opened}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
