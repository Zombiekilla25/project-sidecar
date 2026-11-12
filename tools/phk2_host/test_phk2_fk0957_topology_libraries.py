from __future__ import annotations

from dataclasses import replace
import ctypes
import hashlib
import inspect
import os
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import phk2_fk0957_topology_transport as transport

REAL_FSTAT = os.fstat


class ApprovedLibraryTests(unittest.TestCase):
    def setUp(self):
        self.pin = transport.LIBFTDI_PIN

    def with_test_path(self, path, **changes):
        return replace(self.pin, path=path, **changes)

    @staticmethod
    def fake_root_fstat(fd):
        st = REAL_FSTAT(fd)
        return SimpleNamespace(st_dev=st.st_dev, st_ino=st.st_ino, st_mode=st.st_mode,
                               st_uid=0, st_gid=0, st_nlink=1, st_size=st.st_size,
                               st_mtime_ns=st.st_mtime_ns, st_ctime_ns=st.st_ctime_ns)

    def test_exact_approved_runtime_load_maps_and_stat_identity(self):
        loaded = transport._load_approved_runtime()
        try:
            self.assertEqual(tuple(loaded), tuple(pin.name for pin in transport.LIBRARY_PINS))
            for pin in transport.LIBRARY_PINS:
                item = loaded[pin.name]
                self.assertEqual(item.pin, pin)
                self.assertEqual(item.realpath, str(pin.path))
                self.assertEqual(item.pre_stat, item.post_stat)
                self.assertEqual(item.post_stat[6], pin.size)
                self.assertTrue(item.handle._handle)
        finally:
            for item in loaded.values():
                os.close(item.fd)

    def test_ctypes_transport_abi_prototypes_bind_without_calling_usb_functions(self):
        loaded = transport._load_approved_runtime()
        try:
            native = object.__new__(transport._NativeLibFtdi)
            native._runtime = loaded
            native._usb = loaded["libusb"].handle
            native._ftdi = loaded["libftdi"].handle
            native._bind_functions()
            self.assertEqual(native._ftdi.ftdi_usb_find_all.argtypes,
                             [ctypes.c_void_p, ctypes.POINTER(transport._FtdiDeviceListPtr),
                              ctypes.c_int, ctypes.c_int])
            self.assertEqual(native._ftdi.ftdi_usb_open_dev.argtypes,
                             [ctypes.c_void_p, ctypes.c_void_p])
            self.assertEqual(native._usb.libusb_get_device_descriptor.argtypes,
                             [ctypes.c_void_p, ctypes.POINTER(transport._UsbDeviceDescriptor)])
            self.assertFalse(hasattr(native, "_ctx"))
        finally:
            for item in loaded.values():
                os.close(item.fd)

    def test_public_operation_has_no_library_path_override(self):
        self.assertEqual(tuple(inspect.signature(transport.run_fk0957_topology_discovery).parameters),
                         ("authorized_permit",))

    def test_wrong_hash_same_filename_alternate_symlink_and_writable_file_refuse(self):
        with self.assertRaises(transport.Refusal):
            transport._load_approved_library(replace(self.pin, sha256="0" * 64))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            same_name = root / self.pin.path.name
            shutil.copyfile(self.pin.path, same_name)
            same_name.write_bytes(b"X" * self.pin.size)
            same_name.chmod(0o444)
            with mock.patch.object(transport, "_validate_parent_chain"), \
                 mock.patch.object(transport.os, "fstat", side_effect=self.fake_root_fstat):
                with self.assertRaises(transport.Refusal):
                    transport._load_approved_library(self.with_test_path(same_name))
            link = root / self.pin.path.name
            link.unlink()
            link.symlink_to(self.pin.path)
            with mock.patch.object(transport, "_validate_parent_chain"), \
                 mock.patch.object(transport.os, "fstat", side_effect=self.fake_root_fstat):
                with self.assertRaises(transport.Refusal):
                    transport._load_approved_library(self.with_test_path(link))
            writable = root / "writable.so"
            shutil.copyfile(self.pin.path, writable)
            writable.chmod(0o666)
            with mock.patch.object(transport, "_validate_parent_chain"), \
                 mock.patch.object(transport.os, "fstat", side_effect=self.fake_root_fstat):
                with self.assertRaises(transport.Refusal):
                    transport._load_approved_library(self.with_test_path(writable))

    def test_loader_environment_overrides_fail_before_cdll(self):
        for variable, value in (("LD_LIBRARY_PATH", "/tmp/untrusted"),
                                ("LD_PRELOAD", "/tmp/evil.so"),
                                ("LD_AUDIT", "/tmp/audit.so")):
            with self.subTest(variable=variable), mock.patch.dict(os.environ, {variable: value}), \
                 mock.patch.object(transport.ctypes, "CDLL") as cdll:
                with self.assertRaises(transport.Refusal):
                    transport._load_approved_runtime()
                cdll.assert_not_called()

    def test_stat_inode_and_hash_changes_between_validation_and_load_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / self.pin.path.name
            shutil.copyfile(self.pin.path, path)
            path.chmod(0o444)
            pin = self.with_test_path(path)

            def mutate_same_inode(_name, **_kwargs):
                path.chmod(0o644)
                with path.open("r+b") as stream:
                    stream.seek(128)
                    stream.write(b"Z")
                return mock.Mock()

            with mock.patch.object(transport, "_validate_parent_chain"), \
                 mock.patch.object(transport.os, "fstat", side_effect=self.fake_root_fstat), \
                 mock.patch.object(transport.ctypes, "CDLL", side_effect=mutate_same_inode):
                with self.assertRaises(transport.Refusal):
                    transport._load_approved_library(pin)

            path.chmod(0o644)
            shutil.copyfile(self.pin.path, path)
            path.chmod(0o444)

            def replace_inode(_name, **_kwargs):
                replacement = path.with_suffix(".new")
                shutil.copyfile(self.pin.path, replacement)
                replacement.chmod(0o444)
                os.replace(replacement, path)
                return mock.Mock()

            with mock.patch.object(transport, "_validate_parent_chain"), \
                 mock.patch.object(transport.os, "fstat", side_effect=self.fake_root_fstat), \
                 mock.patch.object(transport.ctypes, "CDLL", side_effect=replace_inode):
                with self.assertRaises(transport.Refusal):
                    transport._load_approved_library(pin)

    def test_build_id_missing_non_elf_unreadable_and_ctypes_failure_refuse(self):
        with self.assertRaises(transport.Refusal):
            transport._load_approved_library(replace(self.pin, build_id="0" * 40))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            missing = root / "missing.so"
            with mock.patch.object(transport, "_validate_parent_chain"), \
                 mock.patch.object(transport.os, "fstat", side_effect=self.fake_root_fstat):
                with self.assertRaises(transport.Refusal):
                    transport._load_approved_library(self.with_test_path(missing))
                no_read = root / "no-read.so"
                no_read.write_bytes(b"not elf")
                no_read.chmod(0)
                with self.assertRaises(transport.Refusal):
                    transport._load_approved_library(self.with_test_path(no_read, size=7))
                non_elf = root / "non-elf.so"
                non_elf.write_bytes(b"not elf")
                non_elf.chmod(0o444)
                digest = hashlib.sha256(b"not elf").hexdigest()
                with self.assertRaises(transport.Refusal):
                    transport._load_approved_library(self.with_test_path(
                        non_elf, size=7, sha256=digest))
        with mock.patch.object(transport.ctypes, "CDLL", side_effect=OSError("load error")):
            with self.assertRaises(transport.Refusal):
                transport._load_approved_library(self.pin)

    def test_loaded_mapping_must_match_approved_realpath(self):
        with mock.patch.object(transport, "_mapped_identity", return_value="/tmp/substitute.so"):
            with self.assertRaises(transport.Refusal):
                transport._load_approved_library(self.pin)


if __name__ == "__main__":
    unittest.main()
