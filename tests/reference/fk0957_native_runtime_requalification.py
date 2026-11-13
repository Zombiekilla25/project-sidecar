"""Offline native-runtime inventory and requalification probe for FK0957.

Only maps shared libraries and resolves symbols. It never creates an FTDI
context, initializes libusb, enumerates USB, or calls a device API. Candidate
pin changes exist only in a disposable copied test tree.
"""
from __future__ import annotations

import argparse
import ctypes
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


REQUIRED_FTDI = (
    "ftdi_new", "ftdi_free", "ftdi_usb_find_all", "ftdi_list_free",
    "ftdi_set_interface", "ftdi_usb_open_dev", "ftdi_set_bitmode",
    "ftdi_set_latency_timer", "ftdi_read_data_set_chunksize",
    "ftdi_write_data_set_chunksize", "ftdi_tcioflush", "ftdi_write_data",
    "ftdi_read_data", "ftdi_usb_close",
)
REQUIRED_USB = ("libusb_get_device_descriptor", "libusb_get_bus_number",
                "libusb_get_port_numbers")


def cmd(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, check=False)


def build_id(path: Path) -> str | None:
    output = cmd(["readelf", "-n", str(path)]).stdout
    match = re.search(r"Build ID:\s*([0-9a-fA-F]+)", output)
    return match.group(1).lower() if match else None


def soname(path: Path) -> str | None:
    output = cmd(["readelf", "-d", str(path)]).stdout
    match = re.search(r"Library soname: \[([^]]+)\]", output)
    return match.group(1) if match else None


def owner_version(path: Path) -> tuple[str | None, str | None]:
    owner = cmd(["dpkg-query", "-S", str(path)]).stdout.strip()
    if not owner or ": " not in owner:
        return owner or None, None
    package = owner.split(": ", 1)[0]
    version = cmd(["dpkg-query", "-W", "-f=${Version}", package]).stdout.strip()
    return owner, version or None


def inventory(path: Path, expected: dict[str, str] | None = None) -> dict[str, object]:
    path = Path(path)
    info: dict[str, object] = {"path": str(path), "exists": path.exists()}
    if not path.exists():
        return info
    st = path.stat()
    raw = path.read_bytes()
    alias = path.absolute()
    chain = [str(alias)]
    cursor = alias
    for _ in range(8):
        try:
            link = cursor.lstat()
        except OSError:
            break
        if not cursor.is_symlink():
            break
        target = os.readlink(cursor)
        cursor = (cursor.parent / target).absolute() if not os.path.isabs(target) else Path(target)
        chain.append(str(cursor))
    package_owner, package_version = owner_version(path)
    info.update({
        "realpath": str(path.resolve(strict=True)),
        "device": f"{os.major(st.st_dev)}:{os.minor(st.st_dev)}",
        "inode": st.st_ino, "links": st.st_nlink, "uid": st.st_uid,
        "gid": st.st_gid, "mode": oct(st.st_mode & 0o777),
        "mtime_ns": st.st_mtime_ns, "ctime_ns": st.st_ctime_ns,
        "symlink_chain": chain,
        "size": st.st_size, "sha256": hashlib.sha256(raw).hexdigest(),
        "build_id": build_id(path), "soname": soname(path),
        "package_owner": package_owner, "package_version": package_version,
        "elf_type": cmd(["file", "-b", str(path)]).stdout.strip(),
    })
    if expected:
        info["old_pin"] = expected
        info["matches_old_sha_build"] = (info["sha256"] == expected.get("sha256") and
                                           info["build_id"] == expected.get("build_id"))
    return info


def loaded_path_for(path: Path) -> str | None:
    st = path.stat()
    dev = f"{os.major(st.st_dev):02x}:{os.minor(st.st_dev):02x}"
    for line in Path("/proc/self/maps").read_text().splitlines():
        parts = line.split(maxsplit=5)
        if len(parts) >= 6 and parts[3].lower() == dev and int(parts[4]) == st.st_ino:
            return str(Path(parts[5].removesuffix(" (deleted)")).resolve())
    return None


def package_history() -> dict[str, object]:
    apt = Path("/var/log/apt/history.log").read_text(errors="replace")
    dpkg = Path("/var/log/dpkg.log").read_text(errors="replace")
    apt_blocks = re.findall(r"Start-Date: 2026-11-13[^\n]*\n.*?End-Date: 2026-11-13[^\n]*",
                            apt, re.S)
    relevant = [block for block in apt_blocks if "libc6:amd64" in block and
                 "2.39-0ubuntu8.9" in block and "2.39-0ubuntu8.12" in block]
    transition = [line for line in dpkg.splitlines()
                  if "2026-11-13" in line and "libc6:amd64" in line and
                  "2.39-0ubuntu8.9 2.39-0ubuntu8.12" in line]
    return {"apt_upgrade_record": relevant, "dpkg_transition_records": transition,
            "cause_is_unattended_upgrade": any("/usr/bin/unattended-upgrade" in b
                                                for b in relevant)}


def apt_signature_and_package_metadata() -> dict[str, object]:
    inrelease_paths = (
        Path("/var/lib/apt/lists/us.archive.ubuntu.com_ubuntu_dists_noble-updates_InRelease"),
        Path("/var/lib/apt/lists/security.ubuntu.com_ubuntu_dists_noble-security_InRelease"),
    )
    signatures = {}
    for path in inrelease_paths:
        if path.exists():
            verify = cmd(["gpgv", "--keyring", "/usr/share/keyrings/ubuntu-archive-keyring.gpg",
                          str(path)])
            signatures[path.name] = {"gpgv_exit": verify.returncode,
                                     "good_signature": verify.returncode == 0,
                                     "keyring": "/usr/share/keyrings/ubuntu-archive-keyring.gpg"}
    pkg = cmd(["apt-cache", "show", "libc6:amd64=2.39-0ubuntu8.12"])
    fields = {}
    for line in pkg.stdout.splitlines():
        if line.startswith(("Package:", "Version:", "Filename:", "Size:", "SHA256:")):
            key, value = line.split(":", 1)
            fields[key] = value.strip()
    archive = Path("/var/cache/apt/archives") / Path(fields.get("Filename", "")).name
    updates_release = inrelease_paths[0]
    index_path = Path("/var/lib/apt/lists/us.archive.ubuntu.com_ubuntu_dists_noble-updates_main_binary-amd64_Packages")
    release_text = updates_release.read_text(errors="replace") if updates_release.exists() else ""
    index_record = re.search(
        r"(?m)^\s*([0-9a-f]{64})\s+(\d+)\s+main/binary-amd64/Packages$",
        release_text)
    index_hash = hashlib.sha256(index_path.read_bytes()).hexdigest() if index_path.exists() else None
    index_size = index_path.stat().st_size if index_path.exists() else None
    return {"inrelease_signatures": signatures, "local_package_index_record": fields,
            "signed_packages_index": {
                "path": str(index_path), "expected_sha256": index_record.group(1) if index_record else None,
                "actual_sha256": index_hash,
                "expected_size": int(index_record.group(2)) if index_record else None,
                "actual_size": index_size,
                "matches_signed_inrelease_sha256": bool(index_record and index_hash == index_record.group(1)
                    and index_size == int(index_record.group(2)))},
            "package_archive_cached": archive.is_file(),
            "package_archive_path": str(archive) if archive.is_file() else None}


def package_file_verification() -> dict[str, object]:
    result = cmd(["dpkg", "-V", "libc6:amd64"])
    sums_path = Path("/var/lib/dpkg/info/libc6:amd64.md5sums")
    recorded = {}
    if sums_path.exists():
        for line in sums_path.read_text(errors="replace").splitlines():
            match = re.fullmatch(r"([0-9a-f]{32})\s+(.+)", line)
            if match and match.group(2) in {
                    "usr/lib/x86_64-linux-gnu/libc.so.6",
                    "usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"}:
                recorded[match.group(2)] = match.group(1)
    actual = {}
    for relative in recorded:
        p = Path("/") / relative
        if p.exists():
            actual[relative] = hashlib.md5(p.read_bytes()).hexdigest()
    return {"dpkg_verify_exit": result.returncode,
            "dpkg_verify_no_differences": result.returncode == 0 and not result.stdout.strip(),
            "reported_difference_count": len(result.stdout.splitlines()),
            "dpkg_md5_manifest_expected": recorded,
            "dpkg_md5_manifest_actual": actual,
            "dpkg_md5_files_match": bool(recorded) and actual == recorded}


def abi_requirements(lib: Path, libc: Path) -> dict[str, object]:
    def versions(path: Path) -> set[str]:
        text = cmd(["readelf", "--version-info", str(path)]).stdout
        return set(re.findall(r"Name: (GLIBC_[0-9.]+)", text))
    required = versions(lib)
    exported = versions(libc)
    return {"library": str(lib), "required_glibc_versions": sorted(required),
            "libc_advertised_versions": sorted(exported),
            "all_required_versions_present": required.issubset(exported)}


def current_mapping_and_symbols(repo: Path) -> dict[str, object]:
    sys.path.insert(0, str(repo / "tools/phk2_host"))
    import phk2_fk0957_topology_transport as transport
    # Prove exact approved fds load and map the candidate bytes. The changed
    # libc pin is locally replaced only in this audit call; no device function
    # or FTDI context is created.
    libc_path = Path("/usr/lib/x86_64-linux-gnu/libc.so.6")
    libc_sha = hashlib.sha256(libc_path.read_bytes()).hexdigest()
    libc_id = build_id(libc_path)
    loaded = {}
    candidate_pins = []
    for pin in transport.LIBRARY_PINS:
        if pin.name == "libc":
            pin = replace(pin, sha256=libc_sha, build_id=libc_id)
        candidate_pins.append(pin)
    handles = {}
    try:
        for pin in candidate_pins:
            item = transport._load_approved_library(pin)
            handles[pin.name] = item
            loaded[pin.name] = {"mapped_path": item.realpath,
                                "preload_stat_matches_postload": item.pre_stat == item.post_stat,
                                "fd_open": item.fd >= 0,
                                "library_hash_matches_candidate": item.pin.sha256 ==
                                hashlib.sha256(item.pin.path.read_bytes()).hexdigest()}
        probe = object.__new__(transport._NativeLibFtdi)
        probe._ftdi = handles["libftdi"].handle
        probe._usb = handles["libusb"].handle
        probe._bind_functions()
        symbol_checks = {
            "libftdi": {name: hasattr(probe._ftdi, name) for name in REQUIRED_FTDI},
            "libusb": {name: hasattr(probe._usb, name) for name in REQUIRED_USB},
        }
    finally:
        for item in handles.values():
            try:
                os.close(item.fd)
            except OSError:
                pass

    # Dynamic loader environment variables are rejected before native loading
    # if set after this interpreter has started. This test does not load a
    # library through an override or open any device.
    env_results = {}
    pin = candidate_pins[0]
    for variable in ("LD_LIBRARY_PATH", "LD_PRELOAD", "LD_AUDIT"):
        before = os.environ.get(variable)
        os.environ[variable] = "/tmp/fk0957-harmless-loader-sentinel"
        try:
            try:
                transport._load_approved_library(pin)
                refused = False
            except transport.Refusal:
                refused = True
            env_results[variable] = refused
        finally:
            if before is None:
                os.environ.pop(variable, None)
            else:
                os.environ[variable] = before
    return {"approved_fd_loaded_libraries": loaded,
            "required_symbol_presence": symbol_checks,
            "loader_override_refused_after_start": env_results,
            "device_functions_called": False,
            "ftdi_context_created": False,
            "usb_enumeration_called": False}


def candidate_pin_test_copy(repo: Path, libc_sha: str, libc_id: str) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="fk0957-runtime-candidate-") as d:
        root = Path(d)
        shutil.copytree(repo / "tools", root / "tools", symlinks=True)
        module = root / "tools/phk2_host/phk2_fk0957_topology_transport.py"
        text = module.read_text()
        text = text.replace("3a15d66867d83762c7f2f1e37359cb8f6c5743edb369c65285cb0b1c4f7498bf", libc_sha)
        text = text.replace("a4a7992a8e66555c8141ab2a08a8465ff6e0ea65", libc_id)
        module.write_text(text)
        (root / ".gitignore").write_text("__pycache__/\n*.py[cod]\n", encoding="ascii")
        init = cmd(["git", "-C", str(root), "init", "-q"])
        if init.returncode:
            raise RuntimeError("temporary candidate Git fixture initialization failed")
        for key, value in (("user.name", "FK0957 Offline Audit"),
                           ("user.email", "fk0957-audit.invalid")):
            cmd(["git", "-C", str(root), "config", key, value])
        if cmd(["git", "-C", str(root), "add", "-A"]).returncode or cmd(
                ["git", "-C", str(root), "commit", "-q", "-m", "temporary candidate pin fixture"]).returncode:
            raise RuntimeError("temporary candidate Git fixture commit failed")
        modules = [
            "test_phk2_fk0957_topology_libraries",
            "test_phk2_fk0957_topology_live_cli",
            "test_phk2_fk0957_topology_transport",
            "test_phk2_fk0957_topology_discovery",
            "test_phk2_fk0957_identity_observer",
            "test_phk2_fk0957_readonly_backend",
            "test_phk2_fk0957_remote_collector",
            "test_phk2_fk0957_remote_orchestrator",
        ]
        env = dict(os.environ)
        for key in ("PYTHONPATH", "PYTHONHOME", "LD_LIBRARY_PATH", "LD_PRELOAD", "LD_AUDIT"):
            env.pop(key, None)
        env["PYTHONPATH"] = str(root / "tools/phk2_host")
        # Run the suites only from the disposable copied tree.
        cp = subprocess.run([sys.executable, "-m", "unittest", "-q", *modules],
                            cwd=root / "tools/phk2_host", env=env, text=True,
                            capture_output=True, check=False)
        output = cp.stdout + cp.stderr
        ran = re.search(r"Ran (\d+) tests?", output)
        failed = re.search(r"FAILED \(([^)]+)\)", output)
        return {"temporary_tree_only": True, "production_modified": False,
                "modules": modules, "exit_code": cp.returncode,
                "tests_run": int(ran.group(1)) if ran else None,
                "failure_summary": failed.group(1) if failed else None,
                "tests_pass": cp.returncode == 0 and "OK" in output}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("production_repo", type=Path)
    args = parser.parse_args()
    repo = args.production_repo.resolve()
    sys.path.insert(0, str(repo / "tools/phk2_host"))
    import phk2_fk0957_topology_transport as transport
    expected = {p.name: {"path": str(p.path), "sha256": p.sha256,
                         "build_id": p.build_id, "soname": p.soname,
                         "size": p.size}
                for p in transport.LIBRARY_PINS}
    libc_pin = expected["libc"]
    loader = Path("/lib64/ld-linux-x86-64.so.2").resolve(strict=True)
    libc = Path("/usr/lib/x86_64-linux-gnu/libc.so.6")
    ftdi = transport.LIBFTDI_REALPATH
    usb = transport.LIBUSB_REALPATH
    inventory_map = {
        "dynamic_loader": inventory(loader),
        "libc": inventory(libc, libc_pin),
        "libftdi": inventory(ftdi, expected["libftdi"]),
        "libusb": inventory(usb, expected["libusb"]),
    }
    for name, path in (("dynamic_loader", loader), ("libc", libc),
                       ("libftdi", ftdi), ("libusb", usb)):
        inventory_map[name]["mapped_in_audit_process"] = loaded_path_for(path)
    loader_alias = Path("/lib64/ld-linux-x86-64.so.2")
    inventory_map["dynamic_loader"]["runtime_alias"] = str(loader_alias)
    inventory_map["dynamic_loader"]["runtime_alias_realpath"] = str(loader_alias.resolve(strict=True))
    inventory_map["libftdi"]["ldd_dependency_closure"] = cmd(["ldd", str(ftdi)]).stdout.splitlines()
    libc_sha = str(inventory_map["libc"]["sha256"])
    libc_id = str(inventory_map["libc"]["build_id"])
    try:
        transport._require_native_files()
        old_pin_preflight = {"refused_as_expected": False, "exception_class": None}
    except Exception as exc:
        old_pin_preflight = {"refused_as_expected": True,
                             "exception_class": type(exc).__name__}
    report = {
        "production_head": subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                                           capture_output=True, text=True, check=True).stdout.strip(),
        "old_reviewed_pins": expected,
        "runtime_inventory": inventory_map,
        "current_production_pin_preflight": old_pin_preflight,
        "package_history": package_history(),
        "apt_signature_and_package_metadata": apt_signature_and_package_metadata(),
        "dpkg_file_verification": package_file_verification(),
        "glibc_abi": {"libftdi": abi_requirements(ftdi, libc),
                      "libusb": abi_requirements(usb, libc)},
        "candidate_runtime_load_and_symbols": current_mapping_and_symbols(repo),
        "candidate_libc_pin_copy_test": candidate_pin_test_copy(repo, libc_sha, libc_id),
        "no_device_io": True,
    }
    native = report["candidate_runtime_load_and_symbols"]
    suites = report["candidate_libc_pin_copy_test"]
    decision = all(row.get("good_signature") for row in
                   report["apt_signature_and_package_metadata"]["inrelease_signatures"].values())
    decision = decision and report["apt_signature_and_package_metadata"][
        "signed_packages_index"]["matches_signed_inrelease_sha256"]
    decision = decision and report["dpkg_file_verification"]["dpkg_verify_no_differences"]
    decision = decision and report["dpkg_file_verification"]["dpkg_md5_files_match"]
    decision = decision and all(v["all_required_versions_present"]
                                for v in report["glibc_abi"].values())
    decision = decision and all(all(v.values()) for v in native["required_symbol_presence"].values())
    decision = decision and all(v["preload_stat_matches_postload"] and
                                v["library_hash_matches_candidate"] and v["fd_open"]
                                for v in native["approved_fd_loaded_libraries"].values())
    decision = decision and all(native["loader_override_refused_after_start"].values())
    decision = decision and suites["tests_pass"] and report["no_device_io"]
    report["native_runtime_requalification_pass"] = bool(decision)
    if decision:
        proposed = {"schema": "FK0957-NATIVE-RUNTIME-PROPOSED-PINS-v1",
                    "status": "PROPOSED_ONLY_NOT_INTEGRATED",
                    "candidate_head": report["production_head"],
                    "runtime": {name: {key: inventory_map[name].get(key) for key in (
                        "path", "realpath", "device", "inode", "links", "uid", "gid",
                        "mode", "size", "sha256", "build_id", "soname", "package_owner",
                        "package_version")}
                        for name in ("dynamic_loader", "libc", "libftdi", "libusb")},
                    "package_provenance": {
                        "unattended_upgrade_confirmed": report["package_history"][
                            "cause_is_unattended_upgrade"],
                        "apt_upgrade_record": report["package_history"]["apt_upgrade_record"],
                        "signed_apt_packages_index": report["apt_signature_and_package_metadata"][
                            "signed_packages_index"]["matches_signed_inrelease_sha256"],
                        "signed_inrelease_checks": report["apt_signature_and_package_metadata"][
                            "inrelease_signatures"],
                        "libc_package_record": report["apt_signature_and_package_metadata"][
                            "local_package_index_record"],
                        "dpkg_file_verification_clean": report["dpkg_file_verification"][
                            "dpkg_verify_no_differences"],
                        "dpkg_manifest_matches_loader_and_libc": report["dpkg_file_verification"][
                            "dpkg_md5_files_match"],
                        "exact_deb_cached": report["apt_signature_and_package_metadata"][
                            "package_archive_cached"]},
                    "tests": {"candidate_pin_fk0957_suite_count": suites["tests_run"],
                              "candidate_pin_fk0957_suite_pass": suites["tests_pass"],
                              "required_symbols_present": True,
                              "loaded_mapping_stat_and_hash_verified": True,
                              "loader_override_env_refused_after_start": True,
                              "device_or_usb_io_performed": False}}
        proposal_path = Path(__file__).resolve().parents[2] / "results/fk0957-proposed-native-pin-set.json"
        proposal_path.parent.mkdir(parents=True, exist_ok=True)
        proposal_path.write_text(json.dumps(proposed, sort_keys=True, indent=2) + "\n",
                                 encoding="utf-8")
        report["proposed_pin_set_path"] = str(proposal_path)
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
