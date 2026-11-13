"""Trusted post-launch bootstrap for the FK0957 CLI (invoked with -I -S)."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys

_EXPECTED_ENV = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C.UTF-8",
    "FK0957_TRUSTED_LAUNCHER": "1",
}


def _refuse() -> int:
    sys.stdout.write('{"status":"REFUSED","phase":"PRELIVE_VALIDATION",'
                     '"code":"TRUSTED_LAUNCHER_REQUIRED"}\n')
    return 2


def main(argv: list[str] | None = None) -> int:
    if (sys.flags.isolated != 1 or sys.flags.no_site != 1 or
            dict(os.environ) != _EXPECTED_ENV):
        return _refuse()
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["--launcher-self-test"]:
        sys.stdout.write(json.dumps({
            "isolated": sys.flags.isolated,
            "no_site": sys.flags.no_site,
            "environment_keys": sorted(os.environ),
            "sitecustomize_loaded": "sitecustomize" in sys.modules,
            "usercustomize_loaded": "usercustomize" in sys.modules,
        }, sort_keys=True, separators=(",", ":")) + "\n")
        return 0
    bootstrap = Path(__file__).resolve()
    repo_root = bootstrap.parents[2]
    host_tools = repo_root / "tools" / "phk2_host"
    if not host_tools.is_dir():
        return _refuse()
    # -S prevents .pth processing. Add only the root-owned system package
    # directory needed for the reviewed Ed25519 dependency.
    system_packages = Path("/usr/lib/python3/dist-packages")
    try:
        info = system_packages.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            return _refuse()
    except OSError:
        return _refuse()
    sys.path[:] = [sysconfig_path for sysconfig_path in sys.path
                   if sysconfig_path and "site-packages" not in sysconfig_path]
    sys.path.append(str(system_packages))
    sys.path.insert(0, str(host_tools))
    try:
        import phk2_fk0957_topology_rgb_cli as live_cli
    except Exception:
        return _refuse()
    return int(live_cli.main(args))


if __name__ == "__main__":
    raise SystemExit(main())
