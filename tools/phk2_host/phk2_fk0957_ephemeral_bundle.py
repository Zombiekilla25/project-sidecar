#!/usr/bin/env python3
"""Deterministic stdlib-only bundle builder and isolated SSH command factory."""
from __future__ import annotations

import ast
import hashlib
import io
import json
from pathlib import Path
import shlex
import stat
import zipfile


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")

MAX_BUNDLE_BYTES = 4 * 1024 * 1024
COLLECTOR_REL = "tools/phk2_host/phk2_fk0957_remote_collector.py"
BACKEND_REL = "tools/phk2_host/phk2_fk0957_readonly_backend.py"
OBSERVER_REL = "tools/phk2_host/phk2_fk0957_identity_observer.py"
RUNNER_REL = "runner.py"
PAYLOAD_RELS = (COLLECTOR_REL, BACKEND_REL, OBSERVER_REL)
STDLIB = set(__import__("sys").stdlib_module_names)
ALLOWED_EXTERNAL_IMPORTS = STDLIB | {"phk2_fk0957_identity_observer", "phk2_fk0957_readonly_backend"}
LAZY_OPTIONAL_IMPORTS = {"cryptography"}


class BundleRefusal(RuntimeError):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _check_import_surface(files: dict[str, bytes]) -> None:
    module_names = {COLLECTOR_REL: "<collector>", BACKEND_REL: "<backend>",
                    OBSERVER_REL: "<observer>", RUNNER_REL: "<runner>"}
    for path, content in files.items():
        if path not in module_names:
            continue
        tree = ast.parse(content.decode("utf-8"), filename=path)

        class ImportAudit(ast.NodeVisitor):
            function_depth = 0

            def visit_FunctionDef(self, node):
                self.function_depth += 1
                self.generic_visit(node)
                self.function_depth -= 1

            visit_AsyncFunctionDef = visit_FunctionDef

            def visit_Import(self, node):
                names = [alias.name.split(".", 1)[0] for alias in node.names]
                self.check(names)

            def visit_ImportFrom(self, node):
                self.check([node.module.split(".", 1)[0]] if node.module else [])

            def visit_Call(self, node):
                if ((isinstance(node.func, ast.Name) and node.func.id == "__import__") or
                        (isinstance(node.func, ast.Attribute) and node.func.attr in {"import_module", "exec_module"})):
                    raise BundleRefusal("dynamic import is prohibited in executable bundle sources")
                self.generic_visit(node)

            def check(self, names):
                for name in names:
                    if name in ALLOWED_EXTERNAL_IMPORTS:
                        continue
                    if name in LAZY_OPTIONAL_IMPORTS and self.function_depth > 0:
                        continue
                    raise BundleRefusal(f"unexpected import in bundle source: {path}")

        ImportAudit().visit(tree)


def _manifest_bytes(*, source_commit: str, session_nonce: str, files: dict[str, bytes]) -> bytes:
    manifest = {
        "schema": "fk0957-ephemeral-execution-bundle", "version": 1,
        "source_commit": source_commit, "session_nonce": session_nonce,
        "collector_source_sha256": sha(files[COLLECTOR_REL]),
        "backend_source_sha256": sha(files[BACKEND_REL]),
        "observer_source_sha256": sha(files[OBSERVER_REL]),
        "runner_source_sha256": sha(files[RUNNER_REL]),
        "files": {name: sha(content) for name, content in sorted(files.items()) if name != RUNNER_REL},
    }
    return _canonical(manifest)


def deterministic_bundle(*, source_commit: str, session_nonce: str,
                         source_root: Path, collector_pin: str, backend_pin: str,
                         observer_pin: str, runner_bytes: bytes) -> tuple[bytes, dict]:
    if not (len(source_commit) == 40 and all(c in "0123456789abcdef" for c in source_commit)):
        raise BundleRefusal("source commit malformed")
    if not (len(session_nonce) == 64 and all(c in "0123456789abcdef" for c in session_nonce)):
        raise BundleRefusal("session nonce malformed")
    files = {rel: (source_root / rel).read_bytes() for rel in PAYLOAD_RELS}
    files[RUNNER_REL] = runner_bytes
    if sha(files[COLLECTOR_REL]) != collector_pin or sha(files[BACKEND_REL]) != backend_pin or sha(files[OBSERVER_REL]) != observer_pin:
        raise BundleRefusal("collector, backend, or observer bytes do not match reviewed local pins")
    _check_import_surface(files)
    manifest_bytes = _manifest_bytes(source_commit=source_commit, session_nonce=session_nonce, files=files)
    payloads = {"manifest.json": manifest_bytes, **files}
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
        for name, data in sorted(payloads.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            archive.writestr(info, data)
    bundle = output.getvalue()
    if len(bundle) > MAX_BUNDLE_BYTES:
        raise BundleRefusal("execution bundle exceeds size limit")
    metadata = json.loads(manifest_bytes.decode("utf-8"))
    metadata["bundle_sha256"] = sha(bundle)
    return bundle, metadata


def inspect_bundle(bundle: bytes, *, expected_bundle_sha256: str, expected_source_commit: str,
                   expected_collector_sha256: str, expected_backend_sha256: str,
                   expected_nonce: str) -> tuple[dict, dict[str, bytes]]:
    if len(bundle) > MAX_BUNDLE_BYTES or sha(bundle) != expected_bundle_sha256:
        raise BundleRefusal("bundle size or hash mismatch")
    try:
        with zipfile.ZipFile(io.BytesIO(bundle), "r") as archive:
            infos = archive.infolist()
            names = [i.filename for i in infos]
            required = sorted(("manifest.json", RUNNER_REL, *PAYLOAD_RELS))
            if names != required or len(names) != len(set(names)):
                raise BundleRefusal("bundle members are missing, duplicate, unexpected, or reordered")
            for info in infos:
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode) or not stat.S_ISREG(mode) or info.file_size > MAX_BUNDLE_BYTES:
                    raise BundleRefusal("bundle contains a nonregular or oversized member")
            raw_manifest = archive.read("manifest.json")
            manifest = json.loads(raw_manifest.decode("utf-8"), object_pairs_hook=_unique_pairs)
            if _canonical(manifest) != raw_manifest:
                raise BundleRefusal("bundle manifest is noncanonical")
            expected_fields = {"schema", "version", "source_commit", "session_nonce", "collector_source_sha256",
                               "backend_source_sha256", "observer_source_sha256", "runner_source_sha256", "files"}
            if set(manifest) != expected_fields:
                raise BundleRefusal("bundle manifest has missing or extra fields")
            if (manifest["schema"] != "fk0957-ephemeral-execution-bundle" or manifest["version"] != 1 or
                    manifest["source_commit"] != expected_source_commit or manifest["session_nonce"] != expected_nonce or
                    manifest["collector_source_sha256"] != expected_collector_sha256 or
                    manifest["backend_source_sha256"] != expected_backend_sha256):
                raise BundleRefusal("bundle metadata differs from local command pins")
            members = {name: archive.read(name) for name in names if name not in ("manifest.json", RUNNER_REL)}
            runner = archive.read(RUNNER_REL)
            if set(members) != set(PAYLOAD_RELS) or any(sha(value) != manifest["files"].get(name) for name, value in members.items()):
                raise BundleRefusal("bundle payload digest mismatch")
            if sha(runner) != manifest["runner_source_sha256"]:
                raise BundleRefusal("bundle runner digest mismatch")
            if sha(members[OBSERVER_REL]) != manifest["observer_source_sha256"]:
                raise BundleRefusal("bundle observer digest mismatch")
            _check_import_surface({**members, RUNNER_REL: runner})
            return manifest, {**members, RUNNER_REL: runner}
    except BundleRefusal:
        raise
    except Exception as exc:
        raise BundleRefusal("bundle archive is malformed or truncated") from exc


BOOTSTRAP_BODY = r'''import hashlib,io,json,sys,zipfile
MAX=4*1024*1024
EXPECTED_NAMES=__EXPECTED_NAMES__
def pairs(items):
 d={}
 for k,v in items:
  if k in d: raise ValueError("duplicate manifest key")
  d[k]=v
 return d
def diag(k,v="YES"):
 print("FK0957_DIAG "+k+"="+v,file=sys.stderr,flush=True)
def fail(error):
 diag("REMOTE_PHASE",phase)
 diag("SSH_ERROR_CLASS",error)
 raise SystemExit(2)
phase="REMOTE_RUNNER_STARTED"
diag(phase)
try:
 if len(sys.argv)!=7 or sys.argv[1]!="FK0957-BUNDLE": fail("BUNDLE_FRAMING_FAILED")
 raw=sys.stdin.buffer.read(MAX+1)
 phase="BUNDLE_RECEIVED"; diag(phase)
 if len(raw)>MAX: fail("BUNDLE_FRAMING_FAILED")
 if hashlib.sha256(raw).hexdigest()!=sys.argv[2]: fail("BUNDLE_HASH_FAILED")
 phase="BUNDLE_HASH_VERIFIED"; diag(phase)
 z=zipfile.ZipFile(io.BytesIO(raw),"r")
 infos=z.infolist(); names=[i.filename for i in infos]
 if names!=EXPECTED_NAMES or len(names)!=len(set(names)): fail("BUNDLE_FRAMING_FAILED")
 for i in infos:
  mode=i.external_attr>>16
  if i.is_dir() or (mode & 0o170000)!=0o100000 or i.file_size>MAX: fail("BUNDLE_FRAMING_FAILED")
 mraw=z.read("manifest.json"); m=json.loads(mraw.decode("utf-8"),object_pairs_hook=pairs)
 if json.dumps(m,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode()!=mraw: fail("BUNDLE_FRAMING_FAILED")
 if set(m)!={"schema","version","source_commit","session_nonce","collector_source_sha256","backend_source_sha256","observer_source_sha256","runner_source_sha256","files"}: fail("BUNDLE_FRAMING_FAILED")
 if (m["schema"]!="fk0957-ephemeral-execution-bundle" or m["version"]!=1 or m["source_commit"]!=sys.argv[3] or m["collector_source_sha256"]!=sys.argv[4] or m["backend_source_sha256"]!=sys.argv[5] or m["session_nonce"]!=sys.argv[6]): fail("BUNDLE_FRAMING_FAILED")
 members={n:z.read(n) for n in names if n not in ("manifest.json","runner.py")}
 if set(members)!=set(m["files"]): fail("BUNDLE_FRAMING_FAILED")
 for n,b in members.items():
  if hashlib.sha256(b).hexdigest()!=m["files"].get(n): fail("BUNDLE_HASH_FAILED")
 runner=z.read("runner.py")
 if hashlib.sha256(runner).hexdigest()!=m["runner_source_sha256"]: fail("BUNDLE_HASH_FAILED")
 phase="MANIFEST_VERIFIED"; diag(phase)
 collector="tools/phk2_host/phk2_fk0957_remote_collector.py"
 backend="tools/phk2_host/phk2_fk0957_readonly_backend.py"
 if hashlib.sha256(members[collector]).hexdigest()!=sys.argv[4]: fail("BUNDLE_HASH_FAILED")
 phase="COLLECTOR_SOURCE_VERIFIED"; diag(phase)
 if hashlib.sha256(members[backend]).hexdigest()!=sys.argv[5]: fail("BUNDLE_HASH_FAILED")
 phase="BACKEND_SOURCE_VERIFIED"; diag(phase)
 ns={"__name__":"__main__","__file__":"<fk0957-ephemeral-runner>","BUNDLE_MANIFEST":m,"BUNDLE_MEMBERS":members,"EXPECTED_COMMIT":sys.argv[3],"EXPECTED_COLLECTOR_SHA256":sys.argv[4],"EXPECTED_BACKEND_SHA256":sys.argv[5],"EXPECTED_SESSION_NONCE":sys.argv[6]}
 exec(compile(runner,"<fk0957-ephemeral-runner>","exec"),ns)
except SystemExit:
 raise
except Exception:
 fail("BUNDLE_FRAMING_FAILED")
'''

def remote_command(*, bundle_sha256: str, source_commit: str, collector_sha256: str,
                   backend_sha256: str, session_nonce: str) -> str:
    pins = ((bundle_sha256, 64), (source_commit, 40), (collector_sha256, 64),
            (backend_sha256, 64), (session_nonce, 64))
    if any(len(value) != size or any(ch not in "0123456789abcdef" for ch in value)
           for value, size in pins):
        raise BundleRefusal("remote command contains malformed pin or nonce")
    names = sorted(("manifest.json", RUNNER_REL, *PAYLOAD_RELS))
    body = BOOTSTRAP_BODY.replace("__EXPECTED_NAMES__", repr(names))
    command = ("FK0957_TARGET=FK0957 /usr/bin/python3 -I -S -c " + shlex.quote(body) +
               " FK0957-BUNDLE " + " ".join((bundle_sha256, source_commit, collector_sha256,
                                               backend_sha256, session_nonce)))
    return command


def _unique_pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result
