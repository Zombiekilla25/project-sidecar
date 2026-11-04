"""Explicit local store for public-safe backend qualification artifacts."""
from __future__ import annotations
import json
import os
from pathlib import Path
import tempfile
from typing import Any

from .qualification import (CUDA_BACKEND,PHK1_BACKEND,load_qualification_artifact,
    pinned_source_hashes)

DEFAULT_STORE=Path.home()/".local/share/project-sidecar/qualifications"

class QualificationStore:
    def __init__(self,root: str|Path|None=None):
        self.root=Path(root).expanduser() if root else DEFAULT_STORE

    @property
    def index_path(self):return self.root/"store-index-v1.json"

    def _indexed_names(self) -> list[str]:
        try:
            obj=json.loads(self.index_path.read_text(encoding="utf-8"))
            names=obj.get("artifacts") if isinstance(obj,dict) and obj.get("schema")=="sidecar-qualification-store-v1" else None
            if not isinstance(names,list):return []
            return sorted({n for n in names if isinstance(n,str) and Path(n).name==n and n.endswith(".json") and n!="store-index-v1.json"})
        except (OSError,ValueError):return []

    def _write_index(self,names: list[str]):
        self.root.mkdir(parents=True,exist_ok=True)
        fd,tmp=tempfile.mkstemp(prefix=".store-index.",dir=self.root,text=True)
        try:
            with os.fdopen(fd,"w",encoding="utf-8") as f:
                json.dump({"schema":"sidecar-qualification-store-v1","artifacts":sorted(set(names))},
                    f,sort_keys=True,separators=(",",":"));f.write("\n");f.flush();os.fsync(f.fileno())
            os.replace(tmp,self.index_path)
        finally:
            try:os.unlink(tmp)
            except FileNotFoundError:pass

    def _validate(self,path: str|Path, *, expected_bitstream_sha256: str|None=None,
                  expected_library_sha256: str|None=None,expected_source_sha256: str|None=None,
                  expected_fixture_sha256: str|None=None):
        obj=json.loads(Path(path).read_text(encoding="utf-8"))
        kwargs={"expected_bitstream_sha256":expected_bitstream_sha256,
            "expected_library_sha256":expected_library_sha256,
            "expected_source_sha256":expected_source_sha256,
            "expected_fixture_sha256":expected_fixture_sha256}
        if obj.get("backend_type")==PHK1_BACKEND:
            kwargs["expected_runner_sha256"],kwargs["expected_backend_sha256"]=pinned_source_hashes()
        return load_qualification_artifact(path,**kwargs)

    def import_file(self,source: str|Path, *, expected_bitstream_sha256: str|None=None,
                    expected_library_sha256: str|None=None,expected_source_sha256: str|None=None,
                    expected_fixture_sha256: str|None=None) -> tuple[Path,Any]:
        source=Path(source)
        if source.stat().st_size>1_048_576:raise ValueError("qualification artifact exceeds 1 MiB")
        try:backend_type=json.loads(source.read_text(encoding="utf-8")).get("backend_type")
        except (OSError,UnicodeError,ValueError,AttributeError) as exc:raise ValueError("qualification artifact cannot be read/parsed") from exc
        if backend_type==PHK1_BACKEND and not expected_bitstream_sha256:
            raise ValueError("PHK1 import requires an expected bitstream SHA256")
        if backend_type==CUDA_BACKEND and not all((expected_library_sha256,expected_source_sha256,expected_fixture_sha256)):
            raise ValueError("CUDA import requires expected library, source, and fixture SHA256 values")
        record=self._validate(source,expected_bitstream_sha256=expected_bitstream_sha256,
            expected_library_sha256=expected_library_sha256,expected_source_sha256=expected_source_sha256,
            expected_fixture_sha256=expected_fixture_sha256)
        raw=json.loads(source.read_text(encoding="utf-8"))
        if record.backend_type==PHK1_BACKEND:
            name=f"phk1-{record.bitstream_sha256[:16]}.json"
        elif record.backend_type==CUDA_BACKEND:
            name=f"cuda-{record.library_sha256[:16]}.json"
        else:raise ValueError("unsupported qualification backend")
        self.root.mkdir(parents=True,exist_ok=True)
        target=self.root/name
        fd,tmp=tempfile.mkstemp(prefix=name+".",dir=self.root,text=True)
        try:
            with os.fdopen(fd,"w",encoding="utf-8") as f:
                json.dump(raw,f,sort_keys=True,separators=(",",":"));f.write("\n");f.flush();os.fsync(f.fileno())
            os.replace(tmp,target)
        finally:
            try:os.unlink(tmp)
            except FileNotFoundError:pass
        self._write_index(self._indexed_names()+[name])
        return target,record

    def records(self) -> list[dict[str,Any]]:
        if not self.root.exists():return []
        out=[]
        for name in self._indexed_names():
            path=self.root/name
            try:
                obj=json.loads(path.read_text(encoding="utf-8"))
                backend=obj.get("backend_type")
                if backend==PHK1_BACKEND:
                    record=self._validate(path,expected_bitstream_sha256=obj.get("bitstream_sha256"))
                    identity={"bitstream_sha256":record.bitstream_sha256,"runner_sha256":record.runner_sha256,
                        "backend_sha256":record.backend_sha256}
                    checks={"transport_version":record.transport_version,"protocol_version":record.protocol_version,
                        "vector_id":record.vector_id,"raw_result_exact":record.raw_result_exact,
                        "canonical_result_exact":record.canonical_result_exact,"cpu_crosscheck":record.cpu_crosscheck,
                        "rollback_verified":record.rollback_pass}
                elif backend==CUDA_BACKEND:
                    record=self._validate(path,expected_library_sha256=obj.get("library_sha256"),
                        expected_source_sha256=obj.get("source_sha256"),expected_fixture_sha256=obj.get("fixture_sha256"))
                    identity={"library_sha256":record.library_sha256,"source_sha256":record.source_sha256,
                        "fixture_sha256":record.fixture_sha256}
                    checks={"device_name":record.device_name,"explicit_device_selection":record.explicit_device_selection}
                else:continue
                out.append({"backend_type":backend,"qualified":record.qualified,
                    "qualification_timestamp":record.qualification_timestamp,"schema_version":obj.get("schema_version"),
                    "identity":identity,"checks":checks,"path":str(path)})
            except (OSError,ValueError,TypeError,KeyError):
                out.append({"backend_type":"unknown","qualified":False,"qualification_timestamp":None,
                    "schema_version":None,"identity":{},"checks":{},"path":str(path),"invalid":True})
        return out

    def find(self,backend_type: str, *, expected_bitstream_sha256: str|None=None,
             expected_library_sha256: str|None=None,expected_source_sha256: str|None=None,
             expected_fixture_sha256: str|None=None) -> Path|None:
        for row in self.records():
            if row["backend_type"]!=backend_type or not row["qualified"]:continue
            path=Path(row["path"])
            try:
                self._validate(path,expected_bitstream_sha256=expected_bitstream_sha256,
                    expected_library_sha256=expected_library_sha256,expected_source_sha256=expected_source_sha256,
                    expected_fixture_sha256=expected_fixture_sha256)
            except (OSError,ValueError,TypeError):continue
            return path
        return None
