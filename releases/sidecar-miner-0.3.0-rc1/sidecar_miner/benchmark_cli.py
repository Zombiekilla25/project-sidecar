"""Offline first-silicon benchmark artifact commands."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import tempfile
from .benchmark import (load_benchmark, analyze_record, fleet_scaling_model,
    bottleneck_classifier, optimization_recommendation, gpu_fk_comparison,
    rollout_recommendations)


def default_store() -> Path:
    base = Path(os.environ.get("XDG_DATA_HOME", Path.home()/".local/share"))
    return base / "project-sidecar" / "benchmarks" / "latest.json"


def _write_atomic(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".benchmark-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, sort_keys=True, indent=2); stream.write("\n")
            stream.flush(); os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        try: os.unlink(name)
        except FileNotFoundError: pass


def _read(path: Path):
    return load_benchmark(path)


def main(argv=None):
    p=argparse.ArgumentParser(prog="sidecar-miner benchmark",description="Offline first-silicon timing analysis")
    sub=p.add_subparsers(dest="command",required=True)
    ingest=sub.add_parser("ingest");ingest.add_argument("file");ingest.add_argument("--store",default=str(default_store()))
    show=sub.add_parser("show");show.add_argument("--store",default=str(default_store()));show.add_argument("--json",action="store_true")
    fleet=sub.add_parser("fleet");fleet.add_argument("--store",default=str(default_store()));fleet.add_argument("--fleet-config");fleet.add_argument("--minimum-gain",type=float);fleet.add_argument("--minimum-efficiency",type=float);fleet.add_argument("--minimum-stage-transactions",type=int);fleet.add_argument("--minimum-observation-seconds",type=float);fleet.add_argument("--maximum-timeout-rate",type=float);fleet.add_argument("--maximum-transport-error-rate",type=float);fleet.add_argument("--json",action="store_true")
    bottleneck=sub.add_parser("bottleneck");bottleneck.add_argument("--store",default=str(default_store()));bottleneck.add_argument("--json",action="store_true")
    compare=sub.add_parser("comparison-schema");compare.add_argument("--json",action="store_true")
    a=p.parse_args(argv)
    try:
        if a.command=="ingest":
            rec=_read(Path(a.file));target=Path(a.store);_write_atomic(target,rec.to_dict())
            print(json.dumps({"status":"PASS","candidate_id":rec.candidate_id,"measured":rec.measured,"store":str(target)},sort_keys=True));return 0
        if a.command=="comparison-schema":
            print(json.dumps(gpu_fk_comparison(),sort_keys=True));return 0
        store=Path(a.store)
        if not store.exists():
            out={"status":"INSUFFICIENT_DATA","reason":"no benchmark artifact ingested","measured":False}
            print(json.dumps(out,sort_keys=True));return 0
        rec=_read(store)
        if a.command=="show":out=analyze_record(rec)
        elif a.command=="bottleneck":out={"status":bottleneck_classifier(rec)["status"],"bottleneck":bottleneck_classifier(rec),"recommendation":optimization_recommendation(rec)}
        else:
            scaling=fleet_scaling_model(rec)
            recs={"recommendations":{"SHOULD_EXPAND_1_TO_2":"INSUFFICIENT_DATA","SHOULD_EXPAND_2_TO_4":"INSUFFICIENT_DATA","SHOULD_EXPAND_4_TO_8":"INSUFFICIENT_DATA"},"reason":"fleet configuration and measured safety evidence are required","performance_advisory_only":True}
            if a.fleet_config:
                from .fleet import FleetController
                from .fleet import RolloutHealthGate
                controller=FleetController.from_config(a.fleet_config)
                supplied=(a.minimum_stage_transactions,a.minimum_observation_seconds,a.maximum_timeout_rate,a.maximum_transport_error_rate)
                gate=RolloutHealthGate(*supplied) if all(v is not None for v in supplied) else None
                recs=rollout_recommendations(rec,controller,minimum_gain=a.minimum_gain,minimum_efficiency=a.minimum_efficiency,health_gate=gate)
            out={"status":scaling["status"],"scaling":scaling,"rollout":recs,"gpu_fk_comparison":gpu_fk_comparison()}
        print(json.dumps(out,sort_keys=True));return 0
    except (OSError,ValueError,KeyError,TypeError) as exc:
        print(json.dumps({"status":"INVALID_ARTIFACT_OR_CONFIG","reason":str(exc)},sort_keys=True));return 2
