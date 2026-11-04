"""First-silicon timing ingestion and conservative offline scaling analysis.

This module only analyzes supplied artifacts. It never probes hardware or
changes fleet state. Predictions are explicitly labeled models; only fields
marked measured in a validated input can be described as measured.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json
import math
from typing import Any

from sidecar_scheduler.ingest import load_phk1_canary
from .fleet import FleetController, RolloutHealthGate, RolloutStage, STAGE_SIZE

BENCHMARK_SCHEMA = "sidecar-first-silicon-benchmark-v1"
LEGACY_CANARY_SCHEMA = "sidecar-phk1-canary-result-v1"
TIMING_KEYS = (
    "host_preparation_us", "transport_in_us", "fpga_compute_us",
    "transport_out_us", "composition_us", "cpu_verification_us",
    "total_e2e_us", "backend_vector_total_us",
)
COMPONENT_KEYS = TIMING_KEYS[:6]
HASH_KEYS = ("bitstream_sha256", "runner_sha256")


def _measurement(value: Any, name: str) -> float | None:
    if value is None or (isinstance(value, str) and value.upper() == "UNKNOWN"):
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a nonnegative number, null, or UNKNOWN")
    if not math.isfinite(value) or value < 0:
        raise ValueError(f"{name} must be finite and nonnegative")
    return float(value)


def _optional_bool(value, name):
    if value is not None and not isinstance(value, bool):
        raise ValueError(f"{name} must be boolean or null")
    return value


def _sha(value, name):
    if value is None:
        return None
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError(f"{name} must be a lowercase SHA256 or null")
    return value


@dataclass(frozen=True)
class BenchmarkRecord:
    schema: str
    candidate_id: str
    measured: bool
    status: str
    job_fingerprint: str
    result_identity: str
    transaction_count: int
    item_count: int | None
    timings_us: dict[str, float | None]
    raw_result_exact: bool | None
    canonical_result_exact: bool | None
    cpu_crosscheck: bool | None
    qualified: bool | None
    bitstream_sha256: str | None
    runner_sha256: str | None
    rollback_available: bool | None
    backend_healthy: bool | None
    stale_result_count: int | None
    source_kind: str

    def to_dict(self):
        return {
            "schema": BENCHMARK_SCHEMA,
            "schema_version": 1,
            "candidate_id": self.candidate_id,
            "measured": self.measured,
            "status": self.status,
            "identity": {"job_fingerprint": self.job_fingerprint, "result_identity": self.result_identity},
            "transaction_count": self.transaction_count,
            "item_count": self.item_count,
            "timings_us": dict(self.timings_us),
            "correctness": {"raw_result_exact": self.raw_result_exact,
                "canonical_result_exact": self.canonical_result_exact, "cpu_crosscheck": self.cpu_crosscheck},
            "qualification": {"qualified": self.qualified, "bitstream_sha256": self.bitstream_sha256,
                "runner_sha256": self.runner_sha256},
            "rollback_available": self.rollback_available,
            "backend_healthy": self.backend_healthy,
            "stale_result_count": self.stale_result_count,
            "source_kind": self.source_kind,
        }


def validate_benchmark_dict(obj: Any) -> BenchmarkRecord:
    """Validate the stable miner benchmark contract, rejecting unknown fields."""
    if not isinstance(obj, dict) or obj.get("schema") != BENCHMARK_SCHEMA or obj.get("schema_version") != 1:
        raise ValueError("unsupported first-silicon benchmark schema")
    required = {"schema", "schema_version", "candidate_id", "measured", "status", "identity",
        "transaction_count", "item_count", "timings_us", "correctness", "qualification",
        "rollback_available", "backend_healthy", "stale_result_count", "source_kind"}
    if set(obj) != required:
        raise ValueError("benchmark artifact has missing or unsupported fields")
    if not isinstance(obj["candidate_id"], str) or not obj["candidate_id"] or len(obj["candidate_id"]) > 96:
        raise ValueError("candidate_id is required and must be at most 96 characters")
    if not all(ch.isalnum() or ch in "._-" for ch in obj["candidate_id"]):
        raise ValueError("candidate_id must be a simple identifier")
    if not isinstance(obj["measured"], bool): raise ValueError("measured must be boolean")
    if obj["status"] not in ("PASS", "FAIL"): raise ValueError("status must be PASS or FAIL")
    ident = obj["identity"]
    if not isinstance(ident, dict) or set(ident) != {"job_fingerprint", "result_identity"}:
        raise ValueError("identity must contain only job_fingerprint and result_identity")
    for key in ("job_fingerprint", "result_identity"):
        if not isinstance(ident[key], str) or not ident[key]: raise ValueError(f"identity.{key} is required")
    tx = obj["transaction_count"]
    if isinstance(tx, bool) or not isinstance(tx, int) or tx <= 0: raise ValueError("transaction_count must be positive")
    count = obj["item_count"]
    if count is not None and (isinstance(count, bool) or not isinstance(count, int) or count <= 0):
        raise ValueError("item_count must be a positive integer or null")
    raw_times = obj["timings_us"]
    if not isinstance(raw_times, dict) or set(raw_times) != set(TIMING_KEYS):
        raise ValueError("timings_us must contain the complete benchmark timing contract")
    times = {key: _measurement(raw_times[key], key) for key in TIMING_KEYS}
    correctness = obj["correctness"]
    if not isinstance(correctness, dict) or set(correctness) != {"raw_result_exact", "canonical_result_exact", "cpu_crosscheck"}:
        raise ValueError("correctness must contain raw, canonical, and CPU crosscheck fields")
    correctness = {k: _optional_bool(v, f"correctness.{k}") for k, v in correctness.items()}
    qualification = obj["qualification"]
    if not isinstance(qualification, dict) or set(qualification) != {"qualified", *HASH_KEYS}:
        raise ValueError("qualification must contain qualification state and image/runner hashes")
    q = _optional_bool(qualification["qualified"], "qualification.qualified")
    hashes = {k: _sha(qualification[k], f"qualification.{k}") for k in HASH_KEYS}
    for key in HASH_KEYS:
        if q is True and hashes[key] is None: raise ValueError(f"qualified artifact requires {key}")
    rollback = _optional_bool(obj["rollback_available"], "rollback_available")
    healthy = _optional_bool(obj["backend_healthy"], "backend_healthy")
    stale = obj["stale_result_count"]
    if stale is not None and (isinstance(stale, bool) or not isinstance(stale, int) or stale < 0):
        raise ValueError("stale_result_count must be a nonnegative integer or null")
    if not isinstance(obj["source_kind"], str) or obj["source_kind"] not in ("PHK1_CANARY", "SYNTHETIC_FIXTURE", "EXTERNAL_BENCHMARK"):
        raise ValueError("unsupported source_kind")
    if obj["source_kind"] == "SYNTHETIC_FIXTURE" and obj["measured"]:
        raise ValueError("synthetic fixtures cannot be marked as measured")
    return BenchmarkRecord(BENCHMARK_SCHEMA, obj["candidate_id"], obj["measured"], obj["status"],
        ident["job_fingerprint"], ident["result_identity"], tx, count, times,
        correctness["raw_result_exact"], correctness["canonical_result_exact"], correctness["cpu_crosscheck"],
        q, hashes["bitstream_sha256"], hashes["runner_sha256"], rollback, healthy, stale, obj["source_kind"])


def _legacy_canary(obj: dict, path: str | Path) -> BenchmarkRecord:
    """Adapt the established canary artifact; never infer missing timing gates."""
    # Run the existing strict job/result/timing parser first.
    parsed = load_phk1_canary(path)
    src = parsed["timings_us"]
    alias = {"host_preparation_us": "host_pack_us", "transport_in_us": "input_stream_us",
        "fpga_compute_us": "fpga_compute_us", "transport_out_us": "output_stream_us",
        "composition_us": "host_compose_us", "cpu_verification_us": "verify_us"}
    timings = {k: _measurement(src.get(v), k) for k, v in alias.items()}
    explicit_total = obj.get("total_e2e_us")
    timings["total_e2e_us"] = _measurement(explicit_total, "total_e2e_us")
    timings["backend_vector_total_us"] = _measurement(src.get("vector_total_us"), "vector_total_us")
    item_count = obj.get("item_count")
    if item_count is not None and (isinstance(item_count, bool) or not isinstance(item_count, int) or item_count <= 0):
        raise ValueError("item_count must be a positive integer")
    return BenchmarkRecord(BENCHMARK_SCHEMA, str(obj.get("candidate_id", "legacy-phk1")), True,
        "PASS" if parsed["status"].upper() == "PASS" else "FAIL", parsed["identity"]["job_fingerprint"],
        parsed["identity"]["result_identity"], 1, item_count, timings,
        _optional_bool(obj.get("raw_result_exact"), "raw_result_exact"),
        _optional_bool(obj.get("canonical_result_exact"), "canonical_result_exact"),
        _optional_bool(obj.get("cpu_crosscheck"), "cpu_crosscheck"),
        _optional_bool(obj.get("qualified"), "qualified"), _sha(obj.get("bitstream_sha256"), "bitstream_sha256"),
        _sha(obj.get("runner_sha256"), "runner_sha256"), _optional_bool(obj.get("rollback_available"), "rollback_available"),
        _optional_bool(obj.get("backend_healthy"), "backend_healthy"), obj.get("stale_result_count"), "PHK1_CANARY")


def load_benchmark(path: str | Path) -> BenchmarkRecord:
    try: obj = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc: raise ValueError("cannot read benchmark artifact") from exc
    if isinstance(obj, dict) and obj.get("schema") == LEGACY_CANARY_SCHEMA:
        return _legacy_canary(obj, path)
    return validate_benchmark_dict(obj)


def single_fk_performance(record: BenchmarkRecord) -> dict:
    times = record.timings_us
    total = times["total_e2e_us"]
    txs = record.transaction_count * 1_000_000 / total if total is not None and total > 0 else None
    items = record.transaction_count * record.item_count * 1_000_000 / total if total and record.item_count else None
    host_parts = (times["host_preparation_us"], times["composition_us"], times["cpu_verification_us"])
    trans_parts = (times["transport_in_us"], times["transport_out_us"])
    host = sum(host_parts) if all(v is not None for v in host_parts) else None
    transport = sum(trans_parts) if all(v is not None for v in trans_parts) else None
    compute = times["fpga_compute_us"]
    def pct(value): return 100.0 * value / total if value is not None and total and total > 0 else None
    known = [times[k] for k in COMPONENT_KEYS]
    component_sum = sum(known) if all(x is not None for x in known) else None
    consistency = "UNKNOWN"
    unattributed = None
    if component_sum is not None and total is not None:
        consistency = "PASS" if component_sum <= total * 1.001 else "OVERLAP_OR_INCONSISTENT"
        unattributed = max(0.0, total - component_sum) if consistency == "PASS" else None
    return {
        "candidate_id": record.candidate_id, "measured": record.measured,
        "total_e2e_latency_us": total, "transactions_per_second": txs,
        "items_per_second": items, "host_preparation_us": times["host_preparation_us"],
        "transport_in_us": times["transport_in_us"], "fpga_compute_us": compute,
        "transport_out_us": times["transport_out_us"], "composition_us": times["composition_us"],
        "cpu_verification_us": times["cpu_verification_us"], "transport_total_us": transport,
        "host_total_us": host, "transport_percent": pct(transport), "compute_percent": pct(compute),
        "host_percent": pct(host), "component_accounting": consistency,
        "unattributed_us": unattributed, "backend_vector_total_us": times["backend_vector_total_us"],
        "predictions_are_simulated": False,
    }


def pipeline_throughput_model(record: BenchmarkRecord) -> dict:
    t = record.timings_us
    keys = ("host_preparation_us", "transport_in_us", "fpga_compute_us", "transport_out_us", "composition_us", "cpu_verification_us")
    if any(t[k] is None for k in keys):
        return {"status": "INSUFFICIENT_DATA", "stages": {k: t[k] for k in keys}, "predictions": {}}
    prepare = t["host_preparation_us"] + t["transport_in_us"]
    compute = t["fpga_compute_us"]
    finish = t["transport_out_us"] + t["composition_us"] + t["cpu_verification_us"]
    cycles = {"SERIAL": prepare + compute + finish,
        "DOUBLE_BUFFERED": max(prepare, compute) + finish,
        "PIPELINED": max(prepare, compute, finish)}
    return {"status": "PASS", "model": "theoretical-steady-state", "predictions_are_simulated": True,
        "stage_us": {"prepare_and_input": prepare, "fpga_compute": compute, "output_compose_verify": finish},
        "predictions": {name: {"cycle_us": cycle, "transactions_per_second": 1_000_000 / cycle if cycle else None}
            for name, cycle in cycles.items()}}


def shared_bottleneck_model(record: BenchmarkRecord) -> dict:
    t = record.timings_us; total = t["total_e2e_us"]; compute = t["fpga_compute_us"]
    if total is None or compute is None or total < compute:
        return {"status": "INSUFFICIENT_DATA", "shared_noncompute_us": None,
            "shared_capacity_transactions_per_second": None, "assumption": "unknown"}
    shared = total - compute
    cap = 1_000_000 / shared if shared > 0 else None
    return {"status": "PASS", "shared_noncompute_us": shared,
        "shared_capacity_transactions_per_second": cap,
        "parallel_compute_us_per_transaction": compute,
        "assumption": "all non-FPGA-compute latency is conservatively serialized/shared across cards"}


def fleet_scaling_model(record: BenchmarkRecord, counts=(1, 2, 4, 8)) -> dict:
    shared = shared_bottleneck_model(record)
    if shared["status"] != "PASS":
        return {"status": "INSUFFICIENT_DATA", "predictions": {}, "model": "conservative-serial-noncompute-v1"}
    overhead = shared["shared_noncompute_us"]; compute = shared["parallel_compute_us_per_transaction"]
    one_tps = 1_000_000 / (overhead + compute) if overhead + compute > 0 else None
    rows = {}
    for n in counts:
        if n not in (1, 2, 4, 8): raise ValueError("fleet model supports FK counts 1, 2, 4, 8")
        latency = overhead + compute / n
        throughput = 1_000_000 / latency if latency > 0 else None
        efficiency = throughput / (n * one_tps) if throughput is not None and one_tps else None
        rows[str(n)] = {"predicted_latency_us": latency, "predicted_transactions_per_second": throughput,
            "scaling_efficiency": efficiency, "scaling_efficiency_percent": efficiency * 100 if efficiency is not None else None}
    return {"status": "PASS", "model": "conservative-serial-noncompute-v1", "predictions_are_simulated": True,
        "assumption": shared["assumption"], "shared_noncompute_us": overhead,
        "parallel_compute_us": compute, "predictions": rows}


def bottleneck_classifier(record: BenchmarkRecord) -> dict:
    perf = single_fk_performance(record); total = perf["total_e2e_latency_us"]
    values = {"HOST_PREPARATION": record.timings_us["host_preparation_us"],
        "TRANSPORT": (record.timings_us["transport_in_us"] + record.timings_us["transport_out_us"]
            if record.timings_us["transport_in_us"] is not None and record.timings_us["transport_out_us"] is not None else None),
        "FPGA_COMPUTE": record.timings_us["fpga_compute_us"],
        "COMPOSITION": record.timings_us["composition_us"],
        "CPU_VERIFICATION": record.timings_us["cpu_verification_us"]}
    if total is None or total <= 0 or any(v is None for v in values.values()):
        return {"status": "INSUFFICIENT_DATA", "limiting_subsystem": "UNKNOWN",
            "stage_percentages": {name: (100 * v / total if v is not None and total else None) for name, v in values.items()},
            "known_stages": [name for name, value in values.items() if value is not None]}
    summed = sum(values.values())
    if summed > total * 1.001:
        return {"status": "INCONSISTENT_MEASUREMENTS", "limiting_subsystem": "UNKNOWN", "stage_percentages": {}}
    values["UNATTRIBUTED_OVERHEAD"] = max(0.0, total - summed)
    percentages = {name: 100.0 * value / total for name, value in values.items()}
    named = {k:v for k,v in percentages.items() if k != "UNATTRIBUTED_OVERHEAD"}
    limiting = max(named, key=named.get)
    if max(named.values()) < 35.0:
        limiting = "BALANCED"
    return {"status": "PASS", "limiting_subsystem": limiting,
        "stage_percentages": percentages, "classification_is_measured": record.measured}


RECOMMENDATIONS = {
    "BALANCED": "No single measured stage dominates; retain the current design and collect more representative workload measurements.",
    "HOST_PREPARATION": "Profile and optimize host input packing; consider larger batches only after preserving job latency limits.",
    "TRANSPORT": "Measure input and output transfer behavior separately and reduce framing/round-trip overhead without conflating transport with FPGA compute.",
    "TRANSPORT_IN": "Measure input transfer behavior and batch framing overhead before changing transport or clock settings.",
    "TRANSPORT_OUT": "Measure output transfer behavior and response framing overhead before changing transport or clock settings.",
    "FPGA_COMPUTE": "Profile the routed compute pipeline and evaluate RTL throughput changes against timing and correctness gates.",
    "COMPOSITION": "Profile canonical result composition and remove host-side copies or redundant transformations if correctness permits.",
    "CPU_VERIFICATION": "Profile the qualified CPU verifier and consider safe parallel verification without weakening the submission gate.",
    "UNATTRIBUTED_OVERHEAD": "Instrument the missing end-to-end interval before optimizing a named subsystem.",
}


def optimization_recommendation(record: BenchmarkRecord) -> dict:
    result = bottleneck_classifier(record)
    if result["status"] != "PASS":
        return {"status": "INSUFFICIENT_DATA", "limiting_subsystem": "UNKNOWN",
            "recommendation": "Capture complete, non-overlapping stage timing before optimizing."}
    bottleneck = result["limiting_subsystem"]
    return {"status": "PASS", "limiting_subsystem": bottleneck,
        "recommendation": RECOMMENDATIONS[bottleneck], "predictions_are_not_measurements": True}


def fleet_safety_state(controller: FleetController) -> dict:
    stage = controller.stage
    active = controller.schedulable_cards()
    required = STAGE_SIZE[stage]
    stage_ok = len(active) == required and not controller.stage_aborted
    cards_ok = all(c.qualified and c.qualification_sha256 and c.rollback_image_sha256 and
        c.expected_bitstream_sha256 and c.health == "healthy" and not c.quarantined for c in active)
    counters_ok = controller.unverified_share_submission_count == 0 and controller.accidental_duplicate_work_count == 0
    return {"stage": stage.value, "active_count": len(active), "required_active_count": required,
        "stage_healthy": stage_ok, "cards_qualified_healthy_with_rollback": cards_ok,
        "share_and_duplicate_safety_counters_clear": counters_ok,
        "performance_advisory_only": True}


def _decision_for_gain(current_tps, target_tps, current_efficiency, minimum_gain, minimum_efficiency, safety_ok):
    if not safety_ok: return "NO"
    if None in (current_tps, target_tps, current_efficiency, minimum_gain, minimum_efficiency): return "INSUFFICIENT_DATA"
    if target_tps <= current_tps: return "NO"
    gain = target_tps / current_tps - 1.0 if current_tps > 0 else None
    return "YES" if gain is not None and gain >= minimum_gain and current_efficiency >= minimum_efficiency else "NO"


def rollout_health_gate_state(controller: FleetController, gate: RolloutHealthGate | None, *, now=None) -> dict:
    """Read-only equivalent of the fleet's advance-stage health checks."""
    if gate is None:
        return {"status": "INSUFFICIENT_DATA", "reason": "rollout health thresholds were not supplied"}
    gate.validate()
    now = controller.clock() if now is None else now
    active = controller.schedulable_cards()
    elapsed = now - controller.stage_started_at
    attempts = controller.stage_attempts
    timeout_rate = controller.stage_timeouts / attempts if attempts else 0.0
    transport_rate = controller.stage_transport_errors / attempts if attempts else 0.0
    checks = {
        "active_count": len(active) == STAGE_SIZE[controller.stage],
        "per_card_successes": all(controller.stage_successful_by_card[c.logical_id] >= gate.minimum_successful_transactions for c in active),
        "observation_period": elapsed >= gate.minimum_observation_seconds,
        "timeout_rate": timeout_rate <= gate.maximum_timeout_rate,
        "transport_error_rate": transport_rate <= gate.maximum_transport_error_rate,
        "zero_incorrect_results": (not gate.require_zero_incorrect_results or controller.stage_bad_results == 0),
    }
    return {"status": "PASS" if all(checks.values()) else "FAIL", "checks": checks,
        "elapsed_seconds": elapsed, "timeout_rate": timeout_rate, "transport_error_rate": transport_rate}


def rollout_recommendations(record: BenchmarkRecord, controller: FleetController,
        *, minimum_gain: float | None = None, minimum_efficiency: float | None = None,
        health_gate: RolloutHealthGate | None = None) -> dict:
    scaling = fleet_scaling_model(record)
    safety = fleet_safety_state(controller)
    health = rollout_health_gate_state(controller, health_gate)
    explicit_fail = (record.status == "FAIL" or record.qualified is False or
        any(v is False for v in (record.raw_result_exact, record.canonical_result_exact, record.cpu_crosscheck,
                                 record.rollback_available, record.backend_healthy)) or
        (record.stale_result_count is not None and record.stale_result_count > 0))
    active_cards = controller.schedulable_cards()
    identity_mismatch = any(
        (record.bitstream_sha256 is not None and c.expected_bitstream_sha256 != record.bitstream_sha256) or
        (record.runner_sha256 is not None and (c.expected_runner_sha256 or controller.expected_runner_sha256) != record.runner_sha256)
        for c in active_cards)
    explicit_fail = explicit_fail or identity_mismatch
    explicit_perf_safety = (record.measured and record.status == "PASS" and record.qualified is True and
        record.raw_result_exact is True and record.canonical_result_exact is True and record.cpu_crosscheck is True and
        record.rollback_available is True and record.backend_healthy is True and record.stale_result_count == 0 and
        record.source_kind != "SYNTHETIC_FIXTURE")
    fleet_ok = safety["stage_healthy"] and safety["cards_qualified_healthy_with_rollback"] and safety["share_and_duplicate_safety_counters_clear"]
    if minimum_gain is not None and not 0 <= minimum_gain <= 10: raise ValueError("minimum_gain must be in [0,10]")
    if minimum_efficiency is not None and not 0 <= minimum_efficiency <= 1: raise ValueError("minimum_efficiency must be in [0,1]")
    if scaling["status"] != "PASS":
        return {"recommendations": {"SHOULD_EXPAND_1_TO_2": "INSUFFICIENT_DATA", "SHOULD_EXPAND_2_TO_4": "INSUFFICIENT_DATA", "SHOULD_EXPAND_4_TO_8": "INSUFFICIENT_DATA"},
            "scaling": scaling, "safety": safety, "reason": "complete measured timing is required", "performance_advisory_only": True}
    predictions = scaling["predictions"]
    current_stage = controller.stage
    transition = {RolloutStage.CANARY_1: (1, 2, "SHOULD_EXPAND_1_TO_2"),
        RolloutStage.EXPAND_2: (2, 4, "SHOULD_EXPAND_2_TO_4"),
        RolloutStage.EXPAND_4: (4, 8, "SHOULD_EXPAND_4_TO_8")}.get(current_stage)
    values = {"SHOULD_EXPAND_1_TO_2": "INSUFFICIENT_DATA", "SHOULD_EXPAND_2_TO_4": "INSUFFICIENT_DATA", "SHOULD_EXPAND_4_TO_8": "INSUFFICIENT_DATA"}
    reason = "only the next gated rollout transition is evaluated"
    if transition:
        current, target, key = transition
        if safety["active_count"] != current:
            values[key] = "NO"; reason = "current stage active-card count does not meet its rollout target"
        elif explicit_fail or not fleet_ok:
            values[key] = "NO"
            reason = "a correctness, qualification, rollback, health, stale-work, or fleet safety gate failed"
        elif not explicit_perf_safety:
            values[key] = "INSUFFICIENT_DATA"
            reason = "correctness, qualification, rollback, backend health, or share-safety gate is not satisfied"
        elif health["status"] == "FAIL":
            values[key] = "NO"
            reason = "configured fleet rollout health gate has not passed"
        elif health["status"] != "PASS":
            values[key] = "INSUFFICIENT_DATA"
            reason = "provide rollout health thresholds and pass the current stage soak gate"
        else:
            now_row=predictions[str(current)]; next_row=predictions[str(target)]
            values[key]=_decision_for_gain(now_row["predicted_transactions_per_second"],
                next_row["predicted_transactions_per_second"],next_row["scaling_efficiency"],minimum_gain,minimum_efficiency,True)
            if values[key] == "INSUFFICIENT_DATA": reason = "operator must provide minimum gain and efficiency thresholds"
    return {"recommendations": values, "scaling": scaling, "safety": safety, "rollout_health_gate": health,
        "reason": reason, "performance_advisory_only": True,
        "no_stage_or_backend_state_changed": True}


def gpu_fk_comparison(*, gpu_throughput_tps=None, fk_throughput_tps=None, gpu_watts=None, fk_watts=None) -> dict:
    values = (gpu_throughput_tps, fk_throughput_tps, gpu_watts, fk_watts)
    for value in values:
        if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0):
            raise ValueError("comparison measurements must be finite and nonnegative")
    gpu_eff = gpu_throughput_tps / gpu_watts if gpu_throughput_tps is not None and gpu_watts else None
    fk_eff = fk_throughput_tps / fk_watts if fk_throughput_tps is not None and fk_watts else None
    return {"schema": "sidecar-gpu-fk-comparison-v1", "schema_version": 1, "measured": all(x is not None for x in values),
        "gpu": {"throughput_transactions_s": gpu_throughput_tps, "power_w": gpu_watts, "throughput_per_watt": gpu_eff},
        "fk": {"throughput_transactions_s": fk_throughput_tps, "power_w": fk_watts, "throughput_per_watt": fk_eff},
        "comparison": {"relative_fk_to_gpu_throughput_per_watt": fk_eff / gpu_eff if fk_eff is not None and gpu_eff else None}}


def analyze_record(record: BenchmarkRecord) -> dict:
    return {"schema": "sidecar-benchmark-status-v1", "candidate_id": record.candidate_id,
        "measured": record.measured, "status": record.status, "performance": single_fk_performance(record),
        "pipeline": pipeline_throughput_model(record), "scaling": fleet_scaling_model(record),
        "bottleneck": bottleneck_classifier(record), "optimization": optimization_recommendation(record),
        "qualification": {"qualified": record.qualified, "bitstream_sha256": record.bitstream_sha256,
            "runner_sha256": record.runner_sha256}, "correctness": {"raw_result_exact": record.raw_result_exact,
            "canonical_result_exact": record.canonical_result_exact, "cpu_crosscheck": record.cpu_crosscheck},
        "rollback_available": record.rollback_available, "backend_healthy": record.backend_healthy,
        "stale_result_count": record.stale_result_count, "hardware_measurements_fabricated": False}
