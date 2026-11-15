#!/usr/bin/env python3
"""Offline MAC-rate/PCIe break-even calculator for PearlHash sidecar studies.

No CUDA, PCIe, miner, pool, or FPGA API is imported or executed.
"""
from __future__ import annotations

import argparse
import json
import math
from typing import Any


DEFAULT_WORK_MACS = 131_072 * 131_072 * 4_096
REGIONS = 1_024
OFFLINE_GPU_TMACS = 75.454830
LIVE_LOGGED_GPU_TMACS = 81.24666666666667
PCIE_GEN3_X4_THEORETICAL_GBPS = 8.0e9 * 4 * (128 / 130) / 8


def _positive_finite(name: str, value: float) -> None:
    if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be a positive finite number")


def analyze(
    *,
    work_macs: int = DEFAULT_WORK_MACS,
    gpu_tmacs: float = OFFLINE_GPU_TMACS,
    margin_percent: float = 0.0,
    fpga_clock_mhz: float = 250.0,
    pcie_bytes: int = 0,
    pcie_effective_gbps: float = 3.15,
    dma_chunks: int = 1,
    dma_startup_us: float = 10.0,
    launch_us: float = 40.0,
    sync_count: int = 2,
    sync_us: float = 25.0,
    measured_cycles: int | None = None,
    fpga_count: int = 1,
    cpu_stage_ms: dict[str, float] | None = None,
) -> dict[str, Any]:
    if type(work_macs) is not int or work_macs <= 0:
        raise ValueError("work_macs must be a positive integer")
    if type(pcie_bytes) is not int or pcie_bytes < 0:
        raise ValueError("pcie_bytes must be a nonnegative integer")
    if type(dma_chunks) is not int or dma_chunks < 1:
        raise ValueError("dma_chunks must be a positive integer")
    if type(sync_count) is not int or sync_count < 0:
        raise ValueError("sync_count must be a nonnegative integer")
    if type(fpga_count) is not int or fpga_count < 1:
        raise ValueError("fpga_count must be a positive integer")
    if measured_cycles is not None and (type(measured_cycles) is not int or measured_cycles <= 0):
        raise ValueError("measured_cycles must be a positive integer when supplied")
    for name, value in (
        ("gpu_tmacs", gpu_tmacs), ("fpga_clock_mhz", fpga_clock_mhz),
        ("pcie_effective_gbps", pcie_effective_gbps),
        ("dma_startup_us", dma_startup_us), ("launch_us", launch_us),
        ("sync_us", sync_us),
    ):
        _positive_finite(name, value)
    if type(margin_percent) not in (int, float) or not math.isfinite(margin_percent) or margin_percent < 0:
        raise ValueError("margin_percent must be a nonnegative finite number")
    cpu_stage_ms = {} if cpu_stage_ms is None else cpu_stage_ms
    cpu_names = {"operand_generation", "noisy_gemm", "transcript_fold", "final_hash"}
    if type(cpu_stage_ms) is not dict or not set(cpu_stage_ms).issubset(cpu_names):
        raise ValueError("cpu_stage_ms must map recognized CPU stage names to milliseconds")
    for name, value in cpu_stage_ms.items():
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            raise ValueError(f"CPU time for {name} must be a nonnegative finite number")

    gpu_rate = gpu_tmacs * 1e12
    target_rate = gpu_rate * (1.0 + margin_percent / 100.0)
    gpu_seconds = work_macs / gpu_rate
    target_seconds = work_macs / target_rate
    link_seconds = pcie_bytes / (pcie_effective_gbps * 1e9)
    control_seconds = (dma_chunks * dma_startup_us + launch_us + sync_count * sync_us) * 1e-6
    transfer_and_control = link_seconds + control_seconds
    compute_budget = target_seconds - transfer_and_control
    required_compute_rate = work_macs / compute_budget if compute_budget > 0 else None
    clock_hz = fpga_clock_mhz * 1e6
    required_cycles_total = max(0.0, compute_budget) * clock_hz
    required_cycles_per_accelerator = required_cycles_total / fpga_count
    required_macs_per_cycle_per_accelerator = (
        target_rate / clock_hz / fpga_count if compute_budget > 0 else None
    )

    measured: dict[str, Any] | None = None
    if measured_cycles is not None:
        compute_seconds = measured_cycles / clock_hz / fpga_count
        e2e_seconds = compute_seconds + transfer_and_control
        e2e_rate = work_macs / e2e_seconds
        measured = {
            "cycles_per_accelerator_for_full_work_unit": measured_cycles,
            "fpga_compute_seconds": compute_seconds,
            "transfer_and_control_seconds": transfer_and_control,
            "end_to_end_seconds": e2e_seconds,
            "end_to_end_tmacs": e2e_rate / 1e12,
            "beats_gpu_baseline": e2e_rate > gpu_rate,
        }

    return {
        "schema": "pearlhash-fk33-breakeven-model-v1",
        "work_unit": {
            "definition": "complete MxN output search with K MACs per output",
            "macs": work_macs,
            "regions": REGIONS if work_macs == DEFAULT_WORK_MACS else None,
            "macs_per_4096x4096_region": 4_096 * 4_096 * 4_096,
        },
        "measured_gpu_reference": {
            "requested_tmacs": gpu_tmacs,
            "equivalent_baseline_seconds_per_work_unit": gpu_seconds,
            "scope_warning": "Rate is the selected benchmark metric; equivalent time is arithmetic, not a new measurement.",
        },
        "targets": {
            "margin_percent": margin_percent,
            "required_end_to_end_tmacs": target_rate / 1e12,
            "deadline_seconds_per_work_unit": target_seconds,
            "fpga_clock_mhz": fpga_clock_mhz,
            "fpga_count_ideal_partition": fpga_count,
            "cycles_per_accelerator_available_after_transfer": required_cycles_per_accelerator,
            "required_macs_per_cycle_per_accelerator": required_macs_per_cycle_per_accelerator,
        },
        "estimated_transport": {
            "pcie_gen3_x4_theoretical_gbps": PCIE_GEN3_X4_THEORETICAL_GBPS / 1e9,
            "effective_gbps_assumption": pcie_effective_gbps,
            "bytes_per_work_unit": pcie_bytes,
            "payload_seconds": link_seconds,
            "dma_chunks_assumed": dma_chunks,
            "dma_startup_us_assumption": dma_startup_us,
            "launch_us_assumption": launch_us,
            "sync_count_assumption": sync_count,
            "sync_us_each_assumption": sync_us,
            "control_seconds": control_seconds,
            "transfer_and_control_seconds": transfer_and_control,
            "compute_budget_seconds": compute_budget,
            "required_fpga_compute_tmacs": required_compute_rate / 1e12 if required_compute_rate else None,
            "target_feasible_with_transport": compute_budget > 0,
        },
        "optional_measured_fpga_result": measured,
        "optional_measured_cpu_stage_ms": {
            "values": cpu_stage_ms,
            "sum_ms": sum(cpu_stage_ms.values()) if cpu_stage_ms else None,
            "completeness": "COMPLETE" if set(cpu_stage_ms) == cpu_names else "PARTIAL_OR_UNAVAILABLE",
        },
        "pipeline_note": "For independent double-buffered batches, steady-state time is max(prep, transfer+compute+return); single-work-unit latency is additive. This model reports additive latency and does not assume overlap.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-macs", type=int, default=DEFAULT_WORK_MACS)
    parser.add_argument("--gpu-tmacs", type=float, default=OFFLINE_GPU_TMACS)
    parser.add_argument("--margin-percent", type=float, default=0.0)
    parser.add_argument("--fpga-clock-mhz", type=float, default=250.0)
    parser.add_argument("--fpga-count", type=int, default=1)
    parser.add_argument("--pcie-bytes", type=int, default=0)
    parser.add_argument("--pcie-effective-gbps", type=float, default=3.15)
    parser.add_argument("--dma-chunks", type=int, default=1)
    parser.add_argument("--dma-startup-us", type=float, default=10.0)
    parser.add_argument("--launch-us", type=float, default=40.0)
    parser.add_argument("--sync-count", type=int, default=2)
    parser.add_argument("--sync-us", type=float, default=25.0)
    parser.add_argument("--measured-cycles", type=int)
    parser.add_argument("--cpu-stage-ms-json", help="JSON object with optional measured CPU stage times")
    parser.add_argument("--output", help="optional JSON output path")
    args = parser.parse_args(argv)
    values = {k: v for k, v in vars(args).items() if k not in {"output", "cpu_stage_ms_json"}}
    if args.cpu_stage_ms_json:
        with open(args.cpu_stage_ms_json, encoding="utf-8") as stream:
            values["cpu_stage_ms"] = json.load(stream)
    result = analyze(**values)
    rendered = json.dumps(result, sort_keys=True, indent=2) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as stream:
            stream.write(rendered)
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
