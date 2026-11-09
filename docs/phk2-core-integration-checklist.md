# PHK2 timing-core integration checklist

When the timing team supplies its routed core commit:

1. Freeze the exact commit and all required RTL hashes in `source_manifest.json`; include the wrapper that implements `PHK2-BOARD-CORE-CONTRACT-v1`.
2. Bind timing evidence to that same commit, exact part `xcvu33p-fsvh2104-2-e`, and nonnegative WNS. Keep the routed timing report and its SHA in the handoff.
3. Include a candidate-specific `tb_timing_core_binding.sv` that instantiates the real core/wrapper and prints `TIMING_CORE_BINDING_TESTS=PASS` only after descriptor, count-one, result backpressure, stale identity, abort, reset, and status checks pass.
4. Run `tools/qualify_phk2_core_binding.py CORE_DIR --expected-commit COMMIT`. It validates every source hash, rejects the stub, compiles all candidate RTL, runs the canonical adapter bench and candidate binding bench.
5. Run `tools/integrate_phk2_timing_core.sh CORE_DIR COMMIT`. It adds the frozen host protocol regression and board-shell/CDC RTL simulation. This script is offline only and has no Vivado or hardware command.
6. Review source manifest and interface diff. Only then change the physical synthesis source list to use the timing-qualified wrapper/core. Keep `phk2_core_stub.sv` in test-only sources.
7. Separately authorize and perform implementation/bitstream work only after the timing team’s real routed result is available. The integration scripts above never run Vivado or emit a bitstream.

The latest committed local core at the time this checklist was written is a single-item data-path measurement wrapper and does not yet meet the transaction-level contract. The integration gate must remain FAIL until a compatible wrapper and timing-bound evidence arrive.
