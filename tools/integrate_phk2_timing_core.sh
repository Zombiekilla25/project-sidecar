#!/usr/bin/env bash
set -Eeuo pipefail
# Future handoff only: source verification, simulation, and protocol regression.
# Deliberately contains no Vivado, bitstream, hardware, USB, or SSH operation.
if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "usage: $0 CANDIDATE_CORE_DIR EXPECTED_COMMIT [REPORT.json]" >&2
  exit 2
fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CORE_DIR="$(realpath "$1")"
COMMIT="$2"
REPORT="${3:-$ROOT/build-reports/phk2-core-integration-$COMMIT.json}"
[[ "$COMMIT" =~ ^[0-9a-f]{40,64}$ ]] || { echo "invalid commit" >&2; exit 2; }
python3 "$ROOT/tools/qualify_phk2_core_binding.py" "$CORE_DIR" \
  --expected-commit "$COMMIT" --output "$REPORT"
python3 "$ROOT/tools/phk2_host/board_qualify.py" >/dev/null
iverilog -g2012 -DPHK2_SIM -s tb_phk2_board -o /tmp/phk2-board-integration.vvp \
  "$ROOT/tests/phk2_board/bscan_stub.sv" \
  "$ROOT/rtl/phk2_board/phk2_async_fifo.sv" \
  "$ROOT/rtl/phk2_board/phk2_protocol_decoder.sv" \
  "$ROOT/rtl/phk2_board/phk2_core_stub.sv" \
  "$ROOT/rtl/phk2_board/phk2_fk33_board_top.sv" \
  "$ROOT/tests/phk2_board/tb_phk2_board.sv"
vvp /tmp/phk2-board-integration.vvp
echo "TIMING_CORE_INTEGRATION=PASS report=$REPORT"
