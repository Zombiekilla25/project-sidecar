#!/usr/bin/env bash
set -Eeuo pipefail
# Exact-commit, temporary archive compile/smoke. Read-only on source repository.
if [[ $# -ne 2 ]]; then echo "usage: $0 CORE_REPOSITORY COMMIT" >&2; exit 2; fi
CORE_REPO="$(realpath "$1")"
COMMIT="$2"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
[[ "$COMMIT" =~ ^[0-9a-f]{40,64}$ ]] || { echo INVALID_COMMIT; exit 2; }
git -C "$CORE_REPO" cat-file -e "$COMMIT^{commit}"
TMP="$(mktemp -d /tmp/phk2-core-import.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
git -C "$CORE_REPO" archive "$COMMIT" | tar -x -C "$TMP"
cd "$TMP"
SHA="$(git -C "$CORE_REPO" show "$COMMIT:rtl/phk2_core_synth_top.sv" | sha256sum | awk '{print $1}')"
echo "CORE_COMMIT=$COMMIT"
echo "CORE_TOP_SHA256=$SHA"
iverilog -g2012 -s tb_current_committed_core_smoke -o "$TMP/core-smoke.vvp" \
  rtl/*.sv rtl/vendor_phk1/*.sv \
  "$SCRIPT_DIR/../tests/phk2_board/tb_current_committed_core_smoke.sv"
vvp "$TMP/core-smoke.vvp"
echo "CORE_IMPORT_COMPILE=PASS"
echo "CORE_IMPORT_HARDWARE_ACCESS=0"
