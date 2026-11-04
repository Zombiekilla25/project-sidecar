#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
out="${1:-$root/build/libsidecar_raw_bscan.so}"
mkdir -p "$(dirname "$out")"
if ! pkg-config --exists libftdi1; then
  echo "libftdi1 development headers/pkg-config metadata are required; refusing an incomplete native build" >&2
  exit 2
fi
cxxflags=$(pkg-config --cflags libftdi1)
libs=$(pkg-config --libs libftdi1)
# Keep the conventional /usr/include root as well as pkg-config's narrower
# libftdi include directory; project sources include <libftdi1/ftdi.h>.
include_root="${PKG_CONFIG_SYSROOT_DIR:-}/usr/include"
# shellcheck disable=SC2086
g++ -std=c++17 -O2 -fPIC -shared -I"$root/tools/phk1_raw_bscan" -I"$include_root" $cxxflags \
  "$root/tools/phk1_raw_bscan/sidecar_transport_abi.cpp" \
  "$root/tools/phk1_raw_bscan/mpsse_backend.cpp" \
  "$root/tools/phk1_raw_bscan/libftdi_io.cpp" \
  "$root/tools/phk1_raw_bscan/usb_selection.cpp" \
  -o "$out" $libs
