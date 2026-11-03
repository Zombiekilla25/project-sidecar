#include "mpsse_backend.hpp"

#include <algorithm>
#include <array>
#include <limits>

namespace sidecar::jtag {
namespace {
constexpr uint32_t kMpsseBaseHz = 30'000'000;  // 60 MHz / 2 after disable-divide-by-5
constexpr uint8_t kTckTdiTmsOutputs = 0x0b;
constexpr uint8_t kIdlePins = 0x08;  // TCK=0, TDI=0, TMS=1; low-byte mask 0x0b

void append_bit(std::vector<uint8_t>& out, size_t bit, uint8_t value) {
  if (value) out[bit / 8] |= uint8_t(1u << (bit % 8));
}
}  // namespace

bool allowed_ir(uint8_t instruction) {
  return instruction == 0x09 || instruction == 0x02 ||
         instruction == 0x03 || instruction == 0x22 || instruction == 0x3f;
}

void MpsseTap::synchronize_and_configure(uint32_t jtag_clock_hz,
                                          ProgressCallback progress) {
  if (ready_) throw std::logic_error("MPSSE already configured");
  if (jtag_clock_hz < 100'000 || jtag_clock_hz > 1'000'000)
    throw std::invalid_argument("clock outside fixed conservative range 100 kHz..1 MHz");
  const uint32_t divisor = kMpsseBaseHz / jtag_clock_hz - 1;
  if (divisor > std::numeric_limits<uint16_t>::max())
    throw std::invalid_argument("clock divisor out of range");

  // Sync is an explicit request/response barrier, not a timing delay.
  if (progress) progress("P09_MPSSE_SYNC");
  const uint8_t bad_command = 0xaa;
  io_.write_exact(&bad_command, 1);
  uint8_t sync[2]{};
  io_.read_exact(sync, sizeof(sync));
  if (sync[0] != 0xfa || sync[1] != 0xaa)
    throw std::runtime_error("MPSSE bad-command synchronization failed");

  if (progress) progress("P10_SET_JTAG_CLOCK");
  const std::array<uint8_t, 9> setup{
      0x97,  // disable adaptive clocking
      0x8a,  // disable divide-by-five
      0x86, uint8_t(divisor & 0xff), uint8_t(divisor >> 8),
      0x85,  // disable loopback
      0x80, kIdlePins, kTckTdiTmsOutputs};
  io_.write_exact(setup.data(), setup.size());
  ready_ = true;
}

void MpsseTap::require_ready() const {
  if (!ready_) throw std::logic_error("MPSSE readiness barrier not passed");
}

void MpsseTap::tms(const std::vector<uint8_t>& bits, uint8_t tdi_level) {
  require_ready();
  if (tdi_level > 1) throw std::invalid_argument("TDI level must be one bit");
  for (size_t base = 0; base < bits.size();) {
    const size_t count = std::min<size_t>(7, bits.size() - base);
    uint8_t packed = 0;
    for (size_t i = 0; i < count; ++i) {
      if (bits[base + i] > 1) throw std::invalid_argument("TMS must be one bit");
      packed |= uint8_t(bits[base + i] << i);
    }
    const uint8_t cmd[3] = {0x6b, uint8_t(count - 1),
                            uint8_t(packed | (tdi_level << 7))};
    io_.write_exact(cmd, sizeof(cmd));
    uint8_t ignored_tdo = 0;
    io_.read_exact(&ignored_tdo, 1);
    base += count;
  }
}

void MpsseTap::reset_tap() {
  require_ready();
  tms({1, 1, 1, 1, 1, 0});
}

std::vector<uint8_t> MpsseTap::shift_data(const uint8_t* tdi, size_t bit_count,
                                          bool last_bit_exits_shift) {
  require_ready();
  if (!bit_count || (tdi == nullptr && bit_count))
    throw std::invalid_argument("empty/null scan");
  const size_t clocks_before_exit = bit_count - (last_bit_exits_shift ? 1 : 0);
  std::vector<uint8_t> tdo((bit_count + 7) / 8, 0);
  size_t offset = 0;

  while (clocks_before_exit - offset >= 8) {
    size_t nbytes = std::min<size_t>((clocks_before_exit - offset) / 8, 65536);
    const uint16_t encoded = uint16_t(nbytes - 1);
    std::vector<uint8_t> cmd;
    cmd.reserve(3 + nbytes);
    cmd.push_back(0x39);  // LSB-first, clock data in and out
    cmd.push_back(uint8_t(encoded & 0xff));
    cmd.push_back(uint8_t(encoded >> 8));
    cmd.insert(cmd.end(), tdi + offset / 8, tdi + offset / 8 + nbytes);
    io_.write_exact(cmd.data(), cmd.size());
    std::vector<uint8_t> rx(nbytes);
    io_.read_exact(rx.data(), rx.size());
    std::copy(rx.begin(), rx.end(), tdo.begin() + offset / 8);
    offset += nbytes * 8;
  }

  const size_t partial = clocks_before_exit - offset;
  if (partial) {
    const uint8_t last = tdi[offset / 8];
    const uint8_t cmd[3] = {0x3b, uint8_t(partial - 1), last};
    io_.write_exact(cmd, sizeof(cmd));
    uint8_t rx = 0;
    io_.read_exact(&rx, 1);
    for (size_t i = 0; i < partial; ++i) append_bit(tdo, offset + i, (rx >> i) & 1);
    offset += partial;
  }

  if (last_bit_exits_shift) {
    const uint8_t bit = (tdi[(bit_count - 1) / 8] >> ((bit_count - 1) % 8)) & 1;
    const uint8_t cmd[3] = {0x6b, 0x00, uint8_t(0x01 | (bit << 7))};
    io_.write_exact(cmd, sizeof(cmd));
    uint8_t rx = 0;
    io_.read_exact(&rx, 1);
    append_bit(tdo, bit_count - 1, rx & 1);
  }
  return tdo;
}

ScanResult MpsseTap::shift_ir(uint8_t instruction, size_t bits) {
  require_ready();
  if (bits != 6 || !allowed_ir(instruction))
    throw std::invalid_argument("IR outside fixed 6-bit identity/PHK1 allowlist");
  tms({1, 1, 0, 0});  // Idle -> Shift-IR
  const uint8_t packed[1] = {instruction};
  auto result = shift_data(packed, bits, true);
  tms({1, 0});  // Update-IR -> Idle
  return {std::move(result), bits};
}

ScanResult MpsseTap::shift_dr(const std::vector<uint8_t>& tdi, size_t bit_count) {
  if (!bit_count || tdi.size() < (bit_count + 7) / 8)
    throw std::invalid_argument("DR input is shorter than scan length");
  tms({1, 0, 0});  // Idle -> Shift-DR
  auto result = shift_data(tdi.data(), bit_count, true);
  tms({1, 0});  // Update-DR -> Idle
  return {std::move(result), bit_count};
}

uint32_t MpsseTap::read_single_vu33p_idcode() {
  reset_tap();
  shift_ir(0x09, 6);  // Xilinx IDCODE instruction
  // Read two 32-bit words. The exact one-device model requires the first
  // word to be the VU33P IDCODE and the next word to be zero fill from the
  // same 32-bit register; a second IDCODE-capable TAP is rejected.
  const auto dr = shift_dr(std::vector<uint8_t>(8, 0), 64);
  if (dr.tdo.size() != 8) throw std::runtime_error("IDCODE response length mismatch");
  if (dr.tdo[4] || dr.tdo[5] || dr.tdo[6] || dr.tdo[7])
    throw std::runtime_error("unexpected extra IDCODE-capable TAP in chain");
  return uint32_t(dr.tdo[0]) | (uint32_t(dr.tdo[1]) << 8) |
         (uint32_t(dr.tdo[2]) << 16) | (uint32_t(dr.tdo[3]) << 24);
}

}  // namespace sidecar::jtag
