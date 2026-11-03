#include "mpsse_backend.hpp"

#include <array>
#include <cassert>
#include <deque>
#include <iostream>
#include <stdexcept>

using namespace sidecar::jtag;

class MockIo final : public Io {
 public:
  void write_exact(const uint8_t* p, size_t n) override {
    if (closed || disconnected) throw std::runtime_error("closed/disconnected");
    size_t i = 0;
    while (i < n) {
      const uint8_t op = p[i++];
      if (op == 0xaa) {
        rx.push_back(bad_sync ? 0xfa : 0xfa);
        rx.push_back(bad_sync ? 0x55 : 0xaa); ++syncs;
      } else if (op == 0x97 || op == 0x8a || op == 0x85) {
        // fixed MPSSE setup commands have no response
      } else if (op == 0x86) {
        i += 2;
      } else if (op == 0x80) {
        i += 2;
      } else if (op == 0x6b) {
        if (i + 2 > n) throw std::runtime_error("short TMS command");
        const unsigned count = p[i++] + 1;
        const uint8_t val = p[i++];
        uint8_t out = 0;
        for (unsigned b = 0; b < count; ++b)
          out |= uint8_t(tick((val >> b) & 1, (val >> 7) & 1) << b);
        rx.push_back(out);
      } else if (op == 0x39) {
        if (i + 2 > n) throw std::runtime_error("short byte shift");
        const size_t count = size_t(p[i]) + (size_t(p[i + 1]) << 8) + 1;
        i += 2;
        if (i + count > n) throw std::runtime_error("short byte data");
        for (size_t k = 0; k < count; ++k) {
          uint8_t out = 0;
          for (unsigned b = 0; b < 8; ++b)
            out |= uint8_t(tick(0, (p[i + k] >> b) & 1) << b);
          rx.push_back(out);
        }
        i += count;
      } else if (op == 0x3b) {
        if (i + 2 > n) throw std::runtime_error("short bit shift");
        const unsigned count = p[i++] + 1;
        const uint8_t data = p[i++];
        uint8_t out = 0;
        for (unsigned b = 0; b < count; ++b)
          out |= uint8_t(tick(0, (data >> b) & 1) << b);
        rx.push_back(out);
      } else {
        throw std::runtime_error("unexpected MPSSE opcode");
      }
    }
  }

  void read_exact(uint8_t* p, size_t n) override {
    if (disconnected) throw std::runtime_error("disconnected");
    if (short_read) throw std::runtime_error("short read");
    if (rx.size() < n) throw std::runtime_error("mock short read");
    for (size_t i = 0; i < n; ++i) { p[i] = rx.front(); rx.pop_front(); }
  }
  void close() noexcept override { closed = true; }

  bool closed = false;
  bool bad_sync = false;
  bool short_read = false;
  bool disconnected = false;
  int forced_tdo = -1;
  uint64_t idcode_chain = 0x04b69093u;
  unsigned syncs = 0;
  std::vector<uint8_t> clock_tms;
  std::vector<uint8_t> clock_tdi;
  std::vector<uint8_t> all_writes;

 private:
  enum State { RESET, IDLE, SEL_DR, CAP_DR, SHIFT_DR, EXIT1_DR,
               UPDATE_DR, SEL_IR, CAP_IR, SHIFT_IR, EXIT1_IR, UPDATE_IR } state = RESET;
  static constexpr uint8_t next[12][2] = {
      {RESET, IDLE}, {IDLE, SEL_DR}, {CAP_DR, SEL_IR}, {SHIFT_DR, EXIT1_DR},
      {SHIFT_DR, EXIT1_DR}, {UPDATE_DR, UPDATE_DR}, {IDLE, SEL_DR},
      {CAP_IR, RESET}, {SHIFT_IR, EXIT1_IR}, {SHIFT_IR, EXIT1_IR},
      {UPDATE_IR, UPDATE_IR}, {IDLE, SEL_DR}};
  uint64_t dr = 0;
  uint8_t ir = 0x09;
  uint8_t ir_shift = 1;
  std::deque<uint8_t> rx;

  unsigned tick(unsigned tms, unsigned tdi) {
    clock_tms.push_back(uint8_t(tms));
    clock_tdi.push_back(uint8_t(tdi));
    unsigned tdo = 0;
    const State old = state;
    if (old == SHIFT_IR) tdo = ir_shift & 1;
    if (old == SHIFT_DR) tdo = unsigned(dr & 1);
    if (old == CAP_IR) ir_shift = 1;
    else if (old == SHIFT_IR) ir_shift = uint8_t((ir_shift >> 1) | (tdi << 5));
    if (old == CAP_DR) dr = (ir == 0x09) ? idcode_chain : 1u;
    else if (old == SHIFT_DR) dr = (dr >> 1) | (uint64_t(tdi) << 63);
    if (old == UPDATE_IR) ir = ir_shift & 0x3f;
    state = State(next[old][tms]);
    if (forced_tdo >= 0) return unsigned(forced_tdo);
    return tdo;
  }
};

int main() {
  unsigned passed = 0, total = 0;
  auto check = [&](bool ok, const char* name) {
    ++total;
    if (!ok) { std::cerr << "FAIL " << name << '\n'; return; }
    ++passed;
    std::cout << "PASS " << name << '\n';
  };

  MockIo io;
  MpsseTap tap(io);
  try {
    tap.synchronize_and_configure(1'000'000);
    check(io.syncs == 1, "sync_barrier");
    check(tap.read_single_vu33p_idcode() == 0x04b69093, "idcode_lsb_first");
  } catch (...) { check(false, "identity_scan"); }

  std::vector<uint8_t> expected_tms{1, 1, 1, 1, 1, 0};
  expected_tms.insert(expected_tms.end(), {1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0});
  expected_tms.insert(expected_tms.end(), {1, 0, 0});
  expected_tms.insert(expected_tms.end(), 63, 0);
  expected_tms.insert(expected_tms.end(), {1, 1, 0});
  check(io.clock_tms == expected_tms && io.clock_tms.size() == 87,
        "idcode_tap_vector_exact");
  std::vector<uint8_t> expected_tdi(87, 0);
  expected_tdi[10] = 1; expected_tdi[13] = 1;
  check(io.clock_tdi.size() == 87 &&
        std::equal(expected_tdi.begin(), expected_tdi.end(), io.clock_tdi.begin()),
        "idcode_tdi_lsb_order");

  check(allowed_ir(0x09) && allowed_ir(0x02) && allowed_ir(0x03) &&
        allowed_ir(0x22) && allowed_ir(0x3f) && !allowed_ir(0x00),
        "ir_allowlist");
  bool invalid_ir_rejected = false;
  try { tap.shift_ir(0x01); } catch (const std::invalid_argument&) { invalid_ir_rejected = true; }
  check(invalid_ir_rejected, "reject_unapproved_ir");

  bool invalid_clock_rejected = false;
  MockIo io2;
  MpsseTap tap2(io2);
  try { tap2.synchronize_and_configure(10'000'000); }
  catch (const std::invalid_argument&) { invalid_clock_rejected = true; }
  check(invalid_clock_rejected, "bounded_clock");

  bool bad_sync_rejected = false;
  MockIo io3; io3.bad_sync = true;
  MpsseTap tap3(io3);
  try { tap3.synchronize_and_configure(1'000'000); }
  catch (const std::runtime_error&) { bad_sync_rejected = true; }
  check(bad_sync_rejected, "reject_bad_mpsse_sync");

  MockIo io4; io4.idcode_chain = 0x0362d09304b69093ULL;
  MpsseTap tap4(io4);
  bool extra_rejected = false;
  try {
    tap4.synchronize_and_configure(1'000'000);
    (void)tap4.read_single_vu33p_idcode();
  } catch (const std::runtime_error&) { extra_rejected = true; }
  check(extra_rejected, "reject_extra_idcode_tap");

  MockIo io5; io5.forced_tdo = 0;
  MpsseTap tap5(io5);
  bool stuck_low_detected = false;
  try {
    tap5.synchronize_and_configure(1'000'000);
    stuck_low_detected = tap5.read_single_vu33p_idcode() != 0x04b69093;
  } catch (...) { stuck_low_detected = true; }
  check(stuck_low_detected, "reject_tdo_stuck_low");

  MockIo io6; io6.forced_tdo = 1;
  MpsseTap tap6(io6);
  bool stuck_high_detected = false;
  try {
    tap6.synchronize_and_configure(1'000'000);
    stuck_high_detected = tap6.read_single_vu33p_idcode() != 0x04b69093;
  } catch (...) { stuck_high_detected = true; }
  check(stuck_high_detected, "reject_tdo_stuck_high");

  MockIo io7; io7.short_read = true;
  MpsseTap tap7(io7);
  bool short_read_detected = false;
  try {
    tap7.synchronize_and_configure(1'000'000);
    tap7.reset_tap();
  } catch (const std::runtime_error&) { short_read_detected = true; }
  check(short_read_detected, "reject_short_read");

  MockIo io8; io8.disconnected = true;
  MpsseTap tap8(io8);
  bool disconnect_detected = false;
  try { tap8.synchronize_and_configure(1'000'000); }
  catch (const std::runtime_error&) { disconnect_detected = true; }
  check(disconnect_detected, "reject_usb_disconnect");

  bool wrong_ir_length_rejected = false;
  try { tap.shift_ir(0x09, 5); }
  catch (const std::invalid_argument&) { wrong_ir_length_rejected = true; }
  check(wrong_ir_length_rejected, "reject_wrong_ir_length");

  MockIo io9;
  MpsseTap tap9(io9);
  tap9.synchronize_and_configure(1'000'000);
  tap9.reset_tap();
  tap9.shift_ir(0x03);
  const std::vector<uint8_t> request_fixture{0xa5, 0x3c};
  (void)tap9.shift_dr(request_fixture, 16);
  std::vector<uint8_t> expected_user_bits;
  for (uint8_t byte : request_fixture)
    for (unsigned bit = 0; bit < 8; ++bit)
      expected_user_bits.push_back((byte >> bit) & 1);
  const size_t request_offset = 6 + 12 + 3;
  check(io9.clock_tdi.size() == request_offset + 16 + 2 &&
        std::equal(expected_user_bits.begin(), expected_user_bits.end(),
                   io9.clock_tdi.begin() + request_offset),
        "user2_request_bytes_shift_lsb_first");

  MockIo io10;
  MpsseTap tap10(io10);
  tap10.synchronize_and_configure(1'000'000);
  tap10.reset_tap();
  tap10.shift_ir(0x03);
  const std::vector<uint8_t> vector_input(196'864, 0xa5);
  const auto vector_scan = tap10.shift_dr(vector_input, 1'574'912);
  check(vector_scan.bits == 1'574'912 && vector_scan.tdo.size() == 196'864,
        "vector001_input_scan_exact_bits");
  const std::vector<uint8_t> vector_output(768, 0);
  tap10.shift_ir(0x02);
  const auto result_scan = tap10.shift_dr(vector_output, 6'144);
  check(result_scan.bits == 6'144 && result_scan.tdo.size() == 768,
        "vector001_output_scan_exact_bits");

  check(passed == total, "suite_summary");
  std::cout << "RESULT=" << passed << '/' << total << '\n';
  return passed == total ? 0 : 1;
}
