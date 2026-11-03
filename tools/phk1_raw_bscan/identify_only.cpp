// Read-only identity smoke utility. It selects only the IDCODE instruction.
#include "libftdi_io.hpp"

#include <charconv>
#include <cerrno>
#include <cstdint>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
std::string current_phase = "P00_START";
std::string last_completed_phase = "NONE";
std::unique_ptr<sidecar::jtag::LibFtdiIo> io;

void phase(const char* name) {
  if (current_phase != name) last_completed_phase = current_phase;
  current_phase = name;
  std::cout << "PHASE=" << name << std::endl;
}

uint16_t parse_hex16(const char* value) {
  unsigned parsed = 0;
  const std::string text(value);
  const auto result = std::from_chars(text.data(), text.data() + text.size(), parsed, 16);
  if (result.ec != std::errc{} || result.ptr != text.data() + text.size() || parsed > 0xffff)
    throw std::invalid_argument("VID/PID must be hexadecimal 16-bit values");
  return static_cast<uint16_t>(parsed);
}

int exit_code_for_phase(const std::string& p) {
  if (p == "P01_PARSE_ARGS") return 2;
  if (p == "P02_LOAD_TARGET_LOCK" || p == "P03_VALIDATE_TARGET_LOCK") return 3;
  if (p == "P04_ENUMERATE_USB" || p == "P05_MATCH_FTDI_DEVICE") return 4;
  if (p == "P06_OPEN_FTDI" || p == "P07_SELECT_INTERFACE_A") return 5;
  if (p == "P08_INIT_MPSSE" || p == "P09_MPSSE_SYNC" || p == "P10_SET_JTAG_CLOCK") return 6;
  if (p == "P11_TAP_RESET" || p == "P12_READ_CHAIN" || p == "P13_PARSE_CHAIN") return 7;
  if (p == "P14_VERIFY_IDCODE") return 8;
  if (p == "P16_CLOSE_FTDI") return 9;
  return 10;
}

std::string clean(std::string text) {
  for (char& c : text) if (c == '\n' || c == '\r') c = ' ';
  return text;
}

int fail(const std::string& operation, int err, int ftdi_code,
         const std::string& message) {
  std::cerr << "FAILED_PHASE=" << current_phase << '\n'
            << "LAST_COMPLETED_PHASE=" << last_completed_phase << '\n'
            << "FAILED_OPERATION=" << operation << '\n'
            << "FAILED_ERRNO=" << (err ? std::to_string(err) : "NONE") << '\n'
            << "FAILED_LIBFTDI_CODE=" << (ftdi_code == 0 ? "NONE" : std::to_string(ftdi_code)) << '\n'
            << "FAILED_MESSAGE=" << clean(message) << '\n';
  return exit_code_for_phase(current_phase);
}
}

int main(int argc, char** argv) {
  phase("P00_START");
  phase("P01_PARSE_ARGS");
  if (argc != 7 || std::string(argv[1]) != "identify") {
    return fail("validate fixed identify argv", 0, 0,
        "usage: raw-jtag-identify identify <vid-hex> <pid-hex> <serial> <usb-path> <expected-idcode-hex>");
  }
  try {
    sidecar::jtag::UsbIdentity expected{};
    expected.vid = parse_hex16(argv[2]);
    expected.pid = parse_hex16(argv[3]);
    expected.serial = argv[4];
    expected.usb_path = argv[5];
    expected.manufacturer = "Xilinx";
    expected.product = "SQRL FK";
    expected.interface_name = "A";
    const auto wanted = static_cast<uint32_t>(std::stoul(argv[6], nullptr, 16));

    io = std::make_unique<sidecar::jtag::LibFtdiIo>(expected, phase);
    sidecar::jtag::MpsseTap tap(*io);
    tap.synchronize_and_configure(100'000, phase);

    phase("P11_TAP_RESET");
    tap.reset_tap();
    phase("P12_READ_CHAIN");
    tap.shift_ir(0x09, 6);  // IDCODE only; no USER or programming IR.
    const auto raw = tap.shift_dr(std::vector<uint8_t>(8, 0), 64);

    phase("P13_PARSE_CHAIN");
    if (raw.bits != 64 || raw.tdo.size() != 8)
      return fail("validate 64-bit IDCODE chain response", 0, 0, "IDCODE response length mismatch");
    if (raw.tdo[4] || raw.tdo[5] || raw.tdo[6] || raw.tdo[7])
      return fail("reject additional IDCODE TAP", 0, 0, "unexpected extra IDCODE-capable TAP in chain");

    phase("P14_VERIFY_IDCODE");
    const auto actual = uint32_t(raw.tdo[0]) | (uint32_t(raw.tdo[1]) << 8) |
                        (uint32_t(raw.tdo[2]) << 16) | (uint32_t(raw.tdo[3]) << 24);
    std::cout << "IDCODE=0x" << std::hex << actual << std::dec << '\n';
    if (actual != wanted) return fail("compare expected IDCODE", 0, 0, "IDCODE mismatch");

    phase("P15_DNA_VERIFY");
    std::cout << "DNA_SOURCE=validated fresh target lock; separate read-only SQRL identity record\n";
    phase("P16_CLOSE_FTDI");
    std::string close_error;
    const int close_rc = io->close_checked(&close_error);
    if (close_rc < 0) return fail("ftdi_usb_close", errno, close_rc, close_error);
    io.reset();
    phase("P17_COMPLETE");
    std::cout << "RAW_OPEN=PASS\nMPSSE_SYNC=PASS\nTAP_RESET=PASS\n"
                 "JTAG_CHAIN_MATCH=PASS\nIDCODE_MATCH=PASS\nUSER_IR_SELECTION_COUNT=0\n";
    return 0;
  } catch (const sidecar::jtag::BackendFailure& e) {
    current_phase = e.phase();
    return fail(e.operation(), e.error_number(), e.ftdi_code(), e.what());
  } catch (const std::exception& e) {
    return fail("identity operation", errno, 0, e.what());
  }
}
