#pragma once

#include <cstdint>
#include <cstddef>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

namespace sidecar::jtag {

using ProgressCallback = std::function<void(const char*)>;

// The only MPSSE-facing interface exposed to the TAP layer. Implementations
// must bind one exact FTDI interface before this object is constructed.
class Io {
 public:
  virtual ~Io() = default;
  virtual void write_exact(const uint8_t* bytes, size_t size) = 0;
  virtual void read_exact(uint8_t* bytes, size_t size) = 0;
  virtual void close() noexcept = 0;
};

struct ScanResult {
  std::vector<uint8_t> tdo;
  size_t bits = 0;
};

class MpsseTap {
 public:
  explicit MpsseTap(Io& io) : io_(io) {}
  void synchronize_and_configure(uint32_t jtag_clock_hz,
                                 ProgressCallback progress = {});
  void reset_tap();
  uint32_t read_single_vu33p_idcode();
  ScanResult shift_ir(uint8_t instruction, size_t bits = 6);
  ScanResult shift_dr(const std::vector<uint8_t>& tdi, size_t bit_count);
  void close() noexcept { io_.close(); }

 private:
  Io& io_;
  bool ready_ = false;
  void tms(const std::vector<uint8_t>& bits, uint8_t tdi_level = 0);
  std::vector<uint8_t> shift_data(const uint8_t* tdi, size_t bit_count,
                                  bool last_bit_exits_shift);
  void require_ready() const;
};

// Strictly permits only the identity register and the three PHK1 USER
// instructions. This is not a general-purpose IR selector.
bool allowed_ir(uint8_t instruction);

}  // namespace sidecar::jtag
