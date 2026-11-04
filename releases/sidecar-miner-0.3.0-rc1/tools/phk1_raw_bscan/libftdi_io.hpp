#pragma once

#include "mpsse_backend.hpp"
#include "usb_identity.hpp"

#include <cstdint>
#include <functional>
#include <string>
#include <stdexcept>
#include <libftdi1/ftdi.h>

namespace sidecar::jtag {

class BackendFailure final : public std::runtime_error {
 public:
  BackendFailure(const std::string& phase, const std::string& operation,
                 int error_number, int ftdi_code, const std::string& message)
      : std::runtime_error(message), phase_(phase), operation_(operation),
        error_number_(error_number), ftdi_code_(ftdi_code) {}
  const std::string& phase() const noexcept { return phase_; }
  const std::string& operation() const noexcept { return operation_; }
  int error_number() const noexcept { return error_number_; }
  int ftdi_code() const noexcept { return ftdi_code_; }
 private:
  std::string phase_, operation_;
  int error_number_, ftdi_code_;
};

class LibFtdiIo final : public Io {
 public:
  explicit LibFtdiIo(const UsbIdentity& expected, ProgressCallback phase = {});
  ~LibFtdiIo() override;
  void write_exact(const uint8_t* bytes, size_t size) override;
  void read_exact(uint8_t* bytes, size_t size) override;
  void close() noexcept override;
  int close_checked(std::string* error = nullptr) noexcept;

 private:
  ::ftdi_context* ctx_ = nullptr;
  ProgressCallback phase_;
};

}  // namespace sidecar::jtag
