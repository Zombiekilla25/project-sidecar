#include "libftdi_io.hpp"
#include "usb_selection.hpp"

#include <libusb-1.0/libusb.h>

#include <array>
#include <climits>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace sidecar::jtag {
namespace {
void trace_context(const char* event, const ftdi_context* ctx,
                   int rc = std::numeric_limits<int>::max()) {
  const auto context = reinterpret_cast<std::uintptr_t>(ctx);
  const auto handle = ctx ? reinterpret_cast<std::uintptr_t>(ctx->usb_dev) : 0;
  std::clog << "FTDI_CONTEXT_EVENT=" << event
            << " CTX=0x" << std::hex << context
            << " USB_DEV=0x" << handle << std::dec;
  if (rc != std::numeric_limits<int>::max()) std::clog << " RETURN=" << rc;
  std::clog << '\n';
}

std::string device_path(libusb_device* dev) {
  const auto bus = libusb_get_bus_number(dev);
  std::array<uint8_t, 8> ports{};
  const int count = libusb_get_port_numbers(dev, ports.data(), ports.size());
  if (count <= 0) throw std::runtime_error("USB topology path unavailable");
  std::ostringstream out;
  out << unsigned(bus) << '-';
  for (int i = 0; i < count; ++i) {
    if (i) out << '.';
    out << unsigned(ports[i]);
  }
  return out.str();
}

UsbCandidateIdentity candidate_identity(ftdi_context* ctx, libusb_device* dev) {
  trace_context("DESCRIPTOR_LOOKUP_BEGIN", ctx);
  std::array<char, 128> manufacturer{}, product{}, serial{};
  const int rc = ftdi_usb_get_strings(ctx, dev, manufacturer.data(), manufacturer.size(),
                                      product.data(), product.size(), serial.data(),
                                      serial.size());
  trace_context("DESCRIPTOR_LOOKUP_END", ctx, rc);
  if (rc < 0)
    throw std::runtime_error("cannot read FTDI USB identity strings");
  return {0x0403, 0x6010, serial.data(), device_path(dev),
          manufacturer.data(), product.data(), "A"};
}
}  // namespace

LibFtdiIo::LibFtdiIo(const UsbIdentity& expected, ProgressCallback phase)
    : phase_(std::move(phase)) {
  if (expected.vid != 0x0403 || expected.pid != 0x6010 || expected.serial.empty() ||
      expected.usb_path.empty() || expected.manufacturer.empty() ||
      expected.product.empty() || expected.interface_name != "A")
    throw std::invalid_argument("all exact USB identity fields are required");

  ctx_ = ftdi_new();
  if (!ctx_) throw BackendFailure("P04_ENUMERATE_USB", "ftdi_new", errno, 0,
                                  "libftdi context allocation failed");
  trace_context("AFTER_NEW", ctx_);
  try {
    if (phase_) phase_("P04_ENUMERATE_USB");
    ftdi_device_list* raw_list = nullptr;
    const int listed = ftdi_usb_find_all(ctx_, &raw_list, expected.vid, expected.pid);
    if (listed < 0) throw BackendFailure("P04_ENUMERATE_USB", "ftdi_usb_find_all",
        errno, listed, ftdi_get_error_string(ctx_));
    const auto free_list = [](ftdi_device_list* p) { ftdi_list_free(&p); };
    std::unique_ptr<ftdi_device_list, decltype(free_list)> list(raw_list, free_list);
    std::vector<UsbCandidateIdentity> candidates;
    std::vector<libusb_device*> devices;
    if (phase_) phase_("P05_MATCH_FTDI_DEVICE");
    size_t selected = 0;
    try {
      for (auto* node = list.get(); node; node = node->next) {
        candidates.push_back(candidate_identity(ctx_, node->dev));
        devices.push_back(node->dev);
      }
      selected = require_unique_exact_candidate(expected, candidates);
    } catch (const std::exception& e) {
      throw BackendFailure("P05_MATCH_FTDI_DEVICE", "exact USB identity match",
                           errno, 0, e.what());
    }

    // FK33's production SQRL path uses FT2232 channel A for MPSSE JTAG.
    // libftdi requires the channel selection before opening the USB handle.
    if (phase_) phase_("P07_SELECT_INTERFACE_A");
    int rc = ftdi_set_interface(ctx_, INTERFACE_A);
    trace_context("SET_INTERFACE_A", ctx_, rc);
    if (rc < 0)
      throw BackendFailure("P07_SELECT_INTERFACE_A", "ftdi_set_interface(INTERFACE_A)",
                           errno, rc, ftdi_get_error_string(ctx_));
    // Open the exact enumerated libusb device, not the first device returned
    // for a matching serial. The list remains alive through this open.
    if (phase_) phase_("P06_OPEN_FTDI");
    rc = ftdi_usb_open_dev(ctx_, devices.at(selected));
    trace_context("USB_OPEN_DEV", ctx_, rc);
    if (rc != 0)
      throw BackendFailure("P06_OPEN_FTDI", "ftdi_usb_open_dev(exact device)",
                           errno, rc, ftdi_get_error_string(ctx_));

    // Confirm the selected handle is still the enumerated physical device.
    // Do not call ftdi_usb_get_strings here: libftdi's implementation closes
    // ctx->usb_dev after a successful descriptor read when a device is open.
    // The serial/manufacturer/product were already matched before open, and
    // this exact libusb_device was passed to ftdi_usb_open_dev.
    auto* opened_device = ctx_->usb_dev ? libusb_get_device(ctx_->usb_dev) : nullptr;
    struct libusb_device_descriptor opened_desc{};
    const bool opened_identity_matches = opened_device &&
        libusb_get_device_descriptor(opened_device, &opened_desc) == 0 &&
        opened_desc.idVendor == expected.vid && opened_desc.idProduct == expected.pid &&
        device_path(opened_device) == expected.usb_path;
    if (!opened_identity_matches)
      throw BackendFailure("P06_OPEN_FTDI", "post-open identity revalidation",
                           errno, 0, "opened FTDI handle identity changed");
    trace_context("AFTER_OPEN", ctx_);
    std::clog << "FTDI_CONTEXT_ID_AFTER_OPEN=0x" << std::hex
              << reinterpret_cast<std::uintptr_t>(ctx_) << std::dec << '\n'
              << "USB_DEVICE_HANDLE_PRESENT_AFTER_OPEN="
              << (ctx_ && ctx_->usb_dev ? "true" : "false") << '\n';
    const char* open_error = ftdi_get_error_string(ctx_);
    std::clog << "FTDI_ERROR_STRING_AFTER_OPEN=" << (open_error ? open_error : "NONE") << '\n';
    list.reset();

    if (phase_) phase_("P08_INIT_MPSSE");
    if (!ctx_ || !ctx_->usb_dev)
      throw BackendFailure("P08_INIT_MPSSE", "validate open FTDI handle before bitmode",
                           errno, -2, "USB device handle missing before bitmode");
    trace_context("BEFORE_BITMODE", ctx_);
    std::clog << "FTDI_CONTEXT_ID_BEFORE_BITMODE=0x" << std::hex
              << reinterpret_cast<std::uintptr_t>(ctx_) << std::dec << '\n'
              << "USB_DEVICE_HANDLE_PRESENT_BEFORE_BITMODE="
              << (ctx_->usb_dev ? "true" : "false") << '\n';
    rc = ftdi_set_bitmode(ctx_, 0x0b, BITMODE_RESET);
    trace_context("BITMODE_RESET", ctx_, rc);
    std::clog << "BITMODE_RESET_RETURN=" << rc << '\n';
    if (rc < 0)
      throw BackendFailure("P08_INIT_MPSSE", "ftdi_set_bitmode(reset/mpsse)",
                           errno, rc, ftdi_get_error_string(ctx_));
    trace_context("BEFORE_MPSSE_BITMODE", ctx_);
    rc = ftdi_set_bitmode(ctx_, 0x0b, BITMODE_MPSSE);
    trace_context("BITMODE_MPSSE", ctx_, rc);
    std::clog << "BITMODE_MPSSE_RETURN=" << rc << '\n';
    if (rc < 0)
      throw BackendFailure("P08_INIT_MPSSE", "latency/chunk/purge configuration",
                           errno, rc, ftdi_get_error_string(ctx_));
    rc = ftdi_set_latency_timer(ctx_, 2);
    if (rc < 0) throw BackendFailure("P08_INIT_MPSSE", "ftdi_set_latency_timer(2)", errno, rc, ftdi_get_error_string(ctx_));
    rc = ftdi_read_data_set_chunksize(ctx_, 16 * 1024);
    if (rc < 0) throw BackendFailure("P08_INIT_MPSSE", "ftdi_read_data_set_chunksize", errno, rc, ftdi_get_error_string(ctx_));
    rc = ftdi_write_data_set_chunksize(ctx_, 16 * 1024);
    if (rc < 0) throw BackendFailure("P08_INIT_MPSSE", "ftdi_write_data_set_chunksize", errno, rc, ftdi_get_error_string(ctx_));
    rc = ftdi_tcioflush(ctx_);
    if (rc < 0) throw BackendFailure("P08_INIT_MPSSE", "ftdi_tcioflush", errno, rc, ftdi_get_error_string(ctx_));
    ctx_->usb_read_timeout = 1000;
    ctx_->usb_write_timeout = 1000;
  } catch (...) {
    close();
    throw;
  }
}

LibFtdiIo::~LibFtdiIo() { close(); }

void LibFtdiIo::write_exact(const uint8_t* bytes, size_t size) {
  if (!ctx_ || !bytes || !size) throw std::logic_error("FTDI handle is closed or write is empty");
  size_t offset = 0;
  while (offset < size) {
    const int chunk = int(std::min<size_t>(size - offset, INT_MAX));
    const int written = ftdi_write_data(ctx_, const_cast<unsigned char*>(bytes + offset), chunk);
    if (written != chunk) throw std::runtime_error("short/failed FTDI write");
    offset += size_t(written);
  }
}

void LibFtdiIo::read_exact(uint8_t* bytes, size_t size) {
  if (!ctx_ || !bytes || !size) throw std::logic_error("FTDI handle is closed or read is empty");
  size_t offset = 0;
  while (offset < size) {
    const int chunk = int(std::min<size_t>(size - offset, INT_MAX));
    const int got = ftdi_read_data(ctx_, bytes + offset, chunk);
    if (got <= 0) throw std::runtime_error("short/failed FTDI read");
    offset += size_t(got);
  }
}

void LibFtdiIo::close() noexcept {
  (void)close_checked();
}

int LibFtdiIo::close_checked(std::string* error) noexcept {
  if (!ctx_) return 0;
  trace_context("CLOSE_BEGIN", ctx_);
  int result = 0;
  if (ctx_->usb_dev) result = ftdi_usb_close(ctx_);
  trace_context("CLOSE_USB_RETURN", ctx_, result);
  if (result < 0 && error) *error = ftdi_get_error_string(ctx_);
  ftdi_free(ctx_);
  std::clog << "FTDI_CONTEXT_EVENT=FREE CTX=0x"
            << std::hex << reinterpret_cast<std::uintptr_t>(ctx_) << std::dec << '\n';
  ctx_ = nullptr;
  return result;
}

}  // namespace sidecar::jtag
