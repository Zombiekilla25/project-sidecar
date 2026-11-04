#pragma once

#include <cstdint>
#include <string>

namespace sidecar::jtag {

struct UsbIdentity {
  uint16_t vid;
  uint16_t pid;
  std::string serial;       // USB serial string, not a wildcard
  std::string usb_path;     // fresh path from a target lock
  std::string manufacturer;
  std::string product;
  std::string interface_name = "A";
};

struct UsbCandidateIdentity {
  uint16_t vid = 0;
  uint16_t pid = 0;
  std::string serial;
  std::string usb_path;
  std::string manufacturer;
  std::string product;
  std::string interface_name;
};

}  // namespace sidecar::jtag
