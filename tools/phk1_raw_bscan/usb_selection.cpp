#include "usb_selection.hpp"

#include <stdexcept>

namespace sidecar::jtag {

bool exact_candidate_match(const UsbIdentity& expected,
                           const UsbCandidateIdentity& candidate) {
  return expected.vid == candidate.vid && expected.pid == candidate.pid &&
         expected.serial == candidate.serial &&
         expected.usb_path == candidate.usb_path &&
         expected.manufacturer == candidate.manufacturer &&
         expected.product == candidate.product &&
         expected.interface_name == "A" && candidate.interface_name == "A";
}

size_t require_unique_exact_candidate(
    const UsbIdentity& expected,
    const std::vector<UsbCandidateIdentity>& candidates) {
  std::optional<size_t> selected;
  for (size_t i = 0; i < candidates.size(); ++i) {
    if (!exact_candidate_match(expected, candidates[i])) continue;
    if (selected) throw std::runtime_error("duplicate exact USB identity; fail closed");
    selected = i;
  }
  if (!selected) throw std::runtime_error("exact USB identity not found");
  return *selected;
}

}  // namespace sidecar::jtag
