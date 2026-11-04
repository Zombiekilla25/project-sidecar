#pragma once

#include "usb_identity.hpp"

#include <optional>
#include <vector>

namespace sidecar::jtag {

bool exact_candidate_match(const UsbIdentity& expected,
                           const UsbCandidateIdentity& candidate);
size_t require_unique_exact_candidate(
    const UsbIdentity& expected,
    const std::vector<UsbCandidateIdentity>& candidates);

}  // namespace sidecar::jtag
