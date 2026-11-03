#include "usb_selection.hpp"

#include <iostream>
#include <stdexcept>

using namespace sidecar::jtag;

int main() {
  const UsbIdentity expected{0x0403, 0x6010, "fixture-target", "1-9.3",
                             "Xilinx", "SQRL FK", "A"};
  const UsbCandidateIdentity target{0x0403, 0x6010, "fixture-target", "1-9.3",
                                    "Xilinx", "SQRL FK", "A"};
  const UsbCandidateIdentity peer{0x0403, 0x6010, "fixture-peer", "1-9.4",
                                  "Xilinx", "SQRL FK", "A"};
  unsigned passed = 0, total = 0;
  auto check = [&](bool value, const char* name) {
    ++total;
    if (value) { ++passed; std::cout << "PASS " << name << '\n'; }
    else std::cout << "FAIL " << name << '\n';
  };
  auto rejects = [&](const std::vector<UsbCandidateIdentity>& candidates) {
    try { (void)require_unique_exact_candidate(expected, candidates); }
    catch (const std::runtime_error&) { return true; }
    return false;
  };
  check(require_unique_exact_candidate(expected, {target, peer}) == 0,
        "select_exact_target_with_distinct_peer_present");
  auto wrong = target; wrong.serial = "wrong";
  check(rejects({wrong}), "reject_wrong_serial");
  wrong = target; wrong.usb_path = "1-9.4";
  check(rejects({wrong}), "reject_wrong_usb_path");
  wrong = target; wrong.interface_name = "B";
  check(rejects({wrong}), "reject_wrong_interface");
  wrong = target; wrong.vid = 0x1234;
  check(rejects({wrong}), "reject_wrong_vid_pid");
  check(rejects({target, target}), "reject_duplicate_exact_match");
  UsbIdentity bad_channel = expected; bad_channel.interface_name = "B";
  bool bad_channel_rejected = false;
  try { (void)require_unique_exact_candidate(bad_channel, {target}); }
  catch (const std::runtime_error&) { bad_channel_rejected = true; }
  check(bad_channel_rejected && !exact_candidate_match(bad_channel, target),
        "reject_unapproved_channel");
  std::cout << "RESULT=" << passed << '/' << total << '\n';
  return passed == total ? 0 : 1;
}
