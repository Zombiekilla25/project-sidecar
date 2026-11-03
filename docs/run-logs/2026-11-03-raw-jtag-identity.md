# Read-only raw JTAG identity qualification

**Date:** 2026-11-03

**Result:** PASS

The corrected libftdi backend passed one 100 kHz read-only identity smoke. It synchronized MPSSE, reset TAP, read the expected JTAG chain and IDCODE, and closed the device cleanly. The same FTDI context and live USB handle were present after open and immediately before both bitmode calls; both calls returned zero. The backend did not perform a post-open string lookup.

Target binding matched the fresh single-target lock and the existing separately qualified read-only DNA evidence. No peer was opened.

The test performed no FPGA programming, XBT reload, PHK1 operation, USER-chain selection, CoE transaction, or PMIC write. The shared bridge returned in attach-only mode; all eight workloads and protected workers recovered cleanly.

The raw backend is qualified for the `RAW_BSCAN` architecture. The program-to-raw handoff dry-run passed 19/19 cases, and the existing fifth-canary control model remains qualified at 13/13 cases. The fifth PHK1 canary is ready for its separately authorized turn; it was not run here.
