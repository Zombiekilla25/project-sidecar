# PHK2 FK33 physical review status

This review uses the authoritative FK33 contract on `xcvu33p-fsvh2104-2-e`. No hardware, JTAG, programming, place/route, or bitstream operation was performed.

## Completed

- The reference PHK1 XDC and applied PHK2 clock fragment match their recorded SHA-256 identities. Vivado reports `clk_p` at BC26 and `clk_n` at BC27, both LVDS. The fragment defines a 5.000 ns input clock.
- The PHK2 clock shell is `IBUFDS -> PLLE4_ADV -> BUFG`, with `DIVCLK_DIVIDE=2`, `CLKFBOUT_MULT=14`, and `CLKOUT0_DIVIDE=8`. For 200 MHz in, PFD is 100 MHz, VCO is 1400 MHz, and core output is 175 MHz (5.714 ns). The clock-only Vivado check recognized these clocks and reported zero DRC violations.
- Reset release holds the core in reset until four core-clock edges after lock; lock loss asynchronously reasserts reset. Simulation: 4/4 startup/reset cases.
- Real-core endpoint controls: 11/11. Async FIFO component test: 100,000 ordered transfers, no drops or duplicates. Board-path CDC pressure test ran 12,000 STATUS request/response frames with randomized transport-clock half-periods and delayed host draining: 2,470,381 aggregate clock edges, no errors, loss, duplicates, or deadlock. Both input and output FIFOs reached full.
- Vivado 2026.1 RTL elaboration of the real PHK2 top completed for the target part. The applied XDC reports exactly two user I/Os, on BC26/BC27; generated 5.714 ns core clock is recognized; RTL-elaboration DRC found zero checks.

## Physical build issue found and corrected

Vivado rejected the original XPM FIFO thresholds for depth 512: programmable full threshold 508 exceeded the maximum 507, and programmable empty threshold 4 was below the minimum 5. The XPM wrapper now uses 507 and 5. These features are not used as the FIFO flow-control contract; `full` and `empty` remain the gating signals. Vivado RTL elaboration now completes. Behavioral FIFO and endpoint tests pass with the updated source.

## Remaining gate

Vivado 2026.1 reports that `report_cdc` and `check_timing` are unsupported before a mapped synthesized design is open. The RTL-elaboration run therefore cannot produce the requested vendor CDC classification or a full timing check. Since the task requires the vendor CDC review to pass before the first authoritative board synthesis, that synthesis remains `NOT_RUN`; the integrated CDC review remains `NOT_RUN`, and route readiness is false. The source-level CDC topology consists of the two XPM asynchronous FIFOs (USER2/TCK to core, core to USER1/DRCK) and a two-stage synchronizer for USER3 status levels. This topology description does not substitute for Vivado CDC results.

| Crossing | Source → destination | RTL mechanism | Current severity/classification |
|---|---|---|---|
| Command bytes | USER2 DRCK → `core_clk` | XPM `xpm_fifo_async`, depth 512, 2 CDC stages | Vendor classification unavailable; blocking review |
| Response bytes | `core_clk` → USER1 DRCK | XPM `xpm_fifo_async`, depth 512, 2 CDC stages | Vendor classification unavailable; blocking review |
| USER3 status levels | `core_clk` → USER3 TCK | Two `ASYNC_REG` stages over six level bits | Vendor classification unavailable; blocking review |
| Domain reset release | PLL-derived core reset → USER1/2/3 DRCK reset pipes | Asynchronous assertion, local two-stage release | Vendor classification unavailable; blocking review |
| PLL lock | `LOCKED` → core reset-release chain | Asynchronous reset assertion, four-cycle synchronous release | Clock shell simulation and clock-only legality pass; integrated CDC classification unavailable |

These crossings are listed as unresolved for vendor classification rather than waived. Vivado RTL elaboration emits two declaration-order warnings in the core, unused/unconnected-port warnings, and the differential termination translation warning; it reports zero critical warnings and zero DRC checks.

Vivado emitted 42 warnings during RTL elaboration. They include two declaration-order warnings in the real core, expected unused/unconnected XPM/core ports, and the inherited differential termination property translation. There were zero critical warnings and zero DRC checks. These warnings are recorded in `vivado.log` during the run and are not presented as a clean mapped-synthesis result.

## Evidence files

- `results/phk2-fk33-rtl-review/clocks.rpt`
- `results/phk2-fk33-rtl-review/drc.rpt`
- `results/phk2-fk33-rtl-review/io.rpt`
- `results/phk2-fk33-clock-legality/`
- `results/phk2-real-core-cdc-stress.json`
- `results/phk2-real-core-endpoint.json`
