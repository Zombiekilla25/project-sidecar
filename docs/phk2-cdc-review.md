# PHK2 board CDC design review

Review outcome: **CDC_DESIGN_REVIEW=PASS for the proposed skeleton structure**. This is a source-level and simulation review; it is not a vendor CDC report or physical qualification.

- USER2 TCK to PHK2 core: byte writes cross through a depth-512 Gray-pointer asynchronous FIFO. Full and occupancy are visible to source flow control. Bytes are accepted only on complete 8-bit shifts. FIFO reset deassertion is synchronized in the USER2 clock domain.
- PHK2 core to USER1 TCK: result bytes cross through a second depth-512 Gray-pointer asynchronous FIFO. Empty and occupancy are visible; the host drains bounded payloads and cannot read an empty FIFO as a valid result.
- Core to USER3 TCK: the six independent level flags are sampled through a two-flop synchronizer with `ASYNC_REG` and `SHREG_EXTRACT=NO` attributes. These flags are sticky/level state, not a narrow pulse protocol.
- Core reset is generated in the core clock domain. Its deassertion passes through a local two-stage reset pipe in each BSCAN domain. FIFO pointer state remains reset until local deassertion completes.
- FIFO pointer crossings use Gray-coded pointers, two-stage synchronization, and local full/empty comparison. Payload buses are not independently synchronized; the FIFO memory and pointer protocol transfer them atomically.
- Simulation exercises independent core and TCK clocks, FIFO pressure, occupancy, empty/full, and order. The top has no descriptor/result package pins.

Before physical integration, the RTL owner must run the vendor CDC checker, confirm the selected XPM FIFO configuration and reset-busy behavior for the exact FPGA part, inspect CDC waivers, and verify timing constraints for TCK and the core clock. Any change to the crossing topology reopens this review.
