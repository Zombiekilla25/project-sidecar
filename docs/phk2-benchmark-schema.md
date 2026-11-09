# PHK2 benchmark schema

Machine-readable records use `docs/schemas/phk2-benchmark-v1.schema.json`. Every field is explicit: clock MHz, tile count, batch, work items/second, transport fraction, FPGA fraction, power (W), and performance/W. Missing measurements are JSON `null`; zero is a measured zero only. `measurement_class` is `MOCK` or `SILICON`; mock runs cannot be presented as silicon performance.

Timing components use `HOST_PACK_US`, `DESCRIPTOR_TX_US`, `FPGA_WORK_US`, `RESULT_RX_US`, `HOST_VERIFY_US`, and `TOTAL_US`. Mock phase times are measured software wall time and are marked mock. PHK1 comparison inputs use the same schema, with no baked-in PHK1/PHK2 rates. The reporter returns an incomplete status and null ratio until both measured work rates are present.
