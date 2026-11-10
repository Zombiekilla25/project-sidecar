# PHK2 first-silicon offline readiness

- **schema:** PHK2-OVERNIGHT-HOST-READINESS-v1
- **base_commit:** 97773443b47be478c819cdb5ebe74989a9b50796
- **each_gate_fails_closed:** True
- **physical_image_qualified:** False
- **live_path_authorized:** False
- **physical_protocol_qualified:** False
- **hardware_access_count:** 0
- **program_attempts:** 0
- **hello_attempts:** 0
- **host_harness_ready:** True
- **physical_adapter_interface_ready:** True
- **image_manifest_ready:** True
- **image_intake_ready:** True
- **canary_precheck_ready:** True
- **fail_closed_tests:** 17
- **fault_scenarios_run:** 51
- **fault_scenarios_pass:** 51
- **fault_scenarios_fail:** 0
- **full_offline_rehearsal_pass:** True
- **ready:** True
- **HOST_HARNESS_READY:** True
- **PHYSICAL_ADAPTER_INTERFACE_READY:** True
- **IMAGE_MANIFEST_READY:** True
- **IMAGE_INTAKE_READY:** True
- **IMAGE_INTAKE_NEGATIVE_TESTS:** 22
- **IMAGE_INTAKE_NEGATIVE_TESTS_PASS:** 22
- **CANARY_PRECHECK_READY:** True
- **CANARY_GATE_TESTS:** 20/20
- **FAIL_CLOSED_TESTS:** 17/17
- **FAULT_SCENARIOS_RUN:** 51
- **FAULT_SCENARIOS_PASS:** 51
- **FAULT_SCENARIOS_FAIL:** 0
- **FULL_OFFLINE_REHEARSAL_PASS:** True
- **PHYSICAL_IMAGE_QUALIFIED:** False
- **LIVE_PATH_AUTHORIZED:** False
- **PHYSICAL_PROTOCOL_QUALIFIED:** False
- **HARDWARE_ACCESS_COUNT:** 0
- **PROGRAM_ATTEMPTS:** 0
- **HELLO_ATTEMPTS:** 0
- **BLOCKERS_TO_FIRST_SILICON:** ['No real routed PHK2 image has passed the mandatory image-intake qualification gates.', 'A physical PHK2 transport/endpoint adapter and durable identity mapping are not implemented or qualified; live path remains disabled.', 'PHK2-specific rollback/recovery readiness and semantic continuity have only mock interfaces here and are not physically qualified.', 'A fresh single-use authorization for the configured one-card scope has not been issued.']
- **scope_note:** Readiness values describe host-side/interface and synthetic offline qualification only; no physical image is qualified.

## Blockers to first silicon

- No real routed PHK2 image has passed the mandatory image-intake qualification gates.
- A physical PHK2 transport/endpoint adapter and durable identity mapping are not implemented or qualified; live path remains disabled.
- PHK2-specific rollback/recovery readiness and semantic continuity have only mock interfaces here and are not physically qualified.
- A fresh single-use authorization for the configured one-card scope has not been issued.

All candidate/image tests used synthetic package fixtures. No FPGA image is qualified by this report.
