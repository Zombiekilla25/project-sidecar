# S05 Target Userspace Compatibility

_Date: 2026-10-31_

Status: **TARGET USERSPACE QUALIFIED**

## Qualification

- Local narrow qualification: **231/231 PASS**.
- Local full retained qualification: **1,253/1,253 PASS**.
- Target narrow qualification: **233/233 PASS**.
- Target full retained qualification: **1,253/1,253 PASS**, **0 failures**, **0 errors**.
- All nine prior portability failure instances and both host-assumption test instances are resolved.

The existing target runtime was used without installing packages or replacing the interpreter. The comparison covered Python 3.12/glibc 2.39 locally and Python 3.14/glibc 2.43 on the target.

## Security contract retained

The exact descriptor inventory remains unchanged. No arbitrary descriptors are allowed, no dynamic allowlist was introduced, and authenticated lifecycle/quarantine recovery remains fail-closed.

Native FFI initialization now occurs in the supervisor privilege phase before fork and descriptor normalization. An unused import was removed. The protected exec child can import its Sidecar modules without initializing libffi before the exact-inventory check. The existing pre-fork initialization order is preserved for privilege operations.

The two ELF tests select the resolved regular executable fixture. Production executable validation still rejects symlinks and requires protected ownership and the correct digest. The wrong-digest assertion remains unchanged. Existing extra-descriptor rejection coverage remains; the descriptor harness additionally imports the S05 child module.

## Safety boundary

This milestone qualifies offline userspace behavior on the target. It does not qualify a protected installation or privileged production launch.

The live bridge PID, process start time, raw command-line SHA256 and listening port were preserved. No service restart, FPGA programming, JTAG access, mining change or protected installation occurred. Runtime evidence and machine-specific state remain outside this public repository.

## Next gate

Controlled protected-boundary installation/readiness qualification requires a separate explicit decision. No installation is authorized by this userspace result. Hardware execution remains separately gated.
