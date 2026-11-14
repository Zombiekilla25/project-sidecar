# Sanitized finding for Middle: success after installer-parent substitution

**Reproduced on:** release candidate `684770dd9657d070c982ce98fe84c839016456a6`, Left descendant `5eb007c92ec4b193ee4d0b08d51019fde711640a`, and Middle installer branch `abe81bc2791b52b546985fdab9db986063a1e721`.

Disposable-root reproducer: hook the installer checkpoint after installed-package verification (also reproduced at `before_finalize`), rename the requested parent directory, and replace it with a fresh directory. `stage_package()` returns SUCCESS; the requested `release` path is absent while a valid package exists under the renamed parent. Repeating with a symlink replacement also returns SUCCESS; in some cases the requested parent is now a symlink, contrary to the path identity gate. On release 684 and Left 5eb, the 36-case matrix found 22 success-after-substitution outcomes; the Middle installer branch found 4/12.

The prior hard-kill reproducer at `before_commit` also leaves the staging directory and owner marker in the renamed original parent. Recovery at the replacement path cannot discover those siblings; recovery using the original renamed parent removes them.

Likely narrow correction: retain the validated parent identity and verify it again after all publish/cleanup checkpoints immediately before reporting success. If identity changed after commit, do not report success for the requested path; use the held directory handle to restore/clean safely where possible, otherwise return a distinct recovery-required result bound to the original operation/parent identity. Add both directory and symlink replacement faults before commit, after commit, after installed verification, before finalization, and through prior-release cleanup.

The normal 12-test package suite passes, so the current fixtures do not cover these parent identity transitions.
