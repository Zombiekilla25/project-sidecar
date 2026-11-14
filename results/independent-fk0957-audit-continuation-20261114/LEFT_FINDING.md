# Sanitized finding for Left: malformed refusal/status type escape

**Reproduced on:** `684770dd9657d070c982ce98fe84c839016456a6` and Left integration commit `5eb007c92ec4b193ee4d0b08d51019fde711640a`.

Construct the canonical REFUSED diagnostic with its normal fields and set `local_state` to `[]`. `refusal_diagnostic()` raises raw `TypeError: unhashable type: 'list'`. The same happens for `publication_state` and `supervisor_state`; dicts and nested list values also trigger it.

For supervisor status, start with the otherwise valid EXITED_REFUSAL status/result and replace a nested result field with `[]`. `code`, `publication_state`, `operation_state`, and `close_from_state` raise `TypeError`; malformed `phase` alone returns UNKNOWN. The outer maintenance code catches `ValueError` around `refusal_diagnostic`, so this TypeError bypasses the bounded fallback and reaches the CLI's generic exception handler.

Independent matrix: 237 cases, 28 raw TypeErrors, 0 unexpected accepts; duplicate outer/nested keys returned UNKNOWN. The previous 200,000-case seeded run recorded 59,063 TypeErrors, 0 unsafe accepts.

Likely narrow correction: type-check string/enumeration fields before set/dict membership, allow only `None` or validated strings for nullable fields, and make the outer parse boundary catch TypeError as a final fail-closed guard. Preserve the valid EXITED_REFUSAL control and all state relationships.
