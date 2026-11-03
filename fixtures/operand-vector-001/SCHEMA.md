# Canonical operand vector schema

Generated offline with the pinned PearlHash reference (`numpy` backend). This is a deterministic CPU reference fixture, **not** a CUDA capture.

| File | Logical shape | Element representation | Byte order |
|---|---:|---|---|
| `A.bin` | 256×2048 | signed int8 | C row-major; one byte/element |
| `B.bin` | 2048×256 | signed int8 | C row-major; one byte/element |
| `A_noised.bin` | 256×2048 | signed int16 | little-endian C row-major |
| `B_noised.bin` | 2048×256 | signed int16 | little-endian C row-major |

The FK mapping probe selects rows `[0,8]` and Pearl's exact 64-column pattern `[0,1,8,9,...,248,249]`. Eight 4×8 tiles each carry 2048 K records. Within each record bytes 0–3 are signed A lanes `[row0,row8,0,0]`; bytes 4–11 are signed B lanes for one consecutive group of eight values from the 64-entry selected-column pattern. Each byte is two's-complement, low-index lane first. No header or trailer is included in the 96-bit operand record stream.
