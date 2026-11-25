# elf-xref

Fast cross-reference and VA tooling for stripped ARM64 ELF binaries.

Built because every existing option was either too slow on a full `.text`
sweep (capstone: ~6 minutes) or required a full disassembler session just
to answer "who references this address".

## What's here

| File | Does |
|---|---|
| `xref_fast.py` | Resolves `ADRP` + `ADD` / `ADRP` + `LDR` pairs to find every reference to one or more target VAs. Decodes the 32-bit words directly — no disassembler. |
| `str_at.py` | Maps a VA to its file offset through section headers and prints the NUL-terminated string sitting there. |
| `dis_at.py` | Disassembles a window around a VA with capstone, marking the target line. |

## Benchmark

Full `.text` sweep of a 4.24 MB stripped arm64 `lib*.so` (785,464 instructions):

| Tool | Time |
|---|---|
| capstone, instruction by instruction, `detail=True` | 14.2 s |
| capstone, single linear sweep, `detail=False` | 2.2 s |
| `xref_fast.py` | **0.6 s** |

The gain comes from decoding four instruction encodings instead of building
a full instruction object for every word.

## Validation

Every resolved reference was cross-checked against capstone by re-decoding
the same word and walking back to the `ADRP` that fed the base register:

| | |
|---|---|
| references emitted | 19,279 |
| independently confirmed | 13,763 |
| confirmed **wrong** | **0** |
| resolving inside a real ELF section | 93.3% |

## Limitations

The register tracking is a heuristic that lives inside one basic block:

- the page map is cleared on any branch — `B`/`BL`, `B.cond`, `CBZ`/`CBNZ`,
  `TBZ`/`TBNZ`, `BR`/`BLR`/`RET`
- chained adds accumulate: `add x8, x8, #0xfb8` followed by
  `add x9, x8, #0x28` resolves to `page+0xfe0`, and `x8` keeps its own value
- `ldr x8, [x8, #imm]` drops the page for `x8`, because the register now
  holds the loaded value, not the address
- writes the tool does not model (`sub`, `mov`, `ldr` into SIMD registers,
  `ldxr`) can leave a stale page and produce a false positive. That is where
  the ~7% of hits that resolve outside any section come from
- data bytes inside `.text` are decoded as instructions, so some hits come
  from constants rather than code

## Install

```
pip install pyelftools capstone
```

## Usage

```
# who references these two addresses?
python xref_fast.py libtarget.so 0x1194530 0x1161e4f

# every reference inside a range
python xref_fast.py libtarget.so --range 0x1194530 0x1194540

# what string lives at this VA?
python str_at.py libtarget.so 0x1161e3a

# disassemble around this VA
python dis_at.py libtarget.so 0x2967e8 0x80 0x80
```

## The encoding trap this exists to avoid

`adrp x1, #0x1161000` followed by `add x1, x1, #0xe3a` resolves to
`0x1161e3a` — not `0x1160e3a`. The page comes from the `adrp` line, the
low 12 bits come from the `add`. Taking the page from the low 16 bits of
the final target produces an address that looks plausible and is wrong.

## License

MIT
