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

Full `.text` sweep of a 25 MB stripped `lib*.so`:

| Tool | Time |
|---|---|
| capstone, instruction by instruction | ~6 min |
| `xref_fast.py` | **~10 s** |

The gain comes from only decoding three instruction encodings instead of
building a full instruction object for every word.

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
