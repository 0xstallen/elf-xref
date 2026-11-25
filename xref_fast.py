#!/usr/bin/env python3
"""Xref rapido de VAs em .text arm64 por decodificacao manual de encoding.

Nao usa capstone: le as palavras de 32 bits e reconhece
    ADRP  xN, page
    ADD   xN, xM, #imm12      (64-bit, shift 0)
    LDR   xN, [xM, #imm12]    (unsigned offset, 64-bit)
e resolve adrp+add / adrp+ldr para a VA final.

~30x mais rapido que capstone para uma varredura completa do .text.

Uso:
    python scripts/xref_fast.py <lib.so> 0x1194530 0x1161e4f
    python scripts/xref_fast.py <lib.so> --range 0x1194530 0x1194540
"""
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile


def text_section(path):
    with path.open("rb") as fh:
        elf = ELFFile(fh)
        for s in elf.iter_sections():
            if s.name == ".text":
                return s["sh_offset"], s["sh_size"], s["sh_addr"]
    raise SystemExit(".text nao encontrada")


def sx(v, bits):
    m = 1 << (bits - 1)
    return (v ^ m) - m


def decode(data, off, size, va_base):
    """Retorna dict reg->page para adrp e lista de (addr, kind, target)."""
    n = size // 4
    words = memoryview(data)[off:off + size].cast("I")
    pages = {}
    out = []
    pc = va_base
    for i in range(n):
        w = words[i]
        a = pc + i * 4
        # ADRP
        if (w & 0x9F000000) == 0x90000000:
            rd = w & 0x1F
            immlo = (w >> 29) & 0x3
            immhi = (w >> 5) & 0x7FFFF
            imm = sx((immhi << 2) | immlo, 21) << 12
            pages[rd] = ((a & ~0xFFF) + imm) & 0xFFFFFFFFFFFF
            continue
        # ADD (immediate) 64-bit: sf=1 op=0 S=0
        if (w & 0xFF800000) == 0x91000000:
            rd = w & 0x1F
            rn = (w >> 5) & 0x1F
            imm12 = (w >> 10) & 0xFFF
            sh = (w >> 22) & 0x1
            if rn in pages:
                out.append((a, "add", pages[rn] + (imm12 << (12 if sh else 0))))
            if rd != rn:
                pages.pop(rd, None)
            continue
        # LDR (unsigned offset) 64-bit
        if (w & 0xFFC00000) == 0xF9400000:
            rd = w & 0x1F
            rn = (w >> 5) & 0x1F
            imm12 = (w >> 10) & 0xFFF
            if rn in pages:
                out.append((a, "ldr", pages[rn] + imm12 * 8))
            if rd != rn:
                pages.pop(rd, None)
            continue
        # LDR 32-bit / LDRB / LDRH tambem podem carregar o ponteiro
        if (w & 0xFFC00000) == 0xB9400000:
            rd = w & 0x1F
            rn = (w >> 5) & 0x1F
            imm12 = (w >> 10) & 0xFFF
            if rn in pages:
                out.append((a, "ldr32", pages[rn] + imm12 * 4))
            if rd != rn:
                pages.pop(rd, None)
            continue
        # qualquer branch/ret limpa o mapa para reduzir falso positivo
        if (w & 0x7C000000) == 0x14000000 or (w & 0xFFFFFC1F) == 0xD65F0000:
            pages.clear()
    return out


def main():
    path = Path(sys.argv[1])
    args = sys.argv[2:]
    if not args:
        raise SystemExit("informe VAs alvo")
    if args[0] == "--range":
        lo, hi = int(args[1], 16), int(args[2], 16)
        sel = lambda t: lo <= t <= hi
        label = f"0x{lo:x}..0x{hi:x}"
    else:
        targets = {int(x, 16) for x in args}
        sel = lambda t: t in targets
        label = ", ".join(hex(t) for t in sorted(targets))

    off, size, va = text_section(path)
    data = path.read_bytes()
    res = decode(data, off, size, va)

    hits = [(a, k, t) for (a, k, t) in res if sel(t)]
    print(f"alvo : {label}")
    print(f"hits : {len(hits)}")
    for a, k, t in hits:
        print(f"  code 0x{a:08x}  {k:6s} -> 0x{t:08x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
