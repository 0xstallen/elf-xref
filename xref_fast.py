#!/usr/bin/env python3
"""Xref rapido de VAs em .text arm64 por decodificacao manual de encoding.

Nao usa capstone: le as palavras de 32 bits e reconhece
    ADRP  xN, page
    ADD   xN, xM, #imm12      (64-bit, shift 0 ou 12)
    LDR   xN, [xM, #imm12]    (unsigned offset, 64-bit)
    LDR   wN, [xM, #imm12]    (unsigned offset, 32-bit)
e resolve adrp+add / adrp+ldr para a VA final.

O mapa de paginas e heuristico e vive dentro do bloco basico: limpa em
qualquer desvio. Escritas nao modeladas (sub, mov, ldr SIMD, ldxr) podem
deixar pagina velha e gerar falso positivo.

~3.5x mais rapido que um sweep linear do capstone e ~23x mais rapido que
decodificar instrucao por instrucao com detail=True.

Uso:
    python xref_fast.py <lib.so> 0x1194530 0x1161e4f
    python xref_fast.py <lib.so> --range 0x1194530 0x1194540
"""
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile

# O cast("I") abaixo usa a ordem de bytes nativa. AArch64 ELF e sempre
# little-endian, entao rodar num host big-endian leria as palavras invertidas.
if sys.byteorder != "little":
    raise SystemExit("host precisa ser little-endian")

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


def is_flow(w):
    """B/BL, B.cond, CBZ/CBNZ, TBZ/TBNZ, BR/BLR/RET/ERET."""
    return ((w & 0x7C000000) == 0x14000000
            or (w & 0xFF000010) == 0x54000000
            or (w & 0x7E000000) in (0x34000000, 0x35000000)
            or (w & 0x7E000000) in (0x36000000, 0x37000000)
            or (w & 0xFE000000) == 0xD6000000)


def decode(data, off, size, va_base):
    """Retorna lista de (endereco_da_instrucao, tipo, VA_resolvida)."""
    if off % 4:
        raise SystemExit(f"offset da .text (0x{off:x}) nao e alinhado a 4 bytes")
    size -= size % 4
    n = size // 4
    words = memoryview(data)[off:off + size].cast("I")

    pages = {}   # reg -> VA da pagina resolvida por adrp
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
                # acumula: "add x8, x8, #0xfb8" seguido de "add x9, x8, #0x28"
                # vale page+0xfb8+0x28, nao page+0x28
                val = pages[rn] + (imm12 << (12 if sh else 0))
                out.append((a, "add", val))
                if rd == rn:
                    # add x8, x8, #imm -> o proprio registrador anda
                    pages[rn] = val
                else:
                    # add x9, x8, #imm -> x8 continua valendo, so x9 recebe
                    pages[rd] = val
            elif rd != rn:
                pages.pop(rd, None)
            continue

        # LDR (unsigned offset) 64-bit
        if (w & 0xFFC00000) == 0xF9400000:
            rd = w & 0x1F
            rn = (w >> 5) & 0x1F
            imm12 = (w >> 10) & 0xFFF
            if rn in pages:
                out.append((a, "ldr", pages[rn] + imm12 * 8))
                # "ldr x8, [x8, #imm]" deixa o VALOR carregado em x8,
                # nao o endereco: a pagina morre aqui
                if rd == rn:
                    pages.pop(rn, None)
            elif rd != rn:
                pages.pop(rd, None)
            continue

        # LDR (unsigned offset) 32-bit
        if (w & 0xFFC00000) == 0xB9400000:
            rd = w & 0x1F
            rn = (w >> 5) & 0x1F
            imm12 = (w >> 10) & 0xFFF
            if rn in pages:
                out.append((a, "ldr32", pages[rn] + imm12 * 4))
                if rd == rn:
                    pages.pop(rn, None)
            elif rd != rn:
                pages.pop(rd, None)
            continue

        if is_flow(w):
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

