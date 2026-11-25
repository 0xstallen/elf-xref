import sys
from pathlib import Path
from elftools.elf.elffile import ELFFile

if len(sys.argv) < 3:
    raise SystemExit("uso: python str_at.py <lib.so> 0xVA [0xVA ...]")

SO = Path(sys.argv[1])
data = SO.read_bytes()

with SO.open('rb') as fh:
    elf = ELFFile(fh)
    segs = []
    for s in elf.iter_sections():
        if s['sh_type'] == 'SHT_NOBITS':
            continue
        if s['sh_size'] == 0:
            continue
        segs.append((s['sh_addr'], s['sh_size'], s['sh_offset'], s.name))


def va_to_off(va):
    for v, size, off, name in segs:
        if v <= va < v + size:
            return off + (va - v)
    return None


for arg in sys.argv[2:]:
    va = int(arg, 16)
    off = va_to_off(va)
    if off is None:
        print(f"0x{va:08x}  <fora do arquivo>")
        continue
    end = data.index(b'\x00', off)
    txt = data[off:end].decode('ascii', 'replace')
    print(f"0x{va:08x}  {txt}")
