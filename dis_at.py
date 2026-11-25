import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from elftools.elf.elffile import ELFFile

if len(sys.argv) < 3:
    raise SystemExit("uso: python dis_at.py <lib.so> 0xVA [antes] [depois]")

SO = sys.argv[1]
VA = int(sys.argv[2], 16)
ANTES = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0x80
DEPOIS = int(sys.argv[4], 16) if len(sys.argv) > 4 else 0x80

with open(SO, 'rb') as f:
    data = f.read()
    elf = ELFFile(f)
    segments = [(s['p_vaddr'], s['p_filesz'], s['p_offset'])
                for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']


def va_to_off(va):
    for v, size, off in segments:
        if v <= va < v + size:
            return off + (va - v)
    return None


start_va = VA - ANTES
off = va_to_off(start_va)
if off is None:
    raise SystemExit(f"0x{start_va:x} nao esta em nenhum segmento PT_LOAD")
chunk = data[off:off + ANTES + DEPOIS]

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = False
md.skipdata = True

for ins in md.disasm(chunk, start_va):
    mark = '   <<<' if ins.address == VA else ''
    print('%08x  %-8s %s%s' % (ins.address, ins.mnemonic, ins.op_str, mark))
