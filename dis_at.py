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
elf = ELFFile(open(SO, 'rb'))


def va_to_off(va):
    for seg in elf.iter_segments():
        if seg['p_type'] != 'PT_LOAD':
            continue
        v = seg['p_vaddr']
        if v <= va < v + seg['p_filesz']:
            return seg['p_offset'] + (va - v)
    return None


start_va = VA - ANTES
off = va_to_off(start_va)
chunk = data[off:off + ANTES + DEPOIS]

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = False
md.skipdata = True

for ins in md.disasm(chunk, start_va):
    mark = '   <<<' if ins.address == VA else ''
    print('%08x  %-8s %s%s' % (ins.address, ins.mnemonic, ins.op_str, mark))
