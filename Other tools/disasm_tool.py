#!/usr/bin/env python
"""Simple SH-2 disassembler for Dragon's Dream binary analysis."""

import struct
import sys

def disasm_sh2(data, file_offset, count, base=0x06010000):
    """Simple SH-2 disassembler for the most common instructions."""
    pc = base + file_offset
    lines = []
    for i in range(0, count * 2, 2):
        off = file_offset + i
        if off + 1 >= len(data):
            break
        insn = (data[off] << 8) | data[off+1]
        addr = base + off
        mnem = f'{insn:04x}'  # default: just hex

        n = (insn >> 8) & 0xF
        m = (insn >> 4) & 0xF
        d_val = insn & 0xF

        if insn == 0x000B:
            mnem = 'rts'
        elif insn == 0x0009:
            mnem = 'nop'
        elif insn == 0x000B:
            mnem = 'rts'
        elif (insn & 0xF000) == 0x2000:
            sub = insn & 0xF
            if sub == 0x6:
                mnem = f'mov.l r{m},@-r{n}'
            elif sub == 0x2:
                mnem = f'mov.l r{m},@r{n}'
            elif sub == 0x1:
                mnem = f'mov.w r{m},@r{n}'
            elif sub == 0x0:
                mnem = f'mov.b r{m},@r{n}'
            elif sub == 0x8:
                mnem = f'tst r{m},r{n}'
            elif sub == 0x9:
                mnem = f'and r{m},r{n}'
            elif sub == 0xB:
                mnem = f'or r{m},r{n}'
            elif sub == 0xF:
                mnem = f'muls.w r{m},r{n}'
        elif (insn & 0xF000) == 0x6000:
            sub = insn & 0xF
            if sub == 0x6:
                mnem = f'mov.l @r{m}+,r{n}'
            elif sub == 0x3:
                mnem = f'mov r{m},r{n}'
            elif sub == 0x2:
                mnem = f'mov.l @r{m},r{n}'
            elif sub == 0x1:
                mnem = f'mov.w @r{m},r{n}'
            elif sub == 0x0:
                mnem = f'mov.b @r{m},r{n}'
            elif sub == 0xC:
                mnem = f'extu.b r{m},r{n}'
            elif sub == 0xD:
                mnem = f'extu.w r{m},r{n}'
            elif sub == 0xE:
                mnem = f'exts.b r{m},r{n}'
            elif sub == 0xF:
                mnem = f'exts.w r{m},r{n}'
        elif (insn & 0xF000) == 0xE000:
            imm = insn & 0xFF
            if imm > 127:
                imm = imm - 256
            mnem = f'mov #{imm},r{n}'
        elif (insn & 0xF000) == 0x7000:
            imm = insn & 0xFF
            if imm > 127:
                imm = imm - 256
            mnem = f'add #{imm},r{n}'
        elif (insn & 0xF000) == 0x3000:
            sub = insn & 0xF
            if sub == 0xC:
                mnem = f'add r{m},r{n}'
            elif sub == 0x0:
                mnem = f'cmp/eq r{m},r{n}'
            elif sub == 0x6:
                mnem = f'cmp/hi r{m},r{n}'
            elif sub == 0x3:
                mnem = f'cmp/ge r{m},r{n}'
            elif sub == 0x2:
                mnem = f'cmp/hs r{m},r{n}'
            elif sub == 0x7:
                mnem = f'cmp/gt r{m},r{n}'
            elif sub == 0x8:
                mnem = f'sub r{m},r{n}'
            elif sub == 0xE:
                mnem = f'addc r{m},r{n}'
        elif (insn & 0xFF00) == 0x8800:
            imm = insn & 0xFF
            mnem = f'cmp/eq #{imm},r0'
        elif (insn & 0xFF00) == 0x8900:
            disp = insn & 0xFF
            if disp > 127:
                disp = disp - 256
            target = addr + 4 + disp * 2
            mnem = f'bt 0x{target:08X}'
        elif (insn & 0xFF00) == 0x8B00:
            disp = insn & 0xFF
            if disp > 127:
                disp = disp - 256
            target = addr + 4 + disp * 2
            mnem = f'bf 0x{target:08X}'
        elif (insn & 0xFF00) == 0x8D00:
            disp = insn & 0xFF
            if disp > 127:
                disp = disp - 256
            target = addr + 4 + disp * 2
            mnem = f'bt/s 0x{target:08X}'
        elif (insn & 0xFF00) == 0x8F00:
            disp = insn & 0xFF
            if disp > 127:
                disp = disp - 256
            target = addr + 4 + disp * 2
            mnem = f'bf/s 0x{target:08X}'
        elif (insn & 0xF000) == 0xA000:
            disp = insn & 0xFFF
            if disp > 2047:
                disp = disp - 4096
            target = addr + 4 + disp * 2
            mnem = f'bra 0x{target:08X}'
        elif (insn & 0xF000) == 0xB000:
            disp = insn & 0xFFF
            if disp > 2047:
                disp = disp - 4096
            target = addr + 4 + disp * 2
            mnem = f'bsr 0x{target:08X}'
        elif (insn & 0xF0FF) == 0x400B:
            mnem = f'jsr @r{n}'
        elif (insn & 0xF0FF) == 0x402B:
            mnem = f'jmp @r{n}'
        elif (insn & 0xF0FF) == 0x4015:
            mnem = f'cmp/pl r{n}'
        elif (insn & 0xF0FF) == 0x4011:
            mnem = f'cmp/pz r{n}'
        elif (insn & 0xF0FF) == 0x4010:
            mnem = f'dt r{n}'
        elif (insn & 0xF0FF) == 0x4008:
            mnem = f'shll2 r{n}'
        elif (insn & 0xF0FF) == 0x4009:
            mnem = f'shlr2 r{n}'
        elif (insn & 0xF0FF) == 0x4000:
            mnem = f'shll r{n}'
        elif (insn & 0xF0FF) == 0x4001:
            mnem = f'shlr r{n}'
        elif (insn & 0xF0FF) == 0x4018:
            mnem = f'shll8 r{n}'
        elif (insn & 0xF0FF) == 0x4019:
            mnem = f'shlr8 r{n}'
        elif (insn & 0xF0FF) == 0x401C:
            mnem = f'shad r{m},r{n}'
        elif (insn & 0xF000) == 0x1000:
            disp4 = insn & 0xF
            mnem = f'mov.l r{m},@({disp4*4},r{n})'
        elif (insn & 0xF000) == 0x5000:
            disp4 = insn & 0xF
            mnem = f'mov.l @({disp4*4},r{m}),r{n}'
        elif (insn & 0xF000) == 0x0000:
            sub = insn & 0xF
            if sub == 0xC:
                mnem = f'mov.b @(r0,r{m}),r{n}'
            elif sub == 0xD:
                mnem = f'mov.w @(r0,r{m}),r{n}'
            elif sub == 0xE:
                mnem = f'mov.l @(r0,r{m}),r{n}'
        elif (insn & 0xF000) == 0xD000:
            disp8 = insn & 0xFF
            pool_addr = (addr & ~3) + 4 + disp8 * 4
            pool_off = pool_addr - base
            if 0 <= pool_off < len(data) - 3:
                val = struct.unpack('>I', data[pool_off:pool_off+4])[0]
                mnem = f'mov.l @(0x{pool_addr:08X}),r{n}  ; =0x{val:08X}'
            else:
                mnem = f'mov.l @(0x{pool_addr:08X}),r{n}'
        elif (insn & 0xF000) == 0x9000:
            disp8 = insn & 0xFF
            pool_addr = addr + 4 + disp8 * 2
            pool_off = pool_addr - base
            if 0 <= pool_off < len(data) - 1:
                val = struct.unpack('>H', data[pool_off:pool_off+2])[0]
                mnem = f'mov.w @(0x{pool_addr:08X}),r{n}  ; =0x{val:04X}'
            else:
                mnem = f'mov.w @(0x{pool_addr:08X}),r{n}'
        elif (insn & 0xFF00) == 0xC600:
            disp8 = insn & 0xFF
            mnem = f'mov.l @({disp8*4},GBR),r0'
        elif (insn & 0xFF00) == 0x8000:
            disp4 = insn & 0xF
            rn = (insn >> 4) & 0xF
            mnem = f'mov.b r0,@({disp4},r{rn})'
        elif (insn & 0xFF00) == 0x8100:
            disp4 = insn & 0xF
            rn = (insn >> 4) & 0xF
            mnem = f'mov.w r0,@({disp4*2},r{rn})'
        elif (insn & 0xFF00) == 0x8400:
            disp4 = insn & 0xF
            rm = (insn >> 4) & 0xF
            mnem = f'mov.b @({disp4},r{rm}),r0'
        elif (insn & 0xFF00) == 0x8500:
            disp4 = insn & 0xF
            rm = (insn >> 4) & 0xF
            mnem = f'mov.w @({disp4*2},r{rm}),r0'
        elif (insn & 0xF00F) == 0x000C:
            mnem = f'mov.b @(r0,r{m}),r{n}'
        elif (insn & 0xF00F) == 0x000D:
            mnem = f'mov.w @(r0,r{m}),r{n}'
        elif (insn & 0xF00F) == 0x000E:
            mnem = f'mov.l @(r0,r{m}),r{n}'
        elif (insn & 0xF00F) == 0x0004:
            mnem = f'mov.b r{m},@(r0,r{n})'
        elif (insn & 0xF00F) == 0x0005:
            mnem = f'mov.w r{m},@(r0,r{n})'
        elif (insn & 0xF00F) == 0x0006:
            mnem = f'mov.l r{m},@(r0,r{n})'

        lines.append(f'  0x{addr:08X}: {data[off]:02x}{data[off+1]:02x}  {mnem}')
    return '\n'.join(lines)


with open('D:/DragonsDreamDecomp/extracted/0.BIN', 'rb') as f:
    data = f.read()

# Parse command line args
if len(sys.argv) >= 3:
    file_offset = int(sys.argv[1], 0)
    count = int(sys.argv[2], 0)
    label = sys.argv[3] if len(sys.argv) > 3 else f'Code at file 0x{file_offset:06X}'
    print(f'=== {label} ===')
    print(disasm_sh2(data, file_offset, count))
else:
    # Default: disassemble login state machine
    print('=== Login State Machine at 0x0601BFA0 (file 0xBFA0) ===')
    print(disasm_sh2(data, 0xBFA0, 100))
