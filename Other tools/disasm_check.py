import struct
import sys

# Read the binary
with open('D:/DragonsDreamDecomp/extracted/0.BIN', 'rb') as f:
    data = f.read()

base = 0x06010000

def disasm_range(start_offset, max_instrs=300, stop_at_rts=True):
    pc = start_offset
    rts_seen = False
    count = 0

    for i in range(max_instrs):
        if pc >= len(data) - 1:
            break
        instr = struct.unpack('>H', data[pc:pc+2])[0]

        mnem = ''

        hi = (instr >> 12) & 0xF

        if instr == 0x000B:
            mnem = 'rts'
            rts_seen = True
        elif instr == 0x0009:
            mnem = 'nop'
        elif hi == 0xE:
            rn = (instr >> 8) & 0xF
            imm = instr & 0xFF
            if imm > 127: imm -= 256
            mnem = f'mov #{imm}, R{rn}'
        elif hi == 0xD:
            rn = (instr >> 8) & 0xF
            disp = instr & 0xFF
            addr = ((pc + 4) & ~3) + disp * 4
            if addr + 3 < len(data):
                val = struct.unpack('>I', data[addr:addr+4])[0]
                mnem = f'mov.l @(0x{addr:06X}), R{rn}  ; = 0x{val:08X}'
            else:
                mnem = f'mov.l @(0x{addr:06X}), R{rn}'
        elif hi == 0x9:
            rn = (instr >> 8) & 0xF
            disp = instr & 0xFF
            addr = (pc + 4) + disp * 2
            if addr + 1 < len(data):
                val = struct.unpack('>H', data[addr:addr+2])[0]
                mnem = f'mov.w @(0x{addr:06X}), R{rn}  ; = 0x{val:04X}'
            else:
                mnem = f'mov.w @(0x{addr:06X}), R{rn}'
        elif (instr >> 8) == 0x2F:
            rm = (instr >> 4) & 0xF
            mnem = f'mov.l R{rm}, @-R15  ; push R{rm}'
        elif instr == 0x4F22:
            mnem = 'sts.l PR, @-R15  ; push PR'
        elif instr == 0x4F26:
            mnem = 'lds.l @R15+, PR  ; pop PR'
        elif instr == 0x4F12:
            mnem = 'sts.l MACL, @-R15'
        elif (instr & 0xF00F) == 0x400B:
            rn = (instr >> 8) & 0xF
            mnem = f'jsr @R{rn}'
        elif (instr & 0xF0FF) == 0x6003:
            rn = (instr >> 8) & 0xF
            rm = (instr >> 4) & 0xF
            mnem = f'mov R{rm}, R{rn}'
        elif (instr & 0xF0FF) == 0x6002:
            rn = (instr >> 8) & 0xF
            rm = (instr >> 4) & 0xF
            mnem = f'mov.l @R{rm}, R{rn}'
        elif (instr & 0xF0FF) == 0x6001:
            rn = (instr >> 8) & 0xF
            rm = (instr >> 4) & 0xF
            mnem = f'mov.w @R{rm}, R{rn}'
        elif (instr & 0xF00F) == 0x6013:
            rn = (instr >> 8) & 0xF
            rm = (instr >> 4) & 0xF
            mnem = f'mov R{rm}, R{rn}  ; (copy)'
        elif (instr >> 8) == 0x88:
            imm = instr & 0xFF
            if imm > 127: imm -= 256
            mnem = f'cmp/eq #{imm}, R0'
        elif (instr >> 8) == 0x89:
            disp = instr & 0xFF
            if disp > 127: disp -= 256
            target = pc + 4 + disp * 2
            mnem = f'bt 0x{target:06X}  (mem 0x{base+target:08X})'
        elif (instr >> 8) == 0x8B:
            disp = instr & 0xFF
            if disp > 127: disp -= 256
            target = pc + 4 + disp * 2
            mnem = f'bf 0x{target:06X}  (mem 0x{base+target:08X})'
        elif (instr >> 8) == 0x8F:
            disp = instr & 0xFF
            if disp > 127: disp -= 256
            target = pc + 4 + disp * 2
            mnem = f'bt/s 0x{target:06X}  (mem 0x{base+target:08X})'
        elif (instr >> 8) == 0x8D:
            disp = instr & 0xFF
            if disp > 127: disp -= 256
            target = pc + 4 + disp * 2
            mnem = f'bt/s 0x{target:06X}  (mem 0x{base+target:08X})'
        elif (instr & 0xF000) == 0xA000:
            disp = instr & 0xFFF
            if disp > 0x7FF: disp -= 0x1000
            target = pc + 4 + disp * 2
            mnem = f'bra 0x{target:06X}  (mem 0x{base+target:08X})'
        elif (instr & 0xF000) == 0xB000:
            disp = instr & 0xFFF
            if disp > 0x7FF: disp -= 0x1000
            target = pc + 4 + disp * 2
            mnem = f'bsr 0x{target:06X}  (mem 0x{base+target:08X})'
        elif (instr & 0xF00F) == 0x2008:
            rn = (instr >> 8) & 0xF
            rm = (instr >> 4) & 0xF
            mnem = f'tst R{rm}, R{rn}'
        elif (instr & 0xF00F) == 0x2001:
            rn = (instr >> 8) & 0xF
            rm = (instr >> 4) & 0xF
            mnem = f'mov.w R{rm}, @R{rn}'
        elif (instr & 0xF00F) == 0x2002:
            rn = (instr >> 8) & 0xF
            rm = (instr >> 4) & 0xF
            mnem = f'mov.l R{rm}, @R{rn}'
        elif (instr & 0xF00F) == 0x200B:
            rn = (instr >> 8) & 0xF
            rm = (instr >> 4) & 0xF
            mnem = f'or R{rm}, R{rn}'
        elif (instr >> 8) == 0x85:
            disp = instr & 0xF
            rm = (instr >> 4) & 0xF
            mnem = f'mov.w @({disp}*2, R{rm}), R0  ; @(R{rm}+0x{disp*2:X})'
        elif (instr >> 8) == 0x84:
            disp = instr & 0xF
            rm = (instr >> 4) & 0xF
            mnem = f'mov.b @({disp}, R{rm}), R0  ; @(R{rm}+0x{disp:X})'
        elif (instr >> 8) == 0x81:
            disp = instr & 0xF
            rm = (instr >> 4) & 0xF
            mnem = f'mov.w R0, @({disp}*2, R{rm})  ; @(R{rm}+0x{disp*2:X})'
        elif (instr >> 8) == 0x80:
            disp = instr & 0xF
            rm = (instr >> 4) & 0xF
            mnem = f'mov.b R0, @({disp}, R{rm})'
        elif (instr & 0xFF00) == 0xC600:
            disp = instr & 0xFF
            mnem = f'mov.l @(R0+GBR), R0  ; GBR[0x{disp*4:X}]'
        elif (instr & 0xFF00) == 0xC900:
            imm = instr & 0xFF
            mnem = f'and #{imm}, R0  ; & 0x{imm:02X}'
        elif (instr & 0xF000) == 0x7000:
            rn = (instr >> 8) & 0xF
            imm = instr & 0xFF
            if imm > 127: imm -= 256
            mnem = f'add #{imm}, R{rn}'
        elif (instr & 0xF00F) == 0x300C:
            rn = (instr >> 8) & 0xF
            rm = (instr >> 4) & 0xF
            mnem = f'add R{rm}, R{rn}'
        elif (instr & 0xF00F) == 0x3008:
            rn = (instr >> 8) & 0xF
            rm = (instr >> 4) & 0xF
            mnem = f'sub R{rm}, R{rn}'
        elif (instr & 0xF00F) == 0x3003:
            rn = (instr >> 8) & 0xF
            rm = (instr >> 4) & 0xF
            mnem = f'cmp/ge R{rm}, R{rn}'
        elif (instr & 0xF00F) == 0x3002:
            rn = (instr >> 8) & 0xF
            rm = (instr >> 4) & 0xF
            mnem = f'cmp/hs R{rm}, R{rn}'
        elif (instr & 0xF00F) == 0x3006:
            rn = (instr >> 8) & 0xF
            rm = (instr >> 4) & 0xF
            mnem = f'cmp/hi R{rm}, R{rn}'
        elif (instr & 0xF00F) == 0x3000:
            rn = (instr >> 8) & 0xF
            rm = (instr >> 4) & 0xF
            mnem = f'cmp/eq R{rm}, R{rn}'
        elif (instr & 0xF00F) == 0x3004:
            rn = (instr >> 8) & 0xF
            rm = (instr >> 4) & 0xF
            mnem = f'div1 R{rm}, R{rn}'
        elif (instr & 0xF0FF) == 0x4008:
            rn = (instr >> 8) & 0xF
            mnem = f'shll2 R{rn}'
        elif (instr & 0xF0FF) == 0x4028:
            rn = (instr >> 8) & 0xF
            mnem = f'shll16 R{rn}'
        elif (instr & 0xF0FF) == 0x4018:
            rn = (instr >> 8) & 0xF
            mnem = f'shll8 R{rn}'
        elif (instr & 0xF0FF) == 0x4009:
            rn = (instr >> 8) & 0xF
            mnem = f'shlr2 R{rn}'
        elif (instr & 0xF0FF) == 0x4019:
            rn = (instr >> 8) & 0xF
            mnem = f'shlr8 R{rn}'
        elif (instr & 0xF0FF) == 0x4029:
            rn = (instr >> 8) & 0xF
            mnem = f'shlr16 R{rn}'
        elif (instr & 0xF00F) == 0x000C:
            rn = (instr >> 8) & 0xF
            rm = (instr >> 4) & 0xF
            mnem = f'mov.b @(R0,R{rm}), R{rn}'
        elif (instr & 0xF00F) == 0x000D:
            rn = (instr >> 8) & 0xF
            rm = (instr >> 4) & 0xF
            mnem = f'mov.w @(R0,R{rm}), R{rn}'
        elif (instr & 0xF00F) == 0x000E:
            rn = (instr >> 8) & 0xF
            rm = (instr >> 4) & 0xF
            mnem = f'mov.l @(R0,R{rm}), R{rn}'
        elif (instr & 0xF00F) == 0x1000:
            rn = (instr >> 8) & 0xF
            rm = (instr >> 4) & 0xF
            disp = instr & 0xF
            mnem = f'mov.l R{rm}, @({disp}*4, R{rn})  ; @(R{rn}+0x{disp*4:X})'
        elif (instr & 0xF00F) == 0x5000:
            rn = (instr >> 8) & 0xF
            rm = (instr >> 4) & 0xF
            disp = instr & 0xF
            mnem = f'mov.l @({disp}*4, R{rm}), R{rn}  ; @(R{rm}+0x{disp*4:X})'
        elif (instr & 0xF00F) == 0x200A:
            rn = (instr >> 8) & 0xF
            rm = (instr >> 4) & 0xF
            mnem = f'xor R{rm}, R{rn}'
        elif (instr & 0xF00F) == 0x600E:
            rn = (instr >> 8) & 0xF
            rm = (instr >> 4) & 0xF
            mnem = f'exts.b R{rm}, R{rn}'
        elif (instr & 0xF00F) == 0x600F:
            rn = (instr >> 8) & 0xF
            rm = (instr >> 4) & 0xF
            mnem = f'exts.w R{rm}, R{rn}'
        elif (instr & 0xF0FF) == 0x6006:
            rn = (instr >> 8) & 0xF
            rm = (instr >> 4) & 0xF
            mnem = f'mov.l @R{rm}+, R{rn}  ; pop'
        elif (instr & 0xF0FF) == 0x4024:
            rn = (instr >> 8) & 0xF
            mnem = f'rotcl R{rn}'
        elif (instr & 0xF00F) == 0x2000:
            rn = (instr >> 8) & 0xF
            rm = (instr >> 4) & 0xF
            mnem = f'mov.b R{rm}, @R{rn}'
        elif (instr & 0xF00F) == 0x000F:
            rn = (instr >> 8) & 0xF
            rm = (instr >> 4) & 0xF
            mnem = f'mac.l @R{rm}+, @R{rn}+'
        elif (instr & 0xFF00) == 0xCB00:
            imm = instr & 0xFF
            mnem = f'or #{imm}, R0'
        elif (instr & 0xFF00) == 0xC800:
            imm = instr & 0xFF
            mnem = f'tst #{imm}, R0'
        elif (instr & 0xF0FF) == 0x4015:
            rn = (instr >> 8) & 0xF
            mnem = f'cmp/pl R{rn}'
        elif (instr & 0xF0FF) == 0x4011:
            rn = (instr >> 8) & 0xF
            mnem = f'cmp/pz R{rn}'
        elif (instr & 0xF00F) == 0x2009:
            rn = (instr >> 8) & 0xF
            rm = (instr >> 4) & 0xF
            mnem = f'and R{rm}, R{rn}'
        elif (instr & 0xF0FF) == 0x4000:
            rn = (instr >> 8) & 0xF
            mnem = f'shll R{rn}'
        elif (instr & 0xF0FF) == 0x4001:
            rn = (instr >> 8) & 0xF
            mnem = f'shlr R{rn}'
        elif (instr & 0xF00F) == 0x000E:
            rn = (instr >> 8) & 0xF
            rm = (instr >> 4) & 0xF
            mnem = f'mov.l @(R0,R{rm}), R{rn}'
        else:
            mnem = f'??? 0x{instr:04X}'

        addr = base + pc
        print(f'  0x{addr:08X} (0x{pc:06X}): {instr:04X}  {mnem}')

        if rts_seen and stop_at_rts:
            break

        pc += 2
        count += 1

if __name__ == '__main__':
    start = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x02C804
    max_i = int(sys.argv[2]) if len(sys.argv) > 2 else 300
    disasm_range(start, max_i)
