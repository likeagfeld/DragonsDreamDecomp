import struct
import sys

with open('D:/DragonsDreamDecomp/extracted/0.BIN', 'rb') as f:
    data = f.read()

base = 0x06010000

def decode(pc):
    instr = struct.unpack('>H', data[pc:pc+2])[0]
    hi = (instr >> 12) & 0xF
    rn = (instr >> 8) & 0xF
    rm = (instr >> 4) & 0xF
    lo = instr & 0xF
    imm8 = instr & 0xFF
    imm8s = imm8 - 256 if imm8 > 127 else imm8
    imm12 = instr & 0xFFF
    imm12s = imm12 - 4096 if imm12 > 2047 else imm12

    # Special encodings
    if instr == 0x000B:
        return 'rts'
    if instr == 0x0009:
        return 'nop'
    if instr == 0x0019:
        return 'div0u'
    if instr == 0x000B:
        return 'rts'
    if instr == 0x002B:
        return 'rte'
    if instr == 0x4F22:
        return 'sts.l PR, @-R15'
    if instr == 0x4F26:
        return 'lds.l @R15+, PR'
    if instr == 0x4F12:
        return 'sts.l MACL, @-R15'
    if instr == 0x4F16:
        return 'lds.l @R15+, MACL'

    # 0x0nmd
    if hi == 0x0:
        if lo == 0x2:
            return f'stc SR, R{rn}'  # or GBR/VBR
        if lo == 0x3:
            if rm & 0x3 == 0x0:
                return f'bsrf R{rn}'
            if rm & 0x3 == 0x2:
                return f'braf R{rn}'
        if lo == 0x4:
            return f'mov.b R{rm}, @(R0,R{rn})'
        if lo == 0x5:
            return f'mov.w R{rm}, @(R0,R{rn})'
        if lo == 0x6:
            return f'mov.l R{rm}, @(R0,R{rn})'
        if lo == 0x7:
            return f'mul.l R{rm}, R{rn}'
        if lo == 0x8:
            if rm == 0:
                return f'clrt'
            if rm == 1:
                return f'sett'
        if lo == 0x9:
            if rm == 0:
                return 'nop'
            if rm == 2:
                return f'movt R{rn}'
        if lo == 0xA:
            return f'sts MACH, R{rn}'
        if lo == 0xB:
            return 'rts'
        if lo == 0xC:
            return f'mov.b @(R0,R{rm}), R{rn}'
        if lo == 0xD:
            return f'mov.w @(R0,R{rm}), R{rn}'
        if lo == 0xE:
            return f'mov.l @(R0,R{rm}), R{rn}'
        if lo == 0xF:
            return f'mac.l @R{rm}+, @R{rn}+'
        return f'??? 0x{instr:04X}'

    # 0x1nmd - mov.l Rm, @(disp,Rn)
    if hi == 0x1:
        return f'mov.l R{rm}, @({lo}*4, R{rn})  ; @(R{rn}+0x{lo*4:X})'

    # 0x2nmd
    if hi == 0x2:
        ops = {0:'mov.b', 1:'mov.w', 2:'mov.l'}
        if lo in ops:
            return f'{ops[lo]} R{rm}, @R{rn}'
        if lo == 4:
            return f'mov.b R{rm}, @-R{rn}'
        if lo == 5:
            return f'mov.w R{rm}, @-R{rn}'
        if lo == 6:
            return f'mov.l R{rm}, @-R{rn}'
        if lo == 7:
            return f'div0s R{rm}, R{rn}'
        if lo == 8:
            return f'tst R{rm}, R{rn}'
        if lo == 9:
            return f'and R{rm}, R{rn}'
        if lo == 0xA:
            return f'xor R{rm}, R{rn}'
        if lo == 0xB:
            return f'or R{rm}, R{rn}'
        if lo == 0xC:
            return f'cmp/str R{rm}, R{rn}'
        if lo == 0xD:
            return f'xtrct R{rm}, R{rn}'
        if lo == 0xE:
            return f'mulu.w R{rm}, R{rn}'
        if lo == 0xF:
            return f'muls.w R{rm}, R{rn}'
        return f'??? 0x{instr:04X}'

    # 0x3nmd
    if hi == 0x3:
        ops3 = {0:'cmp/eq', 2:'cmp/hs', 3:'cmp/ge', 4:'div1', 6:'cmp/hi', 7:'cmp/gt',
                8:'sub', 0xC:'add', 0xE:'addc', 0xA:'subc'}
        if lo in ops3:
            return f'{ops3[lo]} R{rm}, R{rn}'
        return f'??? 0x{instr:04X}'

    # 0x4nxx
    if hi == 0x4:
        if lo == 0xB:
            return f'jsr @R{rn}'
        if lo == 0x8:
            if rm == 0:
                return f'shll2 R{rn}'
            if rm == 1:
                return f'shll8 R{rn}'
            if rm == 2:
                return f'shll16 R{rn}'
        if lo == 0x9:
            if rm == 0:
                return f'shlr2 R{rn}'
            if rm == 1:
                return f'shlr8 R{rn}'
            if rm == 2:
                return f'shlr16 R{rn}'
        if lo == 0x0:
            if rm == 0:
                return f'shll R{rn}'
            if rm == 1:
                return f'dt R{rn}'
            if rm == 2:
                return f'shal R{rn}'
        if lo == 0x1:
            if rm == 0:
                return f'shlr R{rn}'
            if rm == 2:
                return f'shar R{rn}'
        if lo == 0x4:
            if rm == 0:
                return f'rotl R{rn}'
            if rm == 2:
                return f'rotcl R{rn}'
        if lo == 0x5:
            if rm == 0:
                return f'rotr R{rn}'
            if rm == 1:
                return f'cmp/pl R{rn}'
            if rm == 2:
                return f'rotcr R{rn}'
        if lo == 0x2:
            if rm == 0:
                return f'sts.l MACH, @-R{rn}'
            if rm == 1:
                return f'sts.l MACL, @-R{rn}'
            if rm == 2:
                return f'sts.l PR, @-R{rn}'
        if lo == 0x6:
            if rm == 0:
                return f'lds.l @R{rn}+, MACH'
            if rm == 1:
                return f'lds.l @R{rn}+, MACL'
            if rm == 2:
                return f'lds.l @R{rn}+, PR'
        if lo == 0xA:
            return f'lds R{rn}, MACH' if rm == 0 else f'lds R{rn}, MACL' if rm == 1 else f'lds R{rn}, PR' if rm == 2 else f'??? 0x{instr:04X}'
        if lo == 0xE:
            return f'ldc R{rn}, SR' if rm == 0 else f'ldc R{rn}, GBR' if rm == 1 else f'ldc R{rn}, VBR' if rm == 2 else f'??? 0x{instr:04X}'
        return f'??? 0x{instr:04X}'

    # 0x5nmd - mov.l @(disp,Rm), Rn
    if hi == 0x5:
        return f'mov.l @({lo}*4, R{rm}), R{rn}  ; @(R{rm}+0x{lo*4:X})'

    # 0x6nmd
    if hi == 0x6:
        ops6 = {0:'mov.b @R{m}, R{n}', 1:'mov.w @R{m}, R{n}', 2:'mov.l @R{m}, R{n}',
                3:'mov R{m}, R{n}', 4:'mov.b @R{m}+, R{n}', 5:'mov.w @R{m}+, R{n}',
                6:'mov.l @R{m}+, R{n}', 7:'not R{m}, R{n}',
                8:'swap.b R{m}, R{n}', 9:'swap.w R{m}, R{n}',
                0xA:'negc R{m}, R{n}', 0xB:'neg R{m}, R{n}',
                0xC:'extu.b R{m}, R{n}', 0xD:'extu.w R{m}, R{n}',
                0xE:'exts.b R{m}, R{n}', 0xF:'exts.w R{m}, R{n}'}
        if lo in ops6:
            return ops6[lo].format(m=rm, n=rn)
        return f'??? 0x{instr:04X}'

    # 0x7nii - add #imm, Rn
    if hi == 0x7:
        return f'add #{imm8s}, R{rn}'

    # 0x8xxx
    if hi == 0x8:
        sub = (instr >> 8) & 0xF
        if sub == 0x0:
            return f'mov.b R0, @({lo}, R{rm})'
        if sub == 0x1:
            return f'mov.w R0, @({lo}*2, R{rm})  ; @(R{rm}+0x{lo*2:X})'
        if sub == 0x4:
            return f'mov.b @({lo}, R{rm}), R0  ; @(R{rm}+0x{lo:X})'
        if sub == 0x5:
            return f'mov.w @({lo}*2, R{rm}), R0  ; @(R{rm}+0x{lo*2:X})'
        if sub == 0x8:
            return f'cmp/eq #{imm8s}, R0'
        if sub == 0x9:
            d = imm8
            if d > 127: d -= 256
            target = pc + 4 + d * 2
            return f'bt 0x{target:06X}  (mem 0x{base+target:08X})'
        if sub == 0xB:
            d = imm8
            if d > 127: d -= 256
            target = pc + 4 + d * 2
            return f'bf 0x{target:06X}  (mem 0x{base+target:08X})'
        if sub == 0xD:
            d = imm8
            if d > 127: d -= 256
            target = pc + 4 + d * 2
            return f'bt/s 0x{target:06X}  (mem 0x{base+target:08X})'
        if sub == 0xF:
            d = imm8
            if d > 127: d -= 256
            target = pc + 4 + d * 2
            return f'bf/s 0x{target:06X}  (mem 0x{base+target:08X})'
        return f'??? 0x{instr:04X}'

    # 0x9ndd - mov.w @(disp,PC), Rn
    if hi == 0x9:
        addr = (pc + 4) + imm8 * 2
        if addr + 1 < len(data):
            val = struct.unpack('>H', data[addr:addr+2])[0]
            return f'mov.w @(0x{addr:06X}), R{rn}  ; = 0x{val:04X}'
        return f'mov.w @(0x{addr:06X}), R{rn}'

    # 0xAnnn - bra
    if hi == 0xA:
        target = pc + 4 + imm12s * 2
        return f'bra 0x{target:06X}  (mem 0x{base+target:08X})'

    # 0xBnnn - bsr
    if hi == 0xB:
        target = pc + 4 + imm12s * 2
        return f'bsr 0x{target:06X}  (mem 0x{base+target:08X})'

    # 0xCxii
    if hi == 0xC:
        sub = (instr >> 8) & 0xF
        if sub == 0x0:
            return f'mov.b R0, @({imm8}, GBR)'
        if sub == 0x1:
            return f'mov.w R0, @({imm8}*2, GBR)'
        if sub == 0x2:
            return f'mov.l R0, @({imm8}*4, GBR)'
        if sub == 0x4:
            return f'mov.b @({imm8}, GBR), R0'
        if sub == 0x5:
            return f'mov.w @({imm8}*2, GBR), R0'
        if sub == 0x6:
            return f'mov.l @({imm8}*4, GBR), R0  ; GBR[0x{imm8*4:X}]'
        if sub == 0x8:
            return f'tst #{imm8}, R0'
        if sub == 0x9:
            return f'and #{imm8}, R0  ; & 0x{imm8:02X}'
        if sub == 0xA:
            return f'xor #{imm8}, R0'
        if sub == 0xB:
            return f'or #{imm8}, R0'
        if sub == 0xD:
            return f'and.b #{imm8}, @(R0,GBR)'
        return f'??? 0x{instr:04X}'

    # 0xDndd - mov.l @(disp,PC), Rn
    if hi == 0xD:
        addr = ((pc + 4) & ~3) + imm8 * 4
        if addr + 3 < len(data):
            val = struct.unpack('>I', data[addr:addr+4])[0]
            return f'mov.l @(0x{addr:06X}), R{rn}  ; = 0x{val:08X}'
        return f'mov.l @(0x{addr:06X}), R{rn}'

    # 0xEnii - mov #imm, Rn
    if hi == 0xE:
        return f'mov #{imm8s}, R{rn}'

    # 0xFxxx - FPU
    if hi == 0xF:
        return f'fpu 0x{instr:04X}'

    return f'??? 0x{instr:04X}'

def disasm_func(start_offset, max_instrs=400):
    pc = start_offset
    rts_count = 0

    for i in range(max_instrs):
        if pc >= len(data) - 1:
            break
        instr = struct.unpack('>H', data[pc:pc+2])[0]
        mnem = decode(pc)

        addr = base + pc
        print(f'  {addr:08X} ({pc:06X}): {instr:04X}  {mnem}')

        if instr == 0x000B:  # rts
            # Print delay slot
            pc += 2
            if pc < len(data) - 1:
                instr2 = struct.unpack('>H', data[pc:pc+2])[0]
                mnem2 = decode(pc)
                addr2 = base + pc
                print(f'  {addr2:08X} ({pc:06X}): {instr2:04X}  {mnem2}  ; (delay slot)')
            break

        pc += 2

if __name__ == '__main__':
    start = int(sys.argv[1], 16)
    max_i = int(sys.argv[2]) if len(sys.argv) > 2 else 400
    disasm_func(start, max_i)
