import struct
import sys

data = open('0.BIN','rb').read()
base = 0x06010000

def disasm_sh2(data, offset, count, base_addr):
    pc = base_addr + offset
    results = []
    for i in range(count):
        if offset + i*2 + 2 > len(data):
            break
        insn = struct.unpack('>H', data[offset+i*2:offset+i*2+2])[0]
        addr = pc + i*2

        s = '0x%08X: %04X  ' % (addr, insn)

        nibble = (insn >> 12) & 0xF

        if insn == 0x000B:
            s += 'rts'
        elif insn == 0x0009:
            s += 'nop'
        elif nibble == 0xE:
            rn = (insn >> 8) & 0xF
            imm = insn & 0xFF
            if imm > 127: imm -= 256
            s += 'mov #%d,r%d' % (imm, rn)
        elif nibble == 0xD:
            rn = (insn >> 8) & 0xF
            disp = insn & 0xFF
            target = ((addr + 4) & ~3) + disp * 4
            toff = target - base_addr
            if 0 <= toff < len(data) - 3:
                val = struct.unpack('>I', data[toff:toff+4])[0]
                s += 'mov.l @(0x%X,PC),r%d  ; [0x%08X] = 0x%08X' % (disp*4, rn, target, val)
            else:
                s += 'mov.l @(0x%X,PC),r%d  ; [0x%08X]' % (disp*4, rn, target)
        elif nibble == 0xC:
            sub = (insn >> 8) & 0xF
            if sub == 0x6:
                disp = insn & 0xFF
                s += 'mov.l @(0x%X,GBR),r0' % (disp*4)
            elif sub == 0x7:
                disp = insn & 0xFF
                target = ((addr + 4) & ~3) + disp * 4
                s += 'mova @(0x%X,PC),r0  ; r0=0x%08X' % (disp*4, target)
            else:
                s += '??? (0xC%Xxx)' % sub
        elif nibble == 0x9:
            rn = (insn >> 8) & 0xF
            disp = insn & 0xFF
            target = addr + 4 + disp * 2
            toff = target - base_addr
            if 0 <= toff < len(data) - 1:
                val = struct.unpack('>H', data[toff:toff+2])[0]
                s += 'mov.w @(0x%X,PC),r%d  ; [0x%08X] = 0x%04X (%d)' % (disp*2, rn, target, val, val)
            else:
                s += 'mov.w @(0x%X,PC),r%d' % (disp*2, rn)
        elif nibble == 0x8:
            sub = (insn >> 8) & 0xF
            if sub == 0x9:
                disp = insn & 0xFF
                if disp > 127: disp -= 256
                target = addr + 4 + disp * 2
                s += 'bt 0x%08X' % target
            elif sub == 0xB:
                disp = insn & 0xFF
                if disp > 127: disp -= 256
                target = addr + 4 + disp * 2
                s += 'bf 0x%08X' % target
            elif sub == 0xD:
                disp = insn & 0xFF
                if disp > 127: disp -= 256
                target = addr + 4 + disp * 2
                s += 'bt/s 0x%08X' % target
            elif sub == 0xF:
                disp = insn & 0xFF
                if disp > 127: disp -= 256
                target = addr + 4 + disp * 2
                s += 'bf/s 0x%08X' % target
            elif sub == 0x5:
                rm = (insn >> 4) & 0xF
                disp = insn & 0xF
                s += 'mov.w @(%d,r%d),r0' % (disp*2, rm)
            elif sub == 0x1:
                rm = (insn >> 4) & 0xF
                disp = insn & 0xF
                s += 'mov.w r0,@(%d,r%d)' % (disp*2, rm)
            elif sub == 0x0:
                rm = (insn >> 4) & 0xF
                disp = insn & 0xF
                s += 'mov.b r0,@(%d,r%d)' % (disp, rm)
            elif sub == 0x4:
                rm = (insn >> 4) & 0xF
                disp = insn & 0xF
                s += 'mov.b @(%d,r%d),r0' % (disp, rm)
            elif sub == 0x8:
                imm8 = insn & 0xFF
                if imm8 > 127: imm8 -= 256
                s += 'cmp/eq #%d,r0' % imm8
            else:
                s += '??? (0x8%Xxx)' % sub
        elif nibble == 0xA:
            disp = insn & 0xFFF
            if disp > 0x7FF: disp -= 0x1000
            target = addr + 4 + disp * 2
            s += 'bra 0x%08X' % target
        elif nibble == 0xB:
            disp = insn & 0xFFF
            if disp > 0x7FF: disp -= 0x1000
            target = addr + 4 + disp * 2
            s += 'bsr 0x%08X' % target
        elif nibble == 0x4:
            rm = (insn >> 8) & 0xF
            sub = insn & 0xFF
            if sub == 0x0B:
                s += 'jsr @r%d' % rm
            elif sub == 0x2B:
                s += 'jmp @r%d' % rm
            elif sub == 0x08:
                s += 'shll2 r%d' % rm
            elif sub == 0x09:
                s += 'shlr2 r%d' % rm
            elif sub == 0x00:
                s += 'shll r%d' % rm
            elif sub == 0x01:
                s += 'shlr r%d' % rm
            elif sub == 0x18:
                s += 'shll8 r%d' % rm
            elif sub == 0x19:
                s += 'shlr8 r%d' % rm
            elif sub == 0x28:
                s += 'shll16 r%d' % rm
            elif sub == 0x29:
                s += 'shlr16 r%d' % rm
            elif sub == 0x26:
                s += 'lds.l @r%d+,PR' % rm
            elif sub == 0x06:
                s += 'lds.l @r%d+,MACH' % rm
            elif sub == 0x16:
                s += 'lds.l @r%d+,MACL' % rm
            elif sub == 0x15:
                s += 'cmp/pl r%d' % rm
            elif sub == 0x10:
                s += 'dt r%d' % rm
            elif sub == 0x11:
                s += 'cmp/pz r%d' % rm
            elif sub == 0x22:
                s += 'sts.l PR,@-r%d' % rm
            elif sub == 0x24:
                s += 'rotcl r%d' % rm
            elif sub == 0x04:
                s += 'rotl r%d' % rm
            elif sub == 0x05:
                s += 'rotr r%d' % rm
            else:
                s += 'r%d op=0x%02X' % (rm, sub)
        elif nibble == 0x6:
            rn = (insn >> 8) & 0xF
            rm = (insn >> 4) & 0xF
            sub = insn & 0xF
            if sub == 0x3:
                s += 'mov r%d,r%d' % (rm, rn)
            elif sub == 0x2:
                s += 'mov.l @r%d,r%d' % (rm, rn)
            elif sub == 0x1:
                s += 'mov.w @r%d+,r%d' % (rm, rn)
            elif sub == 0x6:
                s += 'mov.l @r%d+,r%d' % (rm, rn)
            elif sub == 0xF:
                s += 'exts.w r%d,r%d' % (rm, rn)
            elif sub == 0xC:
                s += 'extu.b r%d,r%d' % (rm, rn)
            elif sub == 0xD:
                s += 'extu.w r%d,r%d' % (rm, rn)
            elif sub == 0x0:
                s += 'mov.b @r%d,r%d' % (rm, rn)
            elif sub == 0x4:
                s += 'mov.b @r%d+,r%d' % (rm, rn)
            elif sub == 0x8:
                s += 'swap.b r%d,r%d' % (rm, rn)
            elif sub == 0x9:
                s += 'swap.w r%d,r%d' % (rm, rn)
            elif sub == 0xE:
                s += 'exts.b r%d,r%d' % (rm, rn)
            elif sub == 0x7:
                s += 'not r%d,r%d' % (rm, rn)
            else:
                s += 'mov.?? r%d,r%d sub=%d' % (rm, rn, sub)
        elif nibble == 0x2:
            rn = (insn >> 8) & 0xF
            rm = (insn >> 4) & 0xF
            sub = insn & 0xF
            if sub == 0x0:
                s += 'mov.b r%d,@r%d' % (rm, rn)
            elif sub == 0x1:
                s += 'mov.w r%d,@r%d' % (rm, rn)
            elif sub == 0x2:
                s += 'mov.l r%d,@r%d' % (rm, rn)
            elif sub == 0x8:
                s += 'tst r%d,r%d' % (rm, rn)
            elif sub == 0xF:
                s += 'muls.w r%d,r%d' % (rm, rn)
            elif sub == 0x6:
                s += 'mov.l r%d,@-r%d' % (rm, rn)
            elif sub == 0x4:
                s += 'mov.b r%d,@-r%d' % (rm, rn)
            elif sub == 0x5:
                s += 'mov.w r%d,@-r%d' % (rm, rn)
            elif sub == 0xE:
                s += 'mulu.w r%d,r%d' % (rm, rn)
            elif sub == 0x9:
                s += 'and r%d,r%d' % (rm, rn)
            elif sub == 0xA:
                s += 'xor r%d,r%d' % (rm, rn)
            elif sub == 0xB:
                s += 'or r%d,r%d' % (rm, rn)
            else:
                s += '??? r%d,r%d sub=0x2%X' % (rm, rn, sub)
        elif nibble == 0x3:
            rn = (insn >> 8) & 0xF
            rm = (insn >> 4) & 0xF
            sub = insn & 0xF
            if sub == 0x0:
                s += 'cmp/eq r%d,r%d' % (rm, rn)
            elif sub == 0xC:
                s += 'add r%d,r%d' % (rm, rn)
            elif sub == 0x6:
                s += 'cmp/hi r%d,r%d' % (rm, rn)
            elif sub == 0x2:
                s += 'cmp/hs r%d,r%d' % (rm, rn)
            elif sub == 0x8:
                s += 'sub r%d,r%d' % (rm, rn)
            elif sub == 0x3:
                s += 'cmp/ge r%d,r%d' % (rm, rn)
            elif sub == 0x7:
                s += 'cmp/gt r%d,r%d' % (rm, rn)
            elif sub == 0x4:
                s += 'div1 r%d,r%d' % (rm, rn)
            elif sub == 0xE:
                s += 'addc r%d,r%d' % (rm, rn)
            elif sub == 0xA:
                s += 'subc r%d,r%d' % (rm, rn)
            else:
                s += '??? r%d,r%d sub=0x3%X' % (rm, rn, sub)
        elif nibble == 0x7:
            rn = (insn >> 8) & 0xF
            imm = insn & 0xFF
            if imm > 127: imm -= 256
            s += 'add #%d,r%d' % (imm, rn)
        elif nibble == 0x1:
            rn = (insn >> 8) & 0xF
            rm = (insn >> 4) & 0xF
            disp = insn & 0xF
            s += 'mov.l r%d,@(%d,r%d)' % (rm, disp*4, rn)
        elif nibble == 0x5:
            rn = (insn >> 8) & 0xF
            rm = (insn >> 4) & 0xF
            disp = insn & 0xF
            s += 'mov.l @(%d,r%d),r%d' % (disp*4, rm, rn)
        elif nibble == 0x0:
            rn = (insn >> 8) & 0xF
            sub_lo = insn & 0xF
            rm = (insn >> 4) & 0xF
            if sub_lo == 0xD:
                s += 'mov.w @(r0,r%d),r%d' % (rm, rn)
            elif sub_lo == 0xC:
                s += 'mov.b @(r0,r%d),r%d' % (rm, rn)
            elif sub_lo == 0xE:
                s += 'mov.l @(r0,r%d),r%d' % (rm, rn)
            elif sub_lo == 0x4:
                s += 'mov.b r%d,@(r0,r%d)' % (rm, rn)
            elif sub_lo == 0x5:
                s += 'mov.w r%d,@(r0,r%d)' % (rm, rn)
            elif sub_lo == 0x6:
                s += 'mov.l r%d,@(r0,r%d)' % (rm, rn)
            elif sub_lo == 0x7:
                s += 'mul.l r%d,r%d' % (rm, rn)
            elif insn == 0x0002:
                s += 'stc SR,r%d' % rn
            elif insn == 0x000A:
                s += 'sts MACH,r%d' % rn
            elif insn == 0x001A:
                s += 'sts MACL,r%d' % rn
            elif insn == 0x002A:
                s += 'sts PR,r%d' % rn
            else:
                s += 'op0 r%d sub=0x%02X' % (rn, insn & 0xFF)
        else:
            s += '??? nibble=0x%X' % nibble

        results.append(s)
    return results


# Parse command line
if len(sys.argv) < 3:
    print("Usage: python disasm.py <hex_file_offset> <count>")
    sys.exit(1)

offset = int(sys.argv[1], 16)
count = int(sys.argv[2])

for line in disasm_sh2(data, offset, count, base):
    print(line)
