#!/usr/bin/env python
"""SH-2 disassembler for Dragon's Dream binary analysis."""
import struct, sys

with open('D:/DragonsDreamDecomp/extracted/0.BIN', 'rb') as f:
    data = f.read()

def read16(offset):
    return struct.unpack('>H', data[offset:offset+2])[0]

def read32(offset):
    return struct.unpack('>I', data[offset:offset+4])[0]

def sext8(v):
    return v - 0x100 if v & 0x80 else v

def sext12(v):
    return v - 0x1000 if v & 0x800 else v

BASE = 0x06010000

def disasm_one(off):
    insn = read16(off)
    pc = off + BASE
    pc4 = (pc + 4) & 0xFFFFFFFC
    n = (insn >> 12) & 0xF
    rn = (insn >> 8) & 0xF
    rm = (insn >> 4) & 0xF
    lo4 = insn & 0xF
    lo8 = insn & 0xFF

    if insn == 0x0009: return 'nop'
    if insn == 0x000B: return 'rts'
    if insn == 0x0019: return 'div0u'

    if n == 0xE: return 'mov #%d,r%d' % (sext8(lo8), rn)
    if n == 0x7: return 'add #%d,r%d' % (sext8(lo8), rn)

    if n == 0x9:
        addr = (pc + 4) + lo8 * 2
        val = read16(addr - BASE)
        sval = val if val < 0x8000 else val - 0x10000
        return 'mov.w @(0x%08X),r%d  ; =0x%04X (%d)' % (addr, rn, val, sval)

    if n == 0xD:
        addr = pc4 + lo8 * 4
        val = read32(addr - BASE)
        return 'mov.l @(0x%08X),r%d  ; =0x%08X' % (addr, rn, val)

    if n == 0x1: return 'mov.l r%d,@(%d,r%d)' % (rm, lo4*4, rn)
    if n == 0x5: return 'mov.l @(%d,r%d),r%d' % (lo4*4, rm, rn)

    if n == 0xA:
        d = sext12(insn & 0xFFF)
        return 'bra 0x%08X' % (pc + 4 + d*2)
    if n == 0xB:
        d = sext12(insn & 0xFFF)
        return 'bsr 0x%08X' % (pc + 4 + d*2)

    if n == 0x8:
        sub = (insn >> 8) & 0xF
        if sub == 0x0: return 'mov.b r0,@(%d,r%d)' % (lo4, rm)
        if sub == 0x1: return 'mov.w r0,@(%d,r%d)' % (lo4*2, rm)
        if sub == 0x4: return 'mov.b @(%d,r%d),r0' % (lo4, rm)
        if sub == 0x5: return 'mov.w @(%d,r%d),r0' % (lo4*2, rm)
        if sub == 0x8: return 'cmp/eq #%d,r0' % sext8(lo8)
        if sub == 0x9:
            d = sext8(lo8)
            return 'bt 0x%08X' % (pc + 4 + d*2)
        if sub == 0xB:
            d = sext8(lo8)
            return 'bf 0x%08X' % (pc + 4 + d*2)
        if sub == 0xD:
            d = sext8(lo8)
            return 'bt/s 0x%08X' % (pc + 4 + d*2)
        if sub == 0xF:
            d = sext8(lo8)
            return 'bf/s 0x%08X' % (pc + 4 + d*2)

    if n == 0xC:
        sub = (insn >> 8) & 0xF
        if sub == 0x7:
            addr = pc4 + lo8 * 4
            val = read32(addr - BASE)
            return 'mova @(0x%08X),r0  ; =0x%08X' % (addr, val)
        if sub == 0x8: return 'tst #0x%02X,r0' % lo8
        if sub == 0x9: return 'and #0x%02X,r0' % lo8
        if sub == 0xB: return 'or #0x%02X,r0' % lo8

    if n == 0x0:
        if lo4 == 0x2:
            if rm == 0: return 'stc sr,r%d' % rn
        if lo4 == 0x3:
            if rm == 0: return 'bsrf r%d' % rn
            if rm == 2: return 'braf r%d' % rn
        if lo4 == 0x4: return 'mov.b r%d,@(r0,r%d)' % (rm, rn)
        if lo4 == 0x5: return 'mov.w r%d,@(r0,r%d)' % (rm, rn)
        if lo4 == 0x6: return 'mov.l r%d,@(r0,r%d)' % (rm, rn)
        if lo4 == 0x7: return 'mul.l r%d,r%d' % (rm, rn)
        if lo4 == 0xC: return 'mov.b @(r0,r%d),r%d' % (rm, rn)
        if lo4 == 0xD: return 'mov.w @(r0,r%d),r%d' % (rm, rn)
        if lo4 == 0xE: return 'mov.l @(r0,r%d),r%d' % (rm, rn)
        if lo4 == 0xF: return 'mac.l @r%d+,@r%d+' % (rm, rn)

    if n == 0x2:
        ops = {0:'mov.b r%d,@r%d', 1:'mov.w r%d,@r%d', 2:'mov.l r%d,@r%d',
               4:'mov.b r%d,@-r%d', 5:'mov.w r%d,@-r%d', 6:'mov.l r%d,@-r%d',
               7:'div0s r%d,r%d', 8:'tst r%d,r%d', 9:'and r%d,r%d',
               0xA:'xor r%d,r%d', 0xB:'or r%d,r%d', 0xC:'cmp/str r%d,r%d',
               0xD:'xtrct r%d,r%d', 0xE:'mulu.w r%d,r%d', 0xF:'muls.w r%d,r%d'}
        if lo4 in ops: return ops[lo4] % (rm, rn)

    if n == 0x3:
        ops = {0:'cmp/eq r%d,r%d', 2:'cmp/hs r%d,r%d', 3:'cmp/ge r%d,r%d',
               4:'div1 r%d,r%d', 5:'dmulu.l r%d,r%d', 6:'cmp/hi r%d,r%d',
               7:'cmp/gt r%d,r%d', 8:'sub r%d,r%d', 0xA:'subc r%d,r%d',
               0xC:'add r%d,r%d', 0xD:'dmuls.l r%d,r%d', 0xE:'addc r%d,r%d'}
        if lo4 in ops: return ops[lo4] % (rm, rn)

    if n == 0x4:
        singles = {0x00:'shll r%d',0x01:'shlr r%d',0x02:'sts.l mach,@-r%d',
                   0x04:'rotl r%d',0x05:'rotr r%d',0x06:'lds.l @r%d+,mach',
                   0x08:'shll2 r%d',0x09:'shlr2 r%d',0x0A:'lds r%d,mach',
                   0x0B:'jsr @r%d',0x0E:'ldc r%d,sr',0x10:'dt r%d',
                   0x11:'cmp/pz r%d',0x12:'sts.l macl,@-r%d',0x15:'cmp/pl r%d',
                   0x16:'lds.l @r%d+,macl',0x18:'shll8 r%d',0x19:'shlr8 r%d',
                   0x1A:'lds r%d,macl',0x1B:'tas.b @r%d',0x1E:'ldc r%d,gbr',
                   0x20:'shal r%d',0x21:'shar r%d',0x22:'sts.l pr,@-r%d',
                   0x24:'rotcl r%d',0x25:'rotcr r%d',0x26:'lds.l @r%d+,pr',
                   0x28:'shll16 r%d',0x29:'shlr16 r%d',0x2A:'lds r%d,pr',
                   0x2B:'jmp @r%d'}
        if lo8 in singles: return singles[lo8] % rn

    if n == 0x6:
        ops = {0:'mov.b @r%d,r%d', 1:'mov.w @r%d,r%d', 2:'mov.l @r%d,r%d',
               3:'mov r%d,r%d', 4:'mov.b @r%d+,r%d', 5:'mov.w @r%d+,r%d',
               6:'mov.l @r%d+,r%d', 7:'not r%d,r%d', 8:'swap.b r%d,r%d',
               9:'swap.w r%d,r%d', 0xA:'negc r%d,r%d', 0xB:'neg r%d,r%d',
               0xC:'extu.b r%d,r%d', 0xD:'extu.w r%d,r%d',
               0xE:'exts.b r%d,r%d', 0xF:'exts.w r%d,r%d'}
        if lo4 in ops: return ops[lo4] % (rm, rn)

    if (insn & 0xFF00) == 0x4F00:
        return 'add #%d,r15  ; sp adjust' % sext8(lo8)

    return '??? (0x%04X)' % insn


def disasm_range(file_start, count):
    for i in range(count):
        off = file_start + i * 2
        if off + 2 > len(data): break
        pc = off + BASE
        insn = read16(off)
        txt = disasm_one(off)
        print('  %08X [%06X]: %04X  %s' % (pc, off, insn, txt))

if __name__ == '__main__':
    start = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x0323C8
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 400
    disasm_range(start, count)
