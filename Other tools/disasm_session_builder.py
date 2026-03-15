#!/usr/bin/env python3
"""
Disassemble the region around the literal pool at 0x0122F2 which contains
both 1F40 (8000) and 07D0 (2000) timeout values, and 060623D8 (SV send queue).

The literal pool at ~0x060222F2-0x06022320 suggests the function using these
constants is nearby. SH-2 literal pools are typically at the end of a function
or after a branch.

We need to find the function that references these literal pool entries.
"""

import struct

BINARY_PATH = r"D:\DragonsDreamDecomp\extracted\0.BIN"
BASE_ADDR = 0x06010000

def file_to_mem(off):
    return off + BASE_ADDR

def mem_to_file(addr):
    return addr - BASE_ADDR

# SH-2 instruction decoder (subset needed for analysis)
def decode_sh2(opcode, pc):
    """Decode a single SH-2 instruction. Returns mnemonic string."""
    n = (opcode >> 8) & 0xF
    m = (opcode >> 4) & 0xF
    d = opcode & 0xFF

    hi4 = (opcode >> 12) & 0xF

    if opcode == 0x0009:
        return "nop"
    if opcode == 0x000B:
        return "rts"
    if opcode == 0x002B:
        return "rte"

    # MOV.L @(disp,PC),Rn  (1101 nnnn dddd dddd)
    if hi4 == 0xD:
        disp = opcode & 0xFF
        target = (pc & ~3) + 4 + disp * 4
        return f"mov.l @(0x{disp*4:02X},PC),R{n}  ; @0x{target:08X}"

    # MOV.W @(disp,PC),Rn  (1001 nnnn dddd dddd)
    if hi4 == 0x9:
        disp = opcode & 0xFF
        target = pc + 4 + disp * 2
        return f"mov.w @(0x{disp*2:02X},PC),R{n}  ; @0x{target:08X}"

    # MOV #imm,Rn  (1110 nnnn iiii iiii)
    if hi4 == 0xE:
        imm = opcode & 0xFF
        if imm >= 0x80:
            imm_signed = imm - 256
            return f"mov #0x{imm:02X},R{n}  ; ={imm_signed} ({imm:#x})"
        else:
            return f"mov #0x{imm:02X},R{n}  ; ={imm}"

    # ADD #imm,Rn  (0111 nnnn iiii iiii)
    if hi4 == 0x7:
        imm = opcode & 0xFF
        if imm >= 0x80:
            imm_signed = imm - 256
            return f"add #{imm_signed},R{n}"
        else:
            return f"add #{imm},R{n}"

    # MOV.B Rm,@Rn (0010 nnnn mmmm 0000)
    if hi4 == 0x2 and (opcode & 0xF) == 0x0:
        return f"mov.b R{m},@R{n}"
    # MOV.W Rm,@Rn (0010 nnnn mmmm 0001)
    if hi4 == 0x2 and (opcode & 0xF) == 0x1:
        return f"mov.w R{m},@R{n}"
    # MOV.L Rm,@Rn (0010 nnnn mmmm 0010)
    if hi4 == 0x2 and (opcode & 0xF) == 0x2:
        return f"mov.l R{m},@R{n}"

    # MOV.B @Rm,Rn (0110 nnnn mmmm 0000)
    if hi4 == 0x6 and (opcode & 0xF) == 0x0:
        return f"mov.b @R{m},R{n}"
    # MOV.W @Rm,Rn (0110 nnnn mmmm 0001)
    if hi4 == 0x6 and (opcode & 0xF) == 0x1:
        return f"mov.w @R{m},R{n}"
    # MOV.L @Rm,Rn (0110 nnnn mmmm 0010)
    if hi4 == 0x6 and (opcode & 0xF) == 0x2:
        return f"mov.l @R{m},R{n}"

    # MOV Rm,Rn (0110 nnnn mmmm 0011)
    if hi4 == 0x6 and (opcode & 0xF) == 0x3:
        return f"mov R{m},R{n}"

    # MOV.B R0,@(disp,Rn) (10000000 nnnndddd)
    if (opcode >> 8) == 0x80:
        disp = opcode & 0xF
        return f"mov.b R0,@({disp},R{m})"
    # MOV.W R0,@(disp,Rn) (10000001 nnnndddd)
    if (opcode >> 8) == 0x81:
        disp = (opcode & 0xF) * 2
        return f"mov.w R0,@({disp},R{m})"

    # MOV.B @(disp,Rm),R0 (10000100 mmmmdddd)
    if (opcode >> 8) == 0x84:
        disp = opcode & 0xF
        return f"mov.b @({disp},R{m}),R0"
    # MOV.W @(disp,Rm),R0 (10000101 mmmmdddd)
    if (opcode >> 8) == 0x85:
        disp = (opcode & 0xF) * 2
        return f"mov.w @({disp},R{m}),R0"

    # MOV.L Rm,@(disp,Rn) (0001 nnnn mmmm dddd)
    if hi4 == 0x1:
        disp = (opcode & 0xF) * 4
        return f"mov.l R{m},@({disp},R{n})"

    # MOV.L @(disp,Rm),Rn (0101 nnnn mmmm dddd)
    if hi4 == 0x5:
        disp = (opcode & 0xF) * 4
        return f"mov.l @({disp},R{m}),R{n}"

    # MOV.B Rm,@-Rn (0010 nnnn mmmm 0100)
    if hi4 == 0x2 and (opcode & 0xF) == 0x4:
        return f"mov.b R{m},@-R{n}"
    # MOV.W Rm,@-Rn (0010 nnnn mmmm 0101)
    if hi4 == 0x2 and (opcode & 0xF) == 0x5:
        return f"mov.w R{m},@-R{n}"
    # MOV.L Rm,@-Rn (0010 nnnn mmmm 0110)
    if hi4 == 0x2 and (opcode & 0xF) == 0x6:
        return f"mov.l R{m},@-R{n}"

    # MOV.B @Rm+,Rn (0110 nnnn mmmm 0100)
    if hi4 == 0x6 and (opcode & 0xF) == 0x4:
        return f"mov.b @R{m}+,R{n}"
    # MOV.W @Rm+,Rn (0110 nnnn mmmm 0101)
    if hi4 == 0x6 and (opcode & 0xF) == 0x5:
        return f"mov.w @R{m}+,R{n}"
    # MOV.L @Rm+,Rn (0110 nnnn mmmm 0110)
    if hi4 == 0x6 and (opcode & 0xF) == 0x6:
        return f"mov.l @R{m}+,R{n}"

    # MOV.L R0,@(disp,GBR) (11000010 dddddddd)
    if (opcode >> 8) == 0xC6:
        disp = (opcode & 0xFF) * 4
        return f"mov.l R0,@({disp},GBR)"
    # MOV.L @(disp,GBR),R0 (11000110 dddddddd)
    if (opcode >> 8) == 0xC6:
        disp = (opcode & 0xFF) * 4
        return f"mov.l @({disp},GBR),R0"

    # STS.L PR,@-Rn (0100 nnnn 0010 0010)
    if hi4 == 0x4 and (opcode & 0xFF) == 0x22:
        return f"sts.l PR,@-R{n}"
    # LDS.L @Rn+,PR (0100 nnnn 0010 0110)
    if hi4 == 0x4 and (opcode & 0xFF) == 0x26:
        return f"lds.l @R{n}+,PR"

    # JSR @Rm (0100 mmmm 0000 1011)
    if hi4 == 0x4 and (opcode & 0xFF) == 0x0B:
        return f"jsr @R{n}"
    # JMP @Rm (0100 mmmm 0010 1011)
    if hi4 == 0x4 and (opcode & 0xFF) == 0x2B:
        return f"jmp @R{n}"

    # BSR disp (1011 dddddddddddd)
    if hi4 == 0xB:
        disp = opcode & 0xFFF
        if disp >= 0x800:
            disp -= 0x1000
        target = pc + 4 + disp * 2
        return f"bsr 0x{target:08X}"

    # BRA disp (1010 dddddddddddd)
    if hi4 == 0xA:
        disp = opcode & 0xFFF
        if disp >= 0x800:
            disp -= 0x1000
        target = pc + 4 + disp * 2
        return f"bra 0x{target:08X}"

    # BT disp (10001001 dddddddd)
    if (opcode >> 8) == 0x89:
        disp = opcode & 0xFF
        if disp >= 0x80:
            disp -= 0x100
        target = pc + 4 + disp * 2
        return f"bt 0x{target:08X}"
    # BF disp (10001011 dddddddd)
    if (opcode >> 8) == 0x8B:
        disp = opcode & 0xFF
        if disp >= 0x80:
            disp -= 0x100
        target = pc + 4 + disp * 2
        return f"bf 0x{target:08X}"
    # BT/S disp (10001101 dddddddd)
    if (opcode >> 8) == 0x8D:
        disp = opcode & 0xFF
        if disp >= 0x80:
            disp -= 0x100
        target = pc + 4 + disp * 2
        return f"bt/s 0x{target:08X}"
    # BF/S disp (10001111 dddddddd)
    if (opcode >> 8) == 0x8F:
        disp = opcode & 0xFF
        if disp >= 0x80:
            disp -= 0x100
        target = pc + 4 + disp * 2
        return f"bf/s 0x{target:08X}"

    # CMP/EQ #imm,R0 (10001000 iiiiiiii)
    if (opcode >> 8) == 0x88:
        imm = opcode & 0xFF
        return f"cmp/eq #{imm},R0"

    # CMP/EQ Rm,Rn (0011 nnnn mmmm 0000)
    if hi4 == 0x3 and (opcode & 0xF) == 0x0:
        return f"cmp/eq R{m},R{n}"
    # CMP/HS Rm,Rn (0011 nnnn mmmm 0010)
    if hi4 == 0x3 and (opcode & 0xF) == 0x2:
        return f"cmp/hs R{m},R{n}"
    # CMP/GE Rm,Rn (0011 nnnn mmmm 0011)
    if hi4 == 0x3 and (opcode & 0xF) == 0x3:
        return f"cmp/ge R{m},R{n}"
    # CMP/HI Rm,Rn (0011 nnnn mmmm 0110)
    if hi4 == 0x3 and (opcode & 0xF) == 0x6:
        return f"cmp/hi R{m},R{n}"
    # CMP/GT Rm,Rn (0011 nnnn mmmm 0111)
    if hi4 == 0x3 and (opcode & 0xF) == 0x7:
        return f"cmp/gt R{m},R{n}"

    # ADD Rm,Rn (0011 nnnn mmmm 1100)
    if hi4 == 0x3 and (opcode & 0xF) == 0xC:
        return f"add R{m},R{n}"
    # SUB Rm,Rn (0011 nnnn mmmm 1000)
    if hi4 == 0x3 and (opcode & 0xF) == 0x8:
        return f"sub R{m},R{n}"

    # AND Rm,Rn (0010 nnnn mmmm 1001)
    if hi4 == 0x2 and (opcode & 0xF) == 0x9:
        return f"and R{m},R{n}"
    # OR Rm,Rn (0010 nnnn mmmm 1011)
    if hi4 == 0x2 and (opcode & 0xF) == 0xB:
        return f"or R{m},R{n}"
    # XOR Rm,Rn (0010 nnnn mmmm 1010)
    if hi4 == 0x2 and (opcode & 0xF) == 0xA:
        return f"xor R{m},R{n}"
    # TST Rm,Rn (0010 nnnn mmmm 1000)
    if hi4 == 0x2 and (opcode & 0xF) == 0x8:
        return f"tst R{m},R{n}"

    # EXTU.B Rm,Rn (0110 nnnn mmmm 1100)
    if hi4 == 0x6 and (opcode & 0xF) == 0xC:
        return f"extu.b R{m},R{n}"
    # EXTU.W Rm,Rn (0110 nnnn mmmm 1101)
    if hi4 == 0x6 and (opcode & 0xF) == 0xD:
        return f"extu.w R{m},R{n}"
    # EXTS.B Rm,Rn (0110 nnnn mmmm 1110)
    if hi4 == 0x6 and (opcode & 0xF) == 0xE:
        return f"exts.b R{m},R{n}"
    # EXTS.W Rm,Rn (0110 nnnn mmmm 1111)
    if hi4 == 0x6 and (opcode & 0xF) == 0xF:
        return f"exts.w R{m},R{n}"

    # SHLL Rn (0100 nnnn 0000 0000)
    if hi4 == 0x4 and (opcode & 0xFF) == 0x00:
        return f"shll R{n}"
    # SHLR Rn (0100 nnnn 0000 0001)
    if hi4 == 0x4 and (opcode & 0xFF) == 0x01:
        return f"shlr R{n}"
    # SHLL2 Rn (0100 nnnn 0000 1000)
    if hi4 == 0x4 and (opcode & 0xFF) == 0x08:
        return f"shll2 R{n}"
    # SHLR2 Rn (0100 nnnn 0000 1001)
    if hi4 == 0x4 and (opcode & 0xFF) == 0x09:
        return f"shlr2 R{n}"
    # SHLL8 Rn (0100 nnnn 0001 1000)
    if hi4 == 0x4 and (opcode & 0xFF) == 0x18:
        return f"shll8 R{n}"
    # SHLR8 Rn (0100 nnnn 0001 1001)
    if hi4 == 0x4 and (opcode & 0xFF) == 0x19:
        return f"shlr8 R{n}"
    # SHLL16 Rn (0100 nnnn 0010 1000)
    if hi4 == 0x4 and (opcode & 0xFF) == 0x28:
        return f"shll16 R{n}"
    # SHLR16 Rn (0100 nnnn 0010 1001)
    if hi4 == 0x4 and (opcode & 0xFF) == 0x29:
        return f"shlr16 R{n}"

    # SWAP.B Rm,Rn (0110 nnnn mmmm 1000)
    if hi4 == 0x6 and (opcode & 0xF) == 0x8:
        return f"swap.b R{m},R{n}"
    # SWAP.W Rm,Rn (0110 nnnn mmmm 1001)
    if hi4 == 0x6 and (opcode & 0xF) == 0x9:
        return f"swap.w R{m},R{n}"

    # NEG Rm,Rn (0110 nnnn mmmm 1011)
    if hi4 == 0x6 and (opcode & 0xF) == 0xB:
        return f"neg R{m},R{n}"
    # NOT Rm,Rn (0110 nnnn mmmm 0111)
    if hi4 == 0x6 and (opcode & 0xF) == 0x7:
        return f"not R{m},R{n}"

    # MULU.W Rm,Rn (0010 nnnn mmmm 1110)
    if hi4 == 0x2 and (opcode & 0xF) == 0xE:
        return f"mulu.w R{m},R{n}"
    # MULS.W Rm,Rn (0010 nnnn mmmm 1111)
    if hi4 == 0x2 and (opcode & 0xF) == 0xF:
        return f"muls.w R{m},R{n}"

    # STS MACL,Rn (0000 nnnn 0001 1010)
    if hi4 == 0x0 and (opcode & 0xFF) == 0x1A:
        return f"sts MACL,R{n}"
    # STS MACH,Rn (0000 nnnn 0000 1010)
    if hi4 == 0x0 and (opcode & 0xFF) == 0x0A:
        return f"sts MACH,R{n}"
    # STS PR,Rn (0000 nnnn 0010 1010)
    if hi4 == 0x0 and (opcode & 0xFF) == 0x2A:
        return f"sts PR,R{n}"

    # MOV.B R0,@(disp,GBR) (11000000 dddddddd)
    if (opcode >> 8) == 0xC0:
        return f"mov.b R0,@({opcode & 0xFF},GBR)"
    # MOV.W R0,@(disp,GBR) (11000001 dddddddd)
    if (opcode >> 8) == 0xC1:
        return f"mov.w R0,@({(opcode & 0xFF)*2},GBR)"
    # MOV.L R0,@(disp,GBR) (11000010 dddddddd)
    if (opcode >> 8) == 0xC2:
        return f"mov.l R0,@({(opcode & 0xFF)*4},GBR)"
    # MOV.B @(disp,GBR),R0 (11000100 dddddddd)
    if (opcode >> 8) == 0xC4:
        return f"mov.b @({opcode & 0xFF},GBR),R0"
    # MOV.W @(disp,GBR),R0 (11000101 dddddddd)
    if (opcode >> 8) == 0xC5:
        return f"mov.w @({(opcode & 0xFF)*2},GBR),R0"
    # MOV.L @(disp,GBR),R0 (11000110 dddddddd)
    if (opcode >> 8) == 0xC6:
        return f"mov.l @({(opcode & 0xFF)*4},GBR),R0"

    # AND #imm,R0 (11001001 iiiiiiii)
    if (opcode >> 8) == 0xC9:
        return f"and #{opcode & 0xFF},R0"
    # OR #imm,R0 (11001011 iiiiiiii)
    if (opcode >> 8) == 0xCB:
        return f"or #{opcode & 0xFF},R0"
    # XOR #imm,R0 (11001010 iiiiiiii)
    if (opcode >> 8) == 0xCA:
        return f"xor #{opcode & 0xFF},R0"
    # TST #imm,R0 (11001000 iiiiiiii)
    if (opcode >> 8) == 0xC8:
        return f"tst #{opcode & 0xFF},R0"

    # DT Rn (0100 nnnn 0001 0000)
    if hi4 == 0x4 and (opcode & 0xFF) == 0x10:
        return f"dt R{n}"

    # CMP/PL Rn (0100 nnnn 0001 0101)
    if hi4 == 0x4 and (opcode & 0xFF) == 0x15:
        return f"cmp/pl R{n}"
    # CMP/PZ Rn (0100 nnnn 0001 0001)
    if hi4 == 0x4 and (opcode & 0xFF) == 0x11:
        return f"cmp/pz R{n}"

    # MOV.L @(disp,Rm),Rn — 0101nnnnmmmmdddd already handled above

    # MOV.B Rm,@(R0,Rn) (0000 nnnn mmmm 0100)
    if hi4 == 0x0 and (opcode & 0xF) == 0x4:
        return f"mov.b R{m},@(R0,R{n})"
    # MOV.W Rm,@(R0,Rn) (0000 nnnn mmmm 0101)
    if hi4 == 0x0 and (opcode & 0xF) == 0x5:
        return f"mov.w R{m},@(R0,R{n})"
    # MOV.L Rm,@(R0,Rn) (0000 nnnn mmmm 0110)
    if hi4 == 0x0 and (opcode & 0xF) == 0x6:
        return f"mov.l R{m},@(R0,R{n})"
    # MOV.B @(R0,Rm),Rn (0000 nnnn mmmm 1100)
    if hi4 == 0x0 and (opcode & 0xF) == 0xC:
        return f"mov.b @(R0,R{m}),R{n}"
    # MOV.W @(R0,Rm),Rn (0000 nnnn mmmm 1101)
    if hi4 == 0x0 and (opcode & 0xF) == 0xD:
        return f"mov.w @(R0,R{m}),R{n}"
    # MOV.L @(R0,Rm),Rn (0000 nnnn mmmm 1110)
    if hi4 == 0x0 and (opcode & 0xF) == 0xE:
        return f"mov.l @(R0,R{m}),R{n}"

    return f".word 0x{opcode:04X}"


def disasm_region(data, start_file, end_file, resolve_literals=True):
    """Disassemble a region, resolving literal pool references."""
    lines = []
    pc_file = start_file
    while pc_file < end_file:
        if pc_file + 1 >= len(data):
            break
        opcode = struct.unpack('>H', data[pc_file:pc_file+2])[0]
        pc = file_to_mem(pc_file)
        mnemonic = decode_sh2(opcode, pc)

        # Resolve literal pool values for mov.l @(disp,PC)
        extra = ""
        if resolve_literals and (opcode >> 12) == 0xD:
            disp = opcode & 0xFF
            lit_addr = (pc & ~3) + 4 + disp * 4
            lit_file = mem_to_file(lit_addr)
            if 0 <= lit_file + 3 < len(data):
                lit_val = struct.unpack('>I', data[lit_file:lit_file+4])[0]
                extra = f"  => 0x{lit_val:08X}"

        # Resolve mov.w @(disp,PC) too
        if resolve_literals and (opcode >> 12) == 0x9:
            disp = opcode & 0xFF
            lit_addr = pc + 4 + disp * 2
            lit_file = mem_to_file(lit_addr)
            if 0 <= lit_file + 1 < len(data):
                lit_val = struct.unpack('>H', data[lit_file:lit_file+2])[0]
                # Sign extend
                if lit_val >= 0x8000:
                    lit_signed = lit_val - 0x10000
                    extra = f"  => 0x{lit_val:04X} ({lit_signed})"
                else:
                    extra = f"  => 0x{lit_val:04X} ({lit_val})"

        raw_bytes = f"{data[pc_file]:02X} {data[pc_file+1]:02X}"
        lines.append(f"  {pc:08X}: {raw_bytes}  {mnemonic}{extra}")
        pc_file += 2

    return '\n'.join(lines)


def main():
    with open(BINARY_PATH, 'rb') as f:
        data = f.read()

    print("=" * 90)
    print("REGION 1: Around the literal pool at 0x060222F2 containing 1F40 + 07D0 + 060623D8")
    print("  This literal pool is used by code referencing the SV send queue with timeout values")
    print("=" * 90)

    # The literal pool entries are at:
    # 0x060222F2: 1F 40 (could be part of mov.w literal)
    # 0x060222F4: 07 D0 (could be part of mov.w literal)
    # 0x060221F4: 06 06 23 D8 (the queue address)

    # Let's look at 0x060221F4 (file 0x0121F4) which is a 4-byte literal pool entry.
    # The literal pool runs from about 0x060221C0 to 0x06022320
    # Code likely BEFORE this literal pool

    # Let's disassemble backwards from the literal pool start
    # Looking for the function that starts before the literal pool
    # Scan back to find a likely function entry (sts.l pr,@-r15 / mov.l r14,@-r15 pattern)

    # First, let's identify the literal pool boundaries
    print("\nLiteral pool raw data (0x0121C0 - 0x012320):")
    for off in range(0x0121C0, 0x012320, 4):
        if off + 3 < len(data):
            val = struct.unpack('>I', data[off:off+4])[0]
            print(f"  {file_to_mem(off):08X}: {data[off]:02X} {data[off+1]:02X} {data[off+2]:02X} {data[off+3]:02X}  = 0x{val:08X}")

    # Now disassemble the code BEFORE this literal pool
    # The first reference to 060623D8 is at 0x060221F4 in the literal pool
    # SH-2 mov.l @(disp,PC),Rn can reference up to 255*4=1020 bytes ahead
    # So code using this literal could be up to 1020 bytes before 0x060221F4
    # But typically functions are shorter, so let's scan 0x200 bytes before

    print()
    print("=" * 90)
    print("DISASSEMBLY: Function near 0x060221F4 literal pool")
    print("  Starting from 0x06021F00 (well before the literal pool)")
    print("=" * 90)

    # Start at 0x06021F00 and go past the literal pool
    start = mem_to_file(0x06021F00)  # 0x011F00
    end = mem_to_file(0x06022400)    # 0x012400
    print(disasm_region(data, start, end))

    # Now let's check the second reference to 060623D8 at 0x06022650
    print()
    print("=" * 90)
    print("REGION 2: Around the literal pool at 0x06022650 (second 060623D8 ref)")
    print("=" * 90)

    # Scan back from 0x06022650 to find the function
    # The literal pool at 0x06022650 also has:
    # 06 05 6F 5C, 06 03 FD CA, 06 04 06 04

    print("\nLiteral pool raw data (0x012640 - 0x012680):")
    for off in range(0x012640, 0x012680, 4):
        if off + 3 < len(data):
            val = struct.unpack('>I', data[off:off+4])[0]
            print(f"  {file_to_mem(off):08X}: {data[off]:02X} {data[off+1]:02X} {data[off+2]:02X} {data[off+3]:02X}  = 0x{val:08X}")

    # Disassemble the function around here
    start = mem_to_file(0x06022390)  # Some distance before
    end = mem_to_file(0x060228C0)    # Well past the pool
    print()
    print("DISASSEMBLY: Function near 0x06022650 literal pool")
    print(disasm_region(data, start, end))

    # Third reference at 0x06022AB4
    print()
    print("=" * 90)
    print("REGION 3: Around the literal pool at 0x06022AB4 (third 060623D8 ref)")
    print("=" * 90)

    print("\nLiteral pool raw data (0x012AA0 - 0x012AE0):")
    for off in range(0x012AA0, 0x012AE0, 4):
        if off + 3 < len(data):
            val = struct.unpack('>I', data[off:off+4])[0]
            print(f"  {file_to_mem(off):08X}: {data[off]:02X} {data[off+1]:02X} {data[off+2]:02X} {data[off+3]:02X}  = 0x{val:08X}")

    start = mem_to_file(0x06022900)
    end = mem_to_file(0x06022C00)
    print()
    print("DISASSEMBLY: Function near 0x06022AB4 literal pool")
    print(disasm_region(data, start, end))


if __name__ == '__main__':
    main()
