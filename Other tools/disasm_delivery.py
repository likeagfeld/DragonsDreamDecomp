#!/usr/bin/env python3
"""
SH-2 Disassembler for Dragon's Dream delivery function at 0x060423C8.
Reads from file offset 0x0323C8 through ~0x032A00 in extracted/0.BIN.
"""

import struct
import sys

BINARY_PATH = r"D:\DragonsDreamDecomp\extracted\0.BIN"
FILE_OFFSET = 0x0323C8
MEM_BASE    = 0x06010000
MEM_ADDR    = 0x060423C8
LENGTH      = 0x032A00 - 0x0323C8  # ~1592 bytes

def sign_extend_8(v):
    """Sign-extend an 8-bit value."""
    if v & 0x80:
        return v - 0x100
    return v

def sign_extend_12(v):
    """Sign-extend a 12-bit value."""
    if v & 0x800:
        return v - 0x1000
    return v

def rname(r):
    if r == 15:
        return "r15/sp"
    return f"r{r}"

class SH2Disassembler:
    def __init__(self, data, base_addr, file_offset_start):
        self.data = data
        self.base_addr = base_addr
        self.file_offset_start = file_offset_start
        # Pre-load the full binary for literal pool lookups
        with open(BINARY_PATH, "rb") as f:
            self.full_binary = f.read()

    def read_u16(self, offset):
        """Read big-endian uint16 at byte offset within our data."""
        return struct.unpack(">H", self.data[offset:offset+2])[0]

    def read_u32_at_file(self, file_off):
        """Read big-endian uint32 at absolute file offset."""
        if file_off + 4 <= len(self.full_binary):
            return struct.unpack(">L", self.full_binary[file_off:file_off+4])[0]
        return None

    def read_u16_at_file(self, file_off):
        """Read big-endian uint16 at absolute file offset."""
        if file_off + 2 <= len(self.full_binary):
            return struct.unpack(">H", self.full_binary[file_off:file_off+2])[0]
        return None

    def mem_to_file(self, mem_addr):
        """Convert memory address to file offset."""
        return mem_addr - MEM_BASE

    def decode(self, pc, opcode):
        """Decode a single 16-bit SH-2 instruction. Returns (mnemonic, comment)."""

        hi4 = (opcode >> 12) & 0xF

        # ---- Format 0x0xxx ----
        if hi4 == 0x0:
            rn = (opcode >> 8) & 0xF
            rm = (opcode >> 4) & 0xF
            lo4 = opcode & 0xF
            lo8 = opcode & 0xFF

            if opcode == 0x0009:
                return "nop", ""
            elif opcode == 0x000B:
                return "rts", "return"
            elif opcode == 0x0008:
                return "clrt", "T=0"
            elif opcode == 0x0018:
                return "sett", "T=1"
            elif opcode == 0x0019:
                return "div0u", ""
            elif opcode == 0x001B:
                return "sleep", ""
            elif opcode == 0x002B:
                return "rte", "return from exception"
            elif lo4 == 0x2:
                return f"stc    SR, {rname(rn)}", ""
            elif lo4 == 0x3:
                return f"bsrf   {rname(rn)}", f"branch to PC+4+{rname(rn)}"
            elif lo4 == 0x4 and rm == 0:
                return f"mov.b  {rname(rm)}, @(R0,{rname(rn)})", ""
            elif lo4 == 0x5 and rm == 0:
                return f"mov.w  {rname(rm)}, @(R0,{rname(rn)})", ""
            elif lo4 == 0x6 and rm == 0:
                return f"mov.l  {rname(rm)}, @(R0,{rname(rn)})", ""
            elif lo4 == 0x7:
                return f"mul.l  {rname(rm)}, {rname(rn)}", "MACL = Rm * Rn"
            elif lo4 == 0xC:
                return f"mov.b  @(R0,{rname(rm)}), {rname(rn)}", ""
            elif lo4 == 0xD:
                return f"mov.w  @(R0,{rname(rm)}), {rname(rn)}", ""
            elif lo4 == 0xE:
                return f"mov.l  @(R0,{rname(rm)}), {rname(rn)}", ""
            elif lo4 == 0xA:
                return f"sts    MACH, {rname(rn)}", ""
            elif lo8 == 0x29:
                return f"movt   {rname(rn)}", "Rn = T"
            elif lo4 == 0xF:
                return f"mac.l  @{rname(rm)}+, @{rname(rn)}+", ""
            else:
                # More 0x0 variants
                if lo4 == 0x4:
                    return f"mov.b  {rname(rm)}, @(R0,{rname(rn)})", ""
                elif lo4 == 0x5:
                    return f"mov.w  {rname(rm)}, @(R0,{rname(rn)})", ""
                elif lo4 == 0x6:
                    return f"mov.l  {rname(rm)}, @(R0,{rname(rn)})", ""
                return f".word  0x{opcode:04X}", "unknown 0x0xxx"

        # ---- Format 0x1nmd: mov.l Rm, @(d*4,Rn) ----
        if hi4 == 0x1:
            rn = (opcode >> 8) & 0xF
            rm = (opcode >> 4) & 0xF
            d  = opcode & 0xF
            return f"mov.l  {rname(rm)}, @({d*4},{rname(rn)})", ""

        # ---- Format 0x2xxx ----
        if hi4 == 0x2:
            rn = (opcode >> 8) & 0xF
            rm = (opcode >> 4) & 0xF
            lo4 = opcode & 0xF
            ops = {
                0x0: f"mov.b  {rname(rm)}, @{rname(rn)}",
                0x1: f"mov.w  {rname(rm)}, @{rname(rn)}",
                0x2: f"mov.l  {rname(rm)}, @{rname(rn)}",
                0x4: f"mov.b  {rname(rm)}, @-{rname(rn)}",
                0x5: f"mov.w  {rname(rm)}, @-{rname(rn)}",
                0x6: f"mov.l  {rname(rm)}, @-{rname(rn)}",
                0x7: f"div0s  {rname(rm)}, {rname(rn)}",
                0x8: f"tst    {rname(rm)}, {rname(rn)}",
                0x9: f"and    {rname(rm)}, {rname(rn)}",
                0xA: f"xor    {rname(rm)}, {rname(rn)}",
                0xB: f"or     {rname(rm)}, {rname(rn)}",
                0xC: f"cmp/str {rname(rm)}, {rname(rn)}",
                0xD: f"xtrct  {rname(rm)}, {rname(rn)}",
                0xE: f"mulu.w {rname(rm)}, {rname(rn)}",
                0xF: f"muls.w {rname(rm)}, {rname(rn)}",
            }
            if lo4 in ops:
                return ops[lo4], ""
            return f".word  0x{opcode:04X}", "unknown 0x2xxx"

        # ---- Format 0x3xxx ----
        if hi4 == 0x3:
            rn = (opcode >> 8) & 0xF
            rm = (opcode >> 4) & 0xF
            lo4 = opcode & 0xF
            ops = {
                0x0: f"cmp/eq {rname(rm)}, {rname(rn)}",
                0x2: f"cmp/hs {rname(rm)}, {rname(rn)}",
                0x3: f"cmp/ge {rname(rm)}, {rname(rn)}",
                0x4: f"div1   {rname(rm)}, {rname(rn)}",
                0x5: f"dmulu.l {rname(rm)}, {rname(rn)}",
                0x6: f"cmp/hi {rname(rm)}, {rname(rn)}",
                0x7: f"cmp/gt {rname(rm)}, {rname(rn)}",
                0x8: f"sub    {rname(rm)}, {rname(rn)}",
                0xA: f"subc   {rname(rm)}, {rname(rn)}",
                0xB: f"subv   {rname(rm)}, {rname(rn)}",
                0xC: f"add    {rname(rm)}, {rname(rn)}",
                0xD: f"dmuls.l {rname(rm)}, {rname(rn)}",
                0xE: f"addc   {rname(rm)}, {rname(rn)}",
                0xF: f"addv   {rname(rm)}, {rname(rn)}",
            }
            if lo4 in ops:
                return ops[lo4], ""
            return f".word  0x{opcode:04X}", "unknown 0x3xxx"

        # ---- Format 0x4xxx ----
        if hi4 == 0x4:
            rn = (opcode >> 8) & 0xF
            rm = (opcode >> 4) & 0xF
            lo8 = opcode & 0xFF
            lo4 = opcode & 0xF

            if lo8 == 0x0B:
                return f"jsr    @{rname(rn)}", f"call *{rname(rn)}"
            elif lo8 == 0x2B:
                return f"jmp    @{rname(rn)}", f"jump *{rname(rn)}"
            elif lo8 == 0x10:
                return f"dt     {rname(rn)}", f"{rname(rn)}--, T=(Rn==0)"
            elif lo8 == 0x11:
                return f"cmp/pz {rname(rn)}", f"T=({rname(rn)}>=0)"
            elif lo8 == 0x15:
                return f"cmp/pl {rname(rn)}", f"T=({rname(rn)}>0)"
            elif lo8 == 0x00:
                return f"shll   {rname(rn)}", "T=MSB, Rn<<=1"
            elif lo8 == 0x01:
                return f"shlr   {rname(rn)}", "T=LSB, Rn>>=1"
            elif lo8 == 0x04:
                return f"rotl   {rname(rn)}", "T=MSB, rotate left"
            elif lo8 == 0x05:
                return f"rotr   {rname(rn)}", "T=LSB, rotate right"
            elif lo8 == 0x08:
                return f"shll2  {rname(rn)}", "Rn<<=2"
            elif lo8 == 0x09:
                return f"shlr2  {rname(rn)}", "Rn>>=2"
            elif lo8 == 0x18:
                return f"shll8  {rname(rn)}", "Rn<<=8"
            elif lo8 == 0x19:
                return f"shlr8  {rname(rn)}", "Rn>>=8"
            elif lo8 == 0x28:
                return f"shll16 {rname(rn)}", "Rn<<=16"
            elif lo8 == 0x29:
                return f"shlr16 {rname(rn)}", "Rn>>=16"
            elif lo8 == 0x20:
                return f"shal   {rname(rn)}", "T=MSB, arith shift left"
            elif lo8 == 0x21:
                return f"shar   {rname(rn)}", "T=MSB, arith shift right"
            elif lo8 == 0x24:
                return f"rotcl  {rname(rn)}", "rotate left through carry"
            elif lo8 == 0x25:
                return f"rotcr  {rname(rn)}", "rotate right through carry"
            elif lo8 == 0x0E:
                return f"ldc    {rname(rn)}, SR", ""
            elif lo8 == 0x1E:
                return f"ldc    {rname(rn)}, GBR", ""
            elif lo8 == 0x2E:
                return f"ldc    {rname(rn)}, VBR", ""
            elif lo8 == 0x0A:
                return f"lds    {rname(rn)}, MACH", ""
            elif lo8 == 0x1A:
                return f"lds    {rname(rn)}, MACL", ""
            elif lo8 == 0x2A:
                return f"lds    {rname(rn)}, PR", ""
            elif lo8 == 0x06:
                return f"lds.l  @{rname(rn)}+, MACH", ""
            elif lo8 == 0x16:
                return f"lds.l  @{rname(rn)}+, MACL", ""
            elif lo8 == 0x26:
                return f"lds.l  @{rname(rn)}+, PR", ""
            elif lo8 == 0x07:
                return f"ldc.l  @{rname(rn)}+, SR", ""
            elif lo8 == 0x17:
                return f"ldc.l  @{rname(rn)}+, GBR", ""
            elif lo8 == 0x27:
                return f"ldc.l  @{rname(rn)}+, VBR", ""
            elif lo8 == 0x02:
                return f"sts.l  MACH, @-{rname(rn)}", ""
            elif lo8 == 0x12:
                return f"sts.l  MACL, @-{rname(rn)}", ""
            elif lo8 == 0x22:
                return f"sts.l  PR, @-{rname(rn)}", ""
            elif lo8 == 0x03:
                return f"stc.l  SR, @-{rname(rn)}", ""
            elif lo8 == 0x13:
                return f"stc.l  GBR, @-{rname(rn)}", ""
            elif lo8 == 0x23:
                return f"stc.l  VBR, @-{rname(rn)}", ""
            elif lo4 == 0xF:
                return f"mac.w  @{rname(rm)}+, @{rname(rn)}+", ""

            return f".word  0x{opcode:04X}", f"unknown 0x4xxx (lo8=0x{lo8:02X})"

        # ---- Format 0x5nmd: mov.l @(d*4,Rm), Rn ----
        if hi4 == 0x5:
            rn = (opcode >> 8) & 0xF
            rm = (opcode >> 4) & 0xF
            d  = opcode & 0xF
            return f"mov.l  @({d*4},{rname(rm)}), {rname(rn)}", ""

        # ---- Format 0x6xxx ----
        if hi4 == 0x6:
            rn = (opcode >> 8) & 0xF
            rm = (opcode >> 4) & 0xF
            lo4 = opcode & 0xF
            ops = {
                0x0: f"mov.b  @{rname(rm)}, {rname(rn)}",
                0x1: f"mov.w  @{rname(rm)}, {rname(rn)}",
                0x2: f"mov.l  @{rname(rm)}, {rname(rn)}",
                0x3: f"mov    {rname(rm)}, {rname(rn)}",
                0x4: f"mov.b  @{rname(rm)}+, {rname(rn)}",
                0x5: f"mov.w  @{rname(rm)}+, {rname(rn)}",
                0x6: f"mov.l  @{rname(rm)}+, {rname(rn)}",
                0x7: f"not    {rname(rm)}, {rname(rn)}",
                0x8: f"swap.b {rname(rm)}, {rname(rn)}",
                0x9: f"swap.w {rname(rm)}, {rname(rn)}",
                0xA: f"negc   {rname(rm)}, {rname(rn)}",
                0xB: f"neg    {rname(rm)}, {rname(rn)}",
                0xC: f"extu.b {rname(rm)}, {rname(rn)}",
                0xD: f"extu.w {rname(rm)}, {rname(rn)}",
                0xE: f"exts.b {rname(rm)}, {rname(rn)}",
                0xF: f"exts.w {rname(rm)}, {rname(rn)}",
            }
            if lo4 in ops:
                comment = ""
                if lo4 == 0xC:
                    comment = "zero-extend byte"
                elif lo4 == 0xD:
                    comment = "zero-extend word"
                elif lo4 == 0xE:
                    comment = "sign-extend byte"
                elif lo4 == 0xF:
                    comment = "sign-extend word"
                return ops[lo4], comment
            return f".word  0x{opcode:04X}", "unknown 0x6xxx"

        # ---- Format 0x7ndd: add #imm8, Rn ----
        if hi4 == 0x7:
            rn = (opcode >> 8) & 0xF
            imm = sign_extend_8(opcode & 0xFF)
            if imm >= 0:
                return f"add    #{imm}, {rname(rn)}", f"{rname(rn)} += {imm}"
            else:
                return f"add    #{imm}, {rname(rn)}", f"{rname(rn)} -= {-imm}"

        # ---- Format 0x8xxx ----
        if hi4 == 0x8:
            sub = (opcode >> 8) & 0xF

            if sub == 0x0:
                # mov.b R0, @(d, Rn)
                rn = (opcode >> 4) & 0xF
                d  = opcode & 0xF
                return f"mov.b  R0, @({d},{rname(rn)})", ""
            elif sub == 0x1:
                # mov.w R0, @(d*2, Rn)
                rn = (opcode >> 4) & 0xF
                d  = opcode & 0xF
                return f"mov.w  R0, @({d*2},{rname(rn)})", ""
            elif sub == 0x4:
                # mov.b @(d, Rm), R0
                rm = (opcode >> 4) & 0xF
                d  = opcode & 0xF
                return f"mov.b  @({d},{rname(rm)}), R0", ""
            elif sub == 0x5:
                # mov.w @(d*2, Rm), R0
                rm = (opcode >> 4) & 0xF
                d  = opcode & 0xF
                return f"mov.w  @({d*2},{rname(rm)}), R0", ""
            elif sub == 0x8:
                # cmp/eq #imm, R0
                imm = sign_extend_8(opcode & 0xFF)
                return f"cmp/eq #{imm}, R0", f"T=(R0=={imm})"
            elif sub == 0x9:
                # bt disp
                d = sign_extend_8(opcode & 0xFF)
                target = pc + d * 2 + 4
                return f"bt     0x{target:08X}", f"if T=1 goto 0x{target:08X}"
            elif sub == 0xB:
                # bf disp
                d = sign_extend_8(opcode & 0xFF)
                target = pc + d * 2 + 4
                return f"bf     0x{target:08X}", f"if T=0 goto 0x{target:08X}"
            elif sub == 0xD:
                # bt/s disp (delayed branch)
                d = sign_extend_8(opcode & 0xFF)
                target = pc + d * 2 + 4
                return f"bt/s   0x{target:08X}", f"if T=1 goto 0x{target:08X} (delayed)"
            elif sub == 0xF:
                # bf/s disp (delayed branch)
                d = sign_extend_8(opcode & 0xFF)
                target = pc + d * 2 + 4
                return f"bf/s   0x{target:08X}", f"if T=0 goto 0x{target:08X} (delayed)"

            return f".word  0x{opcode:04X}", "unknown 0x8xxx"

        # ---- Format 0x9ndd: mov.w @(disp*2+PC+4), Rn ----
        if hi4 == 0x9:
            rn = (opcode >> 8) & 0xF
            d  = opcode & 0xFF
            pool_addr = pc + d * 2 + 4
            file_off = self.mem_to_file(pool_addr)
            val = self.read_u16_at_file(file_off)
            if val is not None:
                sval = val if val < 0x8000 else val - 0x10000
                return f"mov.w  @(0x{pool_addr:08X}), {rname(rn)}", f"= 0x{val:04X} ({sval})"
            return f"mov.w  @(0x{pool_addr:08X}), {rname(rn)}", "pool read failed"

        # ---- Format 0xAxxx: bra disp12 ----
        if hi4 == 0xA:
            d = sign_extend_12(opcode & 0xFFF)
            target = pc + d * 2 + 4
            return f"bra    0x{target:08X}", f"branch always (delayed)"

        # ---- Format 0xBxxx: bsr disp12 ----
        if hi4 == 0xB:
            d = sign_extend_12(opcode & 0xFFF)
            target = pc + d * 2 + 4
            return f"bsr    0x{target:08X}", f"call 0x{target:08X} (delayed)"

        # ---- Format 0xCxxx ----
        if hi4 == 0xC:
            sub = (opcode >> 8) & 0xF
            imm = opcode & 0xFF
            ops = {
                0x0: f"mov.b  R0, @({imm},GBR)",
                0x1: f"mov.w  R0, @({imm*2},GBR)",
                0x2: f"mov.l  R0, @({imm*4},GBR)",
                0x3: f"trapa  #{imm}",
                0x4: f"mov.b  @({imm},GBR), R0",
                0x5: f"mov.w  @({imm*2},GBR), R0",
                0x6: f"mov.l  @({imm*4},GBR), R0",
                0x7: f"mova   @(0x{pc + imm*4 + 4:08X}), R0",
                0x8: f"tst    #0x{imm:02X}, R0",
                0x9: f"and    #0x{imm:02X}, R0",
                0xA: f"xor    #0x{imm:02X}, R0",
                0xB: f"or     #0x{imm:02X}, R0",
                0xC: f"tst.b  #0x{imm:02X}, @(R0,GBR)",
                0xD: f"and.b  #0x{imm:02X}, @(R0,GBR)",
                0xE: f"xor.b  #0x{imm:02X}, @(R0,GBR)",
                0xF: f"or.b   #0x{imm:02X}, @(R0,GBR)",
            }
            if sub in ops:
                comment = ""
                if sub == 0x8:
                    comment = f"T = (R0 & 0x{imm:02X}) == 0"
                return ops[sub], comment
            return f".word  0x{opcode:04X}", "unknown 0xCxxx"

        # ---- Format 0xDndd: mov.l @(disp*4 + (PC&~3) + 4), Rn ----
        if hi4 == 0xD:
            rn = (opcode >> 8) & 0xF
            d  = opcode & 0xFF
            pool_addr = (pc & ~3) + d * 4 + 4
            file_off = self.mem_to_file(pool_addr)
            val = self.read_u32_at_file(file_off)
            if val is not None:
                return f"mov.l  @(0x{pool_addr:08X}), {rname(rn)}", f"= 0x{val:08X}"
            return f"mov.l  @(0x{pool_addr:08X}), {rname(rn)}", "pool read failed"

        # ---- Format 0xEndd: mov #imm8, Rn (sign-extend) ----
        if hi4 == 0xE:
            rn = (opcode >> 8) & 0xF
            imm = sign_extend_8(opcode & 0xFF)
            if imm >= 0:
                return f"mov    #{imm}, {rname(rn)}", f"= 0x{imm:02X}"
            else:
                return f"mov    #{imm}, {rname(rn)}", f"= 0x{imm & 0xFFFFFFFF:08X}"

        # ---- Format 0xFxxx: FPU (not used here but just in case) ----
        if hi4 == 0xF:
            return f".word  0x{opcode:04X}", "FPU/unknown"

        return f".word  0x{opcode:04X}", "unhandled"

    def disassemble(self):
        """Disassemble the entire range and output annotated listing."""
        lines = []
        i = 0
        while i < len(self.data) - 1:
            pc = self.base_addr + i
            opcode = self.read_u16(i)
            file_off = self.file_offset_start + i

            mnemonic, comment = self.decode(pc, opcode)

            raw_bytes = f"{(opcode >> 8) & 0xFF:02X} {opcode & 0xFF:02X}"

            addr_str = f"0x{pc:08X}"
            foff_str = f"0x{file_off:06X}"

            line = f"  {addr_str}  [{foff_str}]  {raw_bytes}   {opcode:04X}   {mnemonic:<42s}"
            if comment:
                line += f" ; {comment}"
            lines.append(line)

            i += 2

        return lines


def analyze_structure(lines):
    """Add section annotations to help trace the function structure."""
    print("=" * 120)
    print("  SH-2 DISASSEMBLY: delivery function @ 0x060423C8")
    print("  Binary: extracted/0.BIN, file offset 0x0323C8")
    print("  SH-2 big-endian, all instructions 16-bit")
    print("=" * 120)
    print()

    # We'll look for key patterns
    for line in lines:
        print(line)


def main():
    with open(BINARY_PATH, "rb") as f:
        f.seek(FILE_OFFSET)
        data = f.read(LENGTH)

    print(f"Read {len(data)} bytes from file offset 0x{FILE_OFFSET:06X}")
    print(f"Memory range: 0x{MEM_ADDR:08X} - 0x{MEM_ADDR + len(data):08X}")
    print()

    disasm = SH2Disassembler(data, MEM_ADDR, FILE_OFFSET)
    lines = disasm.disassemble()

    analyze_structure(lines)

    # Now do a detailed structural analysis
    print()
    print("=" * 120)
    print("  STRUCTURAL ANALYSIS")
    print("=" * 120)
    print()

    # Look for key patterns in the raw data
    # 1. Find sts.l PR, @-R15 (prologue push) = 0x4F22
    # 2. Find lds.l @R15+, PR (epilogue pop) = 0x4F26
    # 3. Find rts = 0x000B
    # 4. Find jsr = 0x4n0B
    # 5. Find literal pool loads (0xDndd)

    prologue_pushes = []
    epilogue_pops = []
    rts_addrs = []
    jsr_calls = []
    literal_loads = []
    branch_targets = set()

    i = 0
    while i < len(data) - 1:
        pc = MEM_ADDR + i
        opcode = struct.unpack(">H", data[i:i+2])[0]

        # sts.l PR, @-Rn
        if opcode == 0x4F22:
            prologue_pushes.append(pc)
        # mov.l Rm, @-R15
        if (opcode & 0xF0FF) == 0x2F06:
            rm = (opcode >> 4) & 0xF
            prologue_pushes.append((pc, f"push r{rm}"))
        # lds.l @R15+, PR
        if opcode == 0x4F26:
            epilogue_pops.append(pc)
        # mov.l @R15+, Rn
        if (opcode & 0xF0FF) == 0x6F06 or (opcode & 0xF0FF) == 0x6F62:
            pass  # These are different
        if (opcode >> 12) == 0x6 and (opcode & 0xF) == 0x6 and ((opcode >> 4) & 0xF) == 0xF:
            rn = (opcode >> 8) & 0xF
            epilogue_pops.append((pc, f"pop r{rn}"))
        # rts
        if opcode == 0x000B:
            rts_addrs.append(pc)
        # jsr @Rn
        if (opcode & 0xF0FF) == 0x400B:
            rn = (opcode >> 8) & 0xF
            jsr_calls.append((pc, f"jsr @r{rn}"))
        # mov.l @(disp, PC), Rn (literal pool)
        if (opcode >> 12) == 0xD:
            rn = (opcode >> 8) & 0xF
            d = opcode & 0xFF
            pool_addr = (pc & ~3) + d * 4 + 4
            file_off = pool_addr - MEM_BASE
            if file_off + 4 <= len(disasm.full_binary):
                val = struct.unpack(">L", disasm.full_binary[file_off:file_off+4])[0]
                literal_loads.append((pc, rn, pool_addr, val))

        # Collect branch targets
        hi4 = (opcode >> 12) & 0xF
        if hi4 == 0x8:
            sub = (opcode >> 8) & 0xF
            if sub in (0x9, 0xB, 0xD, 0xF):
                d = sign_extend_8(opcode & 0xFF)
                target = pc + d * 2 + 4
                branch_targets.add(target)
        if hi4 == 0xA or hi4 == 0xB:
            d = sign_extend_12(opcode & 0xFFF)
            target = pc + d * 2 + 4
            branch_targets.add(target)

        i += 2

    print("--- PROLOGUE PUSHES (sts.l PR/@-R15, mov.l Rm,@-R15) ---")
    for item in prologue_pushes:
        if isinstance(item, tuple):
            print(f"  0x{item[0]:08X}: {item[1]}")
        else:
            print(f"  0x{item:08X}: sts.l PR, @-R15")

    print()
    print("--- EPILOGUE POPS ---")
    for item in epilogue_pops:
        if isinstance(item, tuple):
            print(f"  0x{item[0]:08X}: {item[1]}")
        else:
            print(f"  0x{item:08X}: lds.l @R15+, PR")

    print()
    print("--- RTS (return) ---")
    for addr in rts_addrs:
        print(f"  0x{addr:08X}")

    print()
    print("--- JSR CALLS ---")
    for addr, desc in jsr_calls:
        print(f"  0x{addr:08X}: {desc}")

    print()
    print("--- LITERAL POOL LOADS ---")
    for pc, rn, pool_addr, val in literal_loads:
        # Try to identify what the literal might be
        desc = ""
        if 0x06000000 <= val <= 0x06FFFFFF:
            desc = f"  (memory address in main RAM)"
        elif 0x20000000 <= val <= 0x2FFFFFFF:
            desc = f"  (cache-through mirror)"
        elif val < 0x1000:
            desc = f"  (small constant: {val})"
        print(f"  0x{pc:08X}: r{rn} = [0x{pool_addr:08X}] = 0x{val:08X}{desc}")

    print()
    print("--- BRANCH TARGETS (labels) ---")
    for t in sorted(branch_targets):
        if MEM_ADDR <= t <= MEM_ADDR + len(data):
            print(f"  0x{t:08X}  (offset +0x{t - MEM_ADDR:04X} from function start)")
        else:
            print(f"  0x{t:08X}  (OUTSIDE function range)")

    print()
    print("=" * 120)
    print("  ANNOTATED DISASSEMBLY WITH LABELS")
    print("=" * 120)
    print()

    # Re-print with labels
    for line in lines:
        # Extract address from line
        addr_str = line.strip().split()[0]
        try:
            addr = int(addr_str, 16)
            if addr in branch_targets:
                print(f"\nlabel_{addr:08X}:")
        except:
            pass
        print(line)


if __name__ == "__main__":
    main()
