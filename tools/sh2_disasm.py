#!/usr/bin/env python3
"""Minimal SH-2 disassembler for Dragon's Dream binary analysis."""
import struct, sys

def disasm_sh2(code, base_addr, length=None):
    """Disassemble SH-2 code. code=bytes, base_addr=memory address."""
    if length is None:
        length = len(code)
    lines = []
    i = 0
    while i < length and i + 1 < len(code):
        op = (code[i] << 8) | code[i+1]
        addr = base_addr + i
        n = (op >> 8) & 0xF
        m = (op >> 4) & 0xF
        d = op & 0xF
        dd = op & 0xFF
        ddd = op & 0xFFF

        s = f"  {addr:08X}: {op:04X}  "

        hi = (op >> 12) & 0xF

        if op == 0x0009: s += "nop"
        elif op == 0x000B: s += "rts"
        elif op == 0x002B: s += "rte"
        elif hi == 0 and d == 2: s += f"stc SR,R{n}"
        elif hi == 0 and (op & 0xFF) == 0x03: s += f"bsrf R{n}"
        elif hi == 0 and (op & 0xFF) == 0x23: s += f"braf R{n}"
        elif hi == 0 and d == 4: s += f"mov.b R{m},@(R0,R{n})"
        elif hi == 0 and d == 5: s += f"mov.w R{m},@(R0,R{n})"
        elif hi == 0 and d == 6: s += f"mov.l R{m},@(R0,R{n})"
        elif hi == 0 and d == 7: s += f"mul.l R{m},R{n}"
        elif hi == 0 and d == 0xC: s += f"mov.b @(R0,R{m}),R{n}"
        elif hi == 0 and d == 0xD: s += f"mov.w @(R0,R{m}),R{n}"
        elif hi == 0 and d == 0xE: s += f"mov.l @(R0,R{m}),R{n}"
        elif hi == 1: s += f"mov.l R{m},@({d*4},R{n})"
        elif hi == 2 and d == 0: s += f"mov.b R{m},@R{n}"
        elif hi == 2 and d == 1: s += f"mov.w R{m},@R{n}"
        elif hi == 2 and d == 2: s += f"mov.l R{m},@R{n}"
        elif hi == 2 and d == 4: s += f"mov.b R{m},@-R{n}"
        elif hi == 2 and d == 5: s += f"mov.w R{m},@-R{n}"
        elif hi == 2 and d == 6: s += f"mov.l R{m},@-R{n}"
        elif hi == 2 and d == 7: s += f"div0s R{m},R{n}"
        elif hi == 2 and d == 8: s += f"tst R{m},R{n}"
        elif hi == 2 and d == 9: s += f"and R{m},R{n}"
        elif hi == 2 and d == 0xA: s += f"xor R{m},R{n}"
        elif hi == 2 and d == 0xB: s += f"or R{m},R{n}"
        elif hi == 2 and d == 0xC: s += f"cmp/str R{m},R{n}"
        elif hi == 2 and d == 0xD: s += f"xtrct R{m},R{n}"
        elif hi == 2 and d == 0xE: s += f"mulu.w R{m},R{n}"
        elif hi == 2 and d == 0xF: s += f"muls.w R{m},R{n}"
        elif hi == 3 and d == 0: s += f"cmp/eq R{m},R{n}"
        elif hi == 3 and d == 2: s += f"cmp/hs R{m},R{n}"
        elif hi == 3 and d == 3: s += f"cmp/ge R{m},R{n}"
        elif hi == 3 and d == 4: s += f"div1 R{m},R{n}"
        elif hi == 3 and d == 5: s += f"dmulu.l R{m},R{n}"
        elif hi == 3 and d == 6: s += f"cmp/hi R{m},R{n}"
        elif hi == 3 and d == 7: s += f"cmp/gt R{m},R{n}"
        elif hi == 3 and d == 8: s += f"sub R{m},R{n}"
        elif hi == 3 and d == 0xC: s += f"add R{m},R{n}"
        elif hi == 3 and d == 0xD: s += f"dmuls.l R{m},R{n}"
        elif hi == 3 and d == 0xE: s += f"addc R{m},R{n}"
        elif hi == 3 and d == 0xF: s += f"addv R{m},R{n}"
        elif hi == 4:
            lo = op & 0xFF
            if lo == 0x00: s += f"shll R{n}"
            elif lo == 0x01: s += f"shlr R{n}"
            elif lo == 0x02: s += f"sts.l MACH,@-R{n}"
            elif lo == 0x04: s += f"rotl R{n}"
            elif lo == 0x05: s += f"rotr R{n}"
            elif lo == 0x06: s += f"lds.l @R{n}+,MACH"
            elif lo == 0x08: s += f"shll2 R{n}"
            elif lo == 0x09: s += f"shlr2 R{n}"
            elif lo == 0x0A: s += f"lds R{n},MACH"
            elif lo == 0x0B: s += f"jsr @R{n}"
            elif lo == 0x10: s += f"dt R{n}"
            elif lo == 0x11: s += f"cmp/pz R{n}"
            elif lo == 0x12: s += f"sts.l MACL,@-R{n}"
            elif lo == 0x15: s += f"cmp/pl R{n}"
            elif lo == 0x18: s += f"shll8 R{n}"
            elif lo == 0x19: s += f"shlr8 R{n}"
            elif lo == 0x1A: s += f"lds R{n},MACL"
            elif lo == 0x1B: s += f"tas.b @R{n}"
            elif lo == 0x20: s += f"shal R{n}"
            elif lo == 0x21: s += f"shar R{n}"
            elif lo == 0x22: s += f"sts.l PR,@-R{n}"
            elif lo == 0x24: s += f"rotcl R{n}"
            elif lo == 0x25: s += f"rotcr R{n}"
            elif lo == 0x26: s += f"lds.l @R{n}+,PR"
            elif lo == 0x28: s += f"shll16 R{n}"
            elif lo == 0x29: s += f"shlr16 R{n}"
            elif lo == 0x2B: s += f"jmp @R{n}"
            elif (lo & 0x0F) == 0x0F: s += f"mac.w @R{m}+,@R{n}+"
            else: s += f"??? (0x{op:04X})"
        elif hi == 5: s += f"mov.l @({d*4},R{m}),R{n}"
        elif hi == 6:
            if d == 0: s += f"mov.b @R{m},R{n}"
            elif d == 1: s += f"mov.w @R{m},R{n}"
            elif d == 2: s += f"mov.l @R{m},R{n}"
            elif d == 3: s += f"mov R{m},R{n}"
            elif d == 4: s += f"mov.b @R{m}+,R{n}"
            elif d == 5: s += f"mov.w @R{m}+,R{n}"
            elif d == 6: s += f"mov.l @R{m}+,R{n}"
            elif d == 7: s += f"not R{m},R{n}"
            elif d == 8: s += f"swap.b R{m},R{n}"
            elif d == 9: s += f"swap.w R{m},R{n}"
            elif d == 0xA: s += f"negc R{m},R{n}"
            elif d == 0xB: s += f"neg R{m},R{n}"
            elif d == 0xC: s += f"extu.b R{m},R{n}"
            elif d == 0xD: s += f"extu.w R{m},R{n}"
            elif d == 0xE: s += f"exts.b R{m},R{n}"
            elif d == 0xF: s += f"exts.w R{m},R{n}"
            else: s += f"??? (0x{op:04X})"
        elif hi == 7:
            imm = dd if dd < 128 else dd - 256
            s += f"add #{imm},R{n}"
        elif hi == 8:
            sub = (op >> 8) & 0xF
            if sub == 0: s += f"mov.b R0,@({d},R{m})"
            elif sub == 1: s += f"mov.w R0,@({d*2},R{m})"
            elif sub == 4: s += f"mov.b @({d},R{m}),R0"
            elif sub == 5: s += f"mov.w @({d*2},R{m}),R0"
            elif sub == 8:
                imm = dd if dd < 128 else dd - 256
                s += f"cmp/eq #{imm},R0"
            elif sub == 9:
                disp = dd if dd < 128 else dd - 256
                target = addr + 4 + disp * 2
                s += f"bt 0x{target:08X}"
            elif sub == 0xB:
                disp = dd if dd < 128 else dd - 256
                target = addr + 4 + disp * 2
                s += f"bf 0x{target:08X}"
            elif sub == 0xD:
                disp = dd if dd < 128 else dd - 256
                target = addr + 4 + disp * 2
                s += f"bt/s 0x{target:08X}"
            elif sub == 0xF:
                disp = dd if dd < 128 else dd - 256
                target = addr + 4 + disp * 2
                s += f"bf/s 0x{target:08X}"
            else: s += f"??? (0x{op:04X})"
        elif hi == 9:
            # mov.w @(disp*2+PC+4), Rn
            lit_addr = (addr + 4 + dd * 2) & 0xFFFFFFFF
            lit_off = lit_addr - base_addr + (i - (addr - base_addr))
            # Can't read literal here easily, just show address
            s += f"mov.w @(0x{lit_addr:08X}),R{n}  ; PC-relative"
        elif hi == 0xA:
            disp = ddd if ddd < 2048 else ddd - 4096
            target = addr + 4 + disp * 2
            s += f"bra 0x{target:08X}"
        elif hi == 0xB:
            disp = ddd if ddd < 2048 else ddd - 4096
            target = addr + 4 + disp * 2
            s += f"bsr 0x{target:08X}"
        elif hi == 0xC:
            sub = (op >> 8) & 0xF
            if sub == 0: s += f"mov.b R0,@({dd},GBR)"
            elif sub == 1: s += f"mov.w R0,@({dd*2},GBR)"
            elif sub == 2: s += f"mov.l R0,@({dd*4},GBR)"
            elif sub == 4: s += f"mov.b @({dd},GBR),R0"
            elif sub == 5: s += f"mov.w @({dd*2},GBR),R0"
            elif sub == 6: s += f"mov.l @({dd*4},GBR),R0"
            elif sub == 7: s += f"mova @(0x{(addr&~3)+4+dd*4:08X}),R0"
            elif sub == 8: s += f"tst #{dd},R0"
            elif sub == 9: s += f"and #{dd},R0"
            elif sub == 0xA: s += f"xor #{dd},R0"
            elif sub == 0xB: s += f"or #{dd},R0"
            else: s += f"??? (0x{op:04X})"
        elif hi == 0xD:
            # mov.l @(disp*4+PC+4 & ~3), Rn
            lit_addr = ((addr + 4) & ~3) + dd * 4
            s += f"mov.l @(0x{lit_addr:08X}),R{n}  ; PC-relative"
        elif hi == 0xE:
            imm = dd if dd < 128 else dd - 256
            s += f"mov #{imm},R{n}"
        elif hi == 0xF:
            s += f"??? (0x{op:04X})  ; FPU?"
        else:
            s += f"??? (0x{op:04X})"

        lines.append(s)
        i += 2
    return lines


if __name__ == '__main__':
    with open('D:/DragonsDreamDecomp/extracted/0.BIN', 'rb') as f:
        data = f.read()

    BASE = 0x06010000

    # Analyze key areas - ROUND 9: gate_set function and caller
    areas = [
        # gate_set function at 0x0603B488
        ("gate_set 0x0603B488 (CORRECTED)", 0x02B488, 100),
        # Who calls vtable[6]? Look at 0x0603B6F0 (state transition, vtable index 13)
        ("State transition 0x0603B6F0 (CORRECTED)", 0x02B6F0, 200),
    ]

    for name, offset, size in areas:
        print(f"\n{'='*60}")
        print(f"  {name} (file 0x{offset:06X}, mem 0x{BASE+offset:08X})")
        print(f"{'='*60}")
        chunk = data[offset:offset+size]
        lines = disasm_sh2(chunk, BASE + offset, size)

        # Also show literal pool values where possible
        for line in lines:
            if "PC-relative" in line and "mov.l" in line:
                # Extract the address and look up the literal
                parts = line.split("@(0x")
                if len(parts) >= 2:
                    addr_str = parts[1].split(")")[0]
                    try:
                        lit_mem = int(addr_str, 16)
                        lit_off = lit_mem - BASE
                        if 0 <= lit_off + 3 < len(data):
                            val = struct.unpack('>I', data[lit_off:lit_off+4])[0]
                            line += f"  = 0x{val:08X}"
                            # Check if it's a string pointer
                            str_off = val - BASE
                            if 0 <= str_off < len(data) and data[str_off] >= 0x20:
                                end = data.find(b'\x00', str_off, str_off+40)
                                if end > str_off:
                                    try:
                                        s = data[str_off:end].decode('ascii')
                                        line += f'  "{s}"'
                                    except: pass
                    except: pass
            if "PC-relative" in line and "mov.w" in line:
                parts = line.split("@(0x")
                if len(parts) >= 2:
                    addr_str = parts[1].split(")")[0]
                    try:
                        lit_mem = int(addr_str, 16)
                        lit_off = lit_mem - BASE
                        if 0 <= lit_off + 1 < len(data):
                            val = struct.unpack('>H', data[lit_off:lit_off+2])[0]
                            line += f"  = 0x{val:04X} ({val})"
                    except: pass
            print(line)
