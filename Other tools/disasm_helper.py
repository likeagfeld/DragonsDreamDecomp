#!/usr/bin/env python
"""SH-2 disassembler helper for Dragon's Dream decomp."""

import struct
import sys

def disasm(word, addr):
    hi = (word >> 12) & 0xF
    lo = word & 0xF
    n = (word >> 8) & 0xF
    m = (word >> 4) & 0xF
    d8 = word & 0xFF
    d4 = word & 0xF
    d12 = word & 0xFFF

    if hi == 0xE:
        imm = d8 if d8 < 128 else d8 - 256
        return f"mov #{imm}, R{n}"
    elif hi == 0x7:
        imm = d8 if d8 < 128 else d8 - 256
        return f"add #{imm}, R{n}"
    elif hi == 0x2:
        if lo == 0: return f"mov.b R{m}, @R{n}"
        if lo == 1: return f"mov.w R{m}, @R{n}"
        if lo == 2: return f"mov.l R{m}, @R{n}"
        if lo == 4: return f"mov.b R{m}, @-R{n}"
        if lo == 5: return f"mov.w R{m}, @-R{n}"
        if lo == 6: return f"mov.l R{m}, @-R{n}"
        if lo == 8: return f"tst R{m}, R{n}"
        if lo == 9: return f"and R{m}, R{n}"
        if lo == 0xA: return f"xor R{m}, R{n}"
        if lo == 0xB: return f"or R{m}, R{n}"
        if lo == 0xD: return f"xtrct R{m}, R{n}"
    elif hi == 0x6:
        if lo == 0: return f"mov.b @R{m}, R{n}"
        if lo == 1: return f"mov.w @R{m}, R{n}"
        if lo == 2: return f"mov.l @R{m}, R{n}"
        if lo == 3: return f"mov R{m}, R{n}"
        if lo == 4: return f"mov.b @R{m}+, R{n}"
        if lo == 5: return f"mov.w @R{m}+, R{n}"
        if lo == 6: return f"mov.l @R{m}+, R{n}"
        if lo == 8: return f"swap.b R{m}, R{n}"
        if lo == 9: return f"swap.w R{m}, R{n}"
        if lo == 0xD: return f"extu.w R{m}, R{n}"
        if lo == 0xE: return f"exts.b R{m}, R{n}"
        if lo == 0xF: return f"exts.w R{m}, R{n}"
    elif hi == 0x0:
        if lo == 4: return f"mov.b R{m}, @(R0,R{n})"
        if lo == 5: return f"mov.w R{m}, @(R0,R{n})"
        if lo == 6: return f"mov.l R{m}, @(R0,R{n})"
        if lo == 0xC: return f"mov.b @(R0,R{m}), R{n}"
        if lo == 0xD: return f"mov.w @(R0,R{m}), R{n}"
        if lo == 0xE: return f"mov.l @(R0,R{m}), R{n}"
        if lo == 9 and m == 0: return "nop"
        if lo == 0xB:
            if m == 0: return f"jsr @R{n}"
            if m == 2: return f"bsrf R{n}"
        if lo == 3:
            if m == 0: return f"braf R{n}"
    elif hi == 0x4:
        if lo == 0xB:
            if m == 0: return f"jsr @R{n}"
            if m == 1: return f"tas.b @R{n}"
            if m == 2: return f"jmp @R{n}"
        if lo == 0x6:
            if m == 0: return f"lds.l @R{n}+, MACH"
            if m == 1: return f"lds.l @R{n}+, MACL"
            if m == 2: return f"lds.l @R{n}+, PR"
        if lo == 0x2:
            if m == 0: return f"stc.l SR, @-R{n}"
            if m == 1: return f"stc.l GBR, @-R{n}"
            if m == 2: return f"stc.l VBR, @-R{n}"
        if lo == 0xE: return f"ldc R{n}, SR"
        if lo == 0x7:
            if m == 0: return f"ldc.l @R{n}+, SR"
            if m == 1: return f"ldc.l @R{n}+, GBR"
        if lo == 0: return f"shll R{n}"
        if lo == 1: return f"shlr R{n}"
        if lo == 8:
            if m == 0: return f"shll2 R{n}"
            if m == 1: return f"shll8 R{n}"
            if m == 2: return f"shll16 R{n}"
        if lo == 9:
            if m == 0: return f"shlr2 R{n}"
            if m == 1: return f"shlr8 R{n}"
            if m == 2: return f"shlr16 R{n}"
        if lo == 5:
            if m == 0: return f"rotr R{n}"
            if m == 2: return f"rotcr R{n}"
        if lo == 4:
            if m == 0: return f"rotl R{n}"
            if m == 2: return f"rotcl R{n}"
        if lo == 0xA:
            if m == 0: return f"lds R{n}, MACH"
            if m == 1: return f"lds R{n}, MACL"
            if m == 2: return f"lds R{n}, PR"
        if lo == 0xF: return f"mac.w @R{m}+, @R{n}+"
        if lo == 0x3:
            if m == 0: return f"stc SR, R{n}"
    elif hi == 0x8:
        if n == 0: return f"mov.b R0, @({d4},R{m})"
        if n == 1: return f"mov.w R0, @({d4*2},R{m})"
        if n == 4: return f"mov.b @({d4},R{m}), R0"
        if n == 5: return f"mov.w @({d4*2},R{m}), R0"
        if n == 9:
            disp = d8 if d8 < 128 else d8 - 256
            return f"bt 0x{addr + 4 + disp * 2:08X}"
        if n == 0xB:
            disp = d8 if d8 < 128 else d8 - 256
            return f"bf 0x{addr + 4 + disp * 2:08X}"
        if n == 0xD:
            disp = d8 if d8 < 128 else d8 - 256
            return f"bt/s 0x{addr + 4 + disp * 2:08X}"
        if n == 0xF:
            disp = d8 if d8 < 128 else d8 - 256
            return f"bf/s 0x{addr + 4 + disp * 2:08X}"
    elif hi == 0x9:
        disp = d8
        target = addr + 4 + disp * 2
        return f"mov.w @(0x{target:08X}), R{n}  ; pc-rel"
    elif hi == 0xD:
        disp = d8
        target = (addr & ~3) + 4 + disp * 4
        return f"mov.l @(0x{target:08X}), R{n}  ; pc-rel"
    elif hi == 0xA:
        disp = d12 if d12 < 2048 else d12 - 4096
        return f"bra 0x{addr + 4 + disp * 2:08X}"
    elif hi == 0xB:
        disp = d12 if d12 < 2048 else d12 - 4096
        return f"bsr 0x{addr + 4 + disp * 2:08X}"
    elif hi == 0x3:
        if lo == 0: return f"cmp/eq R{m}, R{n}"
        if lo == 2: return f"cmp/hs R{m}, R{n}"
        if lo == 3: return f"cmp/ge R{m}, R{n}"
        if lo == 6: return f"cmp/hi R{m}, R{n}"
        if lo == 7: return f"cmp/gt R{m}, R{n}"
        if lo == 8: return f"sub R{m}, R{n}"
        if lo == 0xC: return f"add R{m}, R{n}"
    elif hi == 0x1:
        return f"mov.l R{m}, @({d4*4},R{n})"
    elif hi == 0x5:
        return f"mov.l @({d4*4},R{m}), R{n}"
    elif hi == 0xC:
        if n == 1: return f"and.b #{d8}, @(R0,GBR)"
        if n == 3: return f"or.b #{d8}, @(R0,GBR)"
        if n == 7: return f"mova @(0x{((addr & ~3) + 4 + d8*4):08X}), R0"

    return f"??? (0x{word:04X})"


def disasm_range(filename, start_addr, end_addr, base=0x06010000, annotations=None):
    """Disassemble a range of addresses."""
    if annotations is None:
        annotations = {}
    with open(filename, "rb") as f:
        start_off = start_addr - base
        length = end_addr - start_addr
        f.seek(start_off)
        data = f.read(length)
        for i in range(0, len(data), 2):
            addr = start_addr + i
            word = struct.unpack(">H", data[i:i+2])[0]
            d = disasm(word, addr)
            ann = annotations.get(addr, "")
            print(f"  0x{addr:08X}: {word:04X}  {d}{ann}")


def read_literals(filename, addresses, size=2, base=0x06010000):
    """Read literal pool values."""
    with open(filename, "rb") as f:
        for addr in addresses:
            f.seek(addr - base)
            if size == 2:
                val = struct.unpack(">H", f.read(2))[0]
                print(f"  word at 0x{addr:08X}: 0x{val:04X} ({val})")
            elif size == 4:
                val = struct.unpack(">I", f.read(4))[0]
                print(f"  long at 0x{addr:08X}: 0x{val:08X}")


if __name__ == "__main__":
    BIN = "extracted/0.BIN"
    cmd = sys.argv[1] if len(sys.argv) > 1 else "help"

    if cmd == "func1":
        # Function at 0x0603B51C
        print("=== Function at 0x0603B51C (called with arg via switch table) ===")
        annotations = {
            0x0603B696: "  ; *** VALUE 3 for session[0x01AD] ***",
            0x0603B69C: "  ; STORE 0 at R12+0x01BC = session[0x01BC]",
            0x0603B69E: "  ; R0 = 0x01BC - 15 = 0x01AD",
            0x0603B6A0: "  ; *** STORE 3 at R12+0x01AD = session[0x01AD] ***",
            0x0603B6B4: "  ; STORE 1 at R12+0x01BC = session[0x01BC]",
        }
        disasm_range(BIN, 0x0603B51C, 0x0603B6D0, annotations=annotations)
        print("\n=== Literal pool ===")
        read_literals(BIN, [0x0603B6CA, 0x0603B6CC, 0x0603B6CE, 0x0603B6D0, 0x0603B6D2])
        read_literals(BIN, [0x0603B6D4, 0x0603B6D8, 0x0603B6DC, 0x0603B6E0, 0x0603B6E4, 0x0603B6E8, 0x0603B6EC], size=4)

    elif cmd == "func2":
        # Function at 0x0603B6F0
        print("=== Function at 0x0603B6F0 (called with arg via switch table) ===")
        annotations = {
            0x0603B86A: "  ; *** VALUE 2 for session[0x01AD] ***",
            0x0603B870: "  ; STORE 0 at R12+0x01BC = session[0x01BC]",
            0x0603B872: "  ; R0 = 0x01BC - 15 = 0x01AD",
            0x0603B874: "  ; *** STORE 2 at R12+0x01AD = session[0x01AD] ***",
            0x0603B888: "  ; STORE 1 at R12+0x01BC = session[0x01BC]",
        }
        disasm_range(BIN, 0x0603B6F0, 0x0603B8A8, annotations=annotations)
        print("\n=== Literal pool ===")
        read_literals(BIN, [0x0603B89E, 0x0603B8A0, 0x0603B8A2, 0x0603B8A4, 0x0603B8A6])
        read_literals(BIN, [0x0603B8A8, 0x0603B8AC, 0x0603B8B0, 0x0603B8B4, 0x0603B8B8, 0x0603B8BC, 0x0603B8C0], size=4)

    elif cmd == "callers":
        # Find what calls these functions - search for references
        print("=== Searching for callers of 0x0603B51C and 0x0603B6F0 ===")
        with open(BIN, "rb") as f:
            data = f.read()
            # Search for address values in literal pools
            targets = [0x0603B51C, 0x0603B6F0]
            for target in targets:
                tb = struct.pack(">I", target)
                pos = 0
                while True:
                    idx = data.find(tb, pos)
                    if idx == -1:
                        break
                    addr = 0x06010000 + idx
                    print(f"  Reference to 0x{target:08X} at 0x{addr:08X} (file offset 0x{idx:06X})")
                    pos = idx + 1

    elif cmd == "help":
        print("Usage: python disasm_helper.py [func1|func2|callers]")
