#!/usr/bin/env python3
"""
Search Dragon's Dream Saturn binary for code that builds the 18-byte session response.

Binary: extracted/0.BIN (504,120 bytes, SH-2 big-endian, loaded at 0x06010000)
"""

import struct
import sys

BINARY_PATH = r"D:\DragonsDreamDecomp\extracted\0.BIN"
BASE_ADDR = 0x06010000

def file_to_mem(offset):
    return offset + BASE_ADDR

def mem_to_file(addr):
    return addr - BASE_ADDR

def hexdump(data, offset, context=16):
    """Show hex dump around a position."""
    start = max(0, offset - context)
    end = min(len(data), offset + context)
    lines = []
    for i in range(start, end, 16):
        chunk = data[i:min(i+16, end)]
        hex_part = ' '.join(f'{b:02X}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        marker = ""
        if i <= offset < i + 16:
            marker = f"  <-- target at +{offset - i}"
        lines.append(f"  {file_to_mem(i):08X} (file {i:06X}): {hex_part:<48s} |{ascii_part}|{marker}")
    return '\n'.join(lines)

def main():
    with open(BINARY_PATH, 'rb') as f:
        data = f.read()

    print(f"Binary size: {len(data)} bytes ({len(data):06X})")
    print(f"Memory range: {BASE_ADDR:08X} - {file_to_mem(len(data)):08X}")
    print()

    # =========================================================================
    # Search A: All occurrences of 1F 40 (0x1F40 = 8000)
    # =========================================================================
    print("=" * 80)
    print("SEARCH A: Bytes 1F 40 (0x1F40 = 8000, timeout value)")
    print("=" * 80)

    pattern_1f40 = b'\x1F\x40'
    pos = 0
    count = 0
    while True:
        idx = data.find(pattern_1f40, pos)
        if idx == -1:
            break
        count += 1
        aligned = "4-aligned" if idx % 4 == 0 else f"align={idx%4}"
        # Check if it's part of a 4-byte literal pool entry (00 00 1F 40)
        is_full_32 = ""
        if idx >= 2 and data[idx-2:idx] == b'\x00\x00':
            is_full_32 = " ** 32-bit literal: 0x00001F40 **"
        print(f"\n  [{count}] File offset: 0x{idx:06X}  Mem: 0x{file_to_mem(idx):08X}  ({aligned}){is_full_32}")
        print(hexdump(data, idx, 32))
        pos = idx + 1
    print(f"\n  Total occurrences of 1F 40: {count}")

    # =========================================================================
    # Search B: All occurrences of 07 D0 (0x07D0 = 2000)
    # =========================================================================
    print()
    print("=" * 80)
    print("SEARCH B: Bytes 07 D0 (0x07D0 = 2000, timeout value)")
    print("=" * 80)

    pattern_07d0 = b'\x07\xD0'
    pos = 0
    count = 0
    while True:
        idx = data.find(pattern_07d0, pos)
        if idx == -1:
            break
        count += 1
        aligned = "4-aligned" if idx % 4 == 0 else f"align={idx%4}"
        is_full_32 = ""
        if idx >= 2 and data[idx-2:idx] == b'\x00\x00':
            is_full_32 = " ** 32-bit literal: 0x000007D0 **"
        print(f"\n  [{count}] File offset: 0x{idx:06X}  Mem: 0x{file_to_mem(idx):08X}  ({aligned}){is_full_32}")
        print(hexdump(data, idx, 32))
        pos = idx + 1
    print(f"\n  Total occurrences of 07 D0: {count}")

    # =========================================================================
    # Search C: 4-byte literal 06 06 23 D8 (SV send queue at 0x060623D8)
    # =========================================================================
    print()
    print("=" * 80)
    print("SEARCH C: 4-byte literal 06 06 23 D8 (SV send queue addr 0x060623D8)")
    print("=" * 80)

    pattern_queue = b'\x06\x06\x23\xD8'
    pos = 0
    count = 0
    while True:
        idx = data.find(pattern_queue, pos)
        if idx == -1:
            break
        count += 1
        aligned = "4-aligned" if idx % 4 == 0 else f"align={idx%4}"
        print(f"\n  [{count}] File offset: 0x{idx:06X}  Mem: 0x{file_to_mem(idx):08X}  ({aligned})")
        print(hexdump(data, idx, 48))
        pos = idx + 1
    print(f"\n  Total occurrences: {count}")

    # Also search nearby queue addresses
    for offset_delta in [-0x10, -0x08, -0x04, 0x04, 0x08, 0x10]:
        alt_addr = 0x060623D8 + offset_delta
        alt_bytes = struct.pack('>I', alt_addr)
        idx = data.find(alt_bytes)
        if idx != -1:
            print(f"\n  Also found nearby address 0x{alt_addr:08X} at file 0x{idx:06X} (mem 0x{file_to_mem(idx):08X})")

    # =========================================================================
    # Search D: mov #0xA6, Rn instructions (EnA6 where n=0..F)
    # =========================================================================
    print()
    print("=" * 80)
    print("SEARCH D: SH-2 'mov #0xA6, Rn' instructions (0xEnA6, n=0..15)")
    print("  (0xA6 = -90 signed = 166 unsigned = session marker byte)")
    print("=" * 80)

    count = 0
    for reg in range(16):
        opcode = bytes([(0xE0 | reg), 0xA6])
        pos = 0
        while True:
            idx = data.find(opcode, pos)
            if idx == -1:
                break
            # SH-2 instructions are 2-byte aligned
            if idx % 2 == 0:
                count += 1
                print(f"\n  [{count}] mov #0xA6, R{reg}  at file 0x{idx:06X}  mem 0x{file_to_mem(idx):08X}")
                print(hexdump(data, idx, 32))
            pos = idx + 1
    print(f"\n  Total instruction matches: {count}")

    # =========================================================================
    # Search E: mov #0x44, Rn instructions (En44, flags byte)
    # =========================================================================
    print()
    print("=" * 80)
    print("SEARCH E: SH-2 'mov #0x44, Rn' instructions (0xEn44, n=0..15)")
    print("  (0x44 = 68 = 'D' = flags byte in session response)")
    print("=" * 80)

    count = 0
    for reg in range(16):
        opcode = bytes([(0xE0 | reg), 0x44])
        pos = 0
        while True:
            idx = data.find(opcode, pos)
            if idx == -1:
                break
            if idx % 2 == 0:
                count += 1
                print(f"\n  [{count}] mov #0x44, R{reg}  at file 0x{idx:06X}  mem 0x{file_to_mem(idx):08X}")
                print(hexdump(data, idx, 32))
            pos = idx + 1
    print(f"\n  Total instruction matches: {count}")

    # =========================================================================
    # Search F: mov #0x1C, Rn instructions (En1C, sub-header byte)
    # =========================================================================
    print()
    print("=" * 80)
    print("SEARCH F: SH-2 'mov #0x1C, Rn' instructions (0xEn1C, n=0..15)")
    print("  (0x1C = 28 = sub-header byte in session response)")
    print("=" * 80)

    count = 0
    for reg in range(16):
        opcode = bytes([(0xE0 | reg), 0x1C])
        pos = 0
        while True:
            idx = data.find(opcode, pos)
            if idx == -1:
                break
            if idx % 2 == 0:
                count += 1
                print(f"\n  [{count}] mov #0x1C, R{reg}  at file 0x{idx:06X}  mem 0x{file_to_mem(idx):08X}")
                print(hexdump(data, idx, 32))
            pos = idx + 1
    print(f"\n  Total instruction matches: {count}")

    # =========================================================================
    # Search G: Look for 0xA6 and 0x44 as consecutive byte stores
    # =========================================================================
    print()
    print("=" * 80)
    print("SEARCH G: Byte sequence A6 44 anywhere in binary")
    print("  (First 2 bytes of the session response)")
    print("=" * 80)

    pattern_a644 = b'\xA6\x44'
    pos = 0
    count = 0
    while True:
        idx = data.find(pattern_a644, pos)
        if idx == -1:
            break
        count += 1
        # Check if this could be a data template (has more of the message following)
        following = data[idx:idx+18] if idx + 18 <= len(data) else data[idx:]
        is_template = ""
        if len(following) >= 8 and following[6] == 0x1C:
            is_template = " ** POSSIBLE MESSAGE TEMPLATE (byte[6]=0x1C) **"
        print(f"\n  [{count}] File offset: 0x{idx:06X}  Mem: 0x{file_to_mem(idx):08X}{is_template}")
        print(hexdump(data, idx, 32))
        pos = idx + 1
    print(f"\n  Total occurrences: {count}")

    # =========================================================================
    # Search H: Look for the SV send queue base area 0x060623xx
    # =========================================================================
    print()
    print("=" * 80)
    print("SEARCH H: Any 4-byte pointer in range 0x06062300-0x060624FF")
    print("  (SV send queue area references)")
    print("=" * 80)

    count = 0
    for addr in range(0x06062300, 0x06062500, 4):
        pattern = struct.pack('>I', addr)
        pos = 0
        while True:
            idx = data.find(pattern, pos)
            if idx == -1:
                break
            if idx % 4 == 0:  # Literal pool entries are 4-aligned
                count += 1
                print(f"\n  [{count}] Pointer 0x{addr:08X} at file 0x{idx:06X}  mem 0x{file_to_mem(idx):08X}")
                print(hexdump(data, idx, 32))
            pos = idx + 1
    print(f"\n  Total pointer references: {count}")

    # =========================================================================
    # Search I: Look for "023C" ASCII string (the checksum in the message)
    # =========================================================================
    print()
    print("=" * 80)
    print("SEARCH I: ASCII '023C' in binary (checksum value in session response)")
    print("=" * 80)

    pattern_023c = b'023C'
    pos = 0
    count = 0
    while True:
        idx = data.find(pattern_023c, pos)
        if idx == -1:
            break
        count += 1
        print(f"\n  [{count}] File offset: 0x{idx:06X}  Mem: 0x{file_to_mem(idx):08X}")
        print(hexdump(data, idx, 32))
        pos = idx + 1
    print(f"\n  Total occurrences: {count}")

    # Also search for lowercase
    pattern_023c_low = b'023c'
    pos = 0
    while True:
        idx = data.find(pattern_023c_low, pos)
        if idx == -1:
            break
        count += 1
        print(f"\n  [{count}] (lowercase) File offset: 0x{idx:06X}  Mem: 0x{file_to_mem(idx):08X}")
        print(hexdump(data, idx, 32))
        pos = idx + 1
    print(f"\n  Total occurrences (including lowercase): {count}")

    # =========================================================================
    # Search J: Check if 0x12 (18 decimal) appears as a size parameter
    # near any of the SV queue code. Also search for mov #18, Rn = En12
    # =========================================================================
    print()
    print("=" * 80)
    print("SEARCH J: SH-2 'mov #0x12, Rn' (0xEn12) — loading size 18")
    print("  (18 = length of the session response message)")
    print("=" * 80)

    count = 0
    for reg in range(16):
        opcode = bytes([(0xE0 | reg), 0x12])
        pos = 0
        while True:
            idx = data.find(opcode, pos)
            if idx == -1:
                break
            if idx % 2 == 0:
                count += 1
                print(f"\n  [{count}] mov #0x12, R{reg}  at file 0x{idx:06X}  mem 0x{file_to_mem(idx):08X}")
                print(hexdump(data, idx, 32))
            pos = idx + 1
    print(f"\n  Total instruction matches: {count}")

    # =========================================================================
    # Search K: Known SV library functions — look for references to SV buffer
    # addresses near 0x06062000-0x06062FFF
    # =========================================================================
    print()
    print("=" * 80)
    print("SEARCH K: Key SV-related addresses in literal pools")
    print("=" * 80)

    # The SV send buffer, state vars, etc.
    key_addrs = {
        0x060623C0: "SV send state area (approx)",
        0x060623C8: "SV send state area",
        0x060623D0: "SV send state area",
        0x060623D4: "SV send queue write ptr?",
        0x060623D8: "SV send queue base",
        0x060623DC: "SV send queue",
        0x060623E0: "SV send queue",
        0x060623E8: "SV send queue",
        0x060623F0: "SV send queue",
        0x06062400: "SV area",
        0x06062148: "nMsgSize / SCMD area",
    }

    for addr, desc in sorted(key_addrs.items()):
        pattern = struct.pack('>I', addr)
        pos = 0
        found = False
        while True:
            idx = data.find(pattern, pos)
            if idx == -1:
                break
            found = True
            print(f"\n  0x{addr:08X} ({desc}) at file 0x{idx:06X}  mem 0x{file_to_mem(idx):08X}")
            print(hexdump(data, idx, 32))
            pos = idx + 1
        if not found:
            pass  # Don't print not found to reduce noise

    print()
    print("=" * 80)
    print("DONE")
    print("=" * 80)

if __name__ == '__main__':
    main()
