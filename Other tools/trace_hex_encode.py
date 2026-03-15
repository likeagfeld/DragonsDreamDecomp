#!/usr/bin/env python3
"""
Trace the hex encoding function at 0x06042A14 and the checksum function at 0x060429B6.
Also trace 0x06041CC0 (appears to be checksumming the packet).
"""

import struct

BINARY_PATH = r"D:\DragonsDreamDecomp\extracted\0.BIN"
BASE_ADDR = 0x06010000

def file_to_mem(off):
    return off + BASE_ADDR

def mem_to_file(addr):
    return addr - BASE_ADDR

from disasm_session_builder import decode_sh2

def disasm_func(data, addr, max_bytes=0x200, max_rts=1):
    """Disassemble a function starting at addr."""
    start = mem_to_file(addr)
    end = start + max_bytes
    pc_file = start
    rts_count = 0
    lines = []
    while pc_file < end and pc_file + 1 < len(data):
        opcode = struct.unpack('>H', data[pc_file:pc_file+2])[0]
        pc = file_to_mem(pc_file)
        mnemonic = decode_sh2(opcode, pc)

        extra = ""
        if (opcode >> 12) == 0xD:
            disp = opcode & 0xFF
            lit_addr = (pc & ~3) + 4 + disp * 4
            lit_file = mem_to_file(lit_addr)
            if 0 <= lit_file + 3 < len(data):
                lit_val = struct.unpack('>I', data[lit_file:lit_file+4])[0]
                extra = f"  => 0x{lit_val:08X}"
        if (opcode >> 12) == 0x9:
            disp = opcode & 0xFF
            lit_addr = pc + 4 + disp * 2
            lit_file = mem_to_file(lit_addr)
            if 0 <= lit_file + 1 < len(data):
                lit_val = struct.unpack('>H', data[lit_file:lit_file+2])[0]
                extra = f"  => 0x{lit_val:04X} ({lit_val})"

        lines.append(f"  {pc:08X}: {data[pc_file]:02X} {data[pc_file+1]:02X}  {mnemonic}{extra}")

        if opcode == 0x000B:
            rts_count += 1
            pc_file += 2
            if pc_file + 1 < len(data):
                opcode2 = struct.unpack('>H', data[pc_file:pc_file+2])[0]
                pc2 = file_to_mem(pc_file)
                mnemonic2 = decode_sh2(opcode2, pc2)
                lines.append(f"  {pc2:08X}: {data[pc_file]:02X} {data[pc_file+1]:02X}  {mnemonic2}")
            if rts_count >= max_rts:
                break
        pc_file += 2
    return '\n'.join(lines)


def main():
    with open(BINARY_PATH, 'rb') as f:
        data = f.read()

    print("=" * 80)
    print("Function at 0x06042A14 (hex nibble encoder, called 8 times for hex checksum)")
    print("=" * 80)
    print(disasm_func(data, 0x06042A14, max_rts=1))

    print()
    print("=" * 80)
    print("Function at 0x060429B6 (checksum calculator)")
    print("=" * 80)
    print(disasm_func(data, 0x060429B6, max_rts=1))

    print()
    print("=" * 80)
    print("Function at 0x060429D2 (related to checksum, called nearby)")
    print("=" * 80)
    print(disasm_func(data, 0x060429D2, max_rts=1))

    print()
    print("=" * 80)
    print("Function at 0x06041CC0 (packet checksum/encode)")
    print("=" * 80)
    print(disasm_func(data, 0x06041CC0, max_rts=2))

    print()
    print("=" * 80)
    print("Function at 0x06041CFC (referenced from 0x060222B6)")
    print("=" * 80)
    print(disasm_func(data, 0x06041CFC, max_rts=2))

    # Let's also look at the session state structure at 0x06062314
    # to understand what fields are used
    print()
    print("=" * 80)
    print("Session state structure at 0x06062314 (initialized at 0x060221F8)")
    print("Based on the init function, the structure layout is:")
    print("=" * 80)
    print("  Offset +0:  0  (state flag)")
    print("  Offset +4:  0")
    print("  Offset +8:  0")
    print("  Offset +12: 0")
    print("  Offset +20: 0x1F40 (8000) = send_timeout")
    print("  Offset +24: 0x07D0 (2000) = recv_timeout")
    print("  Offset +28: byte 0x1C at offset 40 stored as: R6=0x1C, mov.b R6,@(R0+R4) where R0=0x28=40")
    print("  Offset +36: 5")
    print()
    print("  Offset +40 (0x28): 0x1C")
    print("  Offset +41 (0x29): R3+R5=0x11 (17)")
    print("  Offset +42 (0x2A): 0x13 (19)")
    print("  Offset +43 (0x2B): 0x1B (27)")
    print("  Offset +44 (0x2C): 0x0D (13)")
    print("  Offset +45 (0x2D): 0x1C (R6)")
    print()
    print("  Offset +48: func_ptr -> 0x06022910 (callback: RTS=nop, does nothing)")
    print("  Offset +52: func_ptr -> 0x06022914 (callback: recv handler)")
    print("  Offset +56: func_ptr -> 0x060229A0 (callback: SV send queue enqueue)")
    print("  Offset +60: func_ptr -> 0x06022A2E (callback: clear send pending)")
    print("  Offset +64: func_ptr -> 0x06022A36 (callback: error/disconnect)")

    # Now let's understand the function at 0x060420AE in pseudocode
    print()
    print("=" * 80)
    print("PSEUDOCODE for 0x060420AE (sv_build_and_send_frame)")
    print("=" * 80)
    print("""
This function builds an SV protocol frame.

Input:
  R4 = session_state_ptr (0x06062314)
  R5 = data_ptr (pointer to payload data)
  R6 = data_remaining_count
  R7 = ? (stored as arg)

The function:
1. Checks state[+36] (callback at offset +36) -- if set, R3=1, else R3=0
   This is the "has_session" flag
2. Checks state[+96] (0x60) for value 2 (connection state)
3. If state 2: jumps to frame building at 0x060420F4

Frame building (starting at 0x060420FC):
  - R0 = 0x44 (68) -> state[+0x44] fetched as R4
  - Calls 0x060457B4(R4) -> R10 = result (allocated buffer?)
  - If R10 == 0: return error 2

  - R13 = R10 + 16 (start of frame data at offset +16)

  Key frame layout at R13:
    [0]  = 0xA6 or 0xA5 (session marker)
    [1]  = 0x33 (flags byte)
    [2:3]= 0x0000 (sequence/checksum, filled later)
    [4:5]= 0x0000 (filled later)
    [6]  = sub-header byte (from state[+40])
    [7]  = 0 initially, then OR'd with flags

  For a SESSION RESPONSE (has_session=true, state[+0]):
    byte[0] = 0xA6 (loaded from literal pool at 0x06042130)
    byte[1] = 0x33 (hardcoded)
    byte[2:3] = 0 (R11=0, stored as word)
    byte[4:5] = 0 (R11=0, stored as word)
    byte[6] = state[+40] = 0x1C (from init)
    byte[7] = 0 initially

    If state[+0] != 0: byte[7] = R9 = 1
    If R12 == initial_count: byte[7] |= 2

  For a SESSION RESPONSE with data (has_session=true):
    byte[8:11] = state[+0x64] = send counter (uint32 BE)
    byte[12:15] = state[+0x6C] = recv counter (uint32 BE)
    Then payload data copied from R8 (data_ptr)
    byte[16:17] = data_len (uint16 BE)

  Checksum at 0x06041CC0 and 0x060429B6 applied to frame
  Result stored in byte[2:3] as checksum

  For SESSION ESTABLISHMENT (has_session=false):
    byte[0] = 0xA5 (loaded from literal pool at 0x06042266)
    byte[2:7] = 8 hex chars of checksum (ASCII encoded via 0x06042A14)
    Payload data also hex-encoded via 0x06042A14

  After building frame:
    Calls 0x060229A0 to enqueue into SV send queue at 0x060623D8
""")

    # Let's look at the hex table used by 0x06042A14
    # The hex encoding function probably uses the table "0123456789abcdef"
    # Let's search for it
    print()
    print("=" * 80)
    print("Function at 0x060457B4 (allocate buffer?)")
    print("=" * 80)
    print(disasm_func(data, 0x060457B4, max_rts=1))

    print()
    print("=" * 80)
    print("Function at 0x060457A2 (related to buffer alloc)")
    print("=" * 80)
    print(disasm_func(data, 0x060457A2, max_rts=1))

    # Also disassemble 0x06042B20 (called at 0x06042314)
    print()
    print("=" * 80)
    print("Function at 0x06042B20 (called after building frame)")
    print("=" * 80)
    print(disasm_func(data, 0x06042B20, max_rts=1))

    # And 0x06042DC6 and 0x06042E30
    print()
    print("=" * 80)
    print("Function at 0x06042DC6")
    print("=" * 80)
    print(disasm_func(data, 0x06042DC6, max_rts=1))

    print()
    print("=" * 80)
    print("Function at 0x06042E30")
    print("=" * 80)
    print(disasm_func(data, 0x06042E30, max_rts=1))


if __name__ == '__main__':
    main()
