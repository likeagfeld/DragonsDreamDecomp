#!/usr/bin/env python3
"""
Deep analysis of the session response builder.

Key finding from previous analysis:
- Function at 0x060222CC: SV send enqueue function
  - Takes R4=pointer to data, R5=size(?)
  - Uses R3=0x12 (18 bytes), R1=0x060623E0 (SV send queue)
  - Called with `mov #0x12, R3` (18 = size of session response)

We need to find who CALLS this function with 18 bytes of A6 44 30 32 33 43 1C...

Strategy: Search for BSR/JSR calls targeting 0x060222CC
Also look for the SV init function at 0x060221F8 which sets up the session
parameters (timeout values 0x1F40 and 0x07D0).
"""

import struct

BINARY_PATH = r"D:\DragonsDreamDecomp\extracted\0.BIN"
BASE_ADDR = 0x06010000

def file_to_mem(off):
    return off + BASE_ADDR

def mem_to_file(addr):
    return addr - BASE_ADDR

def main():
    with open(BINARY_PATH, 'rb') as f:
        data = f.read()

    # =========================================================================
    # The function at 0x060222CC appears to be sv_send_enqueue(data_ptr, size)
    # Actually looking more carefully at the disassembly:
    #   060222CC: mov.l R14,@-R15      ; save R14
    #   060222CE: mov #0x12, R3        ; R3 = 18 !! size of session response
    #   060222D0: mov.l @(0x74,PC),R1  ; R1 = 0x060623E0 (SV send queue)
    #   060222D2: mov.l R13,@-R15      ; save R13
    #   060222D4: sts.l PR,@-R15       ; save return address
    #   060222D6: mov R4,R13           ; R13 = R4 (first argument)
    #   060222D8: add #-4, R15         ; make room on stack
    #   060222DA: mov.l R5,@R15        ; save R5 (second argument) on stack
    #   060222DC: mov.l R0,@(32,GBR)   ; store R0 to GBR+32 ???
    #   060222DE: mov R0,R4            ; R4 = R0
    #   060222E0: mov.l @R1,R2         ; R2 = [0x060623E0] (current queue count?)
    #   060222E2: cmp/hi R3,R2         ; if R2 > 18 (queue full?)
    #   060222E4: bf 0x06022354        ; branch if R2 <= 18

    # Wait -- this doesn't look like a general send function.
    # The 0x12 (18) is compared against the queue level.
    # It's a SESSION INITIALIZATION function that also builds the message.

    # Let me look at what happens after the comparison passes (R2 <= 18)
    # That branch target is 0x06022354 which does:
    #   06022354: mov.b @(6,R4),R0    ; read byte at offset 6 from R4
    #   06022356: tst R0,R0
    #   06022358: bt 0x06022372        ; skip if zero
    #   ...calls 0x06021028 and 0x0601AB9E...
    #   06022372: mov #0x00, R7        ; R7 = 0
    #   06022374: mov.l @R15, R6       ; R6 = saved R5 from stack
    #   06022376: mov.l R14=0x06062484
    #   06022378: mov.l R4=0x06062314
    #   0602237A: mov.l R3=0x060420AE  ; call function
    #   0602237C: jsr @R3              ; call 0x060420AE(R4=0x06062314, R5=R13)
    #   0602237E: mov R13, R5          ; delay slot: R5 = R13 (original R4 arg)

    # So the key call is to 0x060420AE with:
    #   R4 = 0x06062314 (SV session state)
    #   R5 = original argument (pointer to data?)

    # Let's also look for who calls the function at 0x060222CC
    # and the function at 0x060221F8

    targets = [0x060222CC, 0x060221F8, 0x060222AA]

    for target in targets:
        print(f"\n{'='*80}")
        print(f"Finding all BSR/JSR calls to 0x{target:08X}")
        print(f"{'='*80}")

        # Search for BSR instructions that target this address
        # BSR: 1011 dddddddddddd, target = PC + 4 + disp*2
        for file_off in range(0, len(data) - 1, 2):
            opcode = struct.unpack('>H', data[file_off:file_off+2])[0]
            pc = file_to_mem(file_off)

            # BSR
            if (opcode >> 12) == 0xB:
                disp = opcode & 0xFFF
                if disp >= 0x800:
                    disp -= 0x1000
                call_target = pc + 4 + disp * 2
                if call_target == target:
                    print(f"  BSR at 0x{pc:08X} (file 0x{file_off:06X})")
                    # Show context (16 bytes before and after)
                    ctx_start = max(0, file_off - 16)
                    ctx_end = min(len(data), file_off + 18)
                    for ctx_off in range(ctx_start, ctx_end, 2):
                        op = struct.unpack('>H', data[ctx_off:ctx_off+2])[0]
                        marker = " <-- BSR" if ctx_off == file_off else ""
                        print(f"    {file_to_mem(ctx_off):08X}: {op:04X}{marker}")

            # JSR via register: need to check if register loaded with target
            # This is harder - skip for now

    # =========================================================================
    # Now let's analyze the function at 0x060420AE more carefully
    # This appears to be the function that processes the session message
    # =========================================================================
    print(f"\n{'='*80}")
    print(f"Disassembling function at 0x060420AE (session message processor)")
    print(f"{'='*80}")

    from disasm_session_builder import decode_sh2
    start = mem_to_file(0x060420AE)
    end = start + 0x200
    pc_file = start
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

        print(f"  {pc:08X}: {data[pc_file]:02X} {data[pc_file+1]:02X}  {mnemonic}{extra}")

        # Stop at rts
        if opcode == 0x000B:
            # Print one more (delay slot)
            pc_file += 2
            if pc_file + 1 < len(data):
                opcode2 = struct.unpack('>H', data[pc_file:pc_file+2])[0]
                pc2 = file_to_mem(pc_file)
                mnemonic2 = decode_sh2(opcode2, pc2)
                print(f"  {pc2:08X}: {data[pc_file]:02X} {data[pc_file+1]:02X}  {mnemonic2}")
            break
        pc_file += 2

    # =========================================================================
    # Let's also look at 0x060221F8 more carefully - the SV init function
    # It's being called via BSR from somewhere. Let's trace who calls it.
    # =========================================================================

    # The function at 0x060221F8 initializes SV session state at 0x06062314:
    # - Calls 0x06042EF4 (some init)
    # - Sets 0x06062314 fields:
    #   offset +0:  0 (R5=0)
    #   offset +4:  0
    #   offset +8:  0
    #   offset +12: 0
    #   offset +20: 0x1F40 (8000) - timeout
    #   offset +24: 0x07D0 (2000) - timeout
    #   offset +28: 0x1C (via byte store at offset 40)
    #   offset +36: 5
    #   offset +40: 0x1C (R6=0x1C stored as byte at R4+40)
    #   offset +41: 0x11 (17)
    #   offset +42: 0x13 (19)
    #   offset +43: 0x1B (27)
    #   offset +44: 0x0D (13)
    #   offset +45: 0x1C (R6=0x1C again)
    #   offset +48: -> 0x06022910 (function ptr)
    #   offset +52: -> 0x06022914 (function ptr)
    #   offset +56: -> 0x060229A0 (function ptr)
    #   offset +60: -> 0x06022A2E (function ptr)
    #   offset +64: -> 0x06022A36 (function ptr)

    # The 0x1C at offset 40 matches byte[6]=0x1C in the session response!
    # The timeout values 0x1F40 and 0x07D0 match the session response!

    # Let's look at function 0x06022910 (stored as a callback at offset +48)
    # This might be the function that BUILDS the session response

    print(f"\n{'='*80}")
    print(f"Disassembling function at 0x06022910 (session callback at offset +48)")
    print(f"{'='*80}")

    start = mem_to_file(0x06022910)
    end = start + 0x100
    pc_file = start
    rts_count = 0
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

        print(f"  {pc:08X}: {data[pc_file]:02X} {data[pc_file+1]:02X}  {mnemonic}{extra}")

        if opcode == 0x000B:
            rts_count += 1
            pc_file += 2
            if pc_file + 1 < len(data):
                opcode2 = struct.unpack('>H', data[pc_file:pc_file+2])[0]
                pc2 = file_to_mem(pc_file)
                mnemonic2 = decode_sh2(opcode2, pc2)
                print(f"  {pc2:08X}: {data[pc_file]:02X} {data[pc_file+1]:02X}  {mnemonic2}")
            if rts_count >= 1:
                break
        pc_file += 2

    # Function at 0x06022914
    print(f"\n{'='*80}")
    print(f"Disassembling function at 0x06022914 (session callback at offset +52)")
    print(f"{'='*80}")

    start = mem_to_file(0x06022914)
    end = start + 0x200
    pc_file = start
    rts_count = 0
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

        print(f"  {pc:08X}: {data[pc_file]:02X} {data[pc_file+1]:02X}  {mnemonic}{extra}")

        if opcode == 0x000B:
            rts_count += 1
            pc_file += 2
            if pc_file + 1 < len(data):
                opcode2 = struct.unpack('>H', data[pc_file:pc_file+2])[0]
                pc2 = file_to_mem(pc_file)
                mnemonic2 = decode_sh2(opcode2, pc2)
                print(f"  {pc2:08X}: {data[pc_file]:02X} {data[pc_file+1]:02X}  {mnemonic2}")
            if rts_count >= 2:
                break
        pc_file += 2

    # Function at 0x060229A0
    print(f"\n{'='*80}")
    print(f"Disassembling function at 0x060229A0 (session callback at offset +56)")
    print(f"{'='*80}")

    start = mem_to_file(0x060229A0)
    end = start + 0x200
    pc_file = start
    rts_count = 0
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

        print(f"  {pc:08X}: {data[pc_file]:02X} {data[pc_file+1]:02X}  {mnemonic}{extra}")

        if opcode == 0x000B:
            rts_count += 1
            pc_file += 2
            if pc_file + 1 < len(data):
                opcode2 = struct.unpack('>H', data[pc_file:pc_file+2])[0]
                pc2 = file_to_mem(pc_file)
                mnemonic2 = decode_sh2(opcode2, pc2)
                print(f"  {pc2:08X}: {data[pc_file]:02X} {data[pc_file+1]:02X}  {mnemonic2}")
            if rts_count >= 2:
                break
        pc_file += 2

    # Also disassemble 0x06022A2E and 0x06022A36
    for addr in [0x06022A2E, 0x06022A36]:
        print(f"\n{'='*80}")
        print(f"Disassembling function at 0x{addr:08X}")
        print(f"{'='*80}")

        start = mem_to_file(addr)
        end = start + 0x100
        pc_file = start
        rts_count = 0
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

            print(f"  {pc:08X}: {data[pc_file]:02X} {data[pc_file+1]:02X}  {mnemonic}{extra}")

            if opcode == 0x000B:
                rts_count += 1
                pc_file += 2
                if pc_file + 1 < len(data):
                    opcode2 = struct.unpack('>H', data[pc_file:pc_file+2])[0]
                    pc2 = file_to_mem(pc_file)
                    mnemonic2 = decode_sh2(opcode2, pc2)
                    print(f"  {pc2:08X}: {data[pc_file]:02X} {data[pc_file+1]:02X}  {mnemonic2}")
                if rts_count >= 1:
                    break
            pc_file += 2

    # =========================================================================
    # Now let's look at the function 0x060420AE which is called from the
    # SV send enqueue at 0x060222CC->0x06022372->0x0602237A
    # This is likely the "process outgoing SV message" function
    # =========================================================================
    print(f"\n{'='*80}")
    print(f"Disassembling 0x060420AE (called with R4=state_ptr, R5=data_ptr)")
    print(f"This function likely builds/sends the session response message")
    print(f"{'='*80}")

    start = mem_to_file(0x060420AE)
    end = start + 0x400
    pc_file = start
    rts_count = 0
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

        print(f"  {pc:08X}: {data[pc_file]:02X} {data[pc_file+1]:02X}  {mnemonic}{extra}")

        if opcode == 0x000B:
            rts_count += 1
            pc_file += 2
            if pc_file + 1 < len(data):
                opcode2 = struct.unpack('>H', data[pc_file:pc_file+2])[0]
                pc2 = file_to_mem(pc_file)
                mnemonic2 = decode_sh2(opcode2, pc2)
                print(f"  {pc2:08X}: {data[pc_file]:02X} {data[pc_file+1]:02X}  {mnemonic2}")
            if rts_count >= 3:
                break
        pc_file += 2


if __name__ == '__main__':
    main()
