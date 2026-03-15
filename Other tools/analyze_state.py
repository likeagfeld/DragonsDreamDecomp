import struct
import sys

with open('extracted/0.BIN', 'rb') as f:
    data = f.read()

BASE = 0x06010000

def disasm_basic(data, offset, count=60):
    results = []
    for i in range(count):
        pos = offset + i * 2
        if pos + 2 > len(data):
            break
        w = struct.unpack_from('>H', data, pos)[0]
        mem = BASE + pos
        desc = f'{w:04X}'

        if w == 0x000B:
            desc = 'rts'
        elif w == 0x0009:
            desc = 'nop'
        elif (w >> 8) & 0xF0 == 0xE0:
            rn = (w >> 8) & 0x0F
            imm = w & 0xFF
            if imm > 127: imm -= 256
            desc = f'mov #{imm},r{rn}'
        elif (w >> 12) == 0x9:
            rn = (w >> 8) & 0x0F
            disp = w & 0xFF
            target = pos + 4 + disp * 2
            if target + 2 <= len(data):
                val = struct.unpack_from('>H', data, target)[0]
                desc = f'mov.w @(0x{disp:02X},PC),r{rn}  ; =0x{val:04X}'
            else:
                desc = f'mov.w @(0x{disp:02X},PC),r{rn}'
        elif (w >> 12) == 0xD:
            rn = (w >> 8) & 0x0F
            disp = w & 0xFF
            target = (pos + 4) & ~3
            target += disp * 4
            if target + 4 <= len(data):
                val = struct.unpack_from('>I', data, target)[0]
                desc = f'mov.l @(0x{disp:02X},PC),r{rn}  ; =0x{val:08X}'
            else:
                desc = f'mov.l @(0x{disp:02X},PC),r{rn}'
        elif (w >> 12) == 0xB:
            disp = w & 0xFFF
            if disp > 0x7FF: disp -= 0x1000
            target = pos + 4 + disp * 2
            tmem = BASE + target
            desc = f'bsr 0x{target:06X}  ; 0x{tmem:08X}'
        elif (w & 0xF0FF) == 0x400B:
            rn = (w >> 8) & 0x0F
            desc = f'jsr @r{rn}'
        elif (w & 0xF0FF) == 0x402B:
            rn = (w >> 8) & 0x0F
            desc = f'jmp @r{rn}'
        elif (w >> 12) == 0xA:
            disp = w & 0xFFF
            if disp > 0x7FF: disp -= 0x1000
            target = pos + 4 + disp * 2
            tmem = BASE + target
            desc = f'bra 0x{target:06X}  ; 0x{tmem:08X}'
        elif (w >> 8) == 0x89:
            disp = w & 0xFF
            if disp > 127: disp -= 256
            target = pos + 4 + disp * 2
            desc = f'bt 0x{target:06X}'
        elif (w >> 8) == 0x8B:
            disp = w & 0xFF
            if disp > 127: disp -= 256
            target = pos + 4 + disp * 2
            desc = f'bf 0x{target:06X}'
        elif (w >> 8) == 0x8D:
            disp = w & 0xFF
            if disp > 127: disp -= 256
            target = pos + 4 + disp * 2
            desc = f'bt/s 0x{target:06X}'
        elif (w >> 8) == 0x8F:
            disp = w & 0xFF
            if disp > 127: disp -= 256
            target = pos + 4 + disp * 2
            desc = f'bf/s 0x{target:06X}'
        elif (w >> 8) == 0x88:
            imm = w & 0xFF
            if imm > 127: imm -= 256
            desc = f'cmp/eq #{imm},r0'
        elif (w & 0xF00F) == 0x3000:
            rn = (w >> 8) & 0xF; rm = (w >> 4) & 0xF
            desc = f'cmp/eq r{rm},r{rn}'
        elif (w & 0xF00F) == 0x3007:
            rn = (w >> 8) & 0xF; rm = (w >> 4) & 0xF
            desc = f'cmp/gt r{rm},r{rn}'
        elif (w & 0xF00F) == 0x3003:
            rn = (w >> 8) & 0xF; rm = (w >> 4) & 0xF
            desc = f'cmp/ge r{rm},r{rn}'
        elif (w & 0xF0FF) == 0x4015:
            rn = (w >> 8) & 0xF
            desc = f'cmp/pl r{rn}'
        elif (w & 0xF0FF) == 0x4011:
            rn = (w >> 8) & 0xF
            desc = f'cmp/pz r{rn}'
        elif (w & 0xF00F) == 0x2008:
            rn = (w >> 8) & 0xF; rm = (w >> 4) & 0xF
            desc = f'tst r{rm},r{rn}'
        elif (w >> 8) == 0xC8:
            imm = w & 0xFF
            desc = f'tst #{imm},r0'
        elif (w & 0xF00F) == 0x6003:
            rn = (w >> 8) & 0xF; rm = (w >> 4) & 0xF
            desc = f'mov r{rm},r{rn}'
        elif (w & 0xF00F) == 0x6000:
            rn = (w >> 8) & 0xF; rm = (w >> 4) & 0xF
            desc = f'mov.b @r{rm},r{rn}'
        elif (w & 0xF00F) == 0x6001:
            rn = (w >> 8) & 0xF; rm = (w >> 4) & 0xF
            desc = f'mov.w @r{rm},r{rn}'
        elif (w & 0xF00F) == 0x6002:
            rn = (w >> 8) & 0xF; rm = (w >> 4) & 0xF
            desc = f'mov.l @r{rm},r{rn}'
        elif (w & 0xF00F) == 0x2000:
            rn = (w >> 8) & 0xF; rm = (w >> 4) & 0xF
            desc = f'mov.b r{rm},@r{rn}'
        elif (w >> 12) == 0x8 and ((w >> 8) & 0xF) == 0x4:
            rm = (w >> 4) & 0xF; disp = w & 0xF
            desc = f'mov.b @(0x{disp:X},r{rm}),r0'
        elif (w >> 12) == 0x5:
            rn = (w >> 8) & 0xF; rm = (w >> 4) & 0xF; disp = (w & 0xF) * 4
            desc = f'mov.l @(0x{disp:X},r{rm}),r{rn}'
        elif (w >> 12) == 0x1:
            rn = (w >> 8) & 0xF; rm = (w >> 4) & 0xF; disp = (w & 0xF) * 4
            desc = f'mov.l r{rm},@(0x{disp:X},r{rn})'
        elif (w & 0xF0FF) == 0x4022:
            rn = (w >> 8) & 0xF
            desc = f'sts.l pr,@-r{rn}'
        elif (w & 0xF0FF) == 0x4026:
            rn = (w >> 8) & 0xF
            desc = f'lds.l @r{rn}+,pr'
        elif (w >> 12) == 0x7:
            rn = (w >> 8) & 0xF; imm = w & 0xFF
            if imm > 127: imm -= 256
            desc = f'add #{imm},r{rn}'
        elif (w & 0xF00F) == 0x300C:
            rn = (w >> 8) & 0xF; rm = (w >> 4) & 0xF
            desc = f'add r{rm},r{rn}'
        elif (w & 0xF00F) == 0x600C:
            rn = (w >> 8) & 0xF; rm = (w >> 4) & 0xF
            desc = f'extu.b r{rm},r{rn}'
        elif (w & 0xF00F) == 0x600D:
            rn = (w >> 8) & 0xF; rm = (w >> 4) & 0xF
            desc = f'extu.w r{rm},r{rn}'
        elif (w >> 12) == 0x8 and ((w >> 8) & 0xF) == 0x0:
            rn = (w >> 4) & 0xF; disp = w & 0xF
            desc = f'mov.b r0,@(0x{disp:X},r{rn})'
        elif (w >> 12) == 0x8 and ((w >> 8) & 0xF) == 0x1:
            rn = (w >> 4) & 0xF; disp = (w & 0xF) * 2
            desc = f'mov.w r0,@(0x{disp:X},r{rn})'
        elif (w >> 12) == 0x8 and ((w >> 8) & 0xF) == 0x5:
            rm = (w >> 4) & 0xF; disp = (w & 0xF) * 2
            desc = f'mov.w @(0x{disp:X},r{rm}),r0'
        elif (w & 0xF0FF) == 0x4010:
            rn = (w >> 8) & 0xF
            desc = f'dt r{rn}'
        elif (w & 0xF00F) == 0x3008:
            rn = (w >> 8) & 0xF; rm = (w >> 4) & 0xF
            desc = f'sub r{rm},r{rn}'
        elif (w & 0xF00F) == 0x2009:
            rn = (w >> 8) & 0xF; rm = (w >> 4) & 0xF
            desc = f'and r{rm},r{rn}'
        elif (w & 0xF00F) == 0x200B:
            rn = (w >> 8) & 0xF; rm = (w >> 4) & 0xF
            desc = f'or r{rm},r{rn}'
        elif (w >> 8) == 0xC9:
            imm = w & 0xFF
            desc = f'and #{imm},r0'
        elif (w >> 8) == 0xCB:
            imm = w & 0xFF
            desc = f'or #{imm},r0'
        elif (w & 0xF00F) == 0x2002:
            rn = (w >> 8) & 0xF; rm = (w >> 4) & 0xF
            desc = f'mov.l r{rm},@r{rn}'
        elif (w & 0xF00F) == 0x2001:
            rn = (w >> 8) & 0xF; rm = (w >> 4) & 0xF
            desc = f'mov.w r{rm},@r{rn}'
        elif (w & 0xF00F) == 0x6004:
            rn = (w >> 8) & 0xF; rm = (w >> 4) & 0xF
            desc = f'mov.b @r{rm}+,r{rn}'
        elif (w & 0xF00F) == 0x6006:
            rn = (w >> 8) & 0xF; rm = (w >> 4) & 0xF
            desc = f'mov.l @r{rm}+,r{rn}'
        elif (w & 0xF00F) == 0x2006:
            rn = (w >> 8) & 0xF; rm = (w >> 4) & 0xF
            desc = f'mov.l r{rm},@-r{rn}'
        elif (w & 0xF00F) == 0x000C:
            rn = (w >> 8) & 0xF; rm = (w >> 4) & 0xF
            desc = f'mov.b @(r0,r{rm}),r{rn}'
        elif (w & 0xF00F) == 0x000E:
            rn = (w >> 8) & 0xF; rm = (w >> 4) & 0xF
            desc = f'mov.l @(r0,r{rm}),r{rn}'
        elif (w & 0xF00F) == 0x0004:
            rn = (w >> 8) & 0xF; rm = (w >> 4) & 0xF
            desc = f'mov.b r{rm},@(r0,r{rn})'
        elif (w & 0xF00F) == 0x0006:
            rn = (w >> 8) & 0xF; rm = (w >> 4) & 0xF
            desc = f'mov.l r{rm},@(r0,r{rn})'
        elif (w >> 8) == 0xC7:
            disp = (w & 0xFF) * 4
            desc = f'mova @(0x{disp:X},PC),r0'
        elif (w & 0xF0FF) == 0x001A:
            rn = (w >> 8) & 0xF
            desc = f'sts macl,r{rn}'
        elif (w & 0xF00F) == 0x0007:
            rn = (w >> 8) & 0xF; rm = (w >> 4) & 0xF
            desc = f'mul.l r{rm},r{rn}'
        elif (w & 0xF00F) == 0x200F:
            rn = (w >> 8) & 0xF; rm = (w >> 4) & 0xF
            desc = f'muls.w r{rm},r{rn}'
        elif (w & 0xF0FF) == 0x4000:
            rn = (w >> 8) & 0xF
            desc = f'shll r{rn}'
        elif (w & 0xF0FF) == 0x4001:
            rn = (w >> 8) & 0xF
            desc = f'shlr r{rn}'
        elif (w & 0xF0FF) == 0x4008:
            rn = (w >> 8) & 0xF
            desc = f'shll2 r{rn}'
        elif (w & 0xF0FF) == 0x4009:
            rn = (w >> 8) & 0xF
            desc = f'shlr2 r{rn}'
        elif (w & 0xF0FF) == 0x4018:
            rn = (w >> 8) & 0xF
            desc = f'shll8 r{rn}'
        elif (w & 0xF0FF) == 0x4019:
            rn = (w >> 8) & 0xF
            desc = f'shlr8 r{rn}'
        elif (w & 0xF0FF) == 0x4028:
            rn = (w >> 8) & 0xF
            desc = f'shll16 r{rn}'
        elif (w & 0xF0FF) == 0x4029:
            rn = (w >> 8) & 0xF
            desc = f'shlr16 r{rn}'
        elif (w & 0xF00F) == 0x6009:
            rn = (w >> 8) & 0xF; rm = (w >> 4) & 0xF
            desc = f'swap.w r{rm},r{rn}'
        elif (w & 0xF00F) == 0x600E:
            rn = (w >> 8) & 0xF; rm = (w >> 4) & 0xF
            desc = f'exts.b r{rm},r{rn}'
        elif (w & 0xF00F) == 0x600F:
            rn = (w >> 8) & 0xF; rm = (w >> 4) & 0xF
            desc = f'exts.w r{rm},r{rn}'
        elif (w & 0xF00F) == 0x600A:
            rn = (w >> 8) & 0xF; rm = (w >> 4) & 0xF
            desc = f'negc r{rm},r{rn}'
        elif (w & 0xF00F) == 0x600B:
            rn = (w >> 8) & 0xF; rm = (w >> 4) & 0xF
            desc = f'neg r{rm},r{rn}'
        elif (w & 0xF00F) == 0x6008:
            rn = (w >> 8) & 0xF; rm = (w >> 4) & 0xF
            desc = f'swap.b r{rm},r{rn}'
        elif (w & 0xF00F) == 0x000D:
            rn = (w >> 8) & 0xF; rm = (w >> 4) & 0xF
            desc = f'mov.w @(r0,r{rm}),r{rn}'
        elif (w & 0xF00F) == 0x0005:
            rn = (w >> 8) & 0xF; rm = (w >> 4) & 0xF
            desc = f'mov.w r{rm},@(r0,r{rn})'
        elif (w & 0xF0FF) == 0x4024:
            rn = (w >> 8) & 0xF
            desc = f'rotcl r{rn}'
        elif (w & 0xF0FF) == 0x4004:
            rn = (w >> 8) & 0xF
            desc = f'rotl r{rn}'

        results.append((pos, mem, w, desc))
    return results

def disasm_range(start_offset, count, label=""):
    if label:
        print(f"\n{'=' * 80}")
        print(f"{label}")
        print(f"{'=' * 80}")
    for pos, mem, w, desc in disasm_basic(data, start_offset, count):
        print(f'  0x{pos:06X} (0x{mem:08X}): {w:04X}  {desc}')

part = sys.argv[1] if len(sys.argv) > 1 else 'help'

if part == 'state3':
    # State 3 handler (post-BBS): 0x0603BB6E at file 0x02BB6E
    disasm_range(0x02BB6E, 120, "STATE 3 HANDLER (post-BBS) at file 0x02BB6E")

elif part == 'state2':
    # State 2 handler (online/connected): 0x0603C100 at file 0x02C100
    disasm_range(0x02C100, 120, "STATE 2 HANDLER (connected) at file 0x02C100")

elif part == 'mainloop_start':
    # Main loop from 0x00006E
    disasm_range(0x00006E, 80, "MAIN LOOP START at file 0x00006E")

elif part == 'mainloop_init':
    # Before main loop
    disasm_range(0x000000, 60, "PROGRAM START at file 0x000000")

elif part == 'func_0A36':
    # Function at 0x000A36 called from main loop
    disasm_range(0x000A36, 120, "FUNCTION at file 0x000A36 (called from main loop)")

elif part == 'func_15F0':
    # Function at 0x0015F0 called every iteration
    disasm_range(0x0015F0, 80, "FUNCTION at file 0x0015F0 (called every loop)")

elif part == 'func_1778':
    # Function at 0x001778 called from main loop
    disasm_range(0x001778, 120, "FUNCTION at file 0x001778")

elif part == 'func_30ECE':
    # Function at 0x030ECE called from main loop (scmd receive?)
    disasm_range(0x030ECE, 80, "FUNCTION at file 0x030ECE (scmd recv loop)")

elif part == 'func_12008':
    # Function at 0x012008 called every iteration
    disasm_range(0x012008, 80, "FUNCTION at file 0x012008")

elif part == 'search_0x8E':
    # Search for where offsets 0x8E-0x91 are used as byte offsets
    # In SH-2, accessing g_state[0x8E] would be:
    #   mov.l literal_g_state, r_base
    #   mov #0x8E_as_signed, r0  (0x8E = -114 signed, or loaded via mov.w)
    #   mov.b @(r0,r_base), r_dest
    # Since 0x8E > 0x7F, it would be loaded as mov.w from literal pool
    # Let's search for the literal value 0x008E, 0x008F, 0x0090, 0x0091
    for val in [0x008E, 0x008F, 0x0090, 0x0091]:
        packed = struct.pack('>H', val)
        pos = 0
        print(f'\nSearching for literal 0x{val:04X}:')
        while True:
            pos = data.find(packed, pos)
            if pos == -1:
                break
            # Check if this could be a literal pool entry for mov.w
            # by looking for mov.w instructions referencing it
            if pos < 0x045000:
                for dist in range(2, 512, 2):
                    instr_addr = pos - dist
                    if instr_addr < 0:
                        break
                    disp = (pos - instr_addr - 4) // 2
                    if disp < 0 or disp > 255:
                        continue
                    instr = struct.unpack_from('>H', data, instr_addr)[0]
                    # Check for mov.w to any register
                    if (instr >> 12) == 0x9 and (instr & 0xFF) == disp:
                        reg = (instr >> 8) & 0xF
                        imem = BASE + instr_addr
                        print(f'  mov.w to r{reg} at file 0x{instr_addr:06X} (0x{imem:08X}) -> literal at 0x{pos:06X}')
            pos += 1

elif part == 'search_deferred':
    # Search for msg_types 0x0048, 0x006D, 0x025F, 0x02D4
    # These should appear in mov.w literal pools for scmd_new_message calls
    for msg_type in [0x0048, 0x006D, 0x025F, 0x02D4]:
        packed = struct.pack('>H', msg_type)
        print(f'\n--- Searching for msg_type 0x{msg_type:04X} ---')
        pos = 0
        found_any = False
        while True:
            pos = data.find(packed, pos)
            if pos == -1:
                break
            if pos < 0x045000:
                for dist in range(2, 512, 2):
                    instr_addr = pos - dist
                    if instr_addr < 0:
                        break
                    disp = (pos - instr_addr - 4) // 2
                    if disp < 0 or disp > 255:
                        continue
                    instr = struct.unpack_from('>H', data, instr_addr)[0]
                    if (instr >> 12) == 0x9 and (instr & 0xFF) == disp:
                        reg = (instr >> 8) & 0xF
                        imem = BASE + instr_addr
                        if reg == 5:  # r5 = msg_type for scmd_new_message
                            print(f'  CALL SITE: mov.w 0x{msg_type:04X} to r5 at file 0x{instr_addr:06X} (0x{imem:08X})')
                            found_any = True
                            # Show context
                            for ci in range(-6, 10):
                                cpos = instr_addr + ci * 2
                                if 0 <= cpos < len(data) - 1:
                                    cw = struct.unpack_from('>H', data, cpos)[0]
                                    cm = BASE + cpos
                                    marker = ' <---' if ci == 0 else ''
                                    cdesc = f'{cw:04X}'
                                    if (cw >> 12) == 0xD:
                                        rn = (cw >> 8) & 0xF
                                        d = cw & 0xFF
                                        t = ((cpos + 4) & ~3) + d * 4
                                        if t + 4 <= len(data):
                                            v = struct.unpack_from('>I', data, t)[0]
                                            cdesc = f'mov.l r{rn} ; =0x{v:08X}'
                                    elif (cw & 0xF0FF) == 0x400B:
                                        rn = (cw >> 8) & 0xF
                                        cdesc = f'jsr @r{rn}'
                                    print(f'    0x{cpos:06X} (0x{cm:08X}): {cw:04X}  {cdesc}{marker}')
                            print()
            pos += 1
        if not found_any:
            print(f'  No mov.w to r5 found for 0x{msg_type:04X}')
