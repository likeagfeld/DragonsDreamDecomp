import struct
import sys

with open('extracted/0.BIN', 'rb') as f:
    data = f.read()

BASE = 0x06010000

def disasm_basic(data, offset, count=60):
    """Basic SH-2 disassembler for key instructions"""
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
                desc = f'mov.w @(0x{disp:02X},PC),r{rn}  ; =0x{val:04X} (from 0x{target:06X})'
            else:
                desc = f'mov.w @(0x{disp:02X},PC),r{rn}'
        elif (w >> 12) == 0xD:
            rn = (w >> 8) & 0x0F
            disp = w & 0xFF
            target = (pos + 4) & ~3
            target += disp * 4
            if target + 4 <= len(data):
                val = struct.unpack_from('>I', data, target)[0]
                desc = f'mov.l @(0x{disp:02X},PC),r{rn}  ; =0x{val:08X} (from 0x{target:06X})'
            else:
                desc = f'mov.l @(0x{disp:02X},PC),r{rn}'
        elif (w >> 12) == 0xB:
            disp = w & 0xFFF
            if disp > 0x7FF: disp -= 0x1000
            target = pos + 4 + disp * 2
            tmem = BASE + target
            desc = f'bsr 0x{target:06X}  ; mem 0x{tmem:08X}'
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
            desc = f'bra 0x{target:06X}  ; mem 0x{tmem:08X}'
        elif (w >> 8) == 0x89:
            disp = w & 0xFF
            if disp > 127: disp -= 256
            target = pos + 4 + disp * 2
            tmem = BASE + target
            desc = f'bt 0x{target:06X}  ; mem 0x{tmem:08X}'
        elif (w >> 8) == 0x8B:
            disp = w & 0xFF
            if disp > 127: disp -= 256
            target = pos + 4 + disp * 2
            tmem = BASE + target
            desc = f'bf 0x{target:06X}  ; mem 0x{tmem:08X}'
        elif (w >> 8) == 0x8D:
            disp = w & 0xFF
            if disp > 127: disp -= 256
            target = pos + 4 + disp * 2
            tmem = BASE + target
            desc = f'bt/s 0x{target:06X}  ; mem 0x{tmem:08X}'
        elif (w >> 8) == 0x8F:
            disp = w & 0xFF
            if disp > 127: disp -= 256
            target = pos + 4 + disp * 2
            tmem = BASE + target
            desc = f'bf/s 0x{target:06X}  ; mem 0x{tmem:08X}'
        elif (w >> 8) == 0x88:
            imm = w & 0xFF
            if imm > 127: imm -= 256
            desc = f'cmp/eq #{imm},r0'
        elif (w & 0xF00F) == 0x3000:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'cmp/eq r{rm},r{rn}'
        elif (w & 0xF00F) == 0x3007:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'cmp/gt r{rm},r{rn}'
        elif (w & 0xF00F) == 0x3003:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'cmp/ge r{rm},r{rn}'
        elif (w & 0xF0FF) == 0x4015:
            rn = (w >> 8) & 0xF
            desc = f'cmp/pl r{rn}'
        elif (w & 0xF0FF) == 0x4011:
            rn = (w >> 8) & 0xF
            desc = f'cmp/pz r{rn}'
        elif (w & 0xF00F) == 0x2008:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'tst r{rm},r{rn}'
        elif (w >> 8) == 0xC8:
            imm = w & 0xFF
            desc = f'tst #{imm},r0'
        elif (w & 0xF00F) == 0x6003:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'mov r{rm},r{rn}'
        elif (w & 0xF00F) == 0x6000:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'mov.b @r{rm},r{rn}'
        elif (w & 0xF00F) == 0x6001:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'mov.w @r{rm},r{rn}'
        elif (w & 0xF00F) == 0x6002:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'mov.l @r{rm},r{rn}'
        elif (w & 0xF00F) == 0x2000:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'mov.b r{rm},@r{rn}'
        elif (w >> 12) == 0x8 and ((w >> 8) & 0xF) == 0x4:
            rm = (w >> 4) & 0xF
            disp = w & 0xF
            desc = f'mov.b @(0x{disp:X},r{rm}),r0'
        elif (w >> 12) == 0x5:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            disp = (w & 0xF) * 4
            desc = f'mov.l @(0x{disp:X},r{rm}),r{rn}'
        elif (w >> 12) == 0x1:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            disp = (w & 0xF) * 4
            desc = f'mov.l r{rm},@(0x{disp:X},r{rn})'
        elif (w & 0xF0FF) == 0x4022:
            rn = (w >> 8) & 0xF
            desc = f'sts.l pr,@-r{rn}'
        elif (w & 0xF0FF) == 0x4026:
            rn = (w >> 8) & 0xF
            desc = f'lds.l @r{rn}+,pr'
        elif (w >> 12) == 0x7:
            rn = (w >> 8) & 0xF
            imm = w & 0xFF
            if imm > 127: imm -= 256
            desc = f'add #{imm},r{rn}'
        elif (w & 0xF00F) == 0x300C:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'add r{rm},r{rn}'
        elif (w & 0xF00F) == 0x600C:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'extu.b r{rm},r{rn}'
        elif (w & 0xF00F) == 0x600D:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'extu.w r{rm},r{rn}'
        elif (w >> 12) == 0x8 and ((w >> 8) & 0xF) == 0x0:
            rn = (w >> 4) & 0xF
            disp = w & 0xF
            desc = f'mov.b r0,@(0x{disp:X},r{rn})'
        elif (w >> 12) == 0x8 and ((w >> 8) & 0xF) == 0x1:
            rn = (w >> 4) & 0xF
            disp = (w & 0xF) * 2
            desc = f'mov.w r0,@(0x{disp:X},r{rn})'
        elif (w >> 12) == 0x8 and ((w >> 8) & 0xF) == 0x5:
            rm = (w >> 4) & 0xF
            disp = (w & 0xF) * 2
            desc = f'mov.w @(0x{disp:X},r{rm}),r0'
        elif (w & 0xF0FF) == 0x4010:
            rn = (w >> 8) & 0xF
            desc = f'dt r{rn}'
        elif (w & 0xF00F) == 0x3008:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'sub r{rm},r{rn}'
        elif (w & 0xF00F) == 0x2009:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'and r{rm},r{rn}'
        elif (w & 0xF00F) == 0x200B:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'or r{rm},r{rn}'
        elif (w >> 8) == 0xC9:
            imm = w & 0xFF
            desc = f'and #{imm},r0'
        elif (w >> 8) == 0xCB:
            imm = w & 0xFF
            desc = f'or #{imm},r0'
        elif (w & 0xF00F) == 0x400C:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'shad r{rm},r{rn}'
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
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'swap.w r{rm},r{rn}'
        elif (w & 0xF00F) == 0x200E:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'xtrct r{rm},r{rn}'
        elif (w & 0xF00F) == 0x6008:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'swap.b r{rm},r{rn}'
        elif (w & 0xF00F) == 0x600A:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'negc r{rm},r{rn}'
        elif (w & 0xF00F) == 0x600B:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'neg r{rm},r{rn}'
        elif (w & 0xF00F) == 0x600E:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'exts.b r{rm},r{rn}'
        elif (w & 0xF00F) == 0x600F:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'exts.w r{rm},r{rn}'
        elif (w & 0xF00F) == 0x2002:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'mov.l r{rm},@r{rn}'
        elif (w & 0xF00F) == 0x2001:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'mov.w r{rm},@r{rn}'
        elif (w & 0xF00F) == 0x6004:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'mov.b @r{rm}+,r{rn}'
        elif (w & 0xF00F) == 0x6005:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'mov.w @r{rm}+,r{rn}'
        elif (w & 0xF00F) == 0x6006:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'mov.l @r{rm}+,r{rn}'
        elif (w & 0xF00F) == 0x2004:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'mov.b r{rm},@-r{rn}'
        elif (w & 0xF00F) == 0x2005:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'mov.w r{rm},@-r{rn}'
        elif (w & 0xF00F) == 0x2006:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'mov.l r{rm},@-r{rn}'
        elif (w & 0xF00F) == 0x000C:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'mov.b @(r0,r{rm}),r{rn}'
        elif (w & 0xF00F) == 0x000D:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'mov.w @(r0,r{rm}),r{rn}'
        elif (w & 0xF00F) == 0x000E:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'mov.l @(r0,r{rm}),r{rn}'
        elif (w & 0xF00F) == 0x0004:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'mov.b r{rm},@(r0,r{rn})'
        elif (w & 0xF00F) == 0x0005:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'mov.w r{rm},@(r0,r{rn})'
        elif (w & 0xF00F) == 0x0006:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'mov.l r{rm},@(r0,r{rn})'
        elif (w >> 8) == 0xC7:
            disp = (w & 0xFF) * 4
            desc = f'mova @(0x{disp:X},PC),r0'
        elif (w & 0xF0FF) == 0x0002:
            rn = (w >> 8) & 0xF
            desc = f'stc sr,r{rn}'
        elif (w & 0xF0FF) == 0x001A:
            rn = (w >> 8) & 0xF
            desc = f'sts macl,r{rn}'
        elif (w & 0xF0FF) == 0x000A:
            rn = (w >> 8) & 0xF
            desc = f'sts mach,r{rn}'
        elif (w & 0xF00F) == 0x0007:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'mul.l r{rm},r{rn}'
        elif (w & 0xF00F) == 0x200F:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            desc = f'muls.w r{rm},r{rn}'

        results.append((pos, mem, w, desc))
    return results

def disasm_range(start_offset, count, label=""):
    if label:
        print(f"\n{'=' * 80}")
        print(f"{label}")
        print(f"{'=' * 80}")
    for pos, mem, w, desc in disasm_basic(data, start_offset, count):
        print(f'  0x{pos:06X} (0x{mem:08X}): {w:04X}  {desc}')

if len(sys.argv) > 1 and sys.argv[1] == 'part1':
    # Part 1: Disassemble around the LOGOUT_NOTICE call site
    disasm_range(0x0130D0, 110, "FUNCTION CONTAINING LOGOUT_NOTICE CALL (file 0x0130D0 - 0x013200)")

elif len(sys.argv) > 1 and sys.argv[1] == 'part2':
    # Part 2: Main loop at 0x000156
    disasm_range(0x000156, 200, "MAIN LOOP (file 0x000156)")

elif len(sys.argv) > 1 and sys.argv[1] == 'part3':
    # Part 3: Search for references to 0x060600C7 (g_state+0xC7)
    # This would be loaded via mov.l from a literal pool
    target_addr = 0x060600C7
    # Actually g_state base is likely 0x06060000 and +0xC7 is accessed via offset
    # Search for the base address in literal pools
    for base_candidate in [0x06060000, 0x060600C0, 0x060600C7, 0x06060040]:
        packed = struct.pack('>I', base_candidate)
        pos = 0
        while True:
            pos = data.find(packed, pos)
            if pos == -1:
                break
            # Must be 4-byte aligned for mov.l literal pool
            if pos % 4 == 0:
                mem = BASE + pos
                print(f'Found 0x{base_candidate:08X} at file 0x{pos:06X} (mem 0x{mem:08X})')
            pos += 1

elif len(sys.argv) > 1 and sys.argv[1] == 'part4':
    # Part 4: Search for msg_types 0x0048, 0x006D, 0x025F, 0x02D4 in literal pools
    for msg_type in [0x0048, 0x006D, 0x025F, 0x02D4]:
        packed = struct.pack('>H', msg_type)
        print(f'\nSearching for msg_type 0x{msg_type:04X}:')
        pos = 0
        while True:
            pos = data.find(packed, pos)
            if pos == -1:
                break
            mem = BASE + pos
            # Check if this is in code area (roughly < 0x040000)
            if pos < 0x045000:
                # Check if it could be a mov.w literal pool entry
                # by looking for mov.w instructions that reference it
                for dist in range(2, 512, 2):
                    instr_addr = pos - dist
                    if instr_addr < 0:
                        break
                    disp = (pos - instr_addr - 4) // 2
                    if disp < 0 or disp > 255:
                        continue
                    instr = struct.unpack_from('>H', data, instr_addr)[0]
                    expected = 0x9500 | disp  # mov.w to R5
                    if instr == expected:
                        imem = BASE + instr_addr
                        print(f'  mov.w to R5 at file 0x{instr_addr:06X} (0x{imem:08X}) refs literal at 0x{pos:06X}')
            pos += 1

elif len(sys.argv) > 1 and sys.argv[1] == 'part5':
    # Part 5: Search for references to g_state+0x8E through g_state+0x91
    # These are ESP_NOTICE init flags
    # g_state base = 0x06060000, so 0x8E..0x91
    # These would be accessed as mov.b @(disp,Rn),R0 where Rn points to g_state base
    # Or through some other addressing mode

    # Search for the pattern where these offsets appear as mov.b @(0x8E...) instructions
    # SH-2 mov.b @(disp,Rm),R0 only has 4-bit disp (0-15), so 0x8E is too large
    # They'd need to use add/offset from base register

    # Let's search for bytes 0x8E, 0x8F, 0x90, 0x91 as immediate values
    # mov #0x8E is E08E (unsigned) but SH-2 mov #imm is signed -128..127
    # 0x8E = 142 > 127, so it would be negative: mov #-114 = 0xE08E? No, that's r0
    # Actually in SH-2: mov #imm,Rn where imm is sign-extended 8-bit
    # 0x8E as signed 8-bit = -114
    # The value 0x8E would need to be loaded differently

    # Actually, these are just byte offsets. If the base register already has g_state,
    # they could add the offset to get the address.
    # Let's look for where g_state base (0x06060000) is loaded and then how +0x8E is reached

    # First find all references to 0x06060000 or nearby
    g_state_candidates = [0x06060000, 0x06060040, 0x06060080, 0x060600C0]
    for addr in g_state_candidates:
        packed = struct.pack('>I', addr)
        pos = 0
        count = 0
        while True:
            pos = data.find(packed, pos)
            if pos == -1:
                break
            if pos % 4 == 0 and pos < 0x045000:
                mem = BASE + pos
                print(f'Literal 0x{addr:08X} at file 0x{pos:06X} (mem 0x{mem:08X})')
                count += 1
            pos += 1
        if count == 0:
            print(f'No aligned occurrences of 0x{addr:08X} in code area')
