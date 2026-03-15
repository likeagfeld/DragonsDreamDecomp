import struct, sys

data = open('D:/DragonsDreamDecomp/extracted/0.BIN', 'rb').read()
BASE = 0x06010000

def dis_sh2(file_offset, count=40):
    pc = BASE + file_offset
    lines = []
    for i in range(count):
        off = file_offset + i*2
        if off+2 > len(data):
            break
        insn = struct.unpack('>H', data[off:off+2])[0]
        addr = pc + i*2

        line = f'  0x{addr:08X} (f:0x{off:06X}): {insn:04X}  '

        if insn == 0x000B:
            line += 'RTS'
        elif insn == 0x0009:
            line += 'NOP'
        elif (insn & 0xF000) == 0xE000:
            reg = (insn >> 8) & 0xF
            imm = insn & 0xFF
            if imm > 127: imm -= 256
            line += f'MOV #{imm}, R{reg}'
        elif (insn & 0xF000) == 0x7000:
            reg = (insn >> 8) & 0xF
            imm = insn & 0xFF
            if imm > 127: imm -= 256
            line += f'ADD #{imm}, R{reg}'
        elif (insn & 0xF000) == 0xD000:
            reg = (insn >> 8) & 0xF
            disp = insn & 0xFF
            target_addr = (pc + i*2 + 4) & ~3
            target_addr += disp * 4
            target_file = target_addr - BASE
            if 0 <= target_file < len(data)-3:
                val = struct.unpack('>I', data[target_file:target_file+4])[0]
                line += f'MOV.L @(0x{disp*4:X},PC), R{reg}  ; [0x{target_addr:08X}] = 0x{val:08X}'
            else:
                line += f'MOV.L @(0x{disp*4:X},PC), R{reg}'
        elif (insn & 0xF000) == 0x9000:
            reg = (insn >> 8) & 0xF
            disp = insn & 0xFF
            target_addr = (pc + i*2 + 4) + disp * 2
            target_file = target_addr - BASE
            if 0 <= target_file < len(data)-1:
                val = struct.unpack('>H', data[target_file:target_file+2])[0]
                line += f'MOV.W @(0x{disp*2:X},PC), R{reg}  ; [0x{target_addr:08X}] = 0x{val:04X}'
            else:
                line += f'MOV.W @(0x{disp*2:X},PC), R{reg}'
        elif (insn & 0xFF00) == 0xC600:
            disp = insn & 0xFF
            line += f'MOV.L @(0x{disp*4:X},GBR), R0'
        elif (insn & 0xF00F) == 0x6003:
            rn = (insn >> 8) & 0xF
            rm = (insn >> 4) & 0xF
            line += f'MOV R{rm}, R{rn}'
        elif (insn & 0xF00F) == 0x600E:
            rn = (insn >> 8) & 0xF
            rm = (insn >> 4) & 0xF
            line += f'EXTS.B R{rm}, R{rn}'
        elif (insn & 0xF00F) == 0x600F:
            rn = (insn >> 8) & 0xF
            rm = (insn >> 4) & 0xF
            line += f'EXTS.W R{rm}, R{rn}'
        elif (insn & 0xF00F) == 0x2002:
            rn = (insn >> 8) & 0xF
            rm = (insn >> 4) & 0xF
            line += f'MOV.L R{rm}, @R{rn}'
        elif (insn & 0xF00F) == 0x2001:
            rn = (insn >> 8) & 0xF
            rm = (insn >> 4) & 0xF
            line += f'MOV.W R{rm}, @R{rn}'
        elif (insn & 0xF00F) == 0x2000:
            rn = (insn >> 8) & 0xF
            rm = (insn >> 4) & 0xF
            line += f'MOV.B R{rm}, @R{rn}'
        elif (insn & 0xF000) == 0x5000:
            rn = (insn >> 8) & 0xF
            rm = (insn >> 4) & 0xF
            disp = insn & 0xF
            line += f'MOV.L @(0x{disp*4:X},R{rm}), R{rn}'
        elif (insn & 0xF000) == 0x1000:
            rn = (insn >> 8) & 0xF
            rm = (insn >> 4) & 0xF
            disp = insn & 0xF
            line += f'MOV.L R{rm}, @(0x{disp*4:X},R{rn})'
        elif (insn & 0xF000) == 0x8000:
            sub = (insn >> 8) & 0xF
            if sub == 0:
                disp = insn & 0xF
                rm = (insn >> 4) & 0xF
                line += f'MOV.B R0, @(0x{disp:X},R{rm})'
            elif sub == 1:
                disp = insn & 0xF
                rm = (insn >> 4) & 0xF
                line += f'MOV.W R0, @(0x{disp*2:X},R{rm})'
            elif sub == 4:
                disp = insn & 0xF
                rm = (insn >> 4) & 0xF
                line += f'MOV.B @(0x{disp:X},R{rm}), R0'
            elif sub == 5:
                disp = insn & 0xF
                rm = (insn >> 4) & 0xF
                line += f'MOV.W @(0x{disp*2:X},R{rm}), R0'
            elif sub == 9:
                disp = insn & 0xFF
                if disp > 127: disp -= 256
                target = pc + i*2 + 4 + disp*2
                line += f'BT 0x{target:08X}'
            elif sub == 0xB:
                disp = insn & 0xFF
                if disp > 127: disp -= 256
                target = pc + i*2 + 4 + disp*2
                line += f'BF 0x{target:08X}'
            elif sub == 0xD:
                disp = insn & 0xFF
                if disp > 127: disp -= 256
                target = pc + i*2 + 4 + disp*2
                line += f'BT/S 0x{target:08X}'
            elif sub == 0xF:
                disp = insn & 0xFF
                if disp > 127: disp -= 256
                target = pc + i*2 + 4 + disp*2
                line += f'BF/S 0x{target:08X}'
            else:
                line += f'MOV.x (sub=0x{sub:X})'
        elif (insn & 0xF0FF) == 0x4028:
            rn = (insn >> 8) & 0xF
            line += f'SHLL16 R{rn}'
        elif (insn & 0xF0FF) == 0x4029:
            rn = (insn >> 8) & 0xF
            line += f'SHLR16 R{rn}'
        elif (insn & 0xF0FF) == 0x4008:
            rn = (insn >> 8) & 0xF
            line += f'SHLL2 R{rn}'
        elif (insn & 0xF0FF) == 0x4009:
            rn = (insn >> 8) & 0xF
            line += f'SHLR2 R{rn}'
        elif (insn & 0xF0FF) == 0x4000:
            rn = (insn >> 8) & 0xF
            line += f'SHLL R{rn}'
        elif (insn & 0xF0FF) == 0x4001:
            rn = (insn >> 8) & 0xF
            line += f'SHLR R{rn}'
        elif (insn & 0xF00F) == 0x400B:
            rn = (insn >> 8) & 0xF
            rm = (insn >> 4) & 0xF
            line += f'JSR @R{rn}'
        elif (insn & 0xF0FF) == 0x402B:
            rn = (insn >> 8) & 0xF
            line += f'JMP @R{rn}'
        elif (insn & 0xF00F) == 0x300C:
            rn = (insn >> 8) & 0xF
            rm = (insn >> 4) & 0xF
            line += f'ADD R{rm}, R{rn}'
        elif (insn & 0xF00F) == 0x3000:
            rn = (insn >> 8) & 0xF
            rm = (insn >> 4) & 0xF
            line += f'CMP/EQ R{rm}, R{rn}'
        elif (insn & 0xF00F) == 0x3002:
            rn = (insn >> 8) & 0xF
            rm = (insn >> 4) & 0xF
            line += f'CMP/HS R{rm}, R{rn}'
        elif (insn & 0xF00F) == 0x3003:
            rn = (insn >> 8) & 0xF
            rm = (insn >> 4) & 0xF
            line += f'CMP/GE R{rm}, R{rn}'
        elif (insn & 0xF00F) == 0x3006:
            rn = (insn >> 8) & 0xF
            rm = (insn >> 4) & 0xF
            line += f'CMP/HI R{rm}, R{rn}'
        elif (insn & 0xF00F) == 0x3007:
            rn = (insn >> 8) & 0xF
            rm = (insn >> 4) & 0xF
            line += f'CMP/GT R{rm}, R{rn}'
        elif (insn & 0xFF00) == 0x8800:
            imm = insn & 0xFF
            line += f'CMP/EQ #{imm}, R0'
        elif (insn & 0xF000) == 0xA000:
            disp = insn & 0xFFF
            if disp > 0x7FF: disp -= 0x1000
            target = pc + i*2 + 4 + disp*2
            line += f'BRA 0x{target:08X}'
        elif (insn & 0xF000) == 0xB000:
            disp = insn & 0xFFF
            if disp > 0x7FF: disp -= 0x1000
            target = pc + i*2 + 4 + disp*2
            line += f'BSR 0x{target:08X}'
        elif (insn & 0xF0FF) == 0x4015:
            rn = (insn >> 8) & 0xF
            line += f'CMP/PL R{rn}'
        elif (insn & 0xF0FF) == 0x4011:
            rn = (insn >> 8) & 0xF
            line += f'CMP/PZ R{rn}'
        elif (insn & 0xF00F) == 0x000C:
            rn = (insn >> 8) & 0xF
            rm = (insn >> 4) & 0xF
            line += f'MOV.B @(R0,R{rm}), R{rn}'
        elif (insn & 0xF00F) == 0x000D:
            rn = (insn >> 8) & 0xF
            rm = (insn >> 4) & 0xF
            line += f'MOV.W @(R0,R{rm}), R{rn}'
        elif (insn & 0xF00F) == 0x000E:
            rn = (insn >> 8) & 0xF
            rm = (insn >> 4) & 0xF
            line += f'MOV.L @(R0,R{rm}), R{rn}'
        elif (insn & 0xF00F) == 0x0004:
            rn = (insn >> 8) & 0xF
            rm = (insn >> 4) & 0xF
            line += f'MOV.B R{rm}, @(R0,R{rn})'
        elif (insn & 0xF00F) == 0x6002:
            rn = (insn >> 8) & 0xF
            rm = (insn >> 4) & 0xF
            line += f'MOV.L @R{rm}, R{rn}'
        elif (insn & 0xF00F) == 0x6001:
            rn = (insn >> 8) & 0xF
            rm = (insn >> 4) & 0xF
            line += f'MOV.W @R{rm}, R{rn}'
        elif (insn & 0xF00F) == 0x6000:
            rn = (insn >> 8) & 0xF
            rm = (insn >> 4) & 0xF
            line += f'MOV.B @R{rm}, R{rn}'
        elif (insn & 0xF00F) == 0x6006:
            rn = (insn >> 8) & 0xF
            rm = (insn >> 4) & 0xF
            line += f'MOV.L @R{rm}+, R{rn}'
        elif (insn & 0xF00F) == 0x2006:
            rn = (insn >> 8) & 0xF
            rm = (insn >> 4) & 0xF
            line += f'MOV.L R{rm}, @-R{rn}'
        elif (insn & 0xF00F) == 0x3008:
            rn = (insn >> 8) & 0xF
            rm = (insn >> 4) & 0xF
            line += f'SUB R{rm}, R{rn}'
        elif (insn & 0xF00F) == 0x200B:
            rn = (insn >> 8) & 0xF
            rm = (insn >> 4) & 0xF
            line += f'OR R{rm}, R{rn}'
        elif (insn & 0xF00F) == 0x2009:
            rn = (insn >> 8) & 0xF
            rm = (insn >> 4) & 0xF
            line += f'AND R{rm}, R{rn}'
        elif (insn & 0xFF00) == 0xC900:
            imm = insn & 0xFF
            line += f'AND #{imm}, R0'
        elif (insn & 0xFF00) == 0xCB00:
            imm = insn & 0xFF
            line += f'OR #{imm}, R0'
        elif (insn & 0xF00F) == 0x200A:
            rn = (insn >> 8) & 0xF
            rm = (insn >> 4) & 0xF
            line += f'XOR R{rm}, R{rn}'
        elif (insn & 0xF0FF) == 0x4024:
            rn = (insn >> 8) & 0xF
            line += f'ROTCL R{rn}'
        elif (insn & 0xF0FF) == 0x4004:
            rn = (insn >> 8) & 0xF
            line += f'ROTL R{rn}'
        elif (insn & 0xF00F) == 0x200E:
            rn = (insn >> 8) & 0xF
            rm = (insn >> 4) & 0xF
            line += f'MULU.W R{rm}, R{rn}'
        elif (insn & 0xF0FF) == 0x001A:
            rn = (insn >> 8) & 0xF
            line += f'STS MACL, R{rn}'
        elif insn == 0x4F22:
            line += 'STC.L PR, @-R15  (PUSH PR)'
        elif insn == 0x4F26:
            line += 'LDS.L @R15+, PR  (POP PR)'
        elif insn == 0x4F12:
            line += 'STS.L MACL, @-R15'
        elif insn == 0x4F16:
            line += 'LDS.L @R15+, MACL'
        else:
            line += f'??? (0x{insn:04X})'

        lines.append(line)

        # Stop after RTS + delay slot
        if i > 0:
            prev_insn = struct.unpack('>H', data[file_offset + (i-1)*2:file_offset + (i-1)*2 + 2])[0]
            if prev_insn == 0x000B:  # Previous was RTS
                break

    return lines

# Disassemble specific functions
areas = [
    # Function 1: GOTOLIST_REQUEST handler (0x019B) at 0x0604492E
    ("GOTOLIST_REQUEST handler (0x019B)", 0x0492E, 100),

    # Function 2: Button/UI function at 0x0603C500
    ("Button/UI function", 0x2C500, 250),

    # Function 3: Per-frame state 1 at 0x0603BC50
    ("Per-frame state 1", 0x2BC50, 250),
]

for name, offset, count in areas:
    print(f'\n=== {name} at file 0x{offset:06X} (mem 0x{BASE+offset:08X}) ===')
    for l in dis_sh2(offset, count):
        print(l)
