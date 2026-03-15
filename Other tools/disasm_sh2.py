#!/usr/bin/env python3
"""Simple SH-2 disassembler for Dragon's Dream binary analysis."""
import struct
import sys

def read_u16be(data, offset):
    return struct.unpack('>H', data[offset:offset+2])[0]

def read_u32be(data, offset):
    return struct.unpack('>I', data[offset:offset+4])[0]

def disasm_sh2(data, base_addr, file_data=None, file_base=0x06010000):
    """Disassemble SH-2 code. file_data is the full binary for resolving PC-relative loads."""
    lines = []
    i = 0
    while i < len(data) - 1:
        addr = base_addr + i
        w = struct.unpack('>H', data[i:i+2])[0]
        i += 2

        nib = (w >> 12) & 0xF
        comment = ""

        # Try to resolve PC-relative loads
        def resolve_pcrel_l(addr, disp):
            pc = (addr + 4) & ~3
            ea = pc + disp * 4
            if file_data:
                foff = ea - file_base
                if 0 <= foff <= len(file_data) - 4:
                    val = read_u32be(file_data, foff)
                    return ea, f"  ; =0x{val:08X}"
            return ea, ""

        def resolve_pcrel_w(addr, disp):
            pc = addr + 4
            ea = pc + disp * 2
            if file_data:
                foff = ea - file_base
                if 0 <= foff <= len(file_data) - 2:
                    val = read_u16be(file_data, foff)
                    # sign-extend
                    if val > 0x7FFF:
                        val_s = val - 0x10000
                    else:
                        val_s = val
                    return ea, f"  ; =0x{val:04X} ({val_s})"
            return ea, ""

        if w == 0x000B:
            lines.append(f'  {addr:08X}: {w:04X}  rts')
        elif w == 0x0009:
            lines.append(f'  {addr:08X}: {w:04X}  nop')
        elif w == 0x0048:
            lines.append(f'  {addr:08X}: {w:04X}  clrs')
        elif w == 0x0028:
            lines.append(f'  {addr:08X}: {w:04X}  clrmac')
        elif w == 0x0019:
            lines.append(f'  {addr:08X}: {w:04X}  div0u')
        elif w == 0x000A:
            lines.append(f'  {addr:08X}: {w:04X}  sts MACH,r0')
        elif w == 0x001A:
            lines.append(f'  {addr:08X}: {w:04X}  sts MACL,r0')
        elif nib == 0x6:
            rm = (w >> 4) & 0xF
            rn = (w >> 8) & 0xF
            func = w & 0xF
            ops = {0:'mov.b @r%m,r%n', 1:'mov.w @r%m,r%n', 2:'mov.l @r%m,r%n', 3:'mov r%m,r%n',
                   4:'mov.b @r%m+,r%n', 5:'mov.w @r%m+,r%n', 6:'mov.l @r%m+,r%n',
                   7:'not r%m,r%n', 8:'swap.b r%m,r%n', 9:'swap.w r%m,r%n',
                   0xA:'negc r%m,r%n', 0xB:'neg r%m,r%n', 0xC:'extu.b r%m,r%n',
                   0xD:'extu.w r%m,r%n', 0xE:'exts.b r%m,r%n', 0xF:'exts.w r%m,r%n'}
            if func in ops:
                s = ops[func].replace('%m', str(rm)).replace('%n', str(rn))
                lines.append(f'  {addr:08X}: {w:04X}  {s}')
            else:
                lines.append(f'  {addr:08X}: {w:04X}  ???')
        elif nib == 0xE:
            rn = (w >> 8) & 0xF
            imm = w & 0xFF
            if imm > 0x7F:
                imm_s = imm - 256
            else:
                imm_s = imm
            lines.append(f'  {addr:08X}: {w:04X}  mov #{imm_s},r{rn}')
        elif nib == 0x7:
            rn = (w >> 8) & 0xF
            imm = w & 0xFF
            if imm > 0x7F:
                imm_s = imm - 256
            else:
                imm_s = imm
            lines.append(f'  {addr:08X}: {w:04X}  add #{imm_s},r{rn}')
        elif nib == 0x2:
            rm = (w >> 4) & 0xF
            rn = (w >> 8) & 0xF
            func = w & 0xF
            ops = {0:'mov.b r%m,@r%n', 1:'mov.w r%m,@r%n', 2:'mov.l r%m,@r%n',
                   4:'mov.b r%m,@-r%n', 5:'mov.w r%m,@-r%n', 6:'mov.l r%m,@-r%n',
                   7:'div0s r%m,r%n', 8:'tst r%m,r%n', 9:'and r%m,r%n', 0xA:'xor r%m,r%n',
                   0xB:'or r%m,r%n', 0xC:'cmp/str r%m,r%n', 0xD:'xtrct r%m,r%n',
                   0xE:'mulu.w r%m,r%n', 0xF:'muls.w r%m,r%n'}
            if func in ops:
                s = ops[func].replace('%m', str(rm)).replace('%n', str(rn))
                lines.append(f'  {addr:08X}: {w:04X}  {s}')
            else:
                lines.append(f'  {addr:08X}: {w:04X}  ???')
        elif nib == 0x3:
            rm = (w >> 4) & 0xF
            rn = (w >> 8) & 0xF
            func = w & 0xF
            ops = {0:'cmp/eq r%m,r%n', 2:'cmp/hs r%m,r%n', 3:'cmp/ge r%m,r%n',
                   4:'div1 r%m,r%n', 6:'cmp/hi r%m,r%n', 7:'cmp/gt r%m,r%n',
                   8:'sub r%m,r%n', 0xA:'subc r%m,r%n', 0xB:'subv r%m,r%n',
                   0xC:'add r%m,r%n', 0xD:'dmuls.l r%m,r%n', 0xE:'addc r%m,r%n',
                   0xF:'addv r%m,r%n'}
            if func in ops:
                s = ops[func].replace('%m', str(rm)).replace('%n', str(rn))
                lines.append(f'  {addr:08X}: {w:04X}  {s}')
            else:
                lines.append(f'  {addr:08X}: {w:04X}  ???')
        elif nib == 0x4:
            rn = (w >> 8) & 0xF
            func = w & 0xFF
            ops4 = {
                0x0B: f'jsr @r{rn}', 0x2B: f'jmp @r{rn}',
                0x0E: f'ldc r{rn},SR', 0x1E: f'ldc r{rn},GBR', 0x2E: f'ldc r{rn},VBR',
                0x15: f'cmp/pl r{rn}', 0x11: f'cmp/pz r{rn}',
                0x10: f'dt r{rn}', 0x04: f'rotl r{rn}', 0x05: f'rotr r{rn}',
                0x24: f'rotcl r{rn}', 0x25: f'rotcr r{rn}',
                0x20: f'shal r{rn}', 0x21: f'shar r{rn}',
                0x00: f'shll r{rn}', 0x01: f'shlr r{rn}',
                0x08: f'shll2 r{rn}', 0x09: f'shlr2 r{rn}',
                0x18: f'shll8 r{rn}', 0x19: f'shlr8 r{rn}',
                0x28: f'shll16 r{rn}', 0x29: f'shlr16 r{rn}',
                0x0F: f'mac.l @r{rn}+,@r{(w>>4)&0xF}+',
            }
            if func in ops4:
                lines.append(f'  {addr:08X}: {w:04X}  {ops4[func]}')
            else:
                lines.append(f'  {addr:08X}: {w:04X}  4-op r{rn},0x{func:02X}')
        elif nib == 0x8:
            sub = (w >> 8) & 0xF
            if sub == 0xB:
                disp = w & 0xFF
                if disp > 0x7F: disp = disp - 256
                target = addr + 4 + disp * 2
                lines.append(f'  {addr:08X}: {w:04X}  bf 0x{target:08X}')
            elif sub == 0xF:
                disp = w & 0xFF
                if disp > 0x7F: disp = disp - 256
                target = addr + 4 + disp * 2
                lines.append(f'  {addr:08X}: {w:04X}  bf/s 0x{target:08X}')
            elif sub == 0x9:
                disp = w & 0xFF
                if disp > 0x7F: disp = disp - 256
                target = addr + 4 + disp * 2
                lines.append(f'  {addr:08X}: {w:04X}  bt 0x{target:08X}')
            elif sub == 0xD:
                disp = w & 0xFF
                if disp > 0x7F: disp = disp - 256
                target = addr + 4 + disp * 2
                lines.append(f'  {addr:08X}: {w:04X}  bt/s 0x{target:08X}')
            elif sub == 0x8:
                imm = w & 0xFF
                if imm > 0x7F: imm = imm - 256
                lines.append(f'  {addr:08X}: {w:04X}  cmp/eq #{imm},r0')
            elif sub == 0x0:
                rn2 = (w >> 4) & 0xF
                disp = w & 0xF
                lines.append(f'  {addr:08X}: {w:04X}  mov.b @({disp},r{rn2}),r0')
            elif sub == 0x1:
                rn2 = (w >> 4) & 0xF
                disp = w & 0xF
                lines.append(f'  {addr:08X}: {w:04X}  mov.w @({disp*2},r{rn2}),r0')
            elif sub == 0x4:
                rn2 = (w >> 4) & 0xF
                disp = w & 0xF
                lines.append(f'  {addr:08X}: {w:04X}  mov.b r0,@({disp},r{rn2})')
            elif sub == 0x5:
                rn2 = (w >> 4) & 0xF
                disp = w & 0xF
                lines.append(f'  {addr:08X}: {w:04X}  mov.w r0,@({disp*2},r{rn2})')
            else:
                lines.append(f'  {addr:08X}: {w:04X}  8-op 0x{sub:X} ???')
        elif nib == 0xA:
            disp = w & 0xFFF
            if disp > 0x7FF: disp = disp - 4096
            target = addr + 4 + disp * 2
            lines.append(f'  {addr:08X}: {w:04X}  bra 0x{target:08X}')
        elif nib == 0xB:
            disp = w & 0xFFF
            if disp > 0x7FF: disp = disp - 4096
            target = addr + 4 + disp * 2
            lines.append(f'  {addr:08X}: {w:04X}  bsr 0x{target:08X}')
        elif nib == 0xD:
            rn = (w >> 8) & 0xF
            disp = w & 0xFF
            ea, comment = resolve_pcrel_l(addr, disp)
            lines.append(f'  {addr:08X}: {w:04X}  mov.l @(0x{ea:08X}),r{rn}{comment}')
        elif nib == 0x9:
            rn = (w >> 8) & 0xF
            disp = w & 0xFF
            ea, comment = resolve_pcrel_w(addr, disp)
            lines.append(f'  {addr:08X}: {w:04X}  mov.w @(0x{ea:08X}),r{rn}{comment}')
        elif nib == 0xC:
            sub = (w >> 8) & 0xF
            imm = w & 0xFF
            if sub == 0x8:
                lines.append(f'  {addr:08X}: {w:04X}  tst #{imm},r0')
            elif sub == 0x9:
                lines.append(f'  {addr:08X}: {w:04X}  and #{imm},r0')
            elif sub == 0xA:
                lines.append(f'  {addr:08X}: {w:04X}  xor #{imm},r0')
            elif sub == 0xB:
                lines.append(f'  {addr:08X}: {w:04X}  or #{imm},r0')
            elif sub == 0x7:
                lines.append(f'  {addr:08X}: {w:04X}  mova @(disp,PC),r0')
            else:
                lines.append(f'  {addr:08X}: {w:04X}  C-op 0x{sub:X} #{imm}')
        elif nib == 0x1:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            disp = w & 0xF
            lines.append(f'  {addr:08X}: {w:04X}  mov.l r{rm},@({disp*4},r{rn})')
        elif nib == 0x5:
            rn = (w >> 8) & 0xF
            rm = (w >> 4) & 0xF
            disp = w & 0xF
            lines.append(f'  {addr:08X}: {w:04X}  mov.l @({disp*4},r{rm}),r{rn}')
        elif nib == 0x0:
            rm = (w >> 4) & 0xF
            rn = (w >> 8) & 0xF
            func = w & 0xF
            ops0 = {
                0x3: f'bsrf r{rn}', 0xC: f'mov.b @(r0,r{rm}),r{rn}',
                0xD: f'mov.w @(r0,r{rm}),r{rn}', 0xE: f'mov.l @(r0,r{rm}),r{rn}',
                0x4: f'mov.b r{rm},@(r0,r{rn})', 0x5: f'mov.w r{rm},@(r0,r{rn})',
                0x6: f'mov.l r{rm},@(r0,r{rn})', 0x7: f'mul.l r{rm},r{rn}',
                0x2: f'stc SR,r{rn}',
            }
            if func in ops0:
                lines.append(f'  {addr:08X}: {w:04X}  {ops0[func]}')
            else:
                lines.append(f'  {addr:08X}: {w:04X}  0-op r{rn},r{rm},0x{func:X}')
        else:
            lines.append(f'  {addr:08X}: {w:04X}  ???')
    return lines


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='SH-2 disassembler')
    parser.add_argument('binfile', help='Binary file to disassemble')
    parser.add_argument('--offset', '-o', type=lambda x: int(x, 0), required=True, help='File offset (hex or dec)')
    parser.add_argument('--length', '-l', type=lambda x: int(x, 0), default=256, help='Length in bytes')
    parser.add_argument('--base', '-b', type=lambda x: int(x, 0), default=0x06010000, help='Base address')
    args = parser.parse_args()

    with open(args.binfile, 'rb') as f:
        full_data = f.read()

    chunk = full_data[args.offset:args.offset + args.length]
    mem_addr = args.base + args.offset

    lines = disasm_sh2(chunk, mem_addr, full_data, args.base)
    for l in lines:
        print(l)
