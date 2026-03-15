#!/usr/bin/env python3
"""
Trace of BTL_RESULT_NOTICE handler at 0x060181B0.
Handler receives r4 = pointer to payload (after 8-byte header).
"""

# Helper functions:
# read_u16_be(r4=dest, r5=src): reads 2B BE from src, writes u16 to *r4, returns r0 = src+2
# read_u32_be(r4=dest, r5=src): reads 4B BE from src, writes u32 to *r4, returns r0 = src+4
# memcpy(r4=dest, r5=src, r6=count): copies count bytes

# === PROLOGUE ===
# r4 = payload_ptr on entry
# r5 = payload_ptr (0x81B2)
# r10 = game_base (from GBR+8)
# r13 = game_base + 0x00010180 = state struct
# r8 = 0x0603FE68 = memcpy
# r11 = 0

# === HEADER FIELDS (fixed portion) ===
# All reads from payload in sequential order:

payload_offset = 0

# READ #1: read_u16_be(dest=state+0, src=payload+0)
# 0x81D2: jsr read_u16_be
# 0x81D4: r4 = r13 (state+0)   [delay slot]
# r5 = payload_ptr (from 0x81B2)
print(f"[{payload_offset:3d}..{payload_offset+1:3d}] u16 BE -> state[0x00]  (READ #1)")
payload_offset += 2  # now 2

# READ #2: read_u16_be(dest=state+0x16, src=payload+2)
# 0x81D6: r5 = r0 = payload+2
# 0x81DE: jsr read_u16_be
# 0x81E0: r4 = r13+22=state+0x16  [delay slot]
print(f"[{payload_offset:3d}..{payload_offset+1:3d}] u16 BE -> state[0x16]  (READ #2: num_combatants)")
payload_offset += 2  # now 4

# After READ #2: r0 = payload+4, r14 = payload+4
# 0x81E8: r14 += 4 -> r14 = payload+8
# This means payload[4..7] are SKIPPED by the u16 read but r14 jumps over them.
# Wait - actually r14 = r0 = payload+4 then add #4 makes r14 = payload+8.
# So 4 bytes at payload[4..7] are effectively skipped.
print(f"[{payload_offset:3d}..{payload_offset+3:3d}] *** SKIPPED 4 bytes (not read into state)")
payload_offset += 4  # now 8

# READ #3: read_u16_be(dest=state+0x02, src=payload+8)
# 0x81EA: r5 = r14 = payload+8
# 0x81EC: jsr read_u16_be
# 0x81EE: r4 = r13+2=state+0x02  [delay slot]
print(f"[{payload_offset:3d}..{payload_offset+1:3d}] u16 BE -> state[0x02]  (READ #3)")
payload_offset += 2  # now 10

# READ #4: read_u16_be(dest=state+0x04, src=payload+10)
# 0x81F2: r5 = r0 = payload+10
# 0x81F8: jsr read_u16_be
# 0x81FA: r4 = r13+4=state+0x04  [delay slot]
print(f"[{payload_offset:3d}..{payload_offset+1:3d}] u16 BE -> state[0x04]  (READ #4)")
payload_offset += 2  # now 12

# READ #5: read_u16_be(dest=state+0x06, src=payload+12)
# 0x81FE: r5 = r0 = payload+12
# 0x8204: jsr read_u16_be
# 0x8206: r4 = r13+6=state+0x06  [delay slot]
print(f"[{payload_offset:3d}..{payload_offset+1:3d}] u16 BE -> state[0x06]  (READ #5)")
payload_offset += 2  # now 14

# After READ #5: r0 = payload+14, r14 = payload+14
# 0x820E: r14 += 1 -> r14 = payload+15
# SKIP 1 byte at payload[14]
print(f"[{payload_offset:3d}]       *** SKIPPED 1 byte")
payload_offset += 1  # now 15

# READ #6: byte -> state[0x08]
# 0x8210: r0 = *r14++ = payload[15], r14 = payload+16
# 0x8214: state[8] = r0 (mov.b r0,@(8,r13))
print(f"[{payload_offset:3d}]       byte   -> state[0x08]  (READ #6)")
payload_offset += 1  # now 16

# READ #7: memcpy(dest=state+0x0E, src=payload+16, count=8)
# 0x8216: r5 = r14 = payload+16
# 0x8218: jsr memcpy (r8)
# 0x821A: r4 = r13+14=state+0x0E  [delay slot]
# r6 = 8 (set at 0x820A)
print(f"[{payload_offset:3d}..{payload_offset+7:3d}] 8 bytes -> state[0x0E..0x15]  (READ #7: name?)")
payload_offset += 8  # now 24

# READ #8: read_u16_be(dest=state+0x0A, src=payload+24)
# 0x821E: r14 += 8 -> but wait, this is AFTER memcpy, r14 was payload+16
# r14 += 8 -> r14 = payload+24. That lines up with memcpy reading 8 bytes.
# 0x8220: r5 = r14 = payload+24
# 0x8224: jsr read_u16_be
# 0x8226: r4 = r13+10=state+0x0A  [delay slot]
# Wait r4 = r13 (0x8222), then +10 (0x8226 delay) = state+0x0A
print(f"[{payload_offset:3d}..{payload_offset+1:3d}] u16 BE -> state[0x0A]  (READ #8)")
payload_offset += 2  # now 26

# READ #9: read_u16_be(dest=state+0x0C, src=payload+26)
# 0x822A: r5 = r0 = payload+26
# 0x8230: jsr read_u16_be
# 0x8232: r4 = r13+12=state+0x0C  [delay slot]
print(f"[{payload_offset:3d}..{payload_offset+1:3d}] u16 BE -> state[0x0C]  (READ #9)")
payload_offset += 2  # now 28

# After READ #9: r0 = payload+28, r14 = r0 = payload+28
# r11 = 0

# READ #10: byte -> state[0x09]
# 0x8238: r0 = *r14++ = payload[28], r14 = payload+29
# 0x823A: state[9] = r0 (mov.b r0,@(9,r13))
print(f"[{payload_offset:3d}]       byte   -> state[0x09]  (READ #10)")
payload_offset += 1  # now 29

# 0x823C: r0 = 0x01B8 (440)
# 0x823E: r14 += 7 -> r14 = payload+36
# SKIP 7 bytes at payload[29..35]
print(f"[{payload_offset:3d}..{payload_offset+6:3d}] *** SKIPPED 7 bytes")
payload_offset += 7  # now 36

# READs #11-15: 5 individual bytes to state[0x1B8..0x1BC]
# r0 starts at 0x1B8
# 0x8240: r3 = *r14++ = payload[36]
# 0x8242: state[0x1B8] = r3
print(f"[{payload_offset:3d}]       byte   -> state[0x1B8]  (READ #11)")
payload_offset += 1  # now 37

# 0x8244: r3 = *r14++ = payload[37]
# 0x8246: r0 = 0x1B9
# 0x8248: state[0x1B9] = r3
print(f"[{payload_offset:3d}]       byte   -> state[0x1B9]  (READ #12)")
payload_offset += 1  # now 38

# 0x824A: r0 = 0x1BA
# 0x824C: r3 = *r14++ = payload[38]
# 0x824E: state[0x1BA] = r3
print(f"[{payload_offset:3d}]       byte   -> state[0x1BA]  (READ #13)")
payload_offset += 1  # now 39

# 0x8250: r3 = *r14++ = payload[39]
# 0x8252: r0 = 0x1BB
# 0x8254: state[0x1BB] = r3
print(f"[{payload_offset:3d}]       byte   -> state[0x1BB]  (READ #14)")
payload_offset += 1  # now 40

# 0x8256: r0 = 0x1BC
# 0x8258: r3 = *r14++ = payload[40]
# 0x825A: state[0x1BC] = r3
print(f"[{payload_offset:3d}]       byte   -> state[0x1BC]  (READ #15)")
payload_offset += 1  # now 41

# 0x825C: r14 += 3 -> r14 = payload+44
# SKIP 3 bytes at payload[41..43]
print(f"[{payload_offset:3d}..{payload_offset+2:3d}] *** SKIPPED 3 bytes")
payload_offset += 3  # now 44

print()
print(f"=== FIXED HEADER: {payload_offset} bytes total ===")
print()
print(f"=== PER-COMBATANT LOOP (count = state[0x16] from payload[2..3]) ===")
print(f"Each combatant record starts at payload offset {payload_offset}")
print()

loop_start = payload_offset

# Loop body at 0x06018270:
# READ_L1: read_u16_be(dest=sp+8, src=r14)
# 0x8272: r4 = sp
# 0x8274: r4 += 8
# 0x8276: jsr read_u16_be
# 0x8278: r5 = r14  [delay slot]
print(f"[+{payload_offset-loop_start:3d}..+{payload_offset-loop_start+1:3d}] u16 BE -> local[0x08]  (combatant field 1)")
payload_offset += 2

# READ_L2: read_u16_be(dest=sp+0, src=updated)
# 0x827A: r4 = sp
# 0x827E: jsr read_u16_be
# 0x8280: r5 = r0  [delay slot]
# Wait - let me re-check. 0x827A: r4 = sp (mov r15,r4)
# 0x827C: r3 = read_u16_be
# 0x827E: jsr @r3
# 0x8280: r5 = r0  [delay slot: mov r0,r5 where r0 is still the return from READ_L1]
# This writes u16 to @sp (sp[0..1])
print(f"[+{payload_offset-loop_start:3d}..+{payload_offset-loop_start+1:3d}] u16 BE -> local[0x00]  (combatant field 2)")
payload_offset += 2

# r12 = r0 = updated src ptr (after 4 bytes of u16 reads)

# 0x8284: r0 = byte @(1,sp) -- this reads local[1], which is the LOW byte of the u16 just written
# 0x8286: r6 = 16
# 0x8288: store r0 to local[10] (sp+10)
# 0x828A: r4 = sp
# 0x828C: r4 += 12
# 0x828E: jsr memcpy(sp+12, r12, 16)
# 0x8290: r5 = r12  [delay slot]
print(f"[+{payload_offset-loop_start:3d}..+{payload_offset-loop_start+15:3d}] 16 bytes -> local[0x0C..0x1B]  (name, 16 chars)")
payload_offset += 16

# 0x8292: r0 = 28 (0x1C)
# 0x8294: r3 = read_u32_be
# 0x8296: r12 += 16  (src advances past the 16 byte name)
# 0x8298: store r11 (=0) to local[0x1C]
# 0x829A: r4 = sp
# 0x829C: r4 += 56 (0x38)
# 0x829E: jsr read_u32_be(sp+0x38, r12)
# 0x82A0: r5 = r12  [delay slot]
print(f"[+{payload_offset-loop_start:3d}..+{payload_offset-loop_start+3:3d}] u32 BE -> local[0x38]  (combatant field 3)")
payload_offset += 4

# r12 = r0 = updated src
# 0x82A4: r12 += 4
# Wait - r0 is the return from read_u32_be which is src+4
# Then r12 = r0 = src_after_u32, and r12 += 4 means we skip 4 more bytes!
print(f"[+{payload_offset-loop_start:3d}..+{payload_offset-loop_start+3:3d}] *** SKIPPED 4 bytes")
payload_offset += 4

# 0x82A8: r0 = *r12++ = byte
# 0x82AA: local[0x0B] = r0
print(f"[+{payload_offset-loop_start:3d}]       byte   -> local[0x0B]  (combatant field 4)")
payload_offset += 1

# 0x82AC: r3 = *r12++ = byte
# 0x82B0: local[0x26] = r3
print(f"[+{payload_offset-loop_start:3d}]       byte   -> local[0x26]  (combatant field 5)")
payload_offset += 1

# READ_L7: read_u16_be(dest=sp, src=r12)
# 0x82B2: r3 = read_u16_be
# 0x82B4: jsr @r3
# 0x82B6: r5 = r12  [delay slot]
# r4 = sp (set at 0x82A6, not modified since)
# Actually wait - I need to check if r4 was modified. Let me trace:
# 0x82A6: r4 = sp (r15)
# 0x82A8: r0 = *r12++ (uses r12, not r4)
# 0x82AA: store to @(11,r15) (uses r15 directly, not r4)  -- actually 80FB = mov.b r0,@(disp,Rn)
# Hmm, 0x80FB: 1000 0000 1111 1011 -> mov.b r0,@(disp,Rn) format is 10000000nnnndddd
# rn = F = r15, disp = B = 11. So stores r0 to r15+11.
# r4 is unchanged since 0x82A6. So r4 = sp when read_u16_be is called.
print(f"[+{payload_offset-loop_start:3d}..+{payload_offset-loop_start+1:3d}] u16 BE -> local[0x00]  (combatant field 6, overwrites)")
payload_offset += 2

# r14 = r0 = updated src
# r12 = r11 = 0 (0x82BA)

# 0x82BC: r0 = mov.w @r15+  -- pops u16 from stack, sp += 2
# 0x82BE: mov.w r0,@(30,r15) -- stores to new_sp+30
# The u16 just read is stored to the local struct

# 7 individual byte reads from r14:
# 0x82C0: r3 = *r14++, store to new_sp[33]
print(f"[+{payload_offset-loop_start:3d}]       byte   -> local[0x21]  (combatant field 7)")
payload_offset += 1
# 0x82C8: r3 = *r14++, store to new_sp[32]
print(f"[+{payload_offset-loop_start:3d}]       byte   -> local[0x20]  (combatant field 8)")
payload_offset += 1
# 0x82CC: r3 = *r14++, store to new_sp[34]
print(f"[+{payload_offset-loop_start:3d}]       byte   -> local[0x22]  (combatant field 9)")
payload_offset += 1
# 0x82D4: r3 = *r14++, store to new_sp[36]
print(f"[+{payload_offset-loop_start:3d}]       byte   -> local[0x24]  (combatant field 10)")
payload_offset += 1
# 0x82D8: r3 = *r14++, store to new_sp[35]
print(f"[+{payload_offset-loop_start:3d}]       byte   -> local[0x23]  (combatant field 11)")
payload_offset += 1
# 0x82E0: r3 = *r14++, store to new_sp[37]
print(f"[+{payload_offset-loop_start:3d}]       byte   -> local[0x25]  (combatant field 12)")
payload_offset += 1
# 0x82E4: r3 = *r14++, store to new_sp[29]
print(f"[+{payload_offset-loop_start:3d}]       byte   -> local[0x1D]  (combatant field 13)")
payload_offset += 1

# 0x82EA: r14 += 1  -- SKIP 1 byte
print(f"[+{payload_offset-loop_start:3d}]       *** SKIPPED 1 byte")
payload_offset += 1

# 0x82EC-0x8300: 8x read_u16_be loop
# r12 starts at 0 (from r11=0), increments by 2, loops while r12 < 16
# Each iteration: read_u16_be(dest=sp_new+0x28+r12, src=r14)
for i in range(8):
    off = payload_offset - loop_start
    print(f"[+{off:3d}..+{off+1:3d}] u16 BE -> local[0x{0x28+i*2:02X}]  (stat {i+1})")
    payload_offset += 2

combatant_size = payload_offset - loop_start
print()
print(f"=== PER-COMBATANT RECORD: {combatant_size} bytes ===")
print()
print(f"=== TOTAL PAYLOAD SIZE ===")
print(f"Fixed header: 44 bytes")
print(f"Per combatant: {combatant_size} bytes each")
print(f"Total = 44 + N * {combatant_size} where N = num_combatants (payload[2..3])")
