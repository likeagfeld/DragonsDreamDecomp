#!/usr/bin/env python3
"""
Manual trace of CHARDATA_REPLY handler at 0x06013858
r4 = pointer to payload (after 8-byte wire header)

Key helper functions:
  read_u32_be (0x06019FD2): reads 4 bytes BE from r5, stores U32 at @r4, returns r0=r5+4
  read_u16_be (0x06019FF6): reads 2 bytes BE from r5, stores U16 at @r4, returns r0=r5+4
  memcpy_16   (0x0603FE68): copies r6 bytes from r5 to r4

Missing instruction decodings in disassembler:
  0x0F34  = mov.b r3, @(r0, r15)   (store byte to sp+r0)
  0x0FC4  = mov.b r12, @(r0, r15)  (store r12 to sp+r0)
  0x02FC  = mov.b @(r0, r15), r2   (load byte from sp+r0)
  0x03FC  = mov.b @(r0, r15), r3   (load byte from sp+r0)
  0x0DC4  = mov.b r12, @(r0, r13)  (store to char_base+r0)
  0x0D44  = mov.b r4, @(r0, r13)   (store to char_base+r0)
  0x0234  = mov.b r3, @(r0, r2)    (store byte to r2+r0)
  0x02C4  = mov.b r12, @(r0, r2)   (store r12 to r2+r0)
  0x88xx  = cmp/eq #xx, r0
  0x041A  = sts MACL, r4
"""

print("=" * 70)
print("CHARDATA_REPLY (msg_type 0x02D2) Handler Trace")
print("=" * 70)

print("""
=== PROLOGUE (0x06013858 - 0x06013870) ===
  Save r14,r13,r12,r11,r10,r9,r8 on stack
  Save PR (return address) and MACL on stack
  r14 = r4                  ; r14 = payload_ptr (source cursor)
  r13 = 0x0260              ; character data offset in game state
  r15 -= 120                ; allocate 120 bytes of local variables

=== READ HEADER FIELDS (0x06013870 - 0x06013892) ===

  r0 = GBR[8]              ; game_state base pointer
  r4 = r15                  ; r4 = stack frame pointer

  r3 = *r14++              ; payload[0] -> r3 (BYTE: char_type/section_type)
  r8 = r0                  ; r8 = game_state
  r13 += r8                ; r13 = game_state + 0x0260 (char_data_base)

  r0 = 16
  sp[r0] = r3              ; sp[16] = payload[0] (char_type)

  r4 += 4                  ; r4 = sp + 4

  r0 = *r14++              ; payload[1] -> r0 (BYTE: status/result_code)
  sp[8] = r0               ; sp[8] = payload[1] (status)

  r3 = *r14++              ; payload[2] -> r3 (BYTE: entry_count)
  r0 = 20
  sp[20] = r3              ; sp[20] = payload[2] (entry_count)

  r10 = *r14++             ; payload[3] -> r10 (BYTE: entry_size or similar)

  ; Call read_u32_be(dest=sp+4, src=payload+4)
  jsr read_u32_be
    r5 = r14               ; delay slot: r5 = payload + 4
  ; Returns: r0 = payload + 8, sp[4..7] = U32 from payload[4..7]

  r14 = r0                 ; r14 = payload + 8 (cursor past header)

  *** Header so far: 4 bytes (byte fields) + 4 bytes (U32) = 8 bytes ***

  Layout of first 8 bytes of payload:
    [0]   u8  char_type       (stored in sp[16])
    [1]   u8  status          (stored in sp[8])
    [2]   u8  entry_count     (stored in sp[20] and sp[12])
    [3]   u8  entry_size      (stored in r10)
    [4-7] u32 char_id/session (stored at sp[4..7])

=== FORMAT STRING (0x06013894 - 0x060138C8) ===

  r1 = 0x0604C63C          ; format string address
  r0 = 20
  r2 = sp[20] = entry_count ; load byte from sp+20
  r2 = extu.b r2            ; zero-extend
  sp[12] = r2               ; sp[12] = entry_count (as 32-bit)
  push r2                   ; arg4 = entry_count

  r0 = sp[12] (adjusted for push) = sp[8] = status byte (payload[1])
  r0 = extu.b r0
  sp[4] = r0                ; (save for later - adjusted offset)
  push r0                   ; arg3 = status

  r0 = 24 (adjusted: after 2 pushes, sp[24] = original sp[16] = char_type)
  r3 = sp[24] = char_type (payload[0])
  r3 = extu.b r3
  sp[32] = r3               ; save char_type (at adjusted offset = original sp[24])
  push r3                   ; arg2 = char_type
  push r1                   ; arg1 = format string 0x0604C63C

  ; Call sprintf-like(dest=sp+44, fmt=0x0604C63C, char_type, status, entry_count)
  r4 = sp + 44              ; (adjusted: sp+28 before 4 pushes = sp+44 after)
  jsr 0x0604023C

  r15 += 16                 ; pop 4 args

  ; Call strlen on formatted string
  r4 = sp + 28              ; (same buffer, now at sp+28 after pop)
  jsr 0x06020F1C            ; strlen

=== MAIN DISPATCH (0x060138CA - 0x06013968) ===

  r3 = 1
  r2 = sp[12] = entry_count
  r9 = 0x0603FE68           ; memcpy function
  r11 = 0x0606103C          ; global: num_chars_in_slot (byte)

  cmp/gt r3, r2             ; entry_count > 1?
  bf/s 0x06013954           ; if entry_count <= 1, skip to case with 0 or 1 entries
  r12 = 0                   ; (delay slot) r12 = 0

  === If entry_count > 1 (multi-entry processing) ===

  r0 = sp[0]               ; This value was set...
  ; Actually sp[0] might have been set during the sprintf/strlen calls
  ; or it could be the loop counter. Let me check what gets stored at sp[0].
  ; Looking at 0x06013972: 2FC2 = mov.l r12, @r15 => sp[0] = r12 = 0
  ; That's in the case 1 path. So sp[0] is used as loop counter.
  ; But at 0x060138D8 we havent entered case 1 yet...
  ;
  ; Wait: 0x060138D8 is INSIDE the "entry_count > 1" path.
  ; The bf/s branches to 0x06013954 (entry_count <= 1).
  ; If we fall through (entry_count > 1):
  ;   r0 = sp[0] = ???
  ; Hmm, sp[0] was not set. But actually reading uninitialized stack is
  ; common in compiled code when the compiler knows it wont be read first.
  ; Let me reconsider - maybe I miscounted the stack offsets.
  ;
  ; Actually - this might be wrong. Let me look at the NEXT branch:
  ; 0x060138DA: cmp/eq #1, r0  (is r0 == 1?)
  ; 0x060138DC: bf 0x060138E6  (if not 1, skip)
  ;
  ; If r0 == 1:
  ;   0x060138DE: r1 = 0x20200000
  ;   0x060138E0: r2 = 0x06061038 (global pointer)
  ;   0x060138E2: *r2 = r1  (store 0x20200000 to global)
  ;   0x060138E4: *r11 = r12 = 0  (num_chars = 0)
  ;
  ; Then falls through to 0x060138E6:
  ;   0x060138E6: r5 = r14 (source = payload+8)
  ;   0x060138E8: r3 = 0x06061038 (global pointer)
  ;   0x060138EA: r6 = sp[4] = status byte ...
  ;
  ; Hmm wait, sp[4] was set by read_u32_be. So sp[4..7] = the U32 from payload.
  ; But then sp[4] as a word read (mov.l @(4,r15)) would give the full U32.
  ; 56F1 = mov.l @(4, r15), r6 => r6 = the U32 value from payload[4..7]
  ;
  ; Actually wait - let me re-examine. After the sprintf/strlen section,
  ; r15 was restored. The local var layout:
  ;   sp[0]  = ? (maybe uninitialized, used as loop counter later)
  ;   sp[4]  = U32 from payload[4..7]
  ;   sp[8]  = payload[1] (status byte)
  ;   sp[12] = payload[2] (entry_count, zero-extended to 32-bit)
  ;   sp[16] = payload[0] (char_type byte)
  ;   sp[20] = payload[2] (entry_count byte)
  ;
  ; But sp[4] also got written to at 0x060138A4: 1F01 = mov.l r0, @(4, r15)
  ; That was r0 = status byte = payload[1] (zero-extended)
  ; But WAIT - that was when sp was adjusted by pushes!
  ; After 1 push (at 0x0601389E), sp was old_sp - 4
  ; So sp[4] = old_sp[0]. So we stored payload[1] at old_sp[0]!
  ;
  ; Let me redo this more carefully with the push tracking.

  ; Actually this is getting complex. Let me focus on just the data reads
  ; and not the stack frame gymnastics.

  ; After the format string section, we know:
  ;   sp[12] = entry_count
  ;   The U32 was stored but its not clear if sp[4] still has it after
  ;   the pushes overwrote things.
  ;
  ; Key insight: the sprintf section pushes 4 values (16 bytes) then
  ; pops them back (r15 += 16). So the stack frame is restored.
  ; But sp[4] was written twice:
  ;   1. By read_u32_be at sp+4
  ;   2. By 1F01 (mov.l r0, @(4,r15)) when sp was shifted by 1 push
  ;      = stored payload[1] at (sp-4)+4 = sp[0]
  ;
  ; So sp[0] = payload[1] status byte (zero-extended to 32-bit)!
  ; And sp[4] = U32 from payload[4..7] (undisturbed)

  So:
    sp[0]  = payload[1] (status, as u32)   -- set via push-offset trick
    sp[4]  = U32 from payload[4..7]        -- set by read_u32_be
    sp[8]  = payload[1] (status byte)
    sp[12] = payload[2] (entry_count, u32)
    sp[16] = payload[0] (char_type byte)
    sp[20] = payload[2] (entry_count byte)
    sp[24] = payload[0] (char_type, u32)   -- set via push-offset trick
    sp[32] = (from push-offset)

  OK so:
  0x060138D8: r0 = sp[0] = payload[1] (status)
  0x060138DA: cmp/eq #1, r0
  0x060138DC: bf 0x060138E6    ; if status != 1, skip init

  If status == 1:
    *0x06061038 = 0x20200000   ; reset some global pointer
    *0x0606103C = 0            ; reset num_chars = 0

  ; Common path (both status==1 and status!=1):
  0x060138E6: r5 = r14         ; source = current payload cursor (payload+8)
  0x060138EA: r6 = sp[4] = U32 from payload[4..7]
  ; Wait, 56F1 = mov.l @(4, r15), r6
  ; Hmm, but sp[4] was also the U32. But is r6 used as "size" for memcpy?
  ; That would make the U32 = data_chunk_size

  0x060138EC: jsr r9 (memcpy)
    r4 = *(0x06061038)        ; destination = global pointer
  ; memcpy(dest=*global_ptr, src=payload_cursor, size=U32_from_payload)

  After memcpy:
  0x060138F0-0x060138F8:
    r1 = *0x06061038           ; current pointer
    r3 = sp[4] = chunk_size
    r1 += r3                   ; advance pointer by chunk_size
    *0x06061038 = r1           ; save updated pointer

  0x060138FA-0x060138FE:
    r2 = *0x0606103C           ; current num_chars
    r2 += r10                  ; r10 = payload[3] (entries_in_this_chunk)
    *0x0606103C = r2           ; update num_chars

  0x06013900-0x06013906:
    r3 = sp[12] = entry_count (total)
    r1 = sp[0] = status (current page number?)
    cmp/ge r3, r1              ; status >= entry_count?
    bt 0x0601390C              ; if so, done (last page)

  If not last page:
    0x06013908: bra 0x06013B46 ; jump to epilogue (return, wait for more data)

  If last page:
    0x0601390C: r14 = 0x20200000  ; reset to start of accumulated buffer
    0x0601390E: bra 0x06013956    ; jump to single-entry processing
""")

print("""
=== SINGLE-ENTRY / ACCUMULATED PROCESSING (0x06013954 - 0x06013968) ===

  If entry_count <= 1 at 0x060138D4, we jump here:
  0x06013954: *r11 = r10     ; *0x0606103C = payload[3] (num_chars)

  0x06013956: r0 = sp[24] = payload[0] (char_type, as u32)
  ; Actually: 50F6 = mov.l @(24, r15), r0
  ; sp[24] = payload[0] as u32 (set via the push-offset trick at 0x060138AE)

  0x06013958: cmp/eq #1, r0   ; char_type == 1?
  0x0601395A: bt/s 0x0601396E ; if char_type == 1, branch to CASE 1
  0x0601395C: r4 = *r11       ; delay slot: r4 = num_chars

  0x0601395E: cmp/eq #2, r0   ; char_type == 2?
  0x06013960: bt 0x06013A10   ; if char_type == 2, branch to CASE 2

  0x06013962: cmp/eq #3, r0   ; char_type == 3?
  0x06013964: bf 0x0601396A   ; if char_type != 3, branch to DEFAULT
  0x06013966: bra 0x06013B06  ; CASE 3

  0x0601396A: bra 0x06013B3E  ; DEFAULT (unknown char_type)
""")

print("""
=== CASE 1: char_type == 1 (CHARACTER INFO) ===
At 0x0601396E:
  r0 = 0x1925               ; offset into char_data_base for case 1 write
  mov.b r4, @(r0, r13)      ; char_data[0x1925] = num_chars (byte)
  sp[0] = r12 = 0           ; loop counter = 0
  r8 = r12 = 0              ; r8 = accumulated offset (entry index * 28)
  bra 0x06013A02            ; jump to loop condition check

  LOOP BODY (0x06013978):
    r4 = 0x1684              ; base offset for char entries
    r6 = 16                  ; memcpy size = 16 bytes
    r5 = r14                 ; source = payload cursor
    r10 = exts.w r8          ; r10 = signed extend r8 (entry offset)
    r4 += r13                ; r4 = char_data_base + 0x1684
    jsr r9 (memcpy)
      r4 += r10              ; r4 = char_data_base + 0x1684 + entry_offset
    ; memcpy(char_data + 0x1684 + entry_off, payload_cursor, 16)

    r14 += 16                ; advance payload cursor by 16

    ; Read U16:
    r4 = char_data_base + 0x1684 + entry_off
    r3 = char_data_base + 0x1684 + entry_off
    r2 = r3 + 16             ; r2 = entry + 16
    r3 = 0x06019FF6 (read_u16_be)
    r2[0] = r12 = 0          ; entry[16] = 0 (clear byte before read)
    jsr read_u16_be
      r4 += 18               ; dest = entry + 18
    ; read_u16_be(dest=entry+18, src=payload_cursor)
    ; Reads 2 bytes from payload, stores as U16 at entry+18
    ; Returns r0 = updated source ptr

    r14 = r0                 ; advance cursor

    ; Read 5 individual bytes:
    r2 = char_data_base + 0x1684 + entry_off

    r3 = *r14++              ; BYTE from payload
    r0 = 21
    *(r2 + 21) = r3          ; entry[21] = byte

    r3 = *r14++              ; BYTE from payload
    r0 = 22
    *(r2 + 22) = r3          ; entry[22] = byte

    r3 = *r14++              ; BYTE from payload
    r0 = 26
    *(r2 + 26) = r3          ; entry[26] = byte

    r3 = *r14++              ; BYTE from payload
    r0 = 23
    *(r2 + 23) = r3          ; entry[23] = byte

    ; Read 1 byte, zero-extend, store as U16:
    r0 = *r14++              ; BYTE from payload
    r14 += 1                 ; skip 1 byte (padding?)
    r0 = extu.b r0
    entry[24] = r0 (as U16)  ; mov.w r0, @(24, r2)

    ; Call level calc function:
    r10 = char_data_base + 0x1684 + entry_off
    sp[8] = r10              ; save entry pointer
    r4 = r10
    r0 = entry[18] (U16)     ; mov.w @(18, r4), r0  = the experience U16
    jsr 0x0601A490            ; calc_level(experience)
    ; Returns r0 = level (0-7)

    r1 = r10 + 20
    *r1 = r0                  ; entry[20] = calculated level (byte)

    r8 += 28                  ; advance to next entry slot (stride = 28)

    ; Loop counter:
    r3 = sp[0]
    r3 += 1
    sp[0] = r3

  LOOP CHECK (0x06013A02):
    r3 = *r11 = num_chars     ; extu.b
    r2 = sp[0] = loop counter
    cmp/ge r3, r2             ; counter >= num_chars?
    bf 0x06013978             ; if not, continue loop

  After loop: bra 0x06013B46 (epilogue)

  PER-ENTRY WIRE DATA for case 1:
    [0-15]  16 bytes: raw character name data (memcpy)
    [16-17] 2 bytes: U16 experience
    [18]    1 byte: field stored at entry[21]
    [19]    1 byte: field stored at entry[22]
    [20]    1 byte: field stored at entry[26]
    [21]    1 byte: field stored at entry[23]
    [22]    1 byte: field (zero-extended to U16, stored at entry[24])
    [23]    1 byte: padding (skipped)
    Total per entry: 24 bytes
""")

print("""
=== CASE 2: char_type == 2 (DETAILED CHARACTER DATA) ===
At 0x06013A10:
  r0 = 0x1926               ; offset for case 2
  mov.b r12, @(r0, r13)     ; char_data[0x1926] = 0 (r12=0, clear field)
  sp[0] = r12 = 0           ; loop counter = 0
  bra 0x06013AC6            ; jump to loop condition

  LOOP BODY (0x06013A28):
    ; Read U16:
    r4 = sp + 68             ; dest on stack (sp[68..69])
    jsr read_u16_be(dest=sp+68, src=r14)
    ; r0 = updated source ptr
    r13 = r0                 ; r13 = new cursor (payload past U16)

    ; Read 2 bytes:
    r3 = *r13++              ; BYTE
    sp[70] = r3              ; r0=70, mov.b r3, @(r0, r15)
    r3 = *r13++              ; BYTE
    sp[71] = r3              ; r0=71, mov.b r3, @(r0, r15)

    ; memcpy 16 bytes:
    r4 = sp + 72
    jsr memcpy(dest=sp+72, src=r13, size=16)
    ; r13 += 16 via:
    r13 += 16

    ; Read U16:
    sp[88] = r12 = 0         ; clear (r0=88, mov.b r12, @(r0, r15))
    r4 = sp + 90
    jsr read_u16_be(dest=sp+90, src=r13)
    r13 = r0                 ; updated cursor

    ; Read 8 individual bytes:
    r3 = *r13++; sp[93] = r3
    r3 = *r13++; sp[92] = r3
    r3 = *r13++; sp[94] = r3
    r3 = *r13++; sp[95] = r3
    r3 = *r13++; sp[96] = r3
    r3 = *r13++; sp[97] = r3
    r3 = *r13++; sp[98] = r3
    r3 = *r13++; sp[89] = r3

    ; Skip 2 bytes:
    r13 += 2

    ; Read U32:
    jsr read_u32_be(dest=..., src=r13)
    r14 = r0                 ; updated cursor

    ; Reset counters for inner loop:
    r10 = 0
    r13 = 0

    ; INNER LOOP: read 8 x U16 values
    INNER LOOP (0x06013A9E):
      r5 = r14               ; source
      r4 = sp + 100 + r13    ; dest = sp[100 + offset]
      jsr read_u16_be(dest, src)
      r14 = r0               ; updated cursor
      r10 += 1
      r13 += 2               ; advance dest offset by 2
      if r10 < 8: loop
    ; Reads 8 U16 values = 16 bytes from payload

    ; Call process function:
    r4 = sp + 68             ; pointer to the struct we built on stack
    jsr 0x060246C4(r4, r5=1) ; process_char_entry(entry_data, flag=1)

    ; Loop counter:
    r2 = sp[0]
    r2 += 1
    sp[0] = r2

  LOOP CHECK (0x06013AC6):
    r3 = *r11 = num_chars
    r2 = sp[0] = counter
    if counter < num_chars: continue loop

  After loop:
    jsr 0x06024622            ; finalize function
    jsr 0x0601A3B0            ; another finalize

    ; Character selection/equipment setup:
    r0 = 0x1B90
    r4 = game_state[0x1B90]  ; active char index (byte)
    r3 = 0x00A4              ; entry size = 164
    r2 = game_state + 0x1BE0 ; equipment/stats base
    muls.w r3, r4             ; r4 = active_char * 164
    sts MACL, r4
    r4 = exts.w r4
    r4 += r2                  ; r4 = equipment_base + active_char * 164
    jsr 0x0601A328            ; setup_active_char(equipment_entry)

    ; More UI setup:
    r4 = 0x0604C654
    jsr 0x06020F1C (strlen)
    jsr 0x0603AD2C            ; some display function
    bra epilogue

  PER-ENTRY WIRE DATA for case 2:
    [0-1]   U16: char_id or index
    [2]     u8: field A (sp[70])
    [3]     u8: field B (sp[71])
    [4-19]  16 bytes: name or data block (memcpy)
    [20-21] U16: experience or stat
    [22]    u8: -> sp[93]
    [23]    u8: -> sp[92]
    [24]    u8: -> sp[94]
    [25]    u8: -> sp[95]
    [26]    u8: -> sp[96]
    [27]    u8: -> sp[97]
    [28]    u8: -> sp[98]
    [29]    u8: -> sp[89]
    [30-31] 2 bytes: padding (skipped)
    [32-35] U32: some value
    [36-51] 8 x U16: stats/equipment (16 bytes)
    Total per entry: 52 bytes
""")

print("""
=== CASE 3: char_type == 3 (INVENTORY/ITEMS) ===
At 0x06013B06:
  r8 = 0                    ; loop counter
  r0 = 0x1924
  mov.b r4, @(r0, r13)      ; Actually: mov.b r4, @(r0, r13)
                             ; char_data[0x1924] = r4 = num_chars (from r4=*r11)
  r10 = 0                   ; storage offset
  bra 0x06013B32            ; loop check

  LOOP BODY (0x06013B10):
    r3 = 0x1530              ; base offset for items in char struct
    r6 = 16                  ; copy 16 bytes
    r5 = r14                 ; source = payload cursor
    r4 = exts.w r10          ; signed extend r10
    sp[0] = r4               ; save
    r3 += r13                ; r3 = char_data_base + 0x1530
    jsr memcpy
      r4 += r3              ; r4 = char_data_base + 0x1530 + storage_offset
    ; memcpy(char_data + 0x1530 + off, payload, 16)

    ; Store remaining data:
    r3 = sp[0] = storage_offset
    r0 = 16
    r2 = char_data_base + 0x1530 + r3  ; base of this entry
    r14 += 24                ; advance source by 24 bytes total
    ; Wait - we only memcpyed 16 but advance by 24?
    ; Actually 7E18 = add #24, r14. But we already read 16 via memcpy.
    ; Hmm, let me re-check. The memcpy src is r14 (before increment).
    ; After memcpy, r14 is unchanged (memcpy doesnt modify r5).
    ; Actually wait - memcpy_16 at 0x0603FE68 reads from r5 but r5 is
    ; a copy. Let me check - the memcpy function uses r0=r5, then r0++
    ; in the loop. So r5 is not modified. r14 = r5 before the call.
    ; So r14 still points to start of this entry after memcpy.
    ; Then r14 += 24 means: skip 24 bytes of this entry.
    ; But we only stored 16 bytes. The other 8 bytes are:

    ; After memcpy and r14 += 24:
    ; r2 = entry_base
    ; r0 = 16
    ; 02C4 = mov.b r12, @(r0, r2) => entry[16] = 0 (r12=0, clear field)

    r8 += 1                  ; loop counter
    r10 += 17                ; storage stride = 17 bytes per item

  LOOP CHECK (0x06013B32):
    r3 = *r11 = num_chars (actually num_items)
    if r8 < r3: continue loop

  After loop: bra epilogue

  PER-ENTRY WIRE DATA for case 3:
    [0-15]  16 bytes: item data (memcpy to char_data + 0x1530 + offset)
    [16-23] 8 bytes: discarded (cursor advances by 24 but only 16 stored)
    entry[16] is zeroed out (set to 0)
    Total per entry: 24 bytes on wire, 17 bytes in storage
""")

print("""
=== DEFAULT CASE (char_type not 1, 2, or 3) ===
At 0x06013B3E:
  r4 = 0x0604C66C            ; error/debug string
  jsr 0x06020F1C (strlen)     ; just displays a message
  bra epilogue

=== EPILOGUE (0x06013B46) ===
  r15 += 120                  ; free local vars
  Restore MACL, PR, r8-r14
  rts
""")

print("=" * 70)
print("COMPLETE PAYLOAD LAYOUT SUMMARY")
print("=" * 70)
print("""
Common Header (8 bytes):
  Offset  Size  Field
  ------  ----  -----
  0       u8    char_type (1=character_list, 2=character_detail, 3=inventory)
  1       u8    page_number (used for multi-page: 1=first page resets globals)
  2       u8    total_pages (entry_count for multi-page comparison)
  3       u8    num_entries (entries in THIS page/packet)
  4-7     u32   chunk_size (byte count of the entry data that follows)

Entry Data (starts at payload offset 8):

  If total_pages > 1 (MULTI-PAGE MODE):
    - The chunk_size bytes starting at offset 8 are raw-copied to an
      accumulation buffer at 0x06061038
    - num_entries (byte 3) is added to the running count at 0x0606103C
    - When page_number >= total_pages, the accumulated buffer is parsed
      using the same case logic below (with r14 reset to 0x20200000)
    - If page_number == 1, the accumulation buffer pointer is reset

  If total_pages <= 1 (SINGLE-PAGE MODE):
    - num_entries is stored directly
    - Entry data at offset 8 is parsed immediately

--- CASE 1 (char_type=1): Character List Entries ---
  num_entries stored at char_data[0x1925]
  Each entry is 24 bytes on wire, stored in 28-byte slots at char_data+0x1684:

  Wire     Size  Storage    Description
  Offset         Offset
  ------   ----  --------   -----------
  0-15     16B   [0-15]     Character name (raw bytes, likely Shift-JIS)
  16-17    u16   [18-19]    Experience points (BE)
  18       u8    [21]       Class/job type
  19       u8    [22]       Race/gender
  20       u8    [26]       Unknown field
  21       u8    [23]       Unknown field
  22       u8    [24-25]    Status byte (zero-extended to u16 at storage[24])
  23       u8    ---        Padding (skipped, r14 += 1)

  After storing: entry[16] is cleared to 0
  After storing: entry[20] = calc_level(experience) via function at 0x0601A490
  Storage stride: 28 bytes per entry

--- CASE 2 (char_type=2): Detailed Character Data ---
  char_data[0x1926] = 0 (cleared)
  Each entry is 52 bytes on wire, processed via 0x060246C4:

  Wire     Size  Storage    Description
  Offset         (on stack)
  ------   ----  --------   -----------
  0-1      u16   sp[68]     Character ID or slot index
  2        u8    sp[70]     Field A (class?)
  3        u8    sp[71]     Field B (subclass?)
  4-19     16B   sp[72-87]  Character name (raw bytes)
  20-21    u16   sp[90]     Experience or level (sp[88]=0 cleared before)
  22       u8    sp[93]     Stat 1
  23       u8    sp[92]     Stat 2
  24       u8    sp[94]     Stat 3
  25       u8    sp[95]     Stat 4
  26       u8    sp[96]     Stat 5
  27       u8    sp[97]     Stat 6
  28       u8    sp[98]     Stat 7
  29       u8    sp[89]     Stat 8
  30-31    2B    ---        Padding (skipped, r13 += 2)
  32-35    u32   (via call) Some 32-bit value (gold? HP?)
  36-51    8xu16 sp[100-115] Equipment/skill slots (8 x u16 BE)

  After building on stack: passed to 0x060246C4 for processing

  After all entries: calls finalize functions, sets up active character
  equipment at game_state + 0x1BE0 + (active_char_index * 164)

--- CASE 3 (char_type=3): Inventory/Items ---
  num_items stored at char_data[0x1924]
  Each entry is 24 bytes on wire, stored in 17-byte slots at char_data+0x1530:

  Wire     Size  Storage    Description
  Offset         Offset
  ------   ----  --------   -----------
  0-15     16B   [0-15]     Item data block
  16-23    8B    ---        Discarded (not stored, cursor skips full 24)

  Storage[16] = 0 (cleared after memcpy)
  Storage stride: 17 bytes per item
""")

print()
print("TOTAL PAYLOAD SIZE:")
print("  Header: 8 bytes")
print("  + N entries where N = num_entries")
print("  Case 1: 8 + N * 24 bytes")
print("  Case 2: 8 + N * 52 bytes")
print("  Case 3: 8 + N * 24 bytes")
