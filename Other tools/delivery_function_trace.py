#!/usr/bin/env python3
"""
Comprehensive trace of the Dragon's Dream "delivery" function at 0x060423C8.

This script:
1. Disassembles the function from the binary
2. Identifies all sub-functions within the range
3. Provides a detailed annotated trace with C-like pseudocode
4. Answers every question about the function's behavior

Binary: extracted/0.BIN (504,120 bytes, SH-2 big-endian, loaded at base 0x06010000)
Function: 0x060423C8 (file offset 0x0323C8)
Ends:     0x060428F8 (rts + delay slot) -- main function body
          0x060429C8 -- last helper function (checksum)
"""

import struct

BINARY_PATH = r"D:\DragonsDreamDecomp\extracted\0.BIN"
MEM_BASE = 0x06010000

def read_binary():
    with open(BINARY_PATH, "rb") as f:
        return f.read()

def u32be(data, off):
    return struct.unpack(">L", data[off:off+4])[0]

def u16be(data, off):
    return struct.unpack(">H", data[off:off+2])[0]

def u8(data, off):
    return data[off]

def mem_to_file(addr):
    return addr - MEM_BASE

def main():
    data = read_binary()

    print("""
================================================================================
  DELIVERY FUNCTION TRACE: 0x060423C8
  Dragon's Dream (Saturn) - SH-2 Big-Endian
================================================================================

This function processes a received 256-byte block (or variable-size payload).
It is called with:
  r4 = game_state pointer (preserved in r14)
  r5 = payload pointer (the received block)
  r6 = extra parameter (e.g., length or context)

The function signature in C would be approximately:
  int delivery(game_state_t *state, uint8_t *payload, uint32_t param3);

================================================================================
  1. PROLOGUE: Register Saves and Stack Frame
================================================================================

0x060423C8: mov.l  r14, @-sp       ; push r14 (callee-saved)
0x060423CA: mov    #48, r0         ; r0 = 48 (0x30) -- used for sp-relative store
0x060423CC: mov.l  r13, @-sp       ; push r13
0x060423CE: mov    r4, r14         ; r14 = game_state (r4)   *** PRESERVED ***
0x060423D0: mov.l  r12, @-sp       ; push r12
0x060423D2: mov    #0, r13         ; r13 = 0 (constant zero used throughout)
0x060423D4: mov.l  r11, @-sp       ; push r11
0x060423D6: mov    r13, r11        ; r11 = 0
0x060423D8: mov.l  r10, @-sp       ; push r10
0x060423DA: mov.l  r9, @-sp        ; push r9
0x060423DC: mov.l  r8, @-sp        ; push r8
0x060423DE: mov    #1, r9          ; r9 = 1 (constant one, used as bitmask)
0x060423E0: sts.l  PR, @-sp        ; push return address
0x060423E2: add    #-56, sp        ; allocate 56 bytes of local stack space

REGISTERS SAVED: r8, r9, r10, r11, r12, r13, r14, PR (8 pushes = 32 bytes)
LOCAL STACK:     56 bytes
TOTAL FRAME:     88 bytes

Key register assignments after prologue:
  r14 = game_state pointer (r4 input, preserved entire function)
  r13 = 0 (constant zero)
  r9  = 1 (constant one, used as bit mask)
  r11 = 0 (initialized to zero)
  r8  = uninitialized (set later based on bit test)

Stack layout (sp+0 through sp+55):
  sp+0:   scratch (pointer storage)
  sp+4:   scratch (pointer/counter)
  sp+8:   "has_bit0" flag / byte count
  sp+12:  original r5 (payload pointer)  -- saved at 0x060423E4
  sp+16:  copy of payload pointer
  sp+20:  original r6 (param3)           -- saved at 0x060423E6
  sp+24:  hp_value (uint16)
  sp+28:  mp_value (uint16)
  sp+30:  zero-init (via r0=0x30)
  sp+32:  zero-init (via r0=0x20)
  sp+36:  is_0xA6 flag
  sp+40:  zero-init (via r0=0x28)
  sp+44:  checksum value
  sp+48:  extracted_word
  sp+52:  r13=0 (zero-init)

Initialization of stack locals (all zeroed via r13=0):
0x060423E4: mov.l  r5, @(12,sp)    ; sp[12] = payload pointer
0x060423E6: mov.l  r6, @(20,sp)    ; sp[20] = param3
0x060423E8: mov.w  r13, @(r0+sp)   ; sp[48] = 0  (r0=0x30=48)
0x060423EA: mov    #32, r0
0x060423EC: mov.w  r13, @(r0+sp)   ; sp[32] = 0
0x060423EE: mov    #40, r0
0x060423F0: mov.l  r13, @(52,sp)   ; sp[52] = 0
0x060423F2: mov.w  r13, @(r0+sp)   ; sp[40] = 0
0x060423F4: mov    r13, r0         ; r0 = 0
0x060423F6: mov.w  r0, @(24,sp)    ; sp[24] = 0 (hp)
0x060423F8: mov    r13, r0
0x060423FA: mov.w  r0, @(28,sp)    ; sp[28] = 0 (mp)

================================================================================
  2. READING byte[1] AND THE BIT 0 TEST
================================================================================

0x060423FC: mov.l  @(12,sp), r12   ; r12 = payload pointer (from sp[12])
0x060423FE: mov    r12, r3
0x06042400: mov.l  r3, @(16,sp)    ; sp[16] = payload pointer (another copy)
0x06042402: mov.b  @(1,r12), r0    ; R0 = payload[1]  *** THE KEY BYTE ***
0x06042404: extu.b r0, r0          ; zero-extend to 32 bits
0x06042406: tst    r9, r0          ; T = (R0 & 1) == 0  (test bit 0 with r9=1)

  *** THIS IS THE BIT 0 TEST: payload[1] & 0x01 ***

0x06042408: bt/s   0x06042412      ; if bit0==0: goto label_no_bit0 (delayed)
0x0604240A: mov    r13, r8         ;   (delay slot) r8 = 0

  -- bit0 is SET path --
0x0604240C: mov.l  r9, @(8,sp)     ; sp[8] = 1 (has_bit0 = true)
0x0604240E: bra    0x06042414      ; goto common_path
0x06042410: nop

label_no_bit0:                      ; bit0 is CLEAR
0x06042412: mov.l  r13, @(8,sp)    ; sp[8] = 0 (has_bit0 = false)

So after this block:
  - sp[8] = 1 if payload[1] & 0x01, else 0
  - r8 = 0 in both cases (delay slot always executes for bt/s)

================================================================================
  3. EARLY EXIT CHECK (when bit0 is set + state[0x60]==2)
================================================================================

label_common:
0x06042414: mov.l  @(8,sp), r1     ; r1 = has_bit0 flag
0x06042416: tst    r1, r1          ; T = (has_bit0 == 0)
0x06042418: bt     0x06042436      ; if has_bit0==0: skip to main_processing

  -- has_bit0 is true (bit 0 was set) --
0x0604241A: mov    #96, r0         ; r0 = 0x60 (offset 96)
0x0604241C: mov.l  @(r0,r14), r0   ; r0 = game_state[0x60]
0x0604241E: cmp/eq #2, r0          ; T = (game_state[0x60] == 2)
0x06042420: bt     0x06042436      ; if state[0x60]==2: skip to main_processing

  -- has_bit0 AND state[0x60] != 2 --
0x06042422: mov.l  @(60,r14), r1   ; r1 = game_state[0x3C] (the CALLBACK pointer!)
0x06042424: tst    r1, r1          ; T = (callback == NULL)
0x06042426: bt     0x06042432      ; if callback==NULL: skip call

  *** CALLBACK CALL (early exit path) ***
0x06042428: mov.l  @(60,r14), r3   ; r3 = game_state[0x3C] (callback function pointer)
0x0604242A: mov.l  @(20,sp), r6    ; r6 = param3 (original r6)
0x0604242C: mov.l  @(12,sp), r5    ; r5 = payload pointer (original r5)
0x0604242E: jsr    @r3             ; CALL callback(r4=state, r5=payload, r6=param3)
0x06042430: mov    r14, r4         ;   (delay slot) r4 = game_state

  Parameters passed to callback:
    r4 = game_state (r14)
    r5 = payload pointer (original from caller)
    r6 = param3 (original from caller)

0x06042432: bra    0x060428E6      ; goto epilogue (return 1)
0x06042434: mov    #1, r0          ;   (delay slot) return value = 1

  EARLY EXIT SUMMARY:
  If payload[1] bit0 is SET and game_state[0x60] != 2:
    - Call game_state[0x3C](state, payload, param3) if non-NULL
    - Return 1

================================================================================
  4. MAIN PROCESSING PATH (bit0 clear, or state[0x60]==2)
================================================================================

label_main_processing:  ; 0x06042436
0x06042436: mov.b  @r12, r3        ; r3 = payload[0]
0x06042438: mov.w  @pool, r2       ; r2 = 0x00A6 (166 decimal)
0x0604243A: extu.b r3, r3          ; zero-extend
0x0604243C: cmp/eq r2, r3          ; T = (payload[0] == 0xA6)
0x0604243E: bf     0x06042448      ; if payload[0] != 0xA6: goto not_A6

  -- payload[0] == 0xA6 --
0x06042440: mov.l  r9, @(36,sp)    ; sp[36] = 1 (is_0xA6 = true)
0x06042442: mov.b  @(6,r12), r0    ; r0 = payload[6]
0x06042444: bra    0x0604244A
0x06042446: mov    r0, r8          ; r8 = payload[6]  (extraction key)

label_not_A6:  ; 0x06042448
0x06042448: mov.l  r13, @(36,sp)   ; sp[36] = 0 (is_0xA6 = false)

  So:
    sp[36] ("is_0xA6") = 1 if payload[0]==0xA6, else 0
    r8 = payload[6] if is_0xA6, else 0 (from prologue init)

================================================================================
  4a. FIELD EXTRACTION (when is_0xA6 is true)
================================================================================

0x0604244A: mov.l  @(36,sp), r1    ; r1 = is_0xA6
0x0604244C: tst    r1, r1
0x0604244E: bt     0x060424DC      ; if !is_0xA6: goto alternate_extraction

  -- is_0xA6 path: payload starts with 0xA6 --
0x06042450: mov.w  @pool, r0       ; r0 = 0xA6 (offset 166 in game_state)
0x06042452: mov.w  @(r0,r14), r3   ; r3 = game_state[0xA6] (uint16)
0x06042454: extu.w r3, r3
0x06042456: tst    r9, r3          ; T = (game_state[0xA6] & 1) == 0
0x06042458: bf     0x0604247E      ; if bit0 set: skip extraction

  -- game_state[0xA6] bit0 is clear: extract fields from payload --
0x0604245A: mov    r12, r2         ; r2 = payload pointer
0x0604245C: add    #2, r2          ; r2 = &payload[2]
0x0604245E: mov.l  r2, @sp         ; sp[0] = &payload[2] (read cursor)

  Call read_u16(&payload[2]):
0x06042460: bsr    0x060429A2      ; call read_u16_from_cursor (r4=cursor)
0x06042462: mov    r2, r4          ;   (delay) r4 = &payload[2]
  ; Returns uint16 in r0 -- this is "extracted_word"
0x06042464: mov    sp, r1
0x06042466: add    #48, r1         ; r1 = &sp[48]
0x06042468: mov.w  r0, @r1         ; sp[48] = extracted_word

  Call some_copy_function(state, payload):
0x0604246A: mov    r12, r5         ; r5 = payload
0x0604246C: bsr    0x06041CC0      ; call func_06041CC0(state, payload)
0x0604246E: mov    r14, r4         ;   r4 = game_state

  Call checksum(payload_ptr, length):
0x06042470: mov.l  @(20,sp), r5    ; r5 = param3 (length)
0x06042472: mov.l  @(12,sp), r4    ; r4 = payload
0x06042474: bsr    0x060429B6      ; call CHECKSUM function!
0x06042476: nop
  ; Returns checksum in r0
0x06042478: mov    sp, r1
0x0604247A: add    #44, r1
0x0604247C: mov.w  r0, @r1         ; sp[44] = checksum_result

================================================================================
  4b. FIELD EXTRACTION (when has_bit0 is set)
================================================================================

label_0x0604247E:
0x0604247E: mov.l  @(8,sp), r2     ; r2 = has_bit0
0x06042480: tst    r2, r2
0x06042482: bt     0x060424AC      ; if !has_bit0: goto no_bit0_extraction

  -- has_bit0 extraction path --
0x06042484: mov    r12, r3
0x06042486: add    #8, r3          ; r3 = &payload[8]
0x06042488: mov.l  r3, @sp         ; sp[0] = &payload[8]

  Call read_u32(sp, r8):  -- reads 4 bytes with XOR decoding
0x0604248A: mov    sp, r4
0x0604248C: bsr    0x0604291E      ; call read_u32_decoded
0x0604248E: mov    r8, r5          ;   r5 = r8 (XOR key)
0x06042490: mov    r0, r10         ; r10 = first u32 result

  Call read_u32(sp, r8) again:
0x06042492: mov    sp, r4
0x06042494: bsr    0x0604291E
0x06042496: mov    r8, r5
0x06042498: mov.l  @sp, r4         ; r4 = current cursor
0x0604249A: mov    r0, r11         ; r11 = second u32 result

  Call read_u16_from_cursor:
0x0604249C: bsr    0x060429A2      ; call read_u16_from_cursor
0x0604249E: nop
0x060424A0: mov    sp, r1
0x060424A2: add    #32, r1
0x060424A4: mov.w  r0, @r1         ; sp[32] = third field (uint16)

0x060424A6: mov.l  @sp, r3         ; r3 = cursor after reads
0x060424A8: bra    0x06042518      ; goto store_extracted_data
0x060424AA: add    #4, r3          ; r3 += 4 (skip another 4 bytes)

================================================================================
  4c. ALTERNATE EXTRACTION (not is_0xA6, no bit0)
================================================================================

label_0x060424AC:                   ; !has_bit0, !is_0xA6
0x060424AC: mov.l  @(16,sp), r3    ; r3 = payload pointer copy
0x060424AE: mov    sp, r4
0x060424B0: add    #8, r3          ; r3 = &payload[8]
0x060424B2: mov.l  r3, @sp         ; sp[0] = &payload[8]

  Call read_u16_decoded(sp, r8):
0x060424B4: bsr    0x0604296C      ; call read_u16_decoded
0x060424B6: mov    r8, r5          ;   r5 = r8 (XOR key)
  ; sp[40] = result (stored inside callee target area)
0x060424B8: mov    sp, r1
0x060424BA: add    #40, r1
0x060424BC: mov.w  r0, @r1         ; sp[40] = field_u16_a

  Call read_u16_decoded again:
0x060424BE: mov    sp, r4
0x060424C0: bsr    0x0604296C
0x060424C2: mov    r8, r5
0x060424C4: mov.w  r0, @(24,sp)    ; sp[24] = hp_value

  Call read_u32_decoded:
0x060424C6: mov    sp, r4
0x060424C8: bsr    0x0604291E
0x060424CA: mov    r8, r5
0x060424CC: mov    r0, r10         ; r10 = u32 value (experience/gold?)

  Call read_u16_decoded:
0x060424CE: mov    sp, r4
0x060424D0: bsr    0x0604296C
0x060424D2: mov    r8, r5
0x060424D4: mov.w  r0, @(28,sp)    ; sp[28] = mp_value

0x060424D6: bra    0x06042534      ; goto post_extraction
0x060424D8: nop

--- Literal pool data at 0x060424DA ---
0x060424DA: 00 A6   (value 166 = 0xA6 used as offset into game_state)

================================================================================
  4d. ALTERNATE PATH (not is_0xA6 but also different from 4c)
================================================================================

label_0x060424DC:                   ; !is_0xA6, different extraction
0x060424DC: mov.w  @pool, r0       ; r0 = 0xA6
0x060424DE: mov.w  @(r0,r14), r2   ; r2 = game_state[0xA6]
0x060424E0: extu.w r2, r2
0x060424E2: tst    r9, r2          ; T = (game_state[0xA6] & 1) == 0
0x060424E4: bf     0x06042502      ; if bit0 set: skip this block

  -- game_state[0xA6] bit0 clear --
0x060424E6: mov    sp, r1
0x060424E8: mov.w  @(2,r12), r0    ; r0 = *(uint16*)(payload+2)
0x060424EA: mov    r12, r5
0x060424EC: add    #48, r1
0x060424EE: mov.w  r0, @r1         ; sp[48] = payload[2..3] as uint16
0x060424F0: bsr    0x06041CC0      ; call func_06041CC0(state, payload)
0x060424F2: mov    r14, r4

  Call CHECKSUM:
0x060424F4: mov.l  @(20,sp), r5    ; r5 = param3
0x060424F6: mov.l  @(12,sp), r4    ; r4 = payload
0x060424F8: bsr    0x060429B6      ; call CHECKSUM
0x060424FA: nop
0x060424FC: mov    sp, r1
0x060424FE: add    #44, r1
0x06042500: mov.w  r0, @r1         ; sp[44] = checksum_result

label_0x06042502:
  -- Extraction from payload fields (when has_bit0) --
0x06042502: mov.l  @(8,sp), r2     ; r2 = has_bit0
0x06042504: tst    r2, r2
0x06042506: bt     0x06042520      ; if !has_bit0: goto alt_field_read

  -- has_bit0 path: read fields directly from payload bytes 8+ --
0x06042508: mov.l  @(8,r12), r10   ; r10 = *(uint32*)(payload+8)
0x0604250A: mov    sp, r1
0x0604250C: mov.l  @(12,r12), r11  ; r11 = *(uint32*)(payload+12)
0x0604250E: mov    r12, r3
0x06042510: mov.w  @(16,r12), r0   ; r0 = *(uint16*)(payload+16)
0x06042512: add    #32, r1
0x06042514: mov.w  r0, @r1         ; sp[32] = payload[16..17] as uint16
0x06042516: add    #20, r3         ; r3 = &payload[20]

label_store_extracted_data:  ; 0x06042518
0x06042518: mov.l  r3, @(52,sp)    ; sp[52] = data_pointer
0x0604251A: mov.l  r3, @(4,sp)     ; sp[4] = data_pointer
0x0604251C: bra    0x06042534
0x0604251E: nop

label_alt_field_read:  ; 0x06042520
  -- !has_bit0: read from payload header (offsets 8-16) --
0x06042520: mov.l  @(16,sp), r4    ; r4 = payload pointer
0x06042522: mov    sp, r1
0x06042524: mov.w  @(8,r4), r0     ; r0 = *(uint16*)(payload+8)
0x06042526: add    #40, r1
0x06042528: mov.w  r0, @r1         ; sp[40] = payload[8..9]
0x0604252A: mov.w  @(10,r4), r0    ; r0 = *(uint16*)(payload+10)
0x0604252C: mov.w  r0, @(24,sp)    ; sp[24] = payload[10..11] (hp)
0x0604252E: mov.l  @(12,r4), r10   ; r10 = *(uint32*)(payload+12)
0x06042530: mov.w  @(16,r4), r0    ; r0 = *(uint16*)(payload+16)
0x06042532: mov.w  r0, @(28,sp)    ; sp[28] = payload[16..17] (mp)

================================================================================
  5. VALIDATION: Checksum Compare + State Check
================================================================================

label_post_extraction:  ; 0x06042534
0x06042534: mov.w  @pool, r0       ; r0 = 0xA6
0x06042536: mov.w  @(r0,r14), r3   ; r3 = game_state[0xA6]
0x06042538: extu.w r3, r3
0x0604253A: tst    r9, r3          ; T = (game_state[0xA6] & 1) == 0
0x0604253C: bf     0x06042564      ; if bit0 set: skip checksum validation

  -- game_state[0xA6] bit0 is clear: VALIDATE CHECKSUM --
0x0604253E: mov    #48, r0         ; r0 = 0x30
0x06042540: mov.w  @(r0+sp), r2    ; r2 = sp[48] (extracted_word)
0x06042542: mov    #44, r0         ; r0 = 0x2C
0x06042544: mov.w  @(r0+sp), r3    ; r3 = sp[44] (checksum_result)
0x06042546: cmp/eq r3, r2          ; T = (extracted_word == checksum)
0x06042548: bt     0x06042564      ; if match: checksum OK, continue

  *** CHECKSUM MISMATCH! ***
0x0604254A: mov.l  @(60,r14), r0   ; r0 = game_state[0x3C] (callback)
0x0604254C: tst    r0, r0
0x0604254E: bt     0x0604255A      ; if callback==NULL: skip

  -- Call callback on checksum failure --
0x06042550: mov.l  @(60,r14), r3   ; r3 = callback
0x06042552: mov.l  @(20,sp), r6    ; r6 = param3
0x06042554: mov.l  @(12,sp), r5    ; r5 = payload
0x06042556: jsr    @r3             ; callback(state, payload, param3)
0x06042558: mov    r14, r4

0x0604255A: mov    #2, r5          ; r5 = 2
0x0604255C: bsr    0x06041E46      ; call func_06041E46(state, 2)
0x0604255E: mov    r14, r4         ;   -- likely an error/disconnect function

0x06042560: bra    0x060428E4      ; goto epilogue (return 0)
0x06042562: nop

  CHECKSUM VALIDATION SUMMARY:
  - sp[48] = extracted word from payload (expected checksum)
  - sp[44] = computed checksum (from calling 0x060429B6)
  - If they don't match AND game_state[0xA6] bit0 is clear:
    * Call callback(state, payload, param3) if non-NULL
    * Call error_func(state, 2)
    * Return 0

================================================================================
  6. MAIN PROCESSING (after validation passes)
================================================================================

label_validated:  ; 0x06042564
0x06042564: bsr    0x06042E94      ; call func_06042E94(state)
0x06042566: mov    r14, r4         ;   -- some state-update function

  --- Check payload[1] for bits 1 and 6 ---
0x06042568: mov.b  @(1,r12), r0    ; r0 = payload[1]
0x0604256A: mov    #2, r3
0x0604256C: extu.b r0, r4
0x0604256E: tst    r4, r3          ; T = (payload[1] & 0x02) == 0
0x06042570: bf     0x0604257C      ; if bit1 SET: goto has_data_flags

0x06042572: mov    #64, r2         ; r2 = 0x40
0x06042574: tst    r4, r2          ; T = (payload[1] & 0x40) == 0
0x06042576: bf     0x0604257C      ; if bit6 SET: goto has_data_flags

  -- Neither bit1 nor bit6 set: skip to end of data processing --
0x06042578: bra    0x060426AC      ; goto after_linked_list_walk
0x0604257A: nop

  BITS 1 AND 6 CHECK:
  If payload[1] has neither bit 1 (0x02) nor bit 6 (0x40) set,
  skip all the heavy data processing and jump to post-processing.

label_has_data_flags:  ; 0x0604257C
  --- Set up r11 based on has_bit0 flag ---
0x0604257C: mov.l  @(8,sp), r1     ; r1 = has_bit0
0x0604257E: tst    r1, r1
0x06042580: bf/s   0x06042586      ; if has_bit0: branch (delayed)
0x06042582: mov    r13, r4         ;   r4 = 0
0x06042584: mov    r10, r11        ; (only if !has_bit0) r11 = r10

label_0x06042586:
  --- Check r11 against game_state[0x70] ---
0x06042586: mov    #112, r0        ; r0 = 0x70
0x06042588: mov.l  @(r0,r14), r3   ; r3 = game_state[0x70]
0x0604258A: cmp/hi r3, r11         ; T = (r11 > game_state[0x70]) unsigned
0x0604258C: bf     0x06042590      ; if r11 <= state[0x70]: skip
0x0604258E: mov    r9, r4          ; r4 = 1 (overflow flag)

0x06042590: tst    r4, r4
0x06042592: bf     0x060425AA      ; if r4 != 0: goto needs_update

  --- r4 == 0: no overflow, check bit6 ---
0x06042594: mov.b  @(1,r12), r0    ; payload[1]
0x06042596: extu.b r0, r0
0x06042598: tst    #0x40, r0       ; T = (payload[1] & 0x40) == 0
0x0604259A: bf     0x060425A0      ; if bit6 SET: goto handle_bit6

0x0604259C: bra    0x060426AC      ; goto after_linked_list (skip processing)
0x0604259E: nop

label_handle_bit6:  ; 0x060425A0
0x060425A0: bsr    0x06042CA0      ; call func_06042CA0(state) -- "bit6 handler"
0x060425A2: mov    r14, r4
0x060425A4: bra    0x060426AC
0x060425A6: nop

  --- Literal pool ---
  0x060425A8: 00 A6 (constant 166)

================================================================================
  6a. STATE UPDATE PATH (r4 != 0, overflow or bit0-related)
================================================================================

label_needs_update:  ; 0x060425AA
0x060425AA: mov    #112, r0        ; 0x70
0x060425AC: mov.l  r11, @(r0,r14)  ; game_state[0x70] = r11 (new high-water mark)

0x060425AE: mov    #0, r7
0x060425B0: mov    r14, r6
0x060425B2: add    #88, r6         ; r6 = &game_state[0x58]
0x060425B4: mov    r11, r5         ; r5 = r11
0x060425B6: mov    r14, r4
0x060425B8: bsr    0x06042B74      ; call func_06042B74(state+0x5C, r11, &state[0x58], 0)
0x060425BA: add    #92, r4         ;   r4 = &game_state[0x5C]

0x060425BC: mov    r0, r4          ; r4 = return value (some node pointer?)
0x060425BE: tst    r4, r4
0x060425C0: bt     0x06042618      ; if NULL: goto skip_node_processing

  --- Non-NULL: node exists, do further checks ---
0x060425C2: mov    #76, r0         ; 0x4C
0x060425C4: mov.l  @(r0,r14), r2   ; r2 = game_state[0x4C]
0x060425C6: tst    r2, r2
0x060425C8: bt     0x060425DA      ; if state[0x4C]==0: skip

0x060425CA: mov    #88, r0         ; 0x58
0x060425CC: mov.b  @(r0,r14), r3   ; r3 = game_state[0x58] (byte)
0x060425CE: mov    #8, r2
0x060425D0: extu.b r3, r3
0x060425D2: cmp/ge r2, r3          ; T = (game_state[0x58] >= 8)
0x060425D4: bt     0x060425DA      ; if >= 8: skip
0x060425D6: mov    #76, r0
0x060425D8: mov.l  r13, @(r0,r14)  ; game_state[0x4C] = 0 (clear it)

label_0x060425DA:
0x060425DA: mov    #88, r0         ; 0x58
0x060425DC: mov.b  @(r0,r14), r3
0x060425DE: mov    #16, r2
0x060425E0: extu.b r3, r3
0x060425E2: cmp/gt r2, r3          ; T = (game_state[0x58] > 16)
0x060425E4: bf     0x060425EA      ; if <= 16: skip
0x060425E6: mov    #76, r0
0x060425E8: mov.l  r9, @(r0,r14)   ; game_state[0x4C] = 1 (set it)

label_0x060425EA:
  -- Reset state[0x80] and state[0xA5] --
0x060425EA: mov.w  @pool, r0       ; r0 = 0x0080
0x060425EC: mov.l  r13, @(r0,r14)  ; game_state[0x80] = 0
0x060425EE: add    #37, r0         ; r0 = 0xA5
0x060425F0: mov.b  r13, @(r0,r14)  ; game_state[0xA5] = 0
0x060425F2: add    #-33, r0        ; r0 = 0x84
0x060425F4: mov.l  @(r0,r14), r1   ; r1 = game_state[0x84]
0x060425F6: tst    r1, r1
0x060425F8: bt     0x06042602      ; if state[0x84]==0: skip

  -- game_state[0x84] != 0: call func_06042FDA --
0x060425FA: mov.w  @pool, r0       ; r0 = 0x84
0x060425FC: mov.l  @pool32, r3     ; r3 = 0x06042FDA
0x060425FE: jsr    @r3             ; call func_06042FDA(r4=state[0x84])
0x06042600: mov.l  @(r0,r14), r4   ;   (delay) r4 = game_state[0x84]

label_0x06042602:
  -- Check game_state[0x5C] --
0x06042602: mov    #92, r0         ; 0x5C
0x06042604: mov.l  @(r0,r14), r4   ; r4 = game_state[0x5C]
0x06042606: tst    r4, r4
0x06042608: bt     0x06042618      ; if NULL: skip
0x0604260A: mov.l  @(8,r4), r0     ; r0 = node->field_8
0x0604260C: tst    #0x08, r0       ; T = (node->field_8 & 0x08) == 0
0x0604260E: bt     0x06042618      ; if bit3 clear: skip
0x06042610: mov.w  @pool, r0       ; r0 = 0xB8
0x06042612: mov.l  @(r0,r14), r5   ; r5 = game_state[0xB8]
0x06042614: bsr    0x06042DC6      ; call func_06042DC6(state, state[0xB8])
0x06042616: mov    r14, r4

================================================================================
  6b. CHECK BIT6 AFTER STATE UPDATE
================================================================================

label_0x06042618:
0x06042618: mov.b  @(1,r12), r0    ; payload[1]
0x0604261A: extu.b r0, r0
0x0604261C: tst    #0x40, r0       ; T = (payload[1] & 0x40) == 0
0x0604261E: bt     0x06042628      ; if bit6 CLEAR: skip
0x06042620: bsr    0x06042CA0      ; call bit6_handler(state)
0x06042622: mov    r14, r4
0x06042624: bra    0x060426AC      ; goto after_linked_list
0x06042626: nop

================================================================================
  6c. NO-BIT0 FURTHER PROCESSING
================================================================================

label_0x06042628:
0x06042628: mov.l  @(8,sp), r0     ; has_bit0
0x0604262A: tst    r0, r0
0x0604262C: bf     0x0604263E      ; if has_bit0: skip this block

  -- !has_bit0 path: check state[0xC0] --
0x0604262E: mov.w  @pool, r0       ; r0 = 0xC0
0x06042630: mov.l  @(r0,r14), r1   ; r1 = game_state[0xC0]
0x06042632: tst    r1, r1
0x06042634: bt     0x0604263E      ; if state[0xC0]==0: skip
0x06042636: mov.w  @pool, r0       ; r0 = 0xC0
0x06042638: mov.l  r13, @(r0,r14)  ; game_state[0xC0] = 0 (clear it)
0x0604263A: bsr    0x06042CA0      ; call bit6_handler(state) again
0x0604263C: mov    r14, r4

label_0x0604263E:
  -- Accumulate travel distance --
0x0604263E: mov.w  @pool, r0       ; r0 = 0xA8
0x06042640: mov.w  @(r0,r14), r2   ; r2 = game_state[0xA8] (uint16)
0x06042642: mov    #116, r0        ; 0x74
0x06042644: extu.w r2, r2
0x06042646: add    r2, r11         ; r11 += game_state[0xA8]
0x06042648: mov.l  r11, @(r0,r14)  ; game_state[0x74] = r11 (accumulated value)
0x0604264A: mov    #92, r0         ; 0x5C
0x0604264C: bra    0x060426A8      ; goto linked_list_loop_check
0x0604264E: mov.l  @(r0,r14), r11  ; (delay) r11 = game_state[0x5C] (linked list head)

================================================================================
  6d. LINKED LIST WALK
================================================================================

  This section walks a linked list starting at game_state[0x5C].
  Each node appears to be a structure with:
    node[0]  = uint32 (some value, compared against thresholds)
    node[4]  = uint32 (another value)
    node[8]  = uint32 (flags, bit 3 checked)
    node[12] = uint32 (next pointer in linked list)

label_loop_body:  ; 0x06042660
0x06042660: mov.l  @r11, r4        ; r4 = node->field_0
0x06042662: mov    #120, r0        ; 0x78
0x06042664: mov.l  @(r0,r14), r2   ; r2 = game_state[0x78]
0x06042666: cmp/hi r2, r4          ; T = (node->field_0 > state[0x78]) unsigned
0x06042668: bf     0x0604269C      ; if node->f0 <= state[0x78]: skip

0x0604266A: mov    #116, r0        ; 0x74
0x0604266C: mov.l  @(r0,r14), r1   ; r1 = game_state[0x74]
0x0604266E: cmp/hs r1, r4          ; T = (node->f0 >= state[0x74]) unsigned
0x06042670: bt     0x0604269C      ; if node->f0 >= state[0x74]: skip

  -- node->f0 is between state[0x78] and state[0x74] --
0x06042672: mov    #120, r0
0x06042674: mov.l  @r11, r2
0x06042676: mov.l  r2, @(r0,r14)   ; game_state[0x78] = node->field_0
0x06042678: mov.l  @(8,r11), r0    ; r0 = node->field_8
0x0604267A: or     #0x08, r0       ; set bit 3
0x0604267C: mov.l  r0, @(8,r11)    ; node->field_8 |= 0x08

  -- Check callback at state[0x38] (offset 56) --
0x0604267E: mov.l  @(56,r14), r1   ; r1 = game_state[0x38]
0x06042680: tst    r1, r1
0x06042682: bt     0x06042690      ; if NULL: skip callback

0x06042684: mov.l  @(56,r14), r3   ; r3 = callback
0x06042686: mov    r11, r5         ; r5 = node pointer
0x06042688: mov.l  @(4,r11), r6    ; r6 = node->field_4
0x0604268A: add    #16, r5         ; r5 = &node->field_16
0x0604268C: jsr    @r3             ; callback(state, &node[16], node->f4)
0x0604268E: mov    r14, r4

label_0x06042690:
  -- Additional processing after node callback --
0x06042690: mov.w  @pool, r0       ; 0xB8
0x06042692: mov.l  @(r0,r14), r5   ; r5 = game_state[0xB8]
0x06042694: bsr    0x06042DC6      ; call func_06042DC6(state, state[0xB8])
0x06042696: mov    r14, r4
0x06042698: bsr    0x06042E30      ; call func_06042E30(state)
0x0604269A: mov    r14, r4

label_0x0604269C:
  -- Continue list walk: check if node->f0 >= state[0x74] --
0x0604269C: mov.l  @r11, r2
0x0604269E: mov    #116, r0
0x060426A0: mov.l  @(r0,r14), r3   ; r3 = game_state[0x74]
0x060426A2: cmp/hs r3, r2          ; T = (node->f0 >= state[0x74])
0x060426A4: bt     0x060426AC      ; if yes: stop walking

0x060426A6: mov.l  @(12,r11), r11  ; r11 = node->next (follow linked list)

label_loop_check:  ; 0x060426A8
0x060426A8: tst    r11, r11        ; T = (r11 == NULL)
0x060426AA: bf     0x06042660      ; if not NULL: continue loop

================================================================================
  7. AFTER LINKED LIST: has_bit0 PATH (allocate & populate node)
================================================================================

label_after_list:  ; 0x060426AC
0x060426AC: mov.l  @(8,sp), r1     ; r1 = has_bit0
0x060426AE: tst    r1, r1
0x060426B0: bf     0x060426B6      ; if has_bit0: continue
0x060426B2: bra    0x060427AA      ; else: goto no_bit0_final_path
0x060426B4: nop

label_0x060426B6:
  -- Allocate a new node: call func_060457B4(game_state[0x48]) --
0x060426B6: mov    #72, r0         ; 0x48
0x060426B8: mov.l  @pool32, r3     ; r3 = 0x060457B4 (allocator function)
0x060426BA: jsr    @r3             ; r0 = allocate(game_state[0x48])
0x060426BC: mov.l  @(r0,r14), r4   ;   (delay) r4 = game_state[0x48]

0x060426BE: mov    r0, r11         ; r11 = new_node (allocated)
0x060426C0: tst    r11, r11
0x060426C2: bf     0x060426C8      ; if allocation succeeded: continue
0x060426C4: bra    0x060428E6      ; else: return 2 (allocation failure)
0x060426C6: mov    #2, r0

label_0x060426C8:
0x060426C8: mov.l  @(36,sp), r0    ; r0 = is_0xA6
0x060426CA: mov    r11, r9
0x060426CC: tst    r0, r0
0x060426CE: bt/s   0x06042714      ; if !is_0xA6: goto skip_copy_loop (delayed)
0x060426D0: add    #16, r9         ; r9 = &new_node[16] (data area)

  -- is_0xA6: copy data from source to node --
0x060426D2: mov    #32, r0         ; 0x20
0x060426D4: mov.l  r9, @sp         ; sp[0] = dest pointer (r9)
0x060426D6: mov.w  @(r0+sp), r3    ; r3 = sp[32] (length/count)
0x060426D8: mov.l  @(52,sp), r2    ; r2 = sp[52] (source data pointer)
0x060426DA: extu.w r3, r3
0x060426DC: add    r2, r3          ; r3 = source + length (end pointer)
0x060426DE: mov.l  r3, @(8,sp)     ; sp[8] = end pointer
0x060426E0: bra    0x060426FA      ; goto copy_loop_check

label_copy_loop_body:  ; 0x060426E4
0x060426E4: mov.l  @sp, r2         ; r2 = current dest
0x060426E6: add    #1, r2          ; r2++ (advance dest)
0x060426E8: mov.l  r2, @sp         ; store back
0x060426EA: add    #-1, r2         ; restore original r2
0x060426EC: mov.l  r2, @-sp        ; push dest on stack
0x060426EE: mov    sp, r4
0x060426F0: add    #8, r4          ; r4 = pointer to source cursor (sp+8 after push)
0x060426F2: bsr    0x060428FA      ; call read_byte_decoded(cursor, xor_key)
0x060426F4: mov    r8, r5          ;   r5 = r8 (XOR key)
0x060426F6: mov.l  @sp+, r1        ; pop dest address
0x060426F8: mov.b  r0, @r1         ; *dest = decoded_byte

label_copy_check:  ; 0x060426FA
0x060426FA: mov.l  @(8,sp), r3     ; r3 = end pointer
0x060426FC: mov.l  @(4,sp), r2     ; r2 = source data pointer
0x060426FE: cmp/hs r3, r2          ; T = (source >= end)
0x06042700: bf     0x060426E4      ; if source < end: continue copying

  -- Copy complete: compute actual data length --
0x06042702: mov    #32, r0
0x06042704: mov.l  @sp, r3         ; r3 = final dest pointer
0x06042706: sub    r9, r3          ; r3 = dest - node_data_start = bytes written
0x06042708: mov.w  r3, @(r0+sp)    ; sp[32] = actual_copy_length
0x0604270A: bra    0x0604273C
0x0604270C: nop

  --- Literal pool ---
  0x0604270E: 00 B8 (constant 184)
  0x06042710: 0x060457B4 (allocator function address)

================================================================================
  7a. SKIP COPY (not is_0xA6): pad with zeros or copy raw
================================================================================

label_skip_copy:  ; 0x06042714
0x06042714: mov.l  r9, @sp         ; sp[0] = &node[16]
0x06042716: mov    #32, r0
0x06042718: mov.w  @(r0+sp), r5    ; r5 = sp[32] (data length)
0x0604271A: extu.w r5, r5
0x0604271C: cmp/ge r5, r13         ; T = (0 >= length) (i.e., length <= 0)
0x0604271E: bt/s   0x0604273C      ; if length==0: skip (delayed)
0x06042720: mov    r13, r4         ; r4 = 0

  -- Byte copy loop (raw copy from source) --
label_raw_copy:  ; 0x06042722
0x06042722: add    #1, r4          ; r4++ (counter)
0x06042724: mov.l  @sp, r2         ; r2 = dest pointer
0x06042726: cmp/ge r5, r4          ; T = (counter >= length)
0x06042728: add    #1, r2          ; r2++ (advance dest)
0x0604272A: mov.l  r2, @sp         ; store back
0x0604272C: mov.l  @(4,sp), r3     ; r3 = source pointer
0x0604272E: add    #-1, r2         ; restore original dest
0x06042730: add    #1, r3          ; r3++ (advance source)
0x06042732: mov.l  r3, @(4,sp)     ; store back
0x06042734: add    #-1, r3         ; restore original source
0x06042736: mov.b  @r3, r1         ; r1 = *source
0x06042738: bf/s   0x06042722      ; if counter < length: continue
0x0604273A: mov.b  r1, @r2         ; (delay) *dest = *source

================================================================================
  7b. POPULATE NODE FIELDS AND INSERT
================================================================================

label_populate_node:  ; 0x0604273C
0x0604273C: mov.l  r10, @r11       ; node->field_0 = r10 (the u32 value)
0x0604273E: mov    #32, r0
0x06042740: mov.w  @(r0+sp), r2    ; r2 = data_length
0x06042742: mov    r11, r5         ; r5 = node
0x06042744: extu.w r2, r2
0x06042746: mov.l  r2, @(4,r11)    ; node->field_4 = data_length
0x06042748: mov.l  r13, @(8,r11)   ; node->field_8 = 0 (flags cleared)
0x0604274A: mov.l  r13, @(12,r11)  ; node->field_12 = 0 (next = NULL)

  -- Insert node into linked list --
0x0604274C: bsr    0x06042A88      ; call insert_node(state, node)
0x0604274E: mov    r14, r4         ;   r4 = state

0x06042750: tst    r0, r0
0x06042752: bf     0x06042774      ; if insert returned non-zero: skip these checks

  -- Insert returned 0: check thresholds --
0x06042754: mov    #104, r0        ; 0x68
0x06042756: mov.l  @(r0,r14), r3   ; r3 = game_state[0x68]
0x06042758: cmp/hs r3, r10         ; T = (r10 >= state[0x68])
0x0604275A: bt     0x0604276C      ; if r10 >= threshold: goto alt_insert

0x0604275C: mov    #0, r5
0x0604275E: bsr    0x06041E46      ; call func_06041E46(state, 0)
0x06042760: mov    r14, r4
0x06042762: tst    r0, r0
0x06042764: bt/s   0x06042774      ; if returned 0: skip (delayed)
0x06042766: mov    r0, r4
0x06042768: bra    0x060428CA      ; goto return_nonzero_path
0x0604276A: nop

label_0x0604276C:
0x0604276C: mov    r11, r5
0x0604276E: mov    r14, r4
0x06042770: bsr    0x06042B20      ; call func_06042B20(&state[0x54], node)
0x06042772: add    #84, r4         ;   r4 = &game_state[0x54]

================================================================================
  8. SEQUENCE NUMBER / POSITION TRACKING
================================================================================

label_0x06042774:
0x06042774: mov.l  @(24,r14), r3   ; r3 = game_state[0x18] (seq_high?)
0x06042776: mov    #124, r0        ; 0x7C
0x06042778: mov.l  @(20,r14), r2   ; r2 = game_state[0x14] (seq_low?)
0x0604277A: sub    r3, r2          ; r2 = state[0x14] - state[0x18]
0x0604277C: mov.l  @(r0,r14), r3   ; r3 = game_state[0x7C]
0x0604277E: shlr   r2              ; r2 >>= 1 (halve the difference)
0x06042780: add    r3, r2          ; r2 = state[0x7C] + (state[0x14]-state[0x18])/2
0x06042782: cmp/hs r2, r10         ; T = (r10 >= r2) unsigned
0x06042784: bt     0x06042792      ; if r10 >= threshold: goto skip_early_exit

  -- r10 < threshold: check if payload[1] bit3 is set --
0x06042786: mov.b  @(1,r12), r0    ; payload[1]
0x06042788: extu.b r0, r0
0x0604278A: tst    #0x08, r0       ; T = (payload[1] & 0x08) == 0
0x0604278C: bf     0x06042792      ; if bit3 SET: continue anyway
0x0604278E: bra    0x060428D4      ; else: goto callback_and_return
0x06042790: nop

label_0x06042792:
  -- Update state[0x7C] = r10 --
0x06042792: mov    #124, r0        ; 0x7C
0x06042794: mov.l  r10, @(r0,r14)  ; game_state[0x7C] = r10

0x06042796: mov    #0, r5
0x06042798: bsr    0x06041E46      ; call func_06041E46(state, 0)
0x0604279A: mov    r14, r4

0x0604279C: tst    r0, r0
0x0604279E: bf/s   0x060427A6      ; if returned non-zero: goto (delayed)
0x060427A0: mov    r0, r4
0x060427A2: bra    0x060428D4      ; goto callback_and_return
0x060427A4: nop

0x060427A6: bra    0x060428CA      ; goto return_nonzero_path
0x060427A8: nop

================================================================================
  9. NO-BIT0 FINAL PATH (payload[1] bit0 was clear)
================================================================================

label_no_bit0_final:  ; 0x060427AA
0x060427AA: mov    #40, r0         ; 0x28
0x060427AC: mov.w  @(r0+sp), r12   ; r12 = sp[40] (field from extraction)
0x060427AE: mov    #8, r3
0x060427B0: extu.w r12, r12
0x060427B2: tst    r12, r3         ; T = (r12 & 0x08) == 0
0x060427B4: bf     0x060427BA      ; if bit3 SET: continue
0x060427B6: bra    0x060428D4      ; else: goto callback_and_return
0x060427B8: nop

label_0x060427BA:
  -- Bit3 of r12 is set: process status update flags --
0x060427BA: mov    #4, r3
0x060427BC: mov.w  @pool, r0       ; r0 = 0x80
0x060427BE: mov.l  r13, @(r0,r14)  ; game_state[0x80] = 0
0x060427C0: add    #37, r0         ; r0 = 0xA5
0x060427C2: mov.b  r13, @(r0,r14)  ; game_state[0xA5] = 0
0x060427C4: add    #-1, r0         ; r0 = 0xA4
0x060427C6: mov.b  r3, @(r0,r14)   ; game_state[0xA4] = 4

  -- Check game_state[0x00] (first field) --
0x060427C8: mov.l  @r14, r1        ; r1 = game_state[0x00]
0x060427CA: tst    r1, r1
0x060427CC: bt     0x060427DE      ; if state[0]==0: skip

  -- state[0]!=0: check state[0x84] --
0x060427CE: mov.w  @pool, r0       ; r0 = 0x84
0x060427D0: mov.l  @(r0,r14), r1   ; r1 = game_state[0x84]
0x060427D2: tst    r1, r1
0x060427D4: bt     0x060427DE      ; if state[0x84]==0: skip

0x060427D6: mov.w  @pool, r0       ; r0 = 0x84
0x060427D8: mov.l  @pool32, r3     ; r3 = 0x06042FDA
0x060427DA: jsr    @r3             ; call func_06042FDA(state[0x84])
0x060427DC: mov.l  @(r0,r14), r4   ;   r4 = game_state[0x84]

label_0x060427DE:
  -- Process field values, set game_state[0xAC] = 0 --
0x060427DE: mov    #16, r5         ; r5 = 0x10
0x060427E0: mov.w  @pool, r0       ; r0 = 0xAC
0x060427E2: mov    #32, r4         ; r4 = 0x20
0x060427E4: mov.l  r13, @(r0,r14)  ; game_state[0xAC] = 0
0x060427E6: and    r12, r5         ; r5 = r12 & 0x10 (bit4 of status flags)
0x060427E8: mov.l  @r14, r1        ; r1 = game_state[0]
0x060427EA: tst    r1, r1
0x060427EC: bf/s   0x06042888      ; if state[0]!=0: goto existing_entity (delayed)
0x060427EE: and    r12, r4         ; r4 = r12 & 0x20 (bit5 of status flags)

  -- state[0]==0: new entity setup --
0x060427F0: mov    #48, r3         ; r3 = 48 (0x30)
0x060427F2: mov    r3, r0
0x060427F4: add    #118, r0        ; r0 = 166 = 0xA6
0x060427F6: tst    r12, r9         ; T = (r12 & 1) == 0 (check bit0 of status)
0x060427F8: bt/s   0x0604280C      ; if bit0 clear: goto skip_flag_set (delayed)
0x060427FA: mov.w  r3, @(r0,r14)   ; (delay) game_state[0xA6] = 48

  -- r12 bit0 set: check state[4] --
0x060427FC: mov.l  @(4,r14), r2    ; r2 = game_state[0x04]
0x060427FE: tst    r2, r2
0x06042800: bt     0x0604280C      ; if state[4]==0: skip
0x06042802: mov    #1, r3
0x06042804: mov.w  @pool, r0       ; r0 = 0xA6
0x06042806: mov.w  @(r0,r14), r2   ; r2 = game_state[0xA6]
0x06042808: or     r3, r2          ; r2 |= 1 (set bit0)
0x0604280A: mov.w  r2, @(r0,r14)   ; game_state[0xA6] = r2 | 1

label_0x0604280C:
  -- Check r12 bit1 --
0x0604280C: mov    #2, r1
0x0604280E: tst    r12, r1         ; T = (r12 & 2) == 0
0x06042810: bt     0x06042822      ; if bit1 clear: skip
0x06042812: mov.l  @(8,r14), r2    ; r2 = game_state[0x08]
0x06042814: tst    r2, r2
0x06042816: bt     0x06042822      ; if state[8]==0: skip
0x06042818: mov.w  @pool, r0       ; r0 = 0xA6
0x0604281A: mov    #2, r3
0x0604281C: mov.w  @(r0,r14), r2
0x0604281E: or     r3, r2          ; game_state[0xA6] |= 2
0x06042820: mov.w  r2, @(r0,r14)

label_0x06042822:
  -- Check r12 bit2 --
0x06042822: mov    #4, r1
0x06042824: tst    r1, r12         ; T = (r12 & 4) == 0
0x06042826: bt     0x06042838      ; if bit2 clear: skip
0x06042828: mov.l  @(12,r14), r2   ; r2 = game_state[0x0C]
0x0604282A: tst    r2, r2
0x0604282C: bt     0x06042838      ; if state[0xC]==0: skip
0x0604282E: mov    #4, r3
0x06042830: mov.w  @pool, r0       ; 0xA6
0x06042832: mov.w  @(r0,r14), r2
0x06042834: or     r3, r2          ; game_state[0xA6] |= 4
0x06042836: mov.w  r2, @(r0,r14)

label_0x06042838:
  -- If bit4 (r5): update HP thresholds --
0x06042838: tst    r5, r5
0x0604283A: bt     0x06042856      ; if !(r12 & 0x10): skip HP
0x0604283C: mov.w  @(24,sp), r0    ; r0 = hp_value (from extraction)
0x0604283E: extu.w r0, r0
0x06042840: mov.l  @(20,r14), r3   ; r3 = game_state[0x14]
0x06042842: cmp/hs r0, r3          ; T = (state[0x14] >= hp_value)
0x06042844: bt     0x0604284E      ; if state[0x14] >= hp: use hp_value directly
0x06042846: mov.l  @(20,r14), r1   ; r1 = game_state[0x14]
0x06042848: mov.w  @pool, r0       ; r0 = 0xA8
0x0604284A: bra    0x06042856      ; store and skip
0x0604284C: mov.w  r1, @(r0,r14)   ; game_state[0xA8] = state[0x14] (clamped)

label_0x0604284E:
0x0604284E: mov.w  @(24,sp), r0    ; r0 = hp_value
0x06042850: mov.w  @pool, r2       ; r2 = 0xA8
0x06042852: add    r14, r2
0x06042854: mov.w  r0, @r2         ; game_state[0xA8] = hp_value

label_0x06042856:
  -- If bit5 (r4): update MP thresholds --
0x06042856: tst    r4, r4
0x06042858: bt     0x060428AE      ; if !(r12 & 0x20): skip MP
0x0604285A: mov.w  @(28,sp), r0    ; r0 = mp_value
0x0604285C: mov.l  @(24,r14), r3   ; r3 = game_state[0x18]
0x0604285E: extu.w r0, r0
0x06042860: cmp/hs r0, r3          ; T = (state[0x18] >= mp_value)
0x06042862: bt     0x0604286C      ; if so: use mp_value
0x06042864: mov.l  @(24,r14), r1   ; r1 = state[0x18]
0x06042866: mov.w  @pool, r0       ; 0xB0
0x06042868: bra    0x060428AE
0x0604286A: mov.w  r1, @(r0,r14)   ; game_state[0xB0] = state[0x18] (clamped)

label_0x0604286C:
0x0604286C: mov.w  @(28,sp), r0    ; mp_value
0x0604286E: mov.w  @pool, r2       ; 0xB0
0x06042870: add    r14, r2
0x06042872: bra    0x060428AE
0x06042874: mov.w  r0, @r2         ; game_state[0xB0] = mp_value

  --- Literal pools ---
  0x06042876: 0080 (128)
  0x06042878: 0084 (132)
  0x0604287A: 00AC (172)
  0x0604287C: 00A6 (166)
  0x0604287E: 00A8 (168)
  0x06042880: 00B0 (176)
  0x06042884: 0x06042FDA (function pointer)

================================================================================
  9a. EXISTING ENTITY PATH (state[0] != 0)
================================================================================

label_existing_entity:  ; 0x06042888
0x06042888: mov.w  @pool, r2       ; r2 = 0xA6
0x0604288A: tst    r5, r5          ; (r5 = r12 & 0x10)
0x0604288C: mov    sp, r1
0x0604288E: add    #40, r1
0x06042890: mov.w  @r1, r0         ; r0 = sp[40] (status field from extraction)
0x06042892: add    r14, r2         ; r2 = &game_state[0xA6]
0x06042894: and    #0x07, r0       ; r0 = status & 0x07 (keep only low 3 bits)
0x06042896: bt/s   0x060428A2      ; if !(r12 & 0x10): skip HP (delayed)
0x06042898: mov.w  r0, @r2         ; game_state[0xA6] = status & 7

  -- bit4 set: update HP --
0x0604289A: mov.w  @(24,sp), r0    ; hp_value
0x0604289C: mov.w  @pool, r1       ; 0xA8
0x0604289E: add    r14, r1
0x060428A0: mov.w  r0, @r1         ; game_state[0xA8] = hp_value

label_0x060428A2:
  -- Check bit5 for MP --
0x060428A2: tst    r4, r4
0x060428A4: bt     0x060428AE      ; if !(r12 & 0x20): skip MP
0x060428A6: mov.w  @(28,sp), r0    ; mp_value
0x060428A8: mov.w  @pool, r2       ; 0xB0
0x060428AA: add    r14, r2
0x060428AC: mov.w  r0, @r2         ; game_state[0xB0] = mp_value

================================================================================
  10. FINAL STATE UPDATE AND RETURN
================================================================================

label_final_update:  ; 0x060428AE
0x060428AE: mov.w  @pool, r0       ; 0xA8
0x060428B0: mov.w  @(r0,r14), r3   ; r3 = game_state[0xA8]
0x060428B2: mov    #116, r0        ; 0x74
0x060428B4: extu.w r3, r3
0x060428B6: mov.l  r3, @(r0,r14)   ; game_state[0x74] = game_state[0xA8] (as uint32)

  -- Check state[0] for final callback --
0x060428B8: mov.l  @r14, r1        ; r1 = game_state[0]
0x060428BA: tst    r1, r1
0x060428BC: bf     0x060428CE      ; if state[0]!=0: goto set_state_2

  -- state[0]==0: call func_06041E46(state, 1) --
0x060428BE: mov    #1, r5
0x060428C0: bsr    0x06041E46      ; call func_06041E46(state, 1)
0x060428C2: mov    r14, r4
0x060428C4: tst    r0, r0
0x060428C6: bt/s   0x060428CE      ; if returned 0: skip (delayed)
0x060428C8: mov    r0, r4

label_return_nonzero:  ; 0x060428CA
0x060428CA: bra    0x060428E6      ; goto epilogue
0x060428CC: mov    r4, r0          ; (delay) return value = r4

label_set_state_2:  ; 0x060428CE
0x060428CE: mov    #2, r3
0x060428D0: mov    #96, r0         ; 0x60
0x060428D2: mov.l  r3, @(r0,r14)   ; game_state[0x60] = 2

label_callback_and_return:  ; 0x060428D4
  -- Final callback check at state[0x3C] --
0x060428D4: mov.l  @(60,r14), r1   ; r1 = game_state[0x3C] (callback)
0x060428D6: tst    r1, r1
0x060428D8: bt     0x060428E4      ; if NULL: skip

0x060428DA: mov.l  @(60,r14), r2   ; r2 = callback function pointer
0x060428DC: mov.l  @(20,sp), r6    ; r6 = param3
0x060428DE: mov.l  @(12,sp), r5    ; r5 = payload
0x060428E0: jsr    @r2             ; callback(state, payload, param3)
0x060428E2: mov    r14, r4         ;   r4 = game_state

label_return_0:  ; 0x060428E4
0x060428E4: mov    #0, r0          ; return value = 0 (success)

================================================================================
  11. EPILOGUE
================================================================================

label_epilogue:  ; 0x060428E6
0x060428E6: add    #56, sp         ; deallocate 56 bytes of locals
0x060428E8: lds.l  @sp+, PR        ; pop return address
0x060428EA: mov.l  @sp+, r8        ; pop r8
0x060428EC: mov.l  @sp+, r9        ; pop r9
0x060428EE: mov.l  @sp+, r10       ; pop r10
0x060428F0: mov.l  @sp+, r11       ; pop r11
0x060428F2: mov.l  @sp+, r12       ; pop r12
0x060428F4: mov.l  @sp+, r13       ; pop r13
0x060428F6: rts                     ; return (r0 = return value)
0x060428F8: mov.l  @sp+, r14       ; (delay slot) pop r14

  Registers restored in reverse order: r8,r9,r10,r11,r12,r13,r14
  Return value in r0:
    0 = success (normal completion)
    1 = early exit (bit0 set, state!=2, callback invoked)
    2 = allocation failure

================================================================================
  HELPER FUNCTION: read_byte_decoded @ 0x060428FA
================================================================================

  int read_byte_decoded(uint32_t **cursor, uint8_t xor_key)
  Reads one byte from *cursor, advances *cursor, XOR-decodes if byte==xor_key.

  0x060428FA: extu.b r5, r5         ; xor_key = r5 & 0xFF
  0x060428FC: mov.l  @r4, r6        ; r6 = *cursor
  0x060428FE: add    #1, r6
  0x06042900: mov.l  r6, @r4        ; *cursor += 1
  0x06042902: add    #-1, r6        ; r6 = original *cursor
  0x06042904: mov.b  @r6, r6        ; r6 = byte at original position
  0x06042906: extu.b r6, r3         ; r3 = byte (zero-extended)
  0x06042908: cmp/eq r5, r3         ; T = (byte == xor_key)
  0x0604290A: bf     0x0604291A     ; if byte != xor_key: return byte as-is

  -- byte == xor_key: read NEXT byte and XOR with 0x60 --
  0x0604290C: mov.l  @r4, r6        ; r6 = *cursor (already advanced)
  0x0604290E: mov    #96, r3        ; r3 = 0x60
  0x06042910: add    #1, r6
  0x06042912: mov.l  r6, @r4        ; *cursor += 1 (advance again)
  0x06042914: add    #-1, r6
  0x06042916: mov.b  @r6, r6        ; r6 = next byte
  0x06042918: xor    r3, r6         ; r6 ^= 0x60

  0x0604291A: rts
  0x0604291C: mov    r6, r0         ; return decoded byte in r0

  SUMMARY: This is an escape-sequence decoder.
  - If the byte equals the XOR key: consume the NEXT byte and XOR it with 0x60.
  - Otherwise: return the byte unchanged.
  - This means the XOR key byte itself is an escape character.

================================================================================
  HELPER FUNCTION: read_u32_decoded @ 0x0604291E
================================================================================

  uint32_t read_u32_decoded(uint32_t **cursor, uint8_t xor_key)
  Reads 4 decoded bytes (big-endian) and returns a 32-bit value.

  0x0604291E-0x0604296A: Saves r11-r14, PR.
  r11 = 0xFF (mask)
  Calls read_byte_decoded 4 times, shifting and ORing:
    result = (byte0 << 24) | (byte1 << 16) | (byte2 << 8) | byte3
  Returns uint32 in r0.

================================================================================
  HELPER FUNCTION: read_u16_decoded @ 0x0604296C
================================================================================

  uint16_t read_u16_decoded(uint32_t **cursor, uint8_t xor_key)
  Reads 2 decoded bytes (big-endian) and returns a 16-bit value.

  0x0604296C-0x060429A0: Saves r14, PR.
  r14 = 0xFF (mask)
  Calls read_byte_decoded 2 times:
    result = (byte0 << 8) | byte1
  Returns uint16 in r0.

================================================================================
  HELPER FUNCTION: read_u16_from_cursor @ 0x060429A2
================================================================================

  uint16_t read_u16_from_cursor(uint8_t *ptr)
  Reads a raw 16-bit big-endian value from memory (no XOR decoding).

  0x060429A2-0x060429B4: Calls 0x06042C48 with size=4.
  Actually reads 4 bytes raw? (The exact behavior depends on 0x06042C48.)
  Returns uint16 in r0.

================================================================================
  HELPER FUNCTION: checksum @ 0x060429B6
================================================================================

  uint16_t checksum(uint8_t *data, uint16_t length)
  Computes an additive byte sum over `length` bytes.

  0x060429B6: bra    0x060429C0     ; goto loop_check
  0x060429B8: mov    #0, r6         ; sum = 0

  loop_body:
  0x060429BA: mov.b  @r4+, r3      ; r3 = *data++
  0x060429BC: extu.b r3, r3        ; zero-extend
  0x060429BE: add    r3, r6        ; sum += byte

  loop_check:
  0x060429C0: tst    r5, r5        ; T = (length == 0)
  0x060429C2: bf/s   0x060429BA    ; if length > 0: continue (delayed)
  0x060429C4: add    #-1, r5       ;   length--

  0x060429C6: rts
  0x060429C8: mov    r6, r0        ; return sum

  SUMMARY: Simple additive checksum.
  sum = 0; while(length-- > 0) sum += *data++;
  Note: r5 is decremented BEFORE the next iteration check (bf/s delay slot).
  The loop iterates exactly `length` times (0-based countdown).

================================================================================
  COMPLETE PSEUDOCODE SUMMARY
================================================================================
""")

    print("""
int delivery(game_state_t *state, uint8_t *payload, uint32_t param3) {
    // r14=state, r12=payload, sp[12]=payload, sp[20]=param3
    // r13=0, r9=1, r8=0, r11=0

    int has_bit0 = (payload[1] & 0x01) ? 1 : 0;

    // --- EARLY EXIT ---
    if (has_bit0 && state->field_60 != 2) {
        if (state->callback_3C)
            state->callback_3C(state, payload, param3);
        return 1;
    }

    // --- DETERMINE MESSAGE TYPE ---
    int is_A6 = (payload[0] == 0xA6);
    uint8_t xor_key = is_A6 ? payload[6] : 0;

    // --- FIELD EXTRACTION ---
    uint16_t extracted_word = 0, checksum_val = 0;
    uint32_t val_u32 = 0;      // r10
    uint32_t val2_u32 = 0;     // r11
    uint16_t hp = 0, mp = 0;
    uint16_t data_length = 0;  // sp[32]
    uint16_t status_flags = 0; // sp[40]
    uint8_t *data_ptr = NULL;

    if (is_A6) {
        if (!(state->field_A6 & 1)) {
            // Extract word from payload[2..3]
            extracted_word = read_u16_raw(&payload[2]);
            some_copy_func(state, payload);
            checksum_val = checksum(payload, param3);
        }
        if (has_bit0) {
            // Decode fields with XOR escape encoding
            uint8_t *cursor = &payload[8];
            val_u32 = read_u32_decoded(&cursor, xor_key);   // r10
            val2_u32 = read_u32_decoded(&cursor, xor_key);  // r11
            data_length = read_u16_raw(&cursor);
            data_ptr = cursor + 4;
        }
    } else {
        if (!(state->field_A6 & 1)) {
            extracted_word = *(uint16_t*)(payload+2);
            some_copy_func(state, payload);
            checksum_val = checksum(payload, param3);
        }
        if (has_bit0) {
            val_u32 = *(uint32_t*)(payload+8);    // raw, no decoding
            val2_u32 = *(uint32_t*)(payload+12);
            data_length = *(uint16_t*)(payload+16);
            data_ptr = &payload[20];
        } else {
            status_flags = *(uint16_t*)(payload+8);
            hp = *(uint16_t*)(payload+10);
            val_u32 = *(uint32_t*)(payload+12);
            mp = *(uint16_t*)(payload+16);
        }
    }

    // --- CHECKSUM VALIDATION ---
    if (!(state->field_A6 & 1)) {
        if (extracted_word != checksum_val) {
            // CHECKSUM MISMATCH!
            if (state->callback_3C)
                state->callback_3C(state, payload, param3);
            error_func(state, 2);  // 0x06041E46
            return 0;
        }
    }

    // --- MAIN PROCESSING ---
    update_state_func(state);  // 0x06042E94

    if (!(payload[1] & 0x02) && !(payload[1] & 0x40))
        goto after_list_walk;  // skip data processing

    // Set up traversal value
    if (!has_bit0) val2_u32 = val_u32;

    // Check overflow
    int overflow = 0;
    if (val2_u32 > state->field_70) overflow = 1;

    if (!overflow) {
        if (!(payload[1] & 0x40))
            goto after_list_walk;
        bit6_handler(state);     // 0x06042CA0
        goto after_list_walk;
    }

    // --- STATE UPDATE (overflow) ---
    state->field_70 = val2_u32;
    node_t *new = node_alloc_func(state+0x5C, val2_u32, state+0x58, 0);
    if (new) {
        // ... various state field updates ...
        // clear state[0x80], state[0xA5]
        // check state[0x84] and call 0x06042FDA if needed
        // check node at state[0x5C] for bit3 flag -> call 0x06042DC6
    }

    // Check bit6
    if (payload[1] & 0x40) {
        bit6_handler(state);
        goto after_list_walk;
    }

    // Walk linked list at state[0x5C]
    for (node_t *n = state->field_5C; n; n = n->next) {
        if (n->value > state->field_78 && n->value < state->field_74) {
            state->field_78 = n->value;
            n->flags |= 0x08;
            if (state->callback_38)
                state->callback_38(state, &n->data, n->field_4);
            process_node_extra(state, state->field_B8);  // 0x06042DC6
            post_process(state);                          // 0x06042E30
        }
        if (n->value >= state->field_74) break;
    }

after_list_walk:
    if (!has_bit0) goto no_bit0_path;

    // --- HAS_BIT0 PATH: Allocate and insert node ---
    node_t *node = allocator(state->field_48);  // 0x060457B4
    if (!node) return 2;

    if (is_A6) {
        // Copy decoded data into node->data[16+]
        // using read_byte_decoded in a loop
    } else {
        // Raw memcpy of data_length bytes
    }

    node->field_0 = val_u32;     // sequence/position
    node->field_4 = data_length;
    node->field_8 = 0;           // flags
    node->field_12 = NULL;       // next

    insert_node(state, node);     // 0x06042A88
    // ... threshold checks, further inserts ...

    // Update sequence tracking
    state->field_7C = val_u32;
    // ... more processing ...
    goto set_state_and_callback;

no_bit0_path:
    // Process status update (flags in r12 from sp[40])
    if (!(r12 & 0x08)) goto callback_and_return;

    state->field_80 = 0;
    state->field_A5 = 0;
    state->field_A4 = 4;

    if (state->field_0 == 0) {
        // New entity: set state[0xA6] = 48
        // Check bits 0,1,2 of status -> OR into state[0xA6]
        // if bit4: state[0xA8] = min(hp, state[0x14])
        // if bit5: state[0xB0] = min(mp, state[0x18])
    } else {
        // Existing entity:
        // state[0xA6] = status & 0x07
        // if bit4: state[0xA8] = hp
        // if bit5: state[0xB0] = mp
    }

    // Final update
    state->field_74 = state->field_A8;  // HP -> position tracking
    if (state->field_0 == 0) {
        result = func_06041E46(state, 1);
        if (result) return result;
    }
    state->field_60 = 2;

callback_and_return:
    if (state->callback_3C)
        state->callback_3C(state, payload, param3);
    return 0;
}
""")

    # =========================================================================
    # Now verify literal pool values from the actual binary
    # =========================================================================
    print("=" * 80)
    print("  VERIFIED LITERAL POOL VALUES (from binary)")
    print("=" * 80)

    pools_u16 = [
        (0x060424DA, "used at 0x06042438, 0x06042450"),
        (0x060425A8, "used at 0x060424DC, 0x06042534"),
        (0x06042650, ""),
        (0x06042652, ""),
        (0x06042654, ""),
        (0x06042656, ""),
        (0x06042658, ""),
        (0x06042876, ""),
        (0x06042878, ""),
        (0x0604287A, ""),
        (0x0604287C, ""),
        (0x0604287E, ""),
        (0x06042880, ""),
        (0x060429CA, ""),
        (0x060429CC, ""),
        (0x060429CE, ""),
        (0x060429D0, ""),
    ]

    pools_u32 = [
        (0x0604265C, "function pointer"),
        (0x06042710, "allocator function"),
        (0x06042884, "function pointer"),
        (0x06042C3C, ""),
        (0x06042C40, ""),
    ]

    for addr, note in pools_u16:
        foff = mem_to_file(addr)
        val = u16be(data, foff)
        print(f"  [0x{addr:08X}] uint16 = 0x{val:04X} ({val})  {note}")

    print()
    for addr, note in pools_u32:
        foff = mem_to_file(addr)
        val = u32be(data, foff)
        print(f"  [0x{addr:08X}] uint32 = 0x{val:08X}  {note}")

    # =========================================================================
    # Verify the game_state field offsets used
    # =========================================================================
    print()
    print("=" * 80)
    print("  GAME_STATE FIELD MAP (offsets from r14)")
    print("=" * 80)
    fields = [
        (0x00, "uint32", "entity_ptr / first_field (checked for NULL = new entity)"),
        (0x04, "uint32", "some_pointer (checked for NULL in flag setup)"),
        (0x08, "uint32", "some_pointer (checked for NULL in flag setup)"),
        (0x0C, "uint32", "some_pointer (checked for NULL in flag setup)"),
        (0x14, "uint32", "seq_low / current_hp?"),
        (0x18, "uint32", "seq_high / current_mp?"),
        (0x38, "func_ptr", "node_callback (called when node matches range)"),
        (0x3C, "func_ptr", "main_callback (called on early exit & completion)"),
        (0x48, "uint32", "allocator_context (passed to 0x060457B4)"),
        (0x4C, "uint32", "some_flag (cleared/set based on state[0x58])"),
        (0x54, "struct", "some_structure (node inserted here)"),
        (0x58, "uint8", "counter/index (checked against 8 and 16)"),
        (0x5C, "node_ptr", "linked_list_head (node linked list)"),
        (0x60, "uint32", "state_phase (compared to 2 for early exit check)"),
        (0x68, "uint32", "threshold_low"),
        (0x70, "uint32", "high_water_mark (val2_u32 stored here)"),
        (0x74, "uint32", "accumulated_value / position_upper"),
        (0x78, "uint32", "last_processed_value"),
        (0x7C, "uint32", "last_sequence_value"),
        (0x80, "uint32", "cleared to 0 during processing"),
        (0x84, "uint32", "some_pointer (passed to func_06042FDA if non-NULL)"),
        (0xA4, "uint8", "set to 4 during no-bit0 path"),
        (0xA5, "uint8", "cleared to 0 during processing"),
        (0xA6, "uint16", "status_flags (bits 0-2 + others, critical for flow)"),
        (0xA8, "uint16", "hp_threshold / distance_value"),
        (0xAC, "uint32", "cleared to 0 during processing"),
        (0xB0, "uint16", "mp_threshold"),
        (0xB8, "uint32", "passed to func_06042DC6"),
        (0xC0, "uint32", "cleared when !has_bit0 processing"),
    ]
    for off, typ, desc in fields:
        print(f"  +0x{off:02X} ({off:3d})  {typ:<10s}  {desc}")

    # =========================================================================
    # External function calls summary
    # =========================================================================
    print()
    print("=" * 80)
    print("  EXTERNAL FUNCTION CALLS")
    print("=" * 80)
    calls = [
        ("0x06041CC0", "some_copy_func(state, payload)", "Called during checksum extraction path"),
        ("0x06041E46", "error_or_init_func(state, mode)", "mode=0,1,2; called on error and init"),
        ("0x06042A88", "insert_node(state, node)", "Inserts populated node into list"),
        ("0x06042B20", "alt_insert(state+0x54, node)", "Alternative insertion path"),
        ("0x06042B74", "node_alloc_func(s+0x5C, val, s+0x58, 0)", "Allocates in node pool"),
        ("0x06042CA0", "bit6_handler(state)", "Called when payload[1] bit6 is set"),
        ("0x06042DC6", "process_node_extra(state, param)", "Post-node processing"),
        ("0x06042E30", "post_process(state)", "Called after node range match"),
        ("0x06042E94", "update_state(state)", "Called at start of main processing"),
        ("0x06042FDA", "cleanup_func(ptr)", "Called with state[0x84] when non-NULL"),
        ("0x060457B4", "allocator(context)", "Allocates a new node structure"),
    ]
    for addr, sig, desc in calls:
        print(f"  {addr}  {sig:<42s}  {desc}")


if __name__ == "__main__":
    main()
