# Dragon's Dream Decomp Project Memory

## Project Overview
- **Game**: Dragon's Dream — Fujitsu x SEGA Saturn MMORPG (Dec 1997, Japan)
- **Product**: GS-7114, V1.003, released 1997-10-27, Japan-only
- **Goal**: Revival server restoring online functionality
- **Status**: Protocol fully decompiled — ready for server v3 implementation

## CRITICAL: Wire Format (CORRECTED 2026-03-11)
- See [wire-format.md](wire-format.md) for full analysis with evidence
- **8-byte header**: `[2B param1][2B msg_type][4B payload_size][payload_data]`
- **msg_type is NOT wire size** — it's just a unique message identifier (uint16 BE)
- **payload_size is the ACTUAL payload byte count** (uint32 BE)
- **Total wire size = 8 + payload_size** (NOT msg_type!)
- param1 usually 0, dispatch reads msg_type from buffer[2], handlers get buffer+8

## CRITICAL: SV Framing (CORRECTED 2026-03-11)
- **IV header = 8 bytes**: `IV` + 3 hex (size) + 3 hex (~size & 0xFFF)
- **NO \r\n** between header and payload (previous analysis was WRONG)
- **NO checksum** at SV layer — the second field is size COMPLEMENT
- **NO fragmentation** at SV layer — each message = one IV frame
- Hex encoding: lowercase `"0123456789abcdef"` (decode accepts both cases)
- Max IV payload: 4095 bytes (12-bit limit), practical: ~2000B
- Keepalive: `$I'm alive!!\r\n` is CLIENT→SERVER only (separate from IV)
- **CRITICAL**: Server MUST NOT send raw non-IV bytes while client is CONNECTED!
  SV_RecvFrame state 0 at 0x0602272E: any non-'I' byte + CONNECTED → error_dialog(1)
  Server keepalive must be IV-wrapped session ACK frames (flags=0x01, copy_length=0)

## CRITICAL: SV State Machine (CORRECTED 2026-03-12, base=0x06010000)
- **SV library source**: `lib_sv.c` (from assertion strings)
- **SV_Init** at file 0x01219E: clears SV context at 0x202E4B3C
- **SV_Setup** at file 0x0121F8: registers callbacks, inits session, sets [0x202E4B3C]=1
- **SV_Poll** at file 0x0120E8: called from MAIN LOOP (0x000156), calls sv_open + SV_RecvFrame
- **sv_open** at file 0x01253E: send state machine (builds IV header, sends byte-by-byte)
- **SV_RecvFrame** at file 0x0126DA: 3-state receive parser (scan 'I'→'V'+hex→payload)
- **Send queue**: at 0x060623D8, sv_open sends when queue non-empty
- **SV context struct**: at RAM 0x202E4B3C (Work RAM-L, cache-through)
- **SV session struct**: at RAM 0x06062314
- **Connection state [0x06062374]**: offset 0x60 in session struct
  - 0 = Disconnected (set by init/teardown at 0x06041BDE, 0x06041CFC)
  - 1 = Connecting (set by 0x06041D94, called from SV_Setup)
  - 2 = Connected (set by delivery function 0x060423C8 at 0x060428CE)
- **Polling function** at 0x012298: returns 1 if [0x06062374]==2, else 0

## CRITICAL: Session Protocol Layer (CORRECTED 2026-03-12)
- **ALL post-BBS messages** go through session framing (between SV IV and SCMD)
- **Protocol stack**: SCMD → Session Protocol (0x00/0xA6) → SV IV Framing → TCP
- **0x00-type DATA frame (server→client)**: [0]=0x00, [1]=**0x03**(bit0+bit1), [2:4]=checksum,
  [4:6]=zeroed, [6:8]=unused, [8:12]=seq_byte_offset(uint32 BE), [12:16]=ack(uint32 BE), [16:18]=copy_length, [18:20]=0, [20:]=SCMD
- **FLAGS byte [1]**: bit0=has_seq_data (MUST set for seq/ack fields), bit1=has_data, bit6=alt_data
- **Without bit0**: delivery function reads stale values from session context, frame silently dropped
- **CRITICAL: Sequence numbers are BYTE OFFSETS, not frame counters!**
  Evidence: client INIT(seq=0, 74B SCMD) → next client frame seq=74. After dispatch, session[116] = seq + copy_length.
  send_seq starts at 0, incremented by SCMD size (copy_length) after each frame.
- **[12:16] ack_num**: must be > session[112] (starts 0, updated after each accepted frame via cmp/hi)
  ack = send_seq + 1 (monotonically increasing byte offset + 1)
- **ESTABLISH sub-flags**: bit3=ESTABLISH only (0x0008). Do NOT set bit4 with window=0.
- **0xA6 frame (client→server)**: escape-encoded, [6]=escape_byte(0x1C),
  from [8]: 4 escaped bytes→seq, 4 escaped bytes→val2, skip 4 raw, then SCMD data
- **Escape decoding**: if byte==escape_byte, next_byte^0x60 = original
- **Checksum**: sum all bytes with [2:6] zeroed, & 0xFFFF
- Server 0x00: checksum at [2:4] as uint16 BE; Client 0xA6: checksum at [2:6] as 4 ASCII hex
- **send_msg() must wrap SCMD** in 0x00-type session DATA frame before IV encoding

## CRITICAL: Connection Protocol (CORRECTED 2026-03-12)
- **SERVER SENDS FIRST** — Saturn deadlocks without initial server frame
- BBS: ` P\r`→`*\r\n`, `SET...\r`→`*\r\n`, `C NETRPG\r`→`COM\r\n`
- After BBS: Saturn enters post-BBS state 3, calls SV_Setup → [0x06062374]=1
- SV_Poll starts running: SV_RecvFrame scans for 'I','V' header (send queue empty)
- Post-BBS state 3 polls [0x06062374]==2 with 600-frame (~10s) timeout
- **Server must send 256-byte session establishment IV frame** to trigger delivery
- Delivery function at 0x060423C8 sets [0x06062374]=2 (CONNECTED)
- State advances 3→4, Saturn sends 0xA6 session response (18B IV frame)
- **SV_RecvFrame resets to state 0 after EACH delivery** (all frames must be IV-wrapped!)
- **NO separate ack needed** — single establishment with ESTABLISH flag sets state=2
- Server responds with 0x01E8 ESP_NOTICE to 0x0035, login flow continues
- **Session frame format** (from delivery function at 0x060423C8):
  - [0]: 0x00=server→client, 0xA6=client→server (escape-encoded)
  - [1]: frame flags: bit0=has_seq_data, bit1=has_data, bit6=alt_data
  - [2:4]: **uint16 BE checksum** (NOT ASCII hex!), computed with [2:6] zeroed
  - [8:10]: **uint16 BE session flags, bit3=ESTABLISH (0x0008) REQUIRED for state=2**
- Establishment: [0]=0x00, [1]=0x42, [2:4]=cksum, [8:10]=0x0008, rest zeros
- Saturn response: [0]=0xA6, [1]=flags, [2:4]=cksum, [6]=0x1C(escape), [8:12]=timeout_a, [16:18]=timeout_b
- **0x0035 is NOT sent via scmd** — may be the 0xA6 session msg itself or SV-layer direct

## BBS Script Engine (file 0x010128, base=0x06010000)
- Script tables: 12-byte entries [type:4][data:4][param:4]
- Type 1: SEND string, Type 2: WAIT for response, Type 3: END
- MODEM_INIT table at 0x06055D3C (AT, ATZ, user config)
- BBS_LOGIN table at 0x06055DA8 (P, SET commands, wildcard match)
- BBS_CONNECT table at 0x06055DD8 (C HRPG, expects COM response)
- Response matching: substring scan on raw byte stream, NOT line-based

## SCMD Library Functions (confirmed addresses)
| Function | File offset | Mem addr | Description |
|----------|------------|----------|-------------|
| scmd_new_message | 0x149EC | 0x060249EC | Init msg with param1+msg_type |
| scmd_add_byte | 0x14A32 | 0x06024A32 | Add 1 byte |
| scmd_add_word | 0x14B04 | 0x06024B04 | Add 2 bytes (uint16 BE) |
| scmd_add_long | 0x14BDC | 0x06024BDC | Add 4 bytes (uint32 BE) |
| scmd_add_data | 0x14CD0 | 0x06024CD0 | Add N bytes from ptr |
| scmd_send | 0x14E3C | 0x06024E3C | Set payload_size, send |
- Buffer base: 0x202E6148, nMsgSize: 0x06062498, max: 4800B

## Binary Analysis Files
- [wire-format.md](wire-format.md) — wire format proof (CORRECTED)
- [sv-framing.md](sv-framing.md) — SV library analysis (CORRECTED)
- [handler-analysis.md](handler-analysis.md) — 197 handler entries and dispatch
- [handler-payloads-detailed.md](handler-payloads-detailed.md) — **ALL 197 server→client payloads**
- [client-sent-payloads.md](client-sent-payloads.md) — **ALL 104 client→server payloads**
- [message-flow.md](message-flow.md) — 108-entry paired message table + login flow
- [protocol-details.md](protocol-details.md) — 310 message types (NOTE: "wire size" column is WRONG)

## Decompilation Progress — COMPLETE
- **197 server→client handlers**: 24 empty (rts), 173 fully decompiled
- **104 client→server messages**: all payload layouts documented
- **SV framing**: fully decompiled (send + receive state machines)
- **Checksum**: additive byte sum at 0x060429B6 (application layer)
- See handler-payloads-detailed.md and client-sent-payloads.md

## Key File Locations
- `extracted/0.BIN` — Main executable (504,120 bytes), SH-2 big-endian, base=0x06010000
- `server/dragons_dream_server_v3.py` — Revival server v3 (current)
- `server/netlink.py` — DreamPi netlink module (with do_transparent())
- `server/config.ini` — DreamPi dial-code config (handler=transparent for DD)

## Login State Machine (CONFIRMED 2026-03-13)
- **Controller input polling** at 0x06040B22: reads raw Saturn controller data
  - Source bitmask at 0x0606967C = NOT(raw_controller_word), active-high
  - Change detection at 0x0606967E = (new XOR old) AND new
  - Tick function at 0x06013112 copies source → display bitmask at 0x06060E76
- **Login states 0-7** at 0x0603C100 are ALL LOCAL (no SCMD messages sent)
  - State 0: Display character slots from LOCAL backup RAM (session+0xE8C0)
  - State 1: Wait for controller button: A=REVIVE, C=NEW CHAR, B=CANCEL
  - States 3-7: Slot select, create char, prepare flags, reorder, delete
  - After completion, PARENT code sends LOGIN_REQUEST (0x019E)
- **CHARDATA_REPLY (0x02D2) handler** at 0x06013858: multi-type
  - TYPE 1 (char_list): 24B/entry → session+0x1684, count at session+0x1925
  - TYPE 2 (char_detail): 52B/entry → session+0x1BE0, **triggers backup RAM save via 0x0603AD2C**
  - TYPE 3 (inventory): 24B/entry → session+0x1530, count at session+0x1924
  - NOTE: UI reads from session+0xE8C0 (backup RAM), NOT from these server offsets
- **Init flags (g_state+0x8E..0x91)**: deferred-send system, set to 1 by ESP_NOTICE
  - 0x8E→auto-sends STANDARD_REPLY (0x0048), cleared after send
  - 0x8F→auto-sends PARTY_BREAKUP_NOTICE (0x025F)
  - 0x90→auto-sends CMD_BLOCK_REPLY (0x02D4)
  - 0x91→auto-sends SYSTEM_NOTICE (0x006D)
  - Checked by dispatch function at 0x06024442 on each main loop iteration
- **Login flow** (CONFIRMED 2026-03-13): 0x0035→ESP_NOTICE+UPDATE_CHARDATA_REQ (BOTH required!),
  then wait for button, then 0x019E→0x019F→0x01AA→0x02F9+0x02D2(types 1,2,3)+0x019D
- **0x019F in _h_init is EMPIRICALLY REQUIRED**: without it, Saturn times out after ~66s
  (SV timeout 0x07D0=2000). Handler at 0x3578 stores char_id at g_state+0x0260 and
  party data at g_state+0x1BE0, but does NOT set init flags
- **Post-GOTOLIST flow** (CORRECTED 2026-03-15):
  - INFORMATION_NOTICE (0x019D) handler stores data via 0x06019FF6, NO state transitions
  - Client stays in game world state (session[0x01AD]=3)
  - Game world per-frame function (0x0603BB6E) UNCONDITIONALLY sets session[0x01BC]=1
  - On next frame: gate function 0x0603B6F0(1) called
  - Gate check: g_state[0xE8C2]==1 (set during initial login via gate_set(1) at 0x0603B488)
  - If gate PASSES: sets session[0x01BC]=0, session[0x01AD]=2 (login state)
  - If gate FAILS: sets session[0x01BC]=1, stays in game world state
  - **CRITICAL: Connection state machine does NOT re-send 0x0035 (INIT)**
    INIT is only sent ONCE from state 4 at file 0x010664. After sending, bit 7
    is set in R14[0xBF] (0x84), permanently preventing re-send. The state machine
    at file 0x0103C0 dispatches on R14[0xBF] & 0x7F (states 0-7).
  - **Server MUST proactively send ESP_NOTICE + UPDATE_CHARDATA_REQ** after
    INFORMATION_NOTICE in _h_gotolist_notice (same data as _h_init sends)
  - Login flow resumes when client sends LOGIN_REQUEST (0x019E)
  - **login_phase must be reset to 0** in _h_gotolist_notice for re-login
- **gate_set function** (0x0603B488): writes arg to BOTH g_state[0xDDFE] and g_state[0xE8C2]
  - Called with arg=1 via task 6 (vtable[6]) during login->game world transition
  - Both values saved to Saturn backup RAM at 0x202A8080 (offset +2)
  - On boot, backup RAM loaded into g_state+0xDDFC (0x0AC4B) and g_state+0xE8C0 (0x0534B)
  - For fresh save: g_state[0xE8C2]=0, login state 0 func (0x0603D0C8) skips rendering
- **Connection state machine** (file 0x0103C0, struct at R14=0x06061D80):
  - State variable: R14[0xBF] (byte at 0x06061E3F), dispatched via & 0x7F
  - States: 0=init, 1=setup1, 2=setup2, 3=polling, 4=send_INIT, 5-7=post-INIT
  - State 3 (0x010600): calls polling 0x06022298, if CONNECTED sets R14[0xBF]=4
  - State 4 (0x010626): checks bit 7 of R14[0xBF] — if clear, sends INIT + sets bit 7
  - After INIT: R14[0xBF]=0x84, bit 7 permanently prevents re-sending
  - INDEPENDENT of g_state[0x01AD] — does NOT detect game state transitions
- **SV error strings**: 0="No response from host", 1="Error during communication", 2="Server stopped"
  - Error 1 triggers at 0x0602272E/0x060227B8 for non-IV bytes while CONNECTED

## Remaining Work for Server v3
- Game content data extraction (items, monsters, maps from binary data sections)
- Game logic (battle formulas, encounter triggers, level-up calculations)
- Multi-user state management
- RSA32 login encryption handling (Fujitsu RSA32.dll)

## User Preferences
- Wants 100% working implementation, no stubs or guesses
- Wants ALL handlers fully implemented from binary analysis
- Will wait for thorough analysis — NO assumptions
- Testing with real Saturn hardware via DreamPi on local network
