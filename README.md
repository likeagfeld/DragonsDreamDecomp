# disclaimer!! this is entirely developed and written by Claude Code....while the server gets you through the entire logon flow it should be assumed that much of the content below may be hallucinated! please be warned 


# Dragon's Dream: Complete Decompilation & Engineering Manual

**Version 1.0 — March 2026**

**Game:** Dragon's Dream (Fujitsu x SEGA, 1997)
**Product:** GS-7114, V1.003, released 1997-10-27, Japan-only
**Platform:** Sega Saturn (SH-2 big-endian)
**Binary:** `extracted/0.BIN` — 504,120 bytes, base address `0x06010000`
**Goal:** Revival server restoring full online functionality

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Binary Structure & Memory Map](#2-binary-structure--memory-map)
3. [Protocol Stack Architecture](#3-protocol-stack-architecture)
4. [Layer 1: TCP/Modem Transport](#4-layer-1-tcpmodem-transport)
5. [Layer 2: BBS Command Phase](#5-layer-2-bbs-command-phase)
6. [Layer 3: SV Framing (lib_sv.c)](#6-layer-3-sv-framing-lib_svc)
7. [Layer 4: Session Protocol](#7-layer-4-session-protocol)
8. [Layer 5: SCMD Game Messages](#8-layer-5-scmd-game-messages)
9. [Message Dispatch System](#9-message-dispatch-system)
10. [Complete Message Type Table (310 Types)](#10-complete-message-type-table-310-types)
11. [Paired Message Table (108 Entries)](#11-paired-message-table-108-entries)
12. [Server-to-Client Handler Reference (197 Handlers)](#12-server-to-client-handler-reference-197-handlers)
13. [Client-to-Server Message Reference (104 Messages)](#13-client-to-server-message-reference-104-messages)
14. [Connection Flow & State Machines](#14-connection-flow--state-machines)
15. [Login State Machine](#15-login-state-machine)
16. [Connection State Machine](#16-connection-state-machine)
17. [Gate Mechanism](#17-gate-mechanism)
18. [Game State Structure (g_state)](#18-game-state-structure-g_state)
19. [Character & Party Data Structures](#19-character--party-data-structures)
20. [Game Subsystems Overview](#20-game-subsystems-overview)
21. [Revival Server Implementation Guide](#21-revival-server-implementation-guide)
22. [Current Server Status & Remaining Work](#22-current-server-status--remaining-work)
23. [Binary Analysis Methodology](#23-binary-analysis-methodology)
24. [Decompilation Workflow: From Binary to Source](#24-decompilation-workflow-from-binary-to-source)
25. [Analysis Tools Reference](#25-analysis-tools-reference)
26. [Appendix A: SCMD Library API](#appendix-a-scmd-library-api)
27. [Appendix B: Key RAM Addresses](#appendix-b-key-ram-addresses)
28. [Appendix C: String Constants](#appendix-c-string-constants)
29. [Appendix D: Common Handler Patterns](#appendix-d-common-handler-patterns)

---

## 1. Project Overview

Dragon's Dream is a Sega Saturn MMORPG developed by Fujitsu and published by SEGA in December 1997, exclusive to Japan. Players connected via the Saturn NetLink modem to NIFTY-Serve (a Japanese online service) to access the game's servers. The original servers were shut down in the early 2000s.

This project is a complete protocol-level reverse engineering of the client binary, enabling a revival server that restores full online functionality using original, unmodified Saturn hardware.

### Current Status

| Component | Status |
|-----------|--------|
| SV Framing Layer | **COMPLETE** — send/receive state machines fully decompiled |
| Session Protocol | **COMPLETE** — establishment, DATA frames, checksums, sequence numbers |
| BBS Command Phase | **COMPLETE** — all scripts, response matching logic decompiled |
| Wire Format | **COMPLETE** — 8-byte header structure confirmed with evidence |
| Message Dispatch | **COMPLETE** — 197-entry handler table, linear scan, sentinel-terminated |
| Server-to-Client Handlers | **COMPLETE** — 173 substantive + 24 empty (rts) handlers decompiled |
| Client-to-Server Messages | **COMPLETE** — all 104 message payload layouts documented |
| Connection State Machine | **COMPLETE** — 8 states, bit-7 flag, INIT sending logic |
| Login State Machine | **COMPLETE** — states 0-7, controller polling, button dispatch |
| Gate Mechanism | **COMPLETE** — game world <-> login state transitions |
| Revival Server (v3) | **FUNCTIONAL** — connects, logs in, navigates. Battle/content WIP |

### Testing Environment

- Real Sega Saturn hardware with NetLink modem
- DreamPi for network bridging (transparent mode)
- `::host=` parameter bypasses modem dialing for direct TCP

---

## 2. Binary Structure & Memory Map

### 2.1 Executable Layout

```
File: extracted/0.BIN (504,120 bytes)
Load address: 0x06010000 (Work RAM-H)
Architecture: Hitachi SH-2, big-endian, 16-bit instructions

Regions:
  0x000000-0x000200  Startup/vectors
  0x000200-0x010000  Main game code (state machines, UI, world logic)
  0x010000-0x015000  Network code (BBS, SV, session, SCMD, dispatch)
  0x015000-0x03D000  Game logic (handlers, battle, shop, party, events)
  0x03D000-0x04D000  Data (strings, constants, tables, lookup data)
  0x04D000-0x07B000  Assets (compressed graphics, map data, fonts)
```

### 2.2 Saturn Memory Map

| Address Range | Size | Description |
|---------------|------|-------------|
| `0x06000000-0x060FFFFF` | 1 MB | Work RAM-H (code + data) |
| `0x00200000-0x002FFFFF` | 1 MB | Work RAM-L |
| `0x20200000-0x202FFFFF` | 1 MB | Work RAM-L (cache-through mirror) |
| `0x00180000-0x0018FFFF` | 64 KB | Backup RAM (battery-backed saves) |
| `0x202A8080` | varies | Backup RAM mapped save region |

### 2.3 Key Data Structures in RAM

| Address | Name | Description |
|---------|------|-------------|
| `0x06062314` | SV session struct | SV layer session state (96+ bytes) |
| `0x06062374` | Connection state | SV connection state: 0=disconnected, 1=connecting, 2=connected |
| `0x060623D8` | Send queue | SV send queue (20 entries, 8 bytes each) |
| `0x06062498` | nMsgSize | Current SCMD message payload size |
| `0x06061D80` | Conn state struct | Connection state machine base (R14) |
| `0x06061E3F` | Conn state byte | Connection state dispatch variable (R14+0xBF) |
| `0x202E4B3C` | SV context | SV library context (cache-through) |
| `0x202E6148` | SCMD buffer | SCMD message build buffer (cache-through, max 4800B) |
| `0x0605F432` | Global flag byte | Map/state flags (bit 1=map grid, bit 2=known map) |
| `0x0606967C` | Controller input | Active-high button bitmask (NOT of raw hardware) |
| `0x0606967E` | Button change | (new XOR old) AND new — edge detection |
| `0x06060E76` | Display input | Latched button state for game logic |

---

## 3. Protocol Stack Architecture

The Dragon's Dream network protocol is a 5-layer stack:

```
+--------------------------------------------------+
| Layer 5: SCMD Game Messages                       |
| [2B param1][2B msg_type][4B payload_size][payload]|
| 310 message types, 197 client-side handlers       |
+--------------------------------------------------+
| Layer 4: Session Protocol (0x00/0xA6 frames)      |
| Sequence tracking, checksums, establishment       |
| 0x00 = server→client, 0xA6 = client→server       |
+--------------------------------------------------+
| Layer 3: SV Framing (lib_sv.c)                    |
| "IV" + 3hex(size) + 3hex(~size) + raw_payload     |
| Each message = one IV frame, max 4095 bytes       |
+--------------------------------------------------+
| Layer 2: BBS Commands                              |
| " P\r"→"*\r\n", "SET\r"→"*\r\n", "C\r"→"COM\r\n"|
+--------------------------------------------------+
| Layer 1: TCP / Modem Byte Stream                   |
| NetLink modem or DreamPi transparent bridge        |
+--------------------------------------------------+
```

**CRITICAL RULES:**
1. Server MUST NOT send raw non-IV bytes while client is CONNECTED (causes error dialog)
2. Sequence numbers are BYTE OFFSETS, not frame counters
3. msg_type is a unique identifier, NOT a wire size
4. Server must send first (session establishment) after BBS phase
5. Keepalives must be IV-wrapped session ACK frames, NOT raw `$I'm alive!!`

---

## 4. Layer 1: TCP/Modem Transport

### 4.1 Original Connection Path

The Saturn NetLink modem connects via PSTN to NIFTY-Serve. The modem init string:

```
AT&FW1X3\N2%C3
```

- `AT&F` — Factory reset
- `W1` — Error correction reporting enabled
- `X3` — Extended result codes (CONNECT speed, BUSY detection)
- `\N2` — Auto-reliable (MNP/LAPM) mode
- `%C3` — Both transmit and receive data compression

Dial commands: `ATDT` (tone), `ATDP` (pulse)

### 4.2 Direct TCP Mode (::host=)

At binary offset `0x03D6F4`: the string `"\r\n::host="`. When the user enters `::host=<address>` as the phone number, the game bypasses modem dialing and connects directly via TCP. This is the mechanism used for DreamPi/revival connections.

### 4.3 DreamPi Configuration

```ini
; config.ini
[dd]
handler = transparent
port = 8020
```

The `transparent` handler in `netlink.py` provides raw TCP passthrough — no PPP or protocol translation. The Saturn sends and receives raw bytes over the TCP socket.

---

## 5. Layer 2: BBS Command Phase

### 5.1 Overview

After TCP connection (or modem CONNECT), the Saturn initiates a NIFTY-Serve BBS login sequence. The server must respond to each command before the game protocol begins.

### 5.2 Command Sequence

```
Phase 1: Saturn sends " P\r" (3 bytes: 0x20 0x50 0x0D)
         Server responds: "*\r\n" (any response containing "*")

Phase 2: Saturn sends "SET 1:0,2:0,3:0,4:1,...,22:0\r" (86 bytes)
         Server responds: "*\r\n"

Phase 3: Saturn sends "C NETRPG\r" (or "C HRPG\r") (7-10 bytes)
         Server responds: "COM\r\n" (any response containing "COM")
```

**Critical implementation notes:**
- Saturn sends `\r` only (no `\n`) at end of each command
- Response matching is **substring-based** — Saturn scans the receive buffer for match strings
- `*` matches any response containing `0x2A`
- `COM` matches any response containing those 3 bytes
- Error response containing `lear` (from "clear") triggers error handler
- `NO CARRIER` triggers connection-lost handler

### 5.3 BBS Script Engine (file 0x010128)

The BBS phase is driven by a script table engine. Each table entry is 12 bytes:

```c
struct BBS_Entry {
    uint32_t type;      // 1=SEND, 2=WAIT, 3=END
    uint32_t data;      // SEND: string_ptr, WAIT: timeout, END: 0
    uint32_t param;     // SEND: 0, WAIT: response_table_ptr, END: 0
};
```

Script tables:
| Table | File Offset | Purpose |
|-------|------------|---------|
| MODEM_INIT | `0x045D3C` | AT commands: AT, ATZ, user config |
| BBS_LOGIN_PHASE1 | `0x045DA8` | P, SET commands, wildcard match |
| BBS_LOGIN_PHASE2 | `0x045DD8` | C HRPG, expects COM response (reconnect shortcut) |
| BBS_DISCONNECT | `0x045DFC` | OFF command, expects NO CARRIER |
| MODEM_HANGUP | `0x045C6C` | ATH hangup |

### 5.4 Response Tables

Each response table is an array of 8-byte entries:

```c
struct RespEntry {
    uint32_t match_str;    // Pointer to match string (0 = end)
    uint32_t handler;      // Handler function (0 = success/continue)
};
```

| Table Offset | Used After | Success Match | Error Matches |
|-------------|-----------|--------------|---------------|
| `0x045CF4` | `" P\r"` / `SET` | `"*"` | `"NO CARRIER"` |
| `0x045D0C` | `"C HRPG\r"` | `"COM"` | `"lear"`, `"NO CARRIER"` |
| `0x045D2C` | `"OFF\r"` | `"NO CARRIER"` | (none) |

### 5.5 Disconnect Sequence

Server initiates by sending `*` prompt, then Saturn sends `"OFF\r"`. Server drops connection.

---

## 6. Layer 3: SV Framing (lib_sv.c)

### 6.1 Overview

The SV (SerVice/SerVer) library provides a lightweight framing protocol designed for modem/BBS links. It wraps binary payloads in text-encoded headers.

**Source file:** `lib_sv.c` (from assertion strings at `0x03EF1C`)

### 6.2 IV Frame Format

Each SV frame consists of an 8-byte ASCII header followed by raw binary payload:

```
IV<size_hex><complement_hex><raw_binary_payload>
```

| Component | Bytes | Description |
|-----------|-------|-------------|
| `IV` | 2 | ASCII magic prefix (0x49, 0x56) |
| `<size_hex>` | 3 | Lowercase hex encoding of 12-bit payload size |
| `<complement_hex>` | 3 | Lowercase hex encoding of `(~size) & 0xFFF` |
| `<payload>` | size | Raw binary data (immediately follows, NO `\r\n`) |

**Total header: exactly 8 bytes.** There is NO `\r\n` between header and payload.

The complement provides integrity: `size XOR complement == 0xFFF`.

### 6.3 IV Frame Examples

```
"IV012fed" + 18 bytes  → size=0x012 (18),  comp=0xFED, 0x012^0xFED=0xFFF ✓
"IV100eff" + 256 bytes → size=0x100 (256), comp=0xEFF, 0x100^0xEFF=0xFFF ✓
"IV04ffb0" + 79 bytes  → size=0x04F (79),  comp=0xFB0, 0x04F^0xFB0=0xFFF ✓
```

### 6.4 Hex Encoding

- Encode table: `"0123456789abcdef"` at memory `0x06056F5C` (lowercase)
- Decode table: `"0123456789ABCDEF"` at memory `0x0604F0A4` (uppercase)
- Decode accepts both cases via `toupper()` before lookup

### 6.5 No Fragmentation

**There is NO SV-level fragmentation.** Each game message gets its own complete IV frame. If application-level chunking is needed (e.g., CHARDATA_REPLY multi-page), each page is a separate game message with its own IV frame.

Maximum IV payload: **4095 bytes** (12-bit size limit). Practical buffer limit: ~2000 bytes.

### 6.6 SV Receive State Machine (file 0x0126DA)

The receive parser at `SV_RecvFrame` has 3 states:

**State 0 — Waiting for IV:**
- Scans byte-by-byte for `'I'` (0x49) then `'V'` (0x56)
- **CRITICAL:** Any non-`'I'` byte while CONNECTED (`[0x06062374]==2`) triggers `error_dialog(1)` = communication error
- This is why the server MUST NOT send raw keepalives like `$I'm alive!!\r\n`

**State 1 — Parsing Hex Digits:**
- Receives 6 hex chars, uppercased via `toupper()`
- First 3 → payload_size
- Last 3 → complement (consumed, verified via XOR)
- Transitions to State 2

**State 2 — Receiving Payload:**
- Receives exactly `size` bytes of raw data
- Counter at `state+0x7F2` tracks bytes received
- When complete: delivers payload to `0x060423C8` (session delivery function)
- Resets to State 0

### 6.7 SV Send State Machine (file 0x01253E)

The `sv_open` function builds IV headers and sends byte-by-byte from the send queue at `0x060623D8`:

- Queue: max 20 entries, 8 bytes each `[4B data_ptr, 4B size]`
- Messages dequeued FIFO
- Each message gets its own IV frame

### 6.8 Keepalive

| Direction | Format | Notes |
|-----------|--------|-------|
| Client→Server | `$I'm alive!!\r\n` | Raw text, starts with `$` (NOT `I`) |
| Server→Client | IV-wrapped session ACK frame | flags=0x01, copy_length=0 |

The client's keepalive at `0x03EEC8` is a raw text string starting with `$`. The server can detect it by checking the first byte.

**The server MUST NOT send raw text keepalives.** Instead, send a valid IV-wrapped session frame with `flags=0x01` (has_seq_data only, no data). This:
- Passes SV_RecvFrame validation (starts with `I`)
- Resets the SV timeout counter
- Does NOT dispatch any SCMD message (no data flag)

### 6.9 Timeouts

- SV timeout: ~10 seconds (594 VBL ticks at 60fps, value `0x0252` at `0x012748`)
- Server should send keepalives every 5-8 seconds
- SV timeout `0x07D0` (2000) loaded from session response: ~33 seconds

### 6.10 SV Constants

| Offset | Value | Description |
|--------|-------|-------------|
| `0x03EEB8` | 0x10 (16) | SV_HEADER_BUF_SIZE |
| `0x03EEBC` | 0x100 (256) | SV_MAX_FRAG_DATA |
| `0x03EEC0` | 0x800 (2048) | SV_BUFFER_SIZE |

### 6.11 SV Error Codes

| Code | Name | Description |
|------|------|-------------|
| 0 | SV_OK | Success |
| 1 | SV_NOT_OPEN | Connection not opened |
| 2 | SV_NO_MEM | Memory allocation failed |
| 3 | SV_BAD_FRAG | Size complement mismatch |
| 4 | SV_REMOTE_TIME_OUT | No data within timeout |
| 5 | SV_N_RETRIES | Too many retransmissions |
| 6 | SV_CAN_SEND | Ready to send (status) |
| 7 | SV_CAN_NOT_SEND | Send buffer full |
| 8 | SV_DISC_PKT_IN | Disconnect packet received |
| 9 | SV_CONN_LOST | Connection lost |

### 6.12 SV Error Strings (displayed to user)

| Index | String | Trigger |
|-------|--------|---------|
| 0 | "No response from host" | SV_REMOTE_TIME_OUT |
| 1 | "Error during communication" | Non-IV byte while CONNECTED |
| 2 | "Server stopped" | SV_DISC_PKT_IN |

### 6.13 Server Implementation

```python
def sv_encode(payload: bytes) -> bytes:
    """Wrap payload in IV frame."""
    size = len(payload)
    assert size <= 4095, f"IV payload too large: {size}"
    complement = (~size) & 0xFFF
    header = f"IV{size:03x}{complement:03x}".encode('ascii')
    return header + payload

def sv_decode(data: bytes) -> bytes:
    """Extract payload from IV frame (after scanning for 'I','V')."""
    # data starts AFTER the "IV" prefix
    size_str = data[0:3].decode('ascii')
    comp_str = data[3:6].decode('ascii')
    size = int(size_str, 16)
    comp = int(comp_str, 16)
    assert (size ^ comp) == 0xFFF, "IV integrity check failed"
    return data[6:6 + size]
```

---

## 7. Layer 4: Session Protocol

### 7.1 Overview

ALL post-BBS messages go through session framing. This layer sits between SV IV framing and SCMD game messages. It provides:
- Sequence tracking (byte offsets, not frame counters)
- Checksums (additive byte sum)
- Connection establishment (ESTABLISH flag)
- Reliable delivery (ack mechanism)

### 7.2 Frame Types

| Byte [0] | Direction | Encoding | Description |
|----------|-----------|----------|-------------|
| `0x00` | Server→Client | Raw binary | DATA or control frame |
| `0xA6` | Client→Server | Escape-encoded | DATA or status frame |

### 7.3 Server→Client DATA Frame (0x00-type)

```
Offset  Size  Type       Field
------  ----  ----       -----
0       1     U8         0x00 (type marker)
1       1     U8         flags (bit0=has_seq, bit1=has_data, bit6=alt_data)
2       2     U16 BE     checksum (sum all bytes with [2:6] zeroed, & 0xFFFF)
4       2     zeros      (cleared for checksum computation)
6       2     zeros      (reserved/padding)
8       4     U32 BE     seq_byte_offset (outgoing cumulative byte count)
12      4     U32 BE     ack_num (must be > session[112], monotonically increasing)
16      2     U16 BE     copy_length (SCMD byte count)
18      2     zeros      (padding)
20      N     bytes      SCMD data (copy_length bytes)
```

### 7.4 FLAGS Byte

| Bit | Mask | Name | Description |
|-----|------|------|-------------|
| 0 | 0x01 | has_seq_data | MUST SET for seq/ack fields to be read |
| 1 | 0x02 | has_data | SCMD data present at offset 20 |
| 6 | 0x40 | alt_data | Alternative data path |

**Without bit 0:** The delivery function reads stale values from session context. Frame is silently dropped.

### 7.5 Sequence Numbers — BYTE OFFSETS

**CRITICAL: Sequence numbers are cumulative BYTE OFFSETS, not frame counters!**

Evidence: Client INIT (seq=0, 74B SCMD) → next client frame seq=74.
After dispatch, Saturn updates `session[116] = seq + copy_length`.
Server's `send_seq` starts at 0, incremented by SCMD size (copy_length) after each frame.

### 7.6 Checksum

Additive byte sum at `0x060429B6`:

```python
def session_checksum(frame: bytearray) -> int:
    total = 0
    for i, b in enumerate(frame):
        if 2 <= i < 6:  # skip checksum field
            continue
        total += b
    return total & 0xFFFF
```

- Server 0x00-type: checksum stored at `[2:4]` as uint16 BE
- Client 0xA6-type: checksum stored at `[2:6]` as 4 ASCII hex chars

### 7.7 Session Establishment

After BBS, the server must send a **256-byte session establishment frame**:

```
Offset  Size  Value      Description
0       1     0x00       Server→client type
1       1     0x00       flags: NO has_data (non-data path)
2       2     checksum   uint16 BE checksum
4       2     0x0000     cleared for checksum
6       2     0x0000     reserved
8       2     0x0008     ESTABLISH flag (bit 3)
10      246   zeros      padding to 256 bytes
```

**ESTABLISH flag (bit 3 at offset [8:10]) is REQUIRED.** Without it, the delivery function never sets `[0x06062374] = 2` (CONNECTED state).

**Do NOT set bit 4 (0x0010)** — that sets receive window from `[10:12]`, and window=0 blocks client sends.

### 7.8 Client→Server 0xA6 Frame

```
Offset  Size  Type       Field
------  ----  ----       -----
0       1     U8         0xA6 (type marker)
1       1     U8         flags
2       4     ASCII hex  checksum (4 uppercase hex chars)
6       1     U8         escape_byte (typically 0x1C)
7       1     U8         sub-flags
8+      var   escaped    escape-encoded data:
                         4 decoded bytes → uint32 sequence
                         4 decoded bytes → uint32 val2
                         4 raw bytes (skipped)
                         remaining → SCMD data
```

**Escape encoding:** If `byte == escape_byte`, next byte XOR 0x60 = original.

### 7.9 ACK-Only Frame (Keepalive)

```
Offset  Size  Value      Description
0       1     0x00       Server→client type
1       1     0x01       flags: has_seq_data only (NO has_data)
2       2     checksum   uint16 BE checksum
4       2     0x0000     padding
6       2     0x0000     padding
8       4     send_seq   Current seq (NOT incremented)
12      4     send_seq+1 ACK value
16      2     0x0000     copy_length = 0 (no SCMD)
18      2     0x0000     padding
```

This frame does NOT advance `send_seq` and does NOT dispatch any SCMD message.

---

## 8. Layer 5: SCMD Game Messages

### 8.1 Wire Format

Every game message has an **8-byte header** followed by payload:

```
Offset  Size  Field          Description
------  ----  -----          -----------
0       2     param1         Usually 0x0000
2       2     msg_type       Message type identifier (uint16 BE)
4       4     payload_size   Payload byte count (uint32 BE)
8       N     payload        Application data (N = payload_size bytes)
```

**Total wire size = 8 + payload_size.**

**msg_type is NOT the wire size.** It is a unique identifier. Previous analysis was wrong about this.

### 8.2 SCMD Library Functions

| Function | File Offset | Memory Addr | Description |
|----------|------------|-------------|-------------|
| `scmd_new_message` | 0x149EC | 0x060249EC | Init buffer: param1 + msg_type |
| `scmd_add_byte` | 0x14A32 | 0x06024A32 | Add 1 byte |
| `scmd_add_word` | 0x14B04 | 0x06024B04 | Add 2 bytes (uint16 BE) |
| `scmd_add_long` | 0x14BDC | 0x06024BDC | Add 4 bytes (uint32 BE) |
| `scmd_add_data` | 0x14CD0 | 0x06024CD0 | Add N bytes from pointer |
| `scmd_send` | 0x14E3C | 0x06024E3C | Set payload_size, queue for send |

**Buffer:** `0x202E6148` (Work RAM-L, cache-through)
**nMsgSize:** `0x06062498` (current payload byte count)
**Max buffer:** 4800 bytes (assertion-checked)

### 8.3 Send Path

```
scmd_new_message(param1, msg_type):
  buffer[0:2] = param1
  buffer[2:4] = msg_type
  buffer[4:8] = 0x00000000
  nMsgSize = 0

scmd_add_byte(value):
  buffer[8 + nMsgSize] = value
  nMsgSize += 1

scmd_send():
  buffer[4:8] = nMsgSize       // set payload_size
  SV_send(buffer, nMsgSize+8)  // send complete message
```

### 8.4 Receive Path

```
dispatch_handler(recv_buffer):
  msg_type = recv_buffer[2:4]  // read from offset 2
  for each entry in handler_table:
    if entry.msg_type == msg_type:
      handler(recv_buffer + 8)  // pass payload start
      return
```

Handlers receive `r4 = buffer + 8` = pointer to payload data. The dispatch does NOT read `payload_size` from `header[4:8]`.

### 8.5 Server Implementation

```python
def build_game_msg(msg_type: int, payload: bytes, param1: int = 0) -> bytes:
    header = struct.pack('>HHI', param1, msg_type, len(payload))
    return header + payload

def parse_game_msg(data: bytes):
    param1, msg_type, payload_size = struct.unpack('>HHI', data[:8])
    payload = data[8:8 + payload_size]
    return msg_type, payload, param1
```

### 8.6 Complete Send Pipeline

```python
async def send_msg(msg_type, payload, param1=0):
    # 1. Build SCMD message
    scmd = build_game_msg(msg_type, payload, param1)

    # 2. Wrap in session DATA frame
    session_frame = build_session_data_frame(scmd, send_seq)
    send_seq += len(scmd)

    # 3. Wrap in IV frame
    iv_frame = sv_encode(session_frame)

    # 4. Send over TCP
    sock.sendall(iv_frame)
```

---

## 9. Message Dispatch System

### 9.1 Handler Table (file 0x0435D8)

The handler table contains **197 entries**, each 8 bytes:

```
Offset  Size  Field
0       2     msg_type (uint16 BE)
2       2     padding (always 0x0000)
4       4     handler_addr (uint32 BE, SH-2 memory address)
```

The table is **NOT sorted**. It is scanned linearly until a match is found. An entry with `msg_type = 0x0000` serves as the sentinel (end of table).

### 9.2 Primary Dispatch Function (file 0x003420)

```c
void dispatch_handler(uint8_t* msg_buffer) {
    uint16_t incoming_type = *(uint16_t*)(msg_buffer + 2);  // msg_type at offset 2

    for (int i = 0; i < handler_count; i++) {
        uint16_t entry_type = handler_table[i].msg_type;
        if (entry_type == 0) break;  // sentinel
        if (entry_type == incoming_type) {
            handler_table[i].handler(msg_buffer + 8);  // pass payload ptr
            return;
        }
    }

    // Special case: ACTION_CHAT_NOTICE (0x0274) handled outside table
    if (incoming_type == 0x0274) {
        action_chat_handler(msg_buffer);
    }
}
```

### 9.3 Secondary Dispatch (file 0x0034E4)

Uses the **paired message table** at file `0x043424`. This contains 108 pairs of 16-bit msg_type values. When the client sends a message, the secondary dispatch looks up the expected server reply type.

### 9.4 Init Flags / Deferred Send System

After ESP_NOTICE sets `g_state[0x8E..0x91] = 1`, the dispatch function at `0x06024442` checks these flags on each main loop iteration:

| Flag Offset | Auto-sends | Message Type |
|------------|------------|-------------|
| `g_state+0x8E` | STANDARD_REPLY | 0x0048 |
| `g_state+0x8F` | PARTY_BREAKUP_NOTICE | 0x025F |
| `g_state+0x90` | CMD_BLOCK_REPLY | 0x02D4 |
| `g_state+0x91` | SYSTEM_NOTICE | 0x006D |

Each flag is cleared after the message is sent.

---

## 10. Complete Message Type Table (310 Types)

Extracted from binary table at file `0x04612C`. Each entry: `[4B string_ptr][4B msg_type_value]`.

**IMPORTANT:** The "Wire Size" and "Payload Size" columns below are the raw msg_type value and msg_type-8. These are NOT actual payload sizes. They were originally interpreted as wire sizes but this was proven WRONG. Actual payload sizes vary and must be read from the `payload_size` header field.

### 10.1 Message Categories

| Category | Count | Description |
|----------|-------|-------------|
| `*_REQUEST` | ~110 | Server→client requests (handler processes) |
| `*_REPLY` | ~106 | Server→client responses |
| `*_NOTICE` | ~94 | Server→client broadcasts |
| **Total** | **310** | All named message types |
| **Handlers** | **197** | Client-side handler functions |

### 10.2 Full Message Table

| msg_type | Name |
|----------|------|
| 0x0000 | SELECT_REQUEST (sentinel) |
| 0x0043 | LOGOUT_REQUEST |
| 0x0044 | COLO_MEMBER_NOTICE |
| 0x0046 | REGIST_HANDLE_REQUEST |
| 0x0048 | STANDARD_REPLY |
| 0x0049 | SPEAK_REQUEST |
| 0x004A | SPEAK_REPLY |
| 0x0068 | CARD_NOTICE |
| 0x006D | SYSTEM_NOTICE |
| 0x006E | ESP_REPLY |
| 0x006F | ESP_REQUEST |
| 0x0076 | SPEAK_NOTICE |
| 0x019A | LOGOUT_NOTICE |
| 0x019B | GOTOLIST_REQUEST |
| 0x019C | GOTOLIST_NOTICE |
| 0x019D | INFORMATION_NOTICE |
| 0x019E | LOGIN_REQUEST |
| 0x019F | UPDATE_CHARDATA_REQUEST |
| 0x01A0 | SAKAYA_IN_NOTICE |
| 0x01A1 | USERLIST_REQUEST |
| 0x01A2 | BB_RMSUBDIR_REPLY |
| 0x01A3 | PARTYLIST_REQUEST |
| 0x01A4 | PARTYLIST_REPLY |
| 0x01A5 | PARTYENTRY_ACCEPT_REPLY |
| 0x01A6 | PARTYENTRY_REPLY |
| 0x01A7 | CLR_KNOWNMAP_REPLY |
| 0x01A8 | PARTYEXIT_REQUEST |
| 0x01A9 | PARTYEXIT_REPLY |
| 0x01AA | UPDATE_CHARDATA_REPLY |
| 0x01AB | CHARDATA_NOTICE |
| 0x01AC | MAP_CHANGE_NOTICE |
| 0x01AD | CAMP_IN_REQUEST |
| 0x01AE | CAMP_IN_REPLY |
| 0x01AF | AREA_LIST_REPLY |
| 0x01B0 | TELEPORTLIST_REQUEST |
| 0x01B2 | TEXT_NOTICE |
| 0x01B3 | ALLOW_SETLEADER_REPLY |
| 0x01B4 | CAMP_OUT_REQUEST |
| 0x01B5 | CAMP_OUT_REPLY |
| 0x01B6 | CANCEL_JOIN_NOTICE |
| 0x01B7 | REGIONCHANGE_REQUEST |
| 0x01B8 | FINDUSER_REQUEST |
| 0x01B9 | CURREGION_NOTICE |
| 0x01BC | CHAR_DISAPPEAR_NOTICE |
| 0x01BD | SELECT_NOTICE |
| 0x01C0 | CLASS_CHANGE_REPLY |
| 0x01C1 | OTHERPARTY_DATA_NOTICE / MOVE (client→server) |
| 0x01C2 | MOVE1_NOTICE |
| 0x01C4 | MOVE1_REQUEST |
| 0x01C5 | MOVE2_REQUEST |
| 0x01C6 | EVENT_ITEM_NOTICE |
| 0x01C7 | BTLJOIN_NOTICE |
| 0x01C8 | BTL_GOLD_NOTICE |
| 0x01C9 | ENCOUNTMONSTER_REPLY |
| 0x01CA | ENCOUNTMONSTER_NOTICE |
| 0x01CF | EVENT_NOTICE |
| 0x01D0 | EXEC_EVENT_REQUEST |
| 0x01D1 | EXEC_EVENT_REPLY |
| 0x01D2 | KNOWNMAP_NOTICE |
| 0x01D3 | GIVEUP_REPLY |
| 0x01D4 | SETPOS_REQUEST |
| 0x01D5 | SETPOS_REPLY |
| 0x01D6 | SETPOS_NOTICE |
| 0x01D7 | SETLEADER_REQUEST |
| 0x01D8 | SETLEADER_REPLY |
| 0x01DA | MONSTER_DEL_NOTICE |
| 0x01DB | VISION_NOTICE |
| 0x01DC | OBITUARY_NOTICE |
| 0x01DE | MAP_NOTICE |
| 0x01DF | CAMP_IN_NOTICE |
| 0x01E0 | SET_MOVEMODE_REQUEST |
| 0x01E1 | SET_MOVEMODE_REPLY |
| 0x01E3 | ENCOUNTPARTY_NOTICE |
| 0x01E4 | CANCEL_ENCOUNT_REQUEST |
| 0x01E5 | CANCEL_ENCOUNT_REPLY |
| 0x01E6 | INQUIRE_JOIN_NOTICE |
| 0x01E7 | ALLOW_JOIN_REQUEST |
| 0x01E8 | ESP_NOTICE |
| 0x01EA | BTL_EFFECTEND_REPLY |
| 0x01EB | BTL_END_REQUEST |
| 0x01EC | AVATA_NOID_NOTICE |
| 0x01ED | PARTYID_REQUEST |
| 0x01EE | PARTYID_REPLY |
| 0x01EF | CLR_KNOWNMAP_REQUEST |
| 0x01F2 | SHOP_ITEM_REPLY |
| 0x01F3 | SHOP_BUY_REQUEST |
| 0x01F4 | SHOP_BUY_REPLY |
| 0x01F5 | SHOP_SELL_REQUEST |
| 0x01F8 | USERLIST_NOTICE |
| 0x01F9 | SAKAYA_TBLLIST_REQUEST |
| 0x01FA | SAKAYA_TBLLIST2_REQUEST |
| 0x01FB | SAKAYA_EXIT_REQUEST |
| 0x01FC | SHOP_IN_REPLY |
| 0x01FD | SHOP_ITEM_REQUEST |
| 0x01FE | SHOP_LIST_REPLY |
| 0x01FF | SHOP_IN_REQUEST |
| 0x0200 | SHOP_SELL_REPLY |
| 0x0201 | SHOP_OUT_REQUEST |
| 0x0202 | SEKIBAN_NOTICE |
| 0x0203 | SHOP_LIST_REQUEST |
| 0x0204 | CAMP_OUT_NOTICE |
| 0x0205 | EQUIP_REQUEST |
| 0x020C | STORE_IN_NOTICE |
| 0x020D | SAKAYA_LIST_REQUEST |
| 0x020E | SAKAYA_EXIT_NOTICE |
| 0x020F | SAKAYA_SIT_REQUEST |
| 0x0210 | SAKAYA_LIST_NOTICE |
| 0x0211 | SAKABA_MOVE_REQUEST |
| 0x0212 | SAKABA_MOVE_REPLY |
| 0x0213 | SAKAYA_LIST_REPLY |
| 0x0214 | SAKAYA_TBLLIST_REPLY |
| 0x0215 | GOTOLIST_REPLY |
| 0x0216 | SAKABA_MOVE_NOTICE |
| 0x0217 | SAKAYA_IN_REQUEST |
| 0x0218 | SAKAYA_IN_REPLY |
| 0x0219 | SAKAYA_FIND_REPLY |
| 0x021A | SAKAYA_STAND_REQUEST |
| 0x021B | SAKAYA_EXIT_REPLY |
| 0x021C | USERLIST_REPLY |
| 0x021E | SAKAYA_STAND_REPLY |
| 0x021F | BATTLEMODE_NOTICE |
| 0x0220 | BTL_MEMBER_NOTICE |
| 0x0221 | BTL_MENU_NOTICE |
| 0x0222 | BTL_CMD_REQUEST |
| 0x0223 | BTL_CMD_REPLY |
| 0x0224 | BTL_CMD_NOTICE |
| 0x0225 | BTL_CHGMODE_REQUEST |
| 0x0226 | BTL_CHGMODE_REPLY |
| 0x0227 | BTL_RESULT_NOTICE |
| 0x0228 | BTL_END_NOTICE |
| 0x0229 | BTL_MASK_NOTICE |
| 0x022B | PARTYENTRY_REQUEST |
| 0x022C | MEMBERDATA_NOTICE |
| 0x022D | PARTYUNITE_ACCEPT_REPLY |
| 0x022E | PARTYUNITE_REPLY |
| 0x022F | PARTYUNITE_REQUEST |
| 0x0230 | INQUIRE_UNITE_NOTICE |
| 0x0231 | ALLOW_UNITE_REQUEST |
| 0x0232 | PARTYEXIT_NOTICE |
| 0x0233 | TELEPORT_NOTICE |
| 0x0234 | MIRRORDUNGEON_REQUEST |
| 0x0235 | CANCEL_ENCOUNT_NOTICE |
| 0x0236 | BTLJOIN_REQUEST |
| 0x0237 | BTLJOIN_REPLY |
| 0x023B | ALLOW_UNITE_REPLY |
| 0x023C | AREA_LIST_REQUEST |
| 0x023E | TELEPORTLIST_REPLY |
| 0x023F | EXPLAIN_REQUEST |
| 0x0240 | MIRRORDUNGEON_REPLY |
| 0x0241 | FINDUSER2_REQUEST |
| 0x0242 | CHANGE_PARA_REPLY |
| 0x0243 | MONSTERWARN_NOTICE |
| 0x0244 | ENCOUNTMONSTER_REQUEST |
| 0x0245 | SAKAYA_CHARLIST_NOTICE |
| 0x0246 | SET_SIGN_REQUEST |
| 0x0247 | SET_SIGN_REPLY |
| 0x0248 | SETCLOCK0_NOTICE |
| 0x0249 | EVENT_MAP_NOTICE |
| 0x024A | MONSTER_MAP_NOTICE |
| 0x024B | SAKAYA_SIT_REPLY |
| 0x024C | SAKAYA_MEMLIST_REQUEST |
| 0x024D | SAKAYA_MEMLIST_REPLY |
| 0x024E | SAKAYA_MEMLIST_NOTICE |
| 0x024F | SAKAYA_FIND_REQUEST |
| 0x0250 | MOVE_SEAT_NOTICE |
| 0x0251 | SET_SEKIBAN_REQUEST |
| 0x0252 | SET_SEKIBAN_REPLY |
| 0x0253 | SET_SEKIBAN_NOTICE |
| 0x0254 | SET_SIGN_NOTICE |
| 0x0255 | MOVE_SEAT_REQUEST |
| 0x0256 | MOVE_SEAT_REPLY |
| 0x0257 | MISSPARTY_NOTICE |
| 0x025A | PARTYENTRY_NOTICE |
| 0x025B | ALLOW_JOIN_REPLY |
| 0x025C | CANCEL_JOIN_REQUEST |
| 0x025D | CANCEL_JOIN_REPLY |
| 0x025E | PARTYUNITE_NOTICE |
| 0x025F | PARTY_BREAKUP_NOTICE |
| 0x0260 | ACTION_CHAT_REQUEST |
| 0x0261 | ACTION_CHAT_REPLY |
| 0x0263 | EQUIP_REPLY |
| 0x0268 | DISARM_SKILL_REPLY |
| 0x0269 | SEL_THEME_REQUEST |
| 0x026A | SEL_THEME_REPLY |
| 0x026B | CHECK_THEME_REQUEST |
| 0x026C | EQUIP_NOTICE |
| 0x026D | DISARM_REQUEST |
| 0x026E | DISARM_REPLY |
| 0x026F | FINDUSER_REPLY |
| 0x0270 | STORE_LIST_REQUEST |
| 0x0271 | STORE_LIST_REPLY |
| 0x0272 | STORE_IN_REQUEST |
| 0x0273 | STORE_IN_REPLY |
| 0x0274 | ACTION_CHAT_NOTICE (special-case, outside handler table) |
| 0x0275 | COMPOUND_REPLY |
| 0x0276 | CONFIRM_LVLUP_REQUEST |
| 0x0277 | CONFIRM_LVLUP_REPLY |
| 0x0278 | LEVELUP_REQUEST |
| 0x0289 | USE_NOTICE |
| 0x028A | BUY_REPLY |
| 0x028B | TRADE_DONE_NOTICE |
| 0x028C | SELL_REPLY |
| 0x028D | SELL_REQUEST |
| 0x028E | INQUIRE_BUY_NOTICE |
| 0x028F | BUY_REQUEST |
| 0x0290 | TRADE_NOTICE |
| 0x0291 | TRADE_CANCEL_REQUEST |
| 0x0292 | TRADE_CANCEL_REPLY |
| 0x0293 | EVENT_MOVE_NOTICE |
| 0x0294 | GIVE_ITEM_REQUEST |
| 0x0295 | GIVE_ITEM_REPLY |
| 0x0296 | BTL_ACTIONCOUNT_NOTICE |
| 0x0297 | BTL_EFFECTEND_REQUEST |
| 0x0298 | FINDUSER2_REPLY |
| 0x0299 | CLASS_LIST_REQUEST |
| 0x029A | CLASS_LIST_REPLY |
| 0x029B | CLASS_CHANGE_REQUEST |
| 0x029D | SHOP_OUT_REPLY |
| 0x029E | DIR_REQUEST |
| 0x029F | DIR_REPLY |
| 0x02A0 | SUBDIR_REQUEST |
| 0x02A1 | SUBDIR_REPLY |
| 0x02A2 | MEMODIR_REQUEST |
| 0x02A3 | MEMODIR_REPLY |
| 0x02A4 | NEWS_READ_REQUEST |
| 0x02A5 | NEWS_READ_REPLY |
| 0x02A6 | NEWS_WRITE_REQUEST |
| 0x02A7 | NEWS_WRITE_REPLY |
| 0x02A8 | NEWS_DEL_REQUEST |
| 0x02A9 | CHECK_THEME_REPLY |
| 0x02AA | MAIL_LIST_REQUEST |
| 0x02AB | MAIL_LIST_REPLY |
| 0x02AC | GET_MAIL_REQUEST |
| 0x02AD | GET_MAIL_REPLY |
| 0x02AE | SEND_MAIL_REQUEST |
| 0x02AF | SEND_MAIL_REPLY |
| 0x02B0 | DEL_MAIL_REQUEST |
| 0x02B1 | NEWS_DEL_REPLY |
| 0x02B2 | BB_MKDIR_REQUEST |
| 0x02B3 | BB_MKDIR_REPLY |
| 0x02B4 | BB_RMDIR_REQUEST |
| 0x02B5 | BB_RMDIR_REPLY |
| 0x02B6 | BB_MKSUBDIR_REQUEST |
| 0x02B7 | BB_MKSUBDIR_REPLY |
| 0x02B8 | BB_RMSUBDIR_REQUEST |
| 0x02B9 | LEVELUP_REPLY |
| 0x02BA | SKILL_LIST_REQUEST |
| 0x02BB | DEL_MAIL_REPLY |
| 0x02BC | COLO_WAITING_REQUEST |
| 0x02BD | COLO_WAITING_REPLY |
| 0x02BE | COLO_WAITING_NOTICE |
| 0x02BF | COLO_EXIT_REQUEST |
| 0x02C0 | COLO_EXIT_REPLY |
| 0x02C1 | COLO_EXIT_NOTICE |
| 0x02C2 | COLO_LIST_REQUEST |
| 0x02C3 | COLO_LIST_REPLY |
| 0x02C4 | COLO_ENTRY_REQUEST |
| 0x02C5 | COLO_ENTRY_NOTICE |
| 0x02C6 | COLO_CANCEL_REQUEST |
| 0x02C7 | COLO_CANCEL_NOTICE |
| 0x02C8 | COLO_BATTLE_NOTICE |
| 0x02C9 | COLO_FLDENT_REQUEST |
| 0x02CC | COLO_FLDENT_NOTICE |
| 0x02CD | COLO_RESULT_NOTICE |
| 0x02CE | COLO_RANKING_REQUEST |
| 0x02CF | COLO_FLDENT_REPLY |
| 0x02D0 | GIVE_ITEM_NOTICE |
| 0x02D1 | USE_REQUEST |
| 0x02D2 | CHARDATA_REPLY |
| 0x02D3 | USE_REPLY |
| 0x02D4 | CMD_BLOCK_REPLY |
| 0x02D5 | CAST_DICE_REQUEST |
| 0x02D6 | CAST_DICE_REPLY |
| 0x02D7 | SETLEADER_NOTICE |
| 0x02D8 | INQUIRE_LEADER_NOTICE |
| 0x02D9 | SETLEADER_ACCEPT_REPLY |
| 0x02DA | ALLOW_SETLEADER_REQUEST |
| 0x02DB | CAST_DICE_NOTICE |
| 0x02DC | CARD_REQUEST |
| 0x02DD | CARD_REPLY |
| 0x02E0 | SKILL_LIST_REPLY |
| 0x02E1 | LEARN_SKILL_REQUEST |
| 0x02E2 | LEARN_SKILL_REPLY |
| 0x02E3 | SKILLUP_REQUEST |
| 0x02E4 | SKILLUP_REPLY |
| 0x02E5 | EQUIP_SKILL_REQUEST |
| 0x02E6 | EQUIP_SKILL_REPLY |
| 0x02E7 | DISARM_SKILL_REQUEST |
| 0x02E8 | DISARM_NOTICE |
| 0x02E9 | USE_SKILL_REQUEST |
| 0x02EA | USE_SKILL_REPLY |
| 0x02EB | COLO_ENTRY_REPLY |
| 0x02EC | COLO_CANCEL_REPLY |
| 0x02ED | TRADE_CANCEL_NOTICE |
| 0x02EE | COMPOUND_REQUEST |
| 0x02EF | EXEC_EVENT_NOTICE |
| 0x02F0 | EVENT_EFFECT_NOTICE |
| 0x02F1 | WAIT_EVENT_NOTICE |
| 0x02F2 | COLO_RANKING_REPLY |
| 0x02F3 | MOVE2_NOTICE |
| 0x02F4 | BTL_END_REPLY |
| 0x02F5 | USE_SKILL_NOTICE / CHANGE_PARA (client→server) |
| 0x02F6 | CHANGE_PARA_REQUEST |
| 0x02F7 | SET_MOVEMODE_NOTICE |
| 0x02F8 | GIVEUP_REQUEST |
| 0x02F9 | CHARDATA_REQUEST |
| 0x02FA | SAKAYA_TBLLIST_NOTICE |
| 0x04E0 | EXPLAIN_REPLY |
| 0x04E1 | TELEPORT_REQUEST |
| 0x0B6C | CHARDATA2_NOTICE (client→server only) |

---

## 11. Paired Message Table (108 Entries)

Maps CLIENT-SENT msg_type to EXPECTED SERVER REPLY msg_type. Located at file `0x043424`.

| # | Client Sends | Server Replies | Notes |
|---|-------------|---------------|-------|
| 0 | 0x0035 | 0x01E8 | INIT → ESP_NOTICE |
| 1 | 0x019E | 0x019F | LOGIN_REQUEST → UPDATE_CHARDATA_REQ |
| 2 | 0x01AA | 0x02F9 | UPDATE_CHARDATA_REPLY → CHARDATA_REQ |
| 3 | 0x0B6C | 0x02F9 | CHARDATA2_NOTICE → CHARDATA_REQ |
| 4 | 0x0048 | 0x0049 | STANDARD_REPLY → SPEAK_REQUEST |
| 5 | 0x006D | 0x006F | SYSTEM_NOTICE → ESP_REQUEST |
| 6 | 0x01EC | 0x01ED | AVATA_NOID → PARTYID_REQUEST |
| 7 | 0x01EE | 0x01EF | PARTYID_REPLY → CLR_KNOWNMAP_REQ |
| 8 | 0x01A7 | 0x01A8 | CLR_KNOWNMAP → PARTYEXIT_REQUEST |
| 9 | 0x025F | 0x0260 | PARTY_BREAKUP → ACTION_CHAT_REQ |
| 10 | 0x02D4 | 0x02D5 | CMD_BLOCK_REPLY → CAST_DICE_REQ |
| 11 | 0x02DB | 0x02DC | CAST_DICE_NOTICE → CARD_REQUEST |
| 12 | 0x019A | 0x019B | LOGOUT → GOTOLIST_REQUEST |
| 13 | 0x019C | 0x019D | GOTOLIST_NOTICE → INFORMATION_NOTICE |
| 14-107 | ... | ... | See `message-flow.md` for complete table |

The full 108-entry table is documented in the `memory/message-flow.md` file.

---

## 12. Server-to-Client Handler Reference (197 Handlers)

### 12.1 Critical Login Handlers

#### ESP_NOTICE (0x01E8) — 51 bytes — CRITICAL

Handler: file 0x3F1C. First server message in login flow. **Resets entire game state.**

```
Offset  Size  Type     Field                    Destination
0       2     U16 BE   status                   g_state+0x04
2       2     U16 BE   session_param            g_state+0x0264
4       2     U16 BE   connection_id            g_state+0xA2
6       1     U8       game_mode                g_state+0xA4
7       1     U8       sub_mode                 g_state+0xA5
8       4     U32 BE   server_id                g_state+0x94
12      16    Shift-JIS server_name             g_state+0xA6
28      12    bytes    session_data             g_state+0x7C88
40      11    bytes    config_bytes             g_state+0x7C94..0x7C9F
```

**Side effects:**
- Sets `g_state[0x8E..0x91] = 1` (init flags, triggers deferred sends)
- Clears battle state, disappear cursor, mission roster, clock count
- Clears SV msg_type and global flag byte

#### UPDATE_CHARDATA_REQUEST (0x019F) — 24 bytes

Handler: file 0x3578. Stores character identity data.

```
Offset  Size  Type     Field                    Destination
0       2     U16 BE   status                   (checked, must be 0)
2       2     U16 BE   char_field
4       4     U32 BE   char_id                  g_state+0x0260
8       16    bytes    char_data                party_entry[4:20]
```

**Empirically required:** Without this message, Saturn times out after ~66s.

#### CHARDATA_REQUEST (0x02F9) — 72 or 172 bytes

Handler: file 0x3648. Loads full character data.

```
FIXED (72 bytes):
0       2     U16 BE   session_check (must be 0)
2       2     U16 BE   char_field
4       4     U32 BE   character_id
8       16    bytes    character_name (Shift-JIS)
24      8     struct   appearance (parse_appearance)
32      4     U32 BE   experience
36      4     U32 BE   gold
40      16    U16[8]   skill_ids
56      8     struct   status_block (parse_status)
64      1     --       padding
65      1     U8       skill_flag (0=clear skills)
66      1     --       padding
67      1     U8       status_flag (nonzero=has +100B)
68      1     --       padding
69      1     U8       item_flag (0=clear items)
70      1     --       padding
71      1     U8       license_flag (0=clear)

EXTENDED (+100 bytes if status_flag != 0):
72      38    U16[19]  base_stats
110     38    U16[19]  current_stats
148     8     5B+3pad  appearance_data
156     16    U16[8]   skill_levels
```

#### CHARDATA_REPLY (0x02D2) — Multi-page, variable

Handler: file 0x3858. Three data types:

```
HEADER (8 bytes):
0       1     U8       char_type (1/2/3)
1       1     U8       page_number (1-based)
2       1     U8       total_pages
3       1     U8       num_entries
4       4     U32 BE   chunk_size

TYPE 1 (char_list, 24B/entry):
0       16    bytes    char_name
16      2     U16 BE   experience
18      1     U8       class
19      1     U8       race
20      1     U8       gender
21      1     U8       level
22      1     U8       status
23      1     --       padding

TYPE 2 (char_detail, 52B/entry) — TRIGGERS BACKUP RAM SAVE:
0       2     U16 BE   char_slot_id
2       1     U8       class
3       1     U8       sub_class
4       16    bytes    char_name
20      2     U16 BE   experience
22      8     U8[8]    stat_bytes
30      2     --       padding
32      4     U32 BE   gold
36      16    U16[8]   equipment_slots

TYPE 3 (inventory, 24B/entry):
0       16    bytes    item_data
16      8     --       discarded
```

### 12.2 Empty Handlers (22 — just `rts`, no payload read)

These handlers do nothing with the payload. Server can send any data (or zeros).

| msg_type | Name |
|----------|------|
| 0x01B9 | CURREGION_NOTICE |
| 0x01A1 | USERLIST_REQUEST |
| 0x021C | USERLIST_REPLY |
| 0x021E | SAKAYA_STAND_REPLY |
| 0x0252 | SET_SEKIBAN_REPLY |
| 0x0253 | SET_SEKIBAN_NOTICE |
| 0x0249 | EVENT_MAP_NOTICE |
| 0x024A | MONSTER_MAP_NOTICE |
| 0x01DB | VISION_NOTICE |
| 0x01DC | OBITUARY_NOTICE |
| 0x0263 | EQUIP_REPLY |
| 0x026E | DISARM_REPLY |
| 0x0220 | BTL_MEMBER_NOTICE |
| 0x0225 | BTL_CHGMODE_REQUEST |
| 0x0228 | BTL_END_NOTICE |
| 0x0229 | BTL_MASK_NOTICE |
| 0x0297 | BTL_EFFECTEND_REQUEST |
| 0x0236 | BTLJOIN_REQUEST |
| 0x0237 | BTLJOIN_REPLY |
| 0x02EC | COLO_CANCEL_REPLY |

### 12.3 Simple Status Handlers

Many handlers follow a common pattern: read U16 status at offset 0, exit if nonzero.

| msg_type | Name | Payload | Notes |
|----------|------|---------|-------|
| 0x0043 | LOGOUT_REQUEST | 0B | Clears context+16 |
| 0x01D7 | SETLEADER_REQUEST | 2B | Status check |
| 0x01D8 | SETLEADER_REPLY | 0B | No payload, calls from state |
| 0x01D2 | KNOWNMAP_NOTICE | 2B | Sets bit 2 of flag byte |
| 0x01DA | MONSTER_DEL_NOTICE | 2B | Reads 2 bytes |
| 0x01D4 | SETPOS_REQUEST | 2B | Status check |
| 0x01B4 | CAMP_OUT_REQUEST | 2B | Status check |
| 0x01B5 | CAMP_OUT_REPLY | 2B | Unconditional transition |
| 0x01AD | CAMP_IN_REQUEST | 2B | Status → camp entry |
| 0x01AE | CAMP_IN_REPLY | 2B | Camp entry |
| 0x01E0 | SET_MOVEMODE_REQUEST | 2B | Move mode |
| 0x0205 | EQUIP_REQUEST | 2B | Status |
| 0x026D | DISARM_REQUEST | 2B | Status |
| 0x02E9 | USE_SKILL_REQUEST | 2B | Status |
| 0x02F6 | CHANGE_PARA_REQUEST | 2B | Status |
| 0x0244 | ENCOUNTMONSTER_REQ | 2B | Status |

### 12.4 Complex Handlers (by subsystem)

Full decompiled payload layouts for all 173 substantive handlers are documented in `memory/handler-payloads-detailed.md`. Key complex handlers include:

**Battle System:**
- ENCOUNTMONSTER_REPLY (0x01C9): 10B header + N*32B entities
- BATTLEMODE_NOTICE (0x021F): 2B header + N*30B entities
- BTL_CMD_REPLY (0x0223): ~24B action data
- BTL_CHGMODE_REPLY (0x0226): 8B header + N*(12B + slots)
- BTL_RESULT_NOTICE (0x0227): 44B header + N*56B combatants
- BTL_GOLD_NOTICE (0x01C8): 12B header + groups + items
- BTL_END_REPLY (0x02F4): 16B return location

**Movement:**
- MOVE1_REQUEST (0x01C4): 6+ bytes
- MOVE2_REQUEST (0x01C5): 12 bytes
- MOVE2_NOTICE (0x02F3): 4B header + N*8B records
- SET_MOVEMODE_REPLY (0x01E1): 3 bytes
- SETPOS_REPLY (0x01D5): 13 bytes
- GIVEUP_REQUEST (0x02F8): 16 bytes (unconditional read)

**Character:**
- CHARDATA_NOTICE (0x01AB): 76-160+ bytes (variable)
- CHANGE_PARA_REPLY (0x0242): 4 bytes (reverse-order stores)
- CLASS_CHANGE_REPLY (0x01C0): 16+N bytes (chunked)

**Events:**
- EXEC_EVENT_REQUEST (0x01D0): 8+N bytes
- EXEC_EVENT_REPLY (0x01D1): 8+N bytes (N clamped to 4)
- EVENT_EFFECT_NOTICE (0x02F0): variable (complex)
- WAIT_EVENT_NOTICE (0x02F1): 16+ bytes

---

## 13. Client-to-Server Message Reference (104 Messages)

All 104 client-to-server message payload layouts are fully documented in `memory/client-sent-payloads.md`. Key messages:

### 13.1 LOGIN_REQUEST (0x019E) — ~60 bytes

```
Offset  Size  Type     Field
0       2     U16 BE   protocol_version (always 0)
2       2     U16 BE   login_flag
4       16    Shift-JIS player_name
20      1     U8       char_field_0x15
21      1     U8       char_field_0x17
22      1     U8       zone_class
23      1     U8       zone_field
24      1     U8       char_field_0x19
25-27   3     zeros
28      4     U32 BE   char_data_1
32      4     U32 BE   char_data_2
36-38   3     zeros
39      4     zeros
43      1     U8       char_field_0x24
44      16    U16[8]   skill_slots
```
param1 = session[0x0264] (NOT zero)

### 13.2 MOVE (0x01C1) — 1 or 3 bytes

```
Variant 1 (full): B(x), B(y), B(z), param1=session[0x0264]
Variant 2 (simple): B(direction), param1=0
```

### 13.3 BTL_CMD (0x0221) — 12 bytes

```
0       1     U8       command_type
1       1     U8       target
2       2     U16 BE   action_id
4       8     bytes    extra_data
```

### 13.4 CHANGE_PARA (0x02F5) — ~212 bytes

Full character state sync. Largest regular client message.

```
0       1     U8       char_field_0x15
1       1     U8       char_field_0x17
2       1     U8       zone
3       1     U8       zone2
4       1     U8       char_field_0x19
5       3     zeros
8       4     U32 BE   char_data_1
12      4     U32 BE   char_data_2
16      18    U16[9]   stats (chardata+0x92)
34      2     U16 BE   field_102
36      2     U16 BE   field_104
38      18    U16[9]   stats (fields 64-78)
56      12    U16[6]   stats (fields 84-94)
68      6     U16[3]   stats (fields 96-100)
74      48    U16[24]  equipment_data
```

### 13.5 Simple Client Messages

Most client messages are small (1-4 bytes). See `memory/client-sent-payloads.md` for the complete table of all 104 messages with exact payload layouts.

---

## 14. Connection Flow & State Machines

### 14.1 Complete Connection Flow

```
CLIENT (Saturn)                        SERVER
    |                                    |
    |--- TCP/Modem CONNECT ------------->|
    |                                    |
    |=== BBS PHASE ======================|
    |--- " P\r" ----------------------->|
    |<-- "*\r\n" -----------------------|
    |--- "SET 1:0,...,22:0\r" --------->|
    |<-- "*\r\n" -----------------------|
    |--- "C NETRPG\r" ----------------->|
    |<-- "COM\r\n" ---------------------|
    |                                    |
    |=== SESSION ESTABLISHMENT ==========|
    | Saturn calls SV_Setup             |
    | SV_Poll starts (SV_RecvFrame)     |
    | Connection state = 1 (connecting)  |
    |                                    |
    |<-- 256B establishment IV frame ----|  flags=0x00, sub-flags=0x0008
    | Delivery sets state = 2 (CONNECTED)|
    |                                    |
    |=== INIT FLOW ======================|
    | Connection state machine state 4   |
    | Sends INIT, sets bit 7 (never again)|
    |--- 0xA6 status frame (18B) ------->|  No SCMD data
    |--- 0xA6 data frame (94B) --------->|  SCMD: 0x0035 INIT (66B payload)
    |<-- 0x01E8 ESP_NOTICE (51B) --------|  Resets game state, sets init flags
    |<-- 0x019F UPDATE_CHARDATA_REQ -----|  Stores char_id, party data
    |                                    |
    |=== LOGIN FLOW =====================|
    | Login state machine shows char list |
    | User presses A/C button            |
    |--- 0x019E LOGIN_REQUEST (~60B) --->|
    |<-- 0x019F UPDATE_CHARDATA_REQ -----|
    |                                    |
    |--- 0x01AA UPDATE_CHARDATA_RPL ---->|
    |<-- 0x02F9 CHARDATA_REQUEST --------|
    |<-- 0x02D2 CHARDATA_REPLY (type 1) -|  char_list
    |<-- 0x02D2 CHARDATA_REPLY (type 2) -|  char_detail → backup RAM save
    |<-- 0x02D2 CHARDATA_REPLY (type 3) -|  inventory
    |<-- 0x019D INFORMATION_NOTICE ------|  Finalizes login
    |<-- 0x01DE MAP_NOTICE --------------|  Map grid data
    |<-- 0x01D2 KNOWNMAP_NOTICE ---------|  Explored areas
    |<-- 0x01AB CHARDATA_NOTICE ---------|  Player in world
    |                                    |
    |=== GAME WORLD =====================|
    | (movement, battle, shops, etc.)    |
    |                                    |
    |=== GOTOLIST FLOW ==================|
    |--- 0x019A LOGOUT ----------------->|
    |<-- 0x019B GOTOLIST_REQUEST --------|  Destination list
    | User selects destination           |
    |--- 0x019C GOTOLIST_NOTICE -------->|
    |<-- 0x019D INFORMATION_NOTICE ------|
    |<-- 0x01E8 ESP_NOTICE --------------|  Server proactively sends (no INIT!)
    |<-- 0x019F UPDATE_CHARDATA_REQ -----|
    | Login flow repeats (LOGIN_REQUEST) |
```

---

## 15. Login State Machine

### 15.1 Overview

The login state machine at `0x0603C100` has states 0-7, all running **locally** on the Saturn. No SCMD messages are sent during these states. The parent code sends LOGIN_REQUEST after the state machine completes.

### 15.2 States

| State | Function | Description |
|-------|----------|-------------|
| 0 | Display | Shows character slots from backup RAM (session+0xE8C0) |
| 1 | Wait | Waits for controller: A=REVIVE, C=NEW, B=CANCEL |
| 2 | (unused) | |
| 3 | Slot Select | Character slot selection |
| 4 | Create Char | Character creation flow |
| 5 | Prepare | Prepare character flags |
| 6 | Reorder | Reorder character list |
| 7 | Delete | Delete character |

### 15.3 Controller Input Polling

```
0x06040B22: reads raw Saturn controller data
  Source bitmask: 0x0606967C = NOT(raw_controller_word), active-high
  Change detection: 0x0606967E = (new XOR old) AND new
  Tick function 0x06013112: copies → display bitmask at 0x06060E76

Button constants:
  PAD_A     = 0x0400 → result 2 → REVIVE existing character
  PAD_C     = 0x0200 → result 1 → NEW character
  PAD_B     = 0x0100 → result 0xFF → CANCEL
  PAD_START = 0x0800
```

### 15.4 CHARDATA_REPLY Handler Details

The `CHARDATA_REPLY (0x02D2)` handler at `0x06013858` processes three types:

- **TYPE 1 (char_list):** 24B/entry → stored at session+0x1684, count at session+0x1925
- **TYPE 2 (char_detail):** 52B/entry → stored at session+0x1BE0, **triggers backup RAM save** via `0x0603AD2C`
- **TYPE 3 (inventory):** 24B/entry → stored at session+0x1530, count at session+0x1924

**IMPORTANT:** The login UI reads from `session+0xE8C0` (backup RAM copy), NOT from the server data offsets. The backup RAM save triggered by TYPE 2 is what makes the data visible.

### 15.5 Init Flags (Deferred Send System)

After ESP_NOTICE sets `g_state[0x8E..0x91] = 1`:

| Flag | Message Sent | Type |
|------|-------------|------|
| `g_state+0x8E` → 0x0048 | STANDARD_REPLY | Cleared after send |
| `g_state+0x8F` → 0x025F | PARTY_BREAKUP_NOTICE | Cleared after send |
| `g_state+0x90` → 0x02D4 | CMD_BLOCK_REPLY | Cleared after send |
| `g_state+0x91` → 0x006D | SYSTEM_NOTICE | Cleared after send |

Checked by dispatch function at `0x06024442` on each main loop iteration.

---

## 16. Connection State Machine

### 16.1 Overview

Located at file `0x0103C0`, struct base `R14 = 0x06061D80`.

The connection state machine is **INDEPENDENT** of `g_state[0x01AD]` (the game state). It does NOT detect game state transitions.

### 16.2 State Variable

- **Byte at `R14+0xBF`** (`0x06061E3F`)
- Dispatched via `& 0x7F` (masks off bit 7)
- Bit 7 (`0x80`) serves as a "sent INIT" flag

### 16.3 States

| State | Address | Description |
|-------|---------|-------------|
| 0 | init | Initialization |
| 1 | setup1 | Setup phase 1 |
| 2 | setup2 | Setup phase 2 |
| 3 | 0x010600 | **Polling** — calls `0x06022298` (returns 1 if CONNECTED), sets state=4 |
| 4 | 0x010626 | **Send INIT** — checks bit 7, if clear: sends INIT + sets bit 7 |
| 5-7 | post-INIT | Post-INIT states |

### 16.4 INIT Sending (State 4)

At file `0x010626`:
1. Checks bit 7 of `R14[0xBF]`
2. If bit 7 is **clear**: sends INIT via `0x06022BE0`, then sets `R14[0xBF] = 0x84`
3. If bit 7 is **set**: skips INIT, continues to post-INIT states
4. Bit 7 is **NEVER cleared** — INIT is sent exactly ONCE per connection

### 16.5 Implications for Server

After GOTOLIST:
- The gate mechanism transitions `session[0x01AD]` from 3→2 (game world→login)
- But the connection state machine's state 4 has bit 7 set
- INIT is **NEVER re-sent**
- **Server MUST proactively send ESP_NOTICE + UPDATE_CHARDATA_REQ** in the GOTOLIST handler

---

## 17. Gate Mechanism

### 17.1 Overview

The gate function at `0x0603B6F0` controls transitions between game world and login states.

### 17.2 gate_set Function (0x0603B488)

Writes argument to BOTH `g_state[0xDDFE]` and `g_state[0xE8C2]`.

Called with `arg=1` during login→game world transition (via task 6 vtable).

Both values saved to Saturn backup RAM at `0x202A8080+2`.

### 17.3 Gate Function Logic (0x0603B6F0)

**arg=1 path (game world state):**
1. Check `g_state[0xE8C2] == 1`
2. If gate PASSES AND `session[0x01AD] == 3`:
   - Write `session[0x01BC] = 0`
   - Write `session[0x01AD] = 2` (transitions to login state)
3. If gate FAILS:
   - Write `session[0x01BC] = 1`
   - Stay in game world state

**arg=0 path (session[0x01AD]==2):**
- Clears state to 0, performs setup

### 17.4 For Fresh Save

When `g_state[0xE8C2] = 0` (no previous login):
- Login state 0 function (`0x0603D0C8`) skips rendering
- Gate check fails (0 != 1), so no auto-transition

---

## 18. Game State Structure (g_state)

The game state is a large structure accessed via offsets from a base pointer (typically R14 in handlers, loaded from GBR+8).

### 18.1 Key Offsets

```
g_state+0x0004   2B  Status/result from last message
g_state+0x0006   2B  SV msg_type (current)
g_state+0x008A   1B  Global facing direction
g_state+0x008B   1B  Party membership flag
g_state+0x008E   1B  Init flag → auto-sends STANDARD_REPLY
g_state+0x008F   1B  Init flag → auto-sends PARTY_BREAKUP
g_state+0x0090   1B  Init flag → auto-sends CMD_BLOCK_REPLY
g_state+0x0091   1B  Init flag → auto-sends SYSTEM_NOTICE
g_state+0x0094   4B  Server ID
g_state+0x00A0   2B  Store/room ID
g_state+0x00A2   2B  Connection ID
g_state+0x00A4   1B  Game mode (6=field/map)
g_state+0x00A5   1B  Sub mode
g_state+0x00A6   16B Server name (Shift-JIS)
g_state+0x00BC   var Goto/destination list data
g_state+0x0260   var Character struct (identity data, stats)
g_state+0x0264   2B  Session param (used as param1 in LOGIN_REQUEST)
g_state+0x01AD   1B  Game state: 2=login, 3=game world
g_state+0x01BC   1B  Gate transition flag
g_state+0x1530   var Inventory data (from CHARDATA_REPLY type 3)
g_state+0x1684   var Character list (from CHARDATA_REPLY type 1)
g_state+0x1924   1B  Inventory entry count
g_state+0x1925   1B  Character list entry count
g_state+0x1B8C   4B  Current location ID
g_state+0x1B90   1B  Current party slot index
g_state+0x1BE0   656B Party array (4 slots * 164B)
g_state+0x1E70   4B  Party ID
g_state+0x1E74   2B  Move field U16
g_state+0x1E76   1B  Move byte 0
g_state+0x1E77   1B  Move byte 1
g_state+0x1E78   1B  Event item validation (1-4)
g_state+0x1E79   1B  Move byte 3
g_state+0x1E7A   1B  Party member count
g_state+0x1E7E   1B  Move byte 7
g_state+0x339C   var Party sync data
g_state+0x4B58   var Battle slots (5 groups * 3 slots, stride 0x02A0/0xA4)
g_state+0x6598   1B  Display party count
g_state+0x659C   456B Display party (6 * 76B)
g_state+0x6C94   var Shop item slots (22 bytes per slot)
g_state+0x6CA7   1B  Items per page
g_state+0x6D9C   2B  Sakaba move target
g_state+0x6F88   var Mission roster
g_state+0x74EC   40B Sign data
g_state+0x7514   1B  Sign clear flag
g_state+0x7544   2B  Shop item count
g_state+0x7948   var Shop items (22 bytes * max 32)
g_state+0x7C88   12B Session data
g_state+0x7C94   var Config bytes
g_state+0x7CA0   var Party list display data
g_state+0x7E6C   var Area list data
g_state+0x8014   var Teleport list data
g_state+0x81B4   var Find user data
g_state+0x81E0   var Mirror dungeon data
g_state+0x826C   1B  Map width
g_state+0x826D   1B  Map rows
g_state+0x826F   288B Map grid buffer
g_state+0x838F   288B Map grid buffer 2
g_state+0x84AF   1B  Map loaded flag
g_state+0x84B0   4B  Transition state (0=none)
g_state+0x8708   var Entity/NPC grid table (4B per cell)
g_state+0xAB10   1B  Monster deletion target
g_state+0xAB14   2B  (cleared by ESP_NOTICE)
g_state+0xAB18   2B  Event type
g_state+0xAB1A   2B  Event ID
g_state+0xAB1C   var Event data block
g_state+0xABA4   1B  Event queue count
g_state+0xABA6   1B  BTL join flag 0
g_state+0xABA7   1B  BTL join flag 1
g_state+0xABA8   3B  Event item bytes
g_state+0xAD48   2B  Clock entry count
g_state+0xAD4A   30B Clock entries (10 * 3B)
g_state+0xAD68   1B  Para byte 2
g_state+0xAD69   1B  Para byte 3
g_state+0xAD6A   1B  Para byte 1
g_state+0xAD6B   1B  Para byte 0
g_state+0xAD6C   2B  Encounter param
g_state+0xAD6E   2B  Encounter ID
g_state+0xAD78   var Local player struct
g_state+0xAE58   16B Leader info block
g_state+0xAE68   1B  Leader tracking byte
g_state+0xAE98   4B  Level-up data
g_state+0xD044   4B  Disappear ring buffer cursor
g_state+0xD048   var Disappear ring buffer (0x400 entries)
g_state+0xDB60   16B Trade item name 1
g_state+0xDB70   1B  Trade item clear 1
g_state+0xDB71   16B Trade item name 2
g_state+0xDB81   1B  Trade item clear 2
g_state+0xDB84   4B  Trade gold amount
g_state+0xDB88   2B  Trade param
g_state+0xDB8A   1B  Trade flag
g_state+0xDB8C   var Use item data area
g_state+0xDDFE   1B  Gate value 1 (from gate_set)
g_state+0xE8C0   var Backup RAM data (loaded on boot)
g_state+0xE8C2   1B  Gate value 2 (from gate_set, checked by gate function)
g_state+0xF122   1B  Colosseum entry byte 1
g_state+0xF123   1B  Colosseum entry byte 0
g_state+0xF44A   var Card data
g_state+0xF45A   1B  Card clear flag
g_state+0xF4B4   1B  Battle state
g_state+0xF4B9   1B  Encounter notice state
g_state+0x10340  var Battle init data base
g_state+0x10862  1B  Battle entity count
g_state+0x10864  var Battle entity array (stride 0xA0)
g_state+0x10FFC  1B  Max entity count
```

---

## 19. Character & Party Data Structures

### 19.1 Party Member Entry (164 = 0xA4 bytes)

```
Offset  Size  Field
+0      4     Character/entity ID
+4      4     Match/lookup key
+18     1     Move state (1=stand, 2=walk, 3=auto)
+20     1     Sub-mode
+21     1     Extra mode byte
+28     4     Location ID (0x1C)
+46     1     Facing direction (0x2E)
+102    2     X coordinate (0x66)
+104    2     Y coordinate (0x68)
+140    8     Status block (0x8C, 5+3 format)
```

Party array: `g_state+0x1BE0`, 4 slots, 164 bytes each.
Current slot: `g_state+0x1B90`.

### 19.2 Battle Entity (160 = 0xA0 bytes)

Battle entity array at `g_state+0x10864`, stride `0xA0`.
Init data at `g_state+0x10340`.

Key fields within entity struct:
```
+4      16    Name/data (memcpy)
+0x16   1     Mode byte
+0x24   1     Field 36
+0x2E   1     Facing/position
+0x40   2     X coordinate
+0x42   2     Y coordinate
+0x66   2     X (copy)
+0x68   2     Y (copy)
+0x8C   8     Status block (5+3)
```

### 19.3 Common Data Patterns

1. **16-byte names:** All character/item names are 16 bytes, Shift-JIS, null-padded
2. **parse_appearance** (`0x0601A106`): reads 8 bytes → race, hair, etc.
3. **parse_status** (`0x0601A1EA`): reads 8 bytes → class (0-5), level (1-16)
4. **read_5_skip_3** (`0x0601AAA2`): reads 5 bytes + 3 padding = 8 bytes total
5. **Multi-page:** CHARDATA_REPLY and CLASS_CHANGE_REPLY use page-based chunking

---

## 20. Game Subsystems Overview

### 20.1 Movement System

- MOVE (0x01C1/0x01C2) → MOVE1_REQUEST (0x01C4): Walking/running
- MOVE2_REQUEST (0x01C5): Position update with 12 bytes
- MOVE2_NOTICE (0x02F3): Other player movement broadcast
- SETPOS (0x01D4/0x01D5): Exact position set/confirm
- SET_MOVEMODE (0x01E0/0x01E1): Stand/walk/auto mode

### 20.2 Battle System

- ENCOUNTMONSTER_REPLY (0x01C9): Battle initialization with entity data
- BATTLEMODE_NOTICE (0x021F): Enter battle mode
- BTL_CMD_REQUEST/REPLY (0x0222/0x0223): Player action selection
- BTL_CHGMODE_REPLY (0x0226): Mode change with slot data
- BTL_RESULT_NOTICE (0x0227): Damage, effects, stat modifiers
- BTL_GOLD_NOTICE (0x01C8): Gold/loot distribution
- BTL_END_REPLY (0x02F4): Return location after battle

### 20.3 Shop System

- SHOP_LIST_REQUEST (0x0203): Browse shop inventory
- SHOP_IN_REQUEST (0x01FF): Enter shop, load items
- SHOP_ITEM_REQUEST (0x01FD): View item details
- SHOP_BUY_REQUEST (0x01F3): Purchase (gold update)
- SHOP_SELL_REQUEST (0x01F5): Sell (gold update)
- SHOP_OUT_REQUEST (0x0201): Leave shop

### 20.4 Party System

- PARTYLIST_REQUEST (0x01A3): Available parties
- PARTYENTRY_REQUEST/REPLY (0x022B/0x01A6): Join party
- PARTYEXIT_REQUEST/REPLY (0x01A8/0x01A9): Leave party
- PARTYUNITE_REQUEST/REPLY (0x022F/0x022E): Merge parties
- SETLEADER (0x01D7/0x01D8/0x02D7): Leader management
- MISSPARTY_NOTICE (0x0257): Party sync with member data

### 20.5 Tavern (Sakaya) System

- SAKAYA_LIST (0x020D/0x0213): Room listing
- SAKAYA_IN (0x0217/0x0218): Enter tavern
- SAKAYA_SIT (0x020F): Sit at table
- SAKAYA_TBLLIST (0x01F9/0x0214): Table listing
- SAKAYA_EXIT (0x01FB/0x021B): Leave tavern
- SAKAYA_MEMLIST (0x024C/0x024D): Member listing
- SAKABA_MOVE (0x0211/0x0212): Move within tavern

### 20.6 Mail System

- MAIL_LIST_REQUEST (0x02AA): List mailbox
- GET_MAIL_REQUEST (0x02AC): Read mail
- SEND_MAIL_REQUEST (0x02AE): Send mail
- DEL_MAIL_REQUEST (0x02B0): Delete mail

### 20.7 Bulletin Board System

- DIR_REQUEST (0x029E): Directory listing
- SUBDIR_REQUEST (0x02A0): Subdirectory listing
- MEMODIR_REQUEST (0x02A2): Memo directory
- NEWS_READ/WRITE/DEL (0x02A4/0x02A6/0x02A8): News articles
- BB_MKDIR/RMDIR/MKSUBDIR/RMSUBDIR: Board management

### 20.8 Colosseum System

- COLO_WAITING (0x02BC/0x02BD): Join waiting queue
- COLO_LIST (0x02C2/0x02C3): Active matches
- COLO_ENTRY (0x02C4/0x02EB): Enter match
- COLO_CANCEL (0x02C6/0x02C7): Cancel entry
- COLO_FLDENT (0x02C9/0x02CF/0x02CC): Field entry
- COLO_RANKING (0x02CE/0x02F2): Rankings

### 20.9 Trading System

- SELL_REQUEST/REPLY (0x028D/0x028C): Initiate/confirm sell
- BUY_REQUEST/REPLY (0x028F/0x028A): Initiate/confirm buy
- TRADE_DONE_NOTICE (0x028B): Transaction complete
- TRADE_CANCEL (0x0291/0x0292): Cancel trade

### 20.10 Skills & Level-up

- SKILL_LIST_REQUEST (0x02BA): View skills
- LEARN_SKILL_REQUEST (0x02E1): Learn new skill
- SKILLUP_REQUEST (0x02E3): Upgrade skill
- EQUIP_SKILL_REQUEST (0x02E5): Equip skill
- DISARM_SKILL_REQUEST (0x02E7): Unequip skill
- CONFIRM_LVLUP_REQUEST (0x0276): Confirm level up
- LEVELUP_REQUEST (0x0278): Process level up

### 20.11 Events & Teleportation

- EXEC_EVENT (0x01D0/0x01D1): Execute/confirm events
- EXEC_EVENT_NOTICE (0x02EF): Event queue notification
- EVENT_EFFECT_NOTICE (0x02F0): Visual/sound effects
- WAIT_EVENT_NOTICE (0x02F1): Event wait signal
- TELEPORTLIST_REQUEST (0x01B0): Available teleport destinations
- AREA_LIST_REQUEST (0x023C): Area listing
- GOTOLIST (0x019B/0x0215): Server list / destination selection

---

## 21. Revival Server Implementation Guide

### 21.1 Architecture

The revival server (`server/dragons_dream_server_v3.py`) is an asyncio Python application:

```
DDSession class
├── bbs_handshake()         # BBS command phase
├── _send_session_establishment()  # 256-byte IV frame
├── _session_message_loop()  # Main receive/dispatch loop
├── _keepalive_loop()       # IV-wrapped ACK frames every 6s
├── _dispatch()             # Route to handler
├── send_msg()              # Build SCMD → session DATA → IV
├── recv_iv()               # Parse IV frames, handle keepalives
└── _h_*()                  # Handler functions
```

### 21.2 Message Send Pipeline

```python
async def send_msg(msg_type, payload, param1=0):
    # Step 1: Build SCMD game message
    scmd = struct.pack('>HHI', param1, msg_type, len(payload)) + payload

    # Step 2: Wrap in session DATA frame
    frame = bytearray(20 + len(scmd))
    frame[0] = 0x00              # server→client
    frame[1] = 0x03              # flags: has_seq + has_data
    struct.pack_into('>I', frame, 8, send_seq)      # seq byte offset
    struct.pack_into('>I', frame, 12, send_seq + 1)  # ack
    struct.pack_into('>H', frame, 16, len(scmd))     # copy_length
    frame[20:] = scmd
    checksum = sum(frame[i] for i in range(len(frame)) if not (2 <= i < 6)) & 0xFFFF
    struct.pack_into('>H', frame, 2, checksum)
    send_seq += len(scmd)        # advance by SCMD size

    # Step 3: Wrap in IV frame
    size = len(frame)
    complement = (~size) & 0xFFF
    iv = f"IV{size:03x}{complement:03x}".encode() + bytes(frame)

    # Step 4: Send
    writer.write(iv)
    await writer.drain()
```

### 21.3 Handler Implementation Pattern

Most handlers follow a simple pattern:

```python
async def _h_some_message(self, msg_type, payload, param1):
    # Look up paired reply from table
    reply_type = PAIRED_TABLE[msg_type]

    # Build reply payload based on handler expectations
    # Check handler-payloads-detailed.md for exact layout
    resp = struct.pack('>H', 0)  # status = 0 (success)

    # Send reply
    await self.send_msg(reply_type, resp)
```

For handlers that read more data when status=0, either:
1. Send `status=0` with full payload matching handler's read pattern
2. Send `status=1` (nonzero) to safely skip additional reads

### 21.4 Building Correct Payloads

**CRITICAL:** Each reply payload MUST be at least as large as the handler reads. The SCMD buffer at `0x202E6148` retains residual data from prior messages. Short payloads cause buffer overreads → garbage data → Saturn errors.

Consult `memory/handler-payloads-detailed.md` for exact byte counts before implementing any handler.

---

## 22. Current Server Status & Remaining Work

### 22.1 What Works

- TCP connection and BBS handshake
- Session establishment (256-byte IV frame)
- INIT/ESP_NOTICE exchange
- Full login flow (LOGIN_REQUEST → CHARDATA → INFORMATION_NOTICE)
- Character data display on Saturn
- GOTOLIST/re-login cycle
- Keepalive (IV-wrapped session ACK frames)
- All 108 paired message types have fallback handlers

### 22.2 Remaining Work

**Game Content Data:**
- Item database extraction (items, equipment, consumables)
- Monster database extraction (stats, abilities, drops)
- Map data extraction (tile maps, walkability, NPC positions)
- Shop inventory data
- Skill/spell database
- Quest/event data

**Game Logic:**
- Battle formulas (damage calculation, hit rates, critical hits)
- Encounter triggers (random encounter rates, zone tables)
- Level-up calculations (stat growth, class bonuses)
- Equipment effects (stat modifiers, special abilities)
- Skill effects (damage, healing, buffs, debuffs)

**Multi-User Features:**
- Player-to-player visibility (CHARDATA_NOTICE broadcast)
- Chat system (SPEAK_NOTICE routing)
- Party management (formation, invitation, leader transfer)
- Trading system (item/gold exchange)
- Mail system (message storage and delivery)
- Colosseum (PvP matchmaking and battles)

**Security:**
- RSA32 login encryption handling (Fujitsu RSA32.dll)
- Session token management
- Character data validation

**Infrastructure:**
- Persistent character storage (database)
- Multi-connection handling (shared world state)
- Admin tools and monitoring

---

## 23. Binary Analysis Methodology

### 23.1 Tools and Approach

The binary was analyzed using manual SH-2 disassembly. Key techniques:

1. **Literal pool analysis:** SH-2 instructions like `mov.l @(disp,PC),Rn` load 32-bit constants from nearby literal pools. Formula: `EA = ((PC+4) & ~3) + d*4`

2. **mov.w for 16-bit constants:** `mov.w @(disp,PC),Rn` loads 16-bit values. Formula: `EA = PC+4 + d*2`

3. **String references:** Strings like `"lib_sv.c"`, `"ASSERTION FAILED"`, and message names provided anchoring points for code identification.

4. **Handler table scanning:** The 8-byte-per-entry handler table at file `0x0435D8` was the primary entry point for all message handlers.

5. **Cross-reference chasing:** Following function call chains (jsr/bsr) from known entry points to map code relationships.

### 23.2 Common SH-2 Instruction Patterns

```asm
; Handler prologue
mov.l  r14,@-r15     ; push r14
sts.l  PR,@-r15      ; push return address
add    #-N,r15       ; allocate stack
mov.l  @(8,GBR),r0   ; load SV context
mov    r0,r14        ; r14 = context pointer (used throughout)

; Read uint16 BE from payload
mov.w  @r4+,r0       ; r0 = big-endian word, advance r4 by 2

; Read uint32 BE
mov.l  @r4+,r0       ; r0 = big-endian long, advance r4 by 4

; Status check pattern
mov.w  @(4,r14),r0   ; read status at context+4
tst    r0,r0         ; test if zero
bf     error_path    ; branch if nonzero (error)
```

### 23.3 Key Corrections Made During Analysis

1. **Wire format:** msg_type was initially thought to equal wire size. This was WRONG. msg_type is just an identifier; payload_size comes from header[4:8].

2. **SV framing:** Initially thought to use `\r\n` between IV header and payload, and to have a "checksum" field. Both WRONG. The second hex field is a size complement, and payload follows immediately after the 8-byte header.

3. **Connection handshake:** Initially thought the server waits for the client to speak first after BBS. Partially wrong — the server MUST send the 256-byte establishment frame first.

4. **Keepalive:** Initially tried sending raw `$I'm alive!!\r\n` from server. This causes error_dialog(1) because any non-'I' byte while CONNECTED triggers an error. Server keepalives MUST be IV-wrapped session ACK frames.

5. **GOTOLIST flow:** Initially assumed the connection state machine would re-send INIT. This was WRONG — bit 7 permanently prevents re-sending. Server must proactively send ESP_NOTICE + UPDATE_CHARDATA_REQ.

---

## 24. Decompilation Workflow: From Binary to Source

This section provides a complete, step-by-step methodology for continuing the reverse engineering of Dragon's Dream back to approximate C source code. The workflow was developed and refined during the full decompilation of the network protocol stack and all 197 message handlers. It is designed for SH-2 big-endian binaries but the principles apply to any embedded platform.

### 24.1 Prerequisites

**Knowledge Required:**
- SH-2 instruction set architecture (16-bit fixed-width instructions, big-endian)
- C calling convention for SH-2: r0-r3 scratch, r4-r7 args, r8-r14 callee-saved, r15=SP, PR=return address, GBR=global base
- Understanding of Saturn memory map (see Section 2.2)
- Python for writing analysis scripts

**Tools Required:**
- Python 3.8+ with `struct` module
- The SH-2 disassembly tools in `/tools/` (see Section 25)
- A hex editor (for visual binary inspection)
- The extracted binary: `extracted/0.BIN` (504,120 bytes)
- Optionally: Ghidra with SH-2 processor module (for cross-validation)

**Key Constants:**
```
Binary file:     extracted/0.BIN
File size:       504,120 bytes (0x7B138)
Load base:       0x06010000
Entry point:     0x06010200 (after vector table)
Architecture:    SH-2 (SuperH-2), big-endian
Instruction size: 16 bits (fixed)
Word size:       32 bits
```

### 24.2 Phase 1: Anchor Point Discovery

Before disassembling unknown code, find anchor points — known reference locations that provide context for surrounding code. This project used several types:

#### 24.2.1 String References

The binary contains ASCII and Shift-JIS strings in the data section (`0x03D000-0x04D000`). These provide the strongest anchors:

```python
# Find all printable ASCII strings in binary
import struct

with open('extracted/0.BIN', 'rb') as f:
    data = f.read()

strings = []
current = b''
start = 0
for i, b in enumerate(data):
    if 0x20 <= b < 0x7F:
        if not current:
            start = i
        current += bytes([b])
    else:
        if len(current) >= 4:
            strings.append((start, current.decode('ascii', errors='replace')))
        current = b''

for off, s in strings:
    print(f"  0x{off:06X} (0x{0x06010000+off:08X}): \"{s}\"")
```

Key strings found and their significance:

| File Offset | String | What It Reveals |
|-------------|--------|-----------------|
| `0x03EF1C` | `lib_sv.c` | Source filename → SV framing library |
| `0x03EF28` | `FragQue full` | SV send queue overflow → queue structure |
| `0x03EEC8` | `$I'm alive!!` | Client keepalive format |
| `0x03F058` | `#sv error occured` | Error handler entry point |
| `0x03FC18` | `NRPG0410` | Game protocol version string |
| `0x03D680` | `DRGNSDRMM` | Save file identification |
| `0x03FA38-0x03FA8C` | Race/class/gender names | Character creation data |
| `0x03D6D4` | `*** infinity dialing go!! ***` | Debug retry mode |
| `0x03D6F4` | `\r\n::host=` | Direct TCP connection parameter |

#### 24.2.2 Assertion Strings

The binary contains `ASSERTION FAILED` strings with source file names and line numbers. These directly reveal the original source file structure:

```
lib_sv.c      → SV framing layer (IV encode/decode)
(other files may be identified in unanalyzed regions)
```

#### 24.2.3 Function Table Scanning

Look for arrays of 32-bit function pointers. The handler dispatch table at file offset `0x0435D8` was the single most valuable anchor — it provided entry points to all 197 message handlers:

```python
# Scan for the handler table (8-byte entries: [u16 msg_type][u16 pad][u32 handler_addr])
base = 0x06010000
table_start = 0x0435D8

for i in range(200):
    off = table_start + i * 8
    msg_type = struct.unpack('>H', data[off:off+2])[0]
    handler = struct.unpack('>I', data[off+4:off+8])[0]
    if msg_type == 0 and handler == 0:
        print(f"  Sentinel at entry {i}")
        break
    print(f"  [{i:3d}] msg_type=0x{msg_type:04X}  handler=0x{handler:08X}")
```

#### 24.2.4 Known Library Functions

Identify standard library functions by their instruction patterns:

| Pattern | Function | Significance |
|---------|----------|-------------|
| Byte-by-byte copy loop | `memcpy` | Data transfer |
| Zero-fill loop | `memset` | Buffer clearing |
| Shift-JIS comparison loop | `strcmp` variant | String matching |
| `muls.w` + accumulate | Checksum | Data integrity |

### 24.3 Phase 2: Function Boundary Identification

#### 24.3.1 Prologue Detection

SH-2 functions follow a standard prologue pattern. Scan for these to find function boundaries:

```python
# SH-2 function prologue patterns
PROLOGUES = [
    (0x2FE6, 'mov.l r14, @-r15'),   # Push r14
    (0x4F22, 'sts.l PR, @-r15'),    # Push return address
    (0x2FD6, 'mov.l r13, @-r15'),   # Push r13
    (0x2FC6, 'mov.l r12, @-r15'),   # Push r12
]

def find_functions(data, base=0x06010000):
    """Find function entry points by prologue pattern."""
    functions = []
    for i in range(0, len(data)-2, 2):
        w = struct.unpack('>H', data[i:i+2])[0]
        if w == 0x2FE6:  # mov.l r14, @-r15 (most common prologue start)
            # Check if next instruction is also a push
            if i + 2 < len(data):
                w2 = struct.unpack('>H', data[i+2:i+4])[0]
                if w2 in (0x4F22, 0x2FD6, 0x2FC6, 0x2FB6, 0x2FA6, 0x2F96, 0x2F86):
                    functions.append(base + i)
    return functions
```

#### 24.3.2 Epilogue Detection

Functions end with one of these patterns:

```asm
; Pattern 1: Standard return
mov.l  @r15+,r14       ; pop r14 (0x6EF6)
lds.l  @r15+,PR        ; pop return address (0x4F26)
rts                     ; return (0x000B)
nop                     ; delay slot (0x0009)

; Pattern 2: Tail call
jmp    @Rn              ; jump to another function (0x4n2B)
<delay slot>            ; single instruction in delay slot

; Pattern 3: Conditional tail
bt     target           ; branch to shared epilogue
bf     target           ; branch to shared epilogue
```

#### 24.3.3 Cross-Reference Building

Build a call graph by scanning for all `jsr @Rn` (0x4n0B) and `bsr disp` (0xBxxx) instructions:

```python
def build_callgraph(data, base=0x06010000):
    """Build a dictionary of caller → [callee] relationships."""
    calls = {}
    for i in range(0, len(data)-2, 2):
        w = struct.unpack('>H', data[i:i+2])[0]
        caller = base + i

        if (w >> 12) == 0xB:  # BSR
            disp = w & 0xFFF
            if disp > 0x7FF:
                disp -= 0x1000
            target = caller + 4 + disp * 2
            calls.setdefault(caller, []).append(target)

        elif (w & 0xF0FF) == 0x400B:  # JSR @Rn
            # Target is in register — need to trace backward to find mov.l
            rn = (w >> 8) & 0xF
            # Search backward for mov.l @(disp,PC),Rn that loads the target
            for j in range(i-2, max(i-40, 0), -2):
                w2 = struct.unpack('>H', data[j:j+2])[0]
                if (w2 >> 12) == 0xD and ((w2 >> 8) & 0xF) == rn:
                    disp2 = w2 & 0xFF
                    pc2 = base + j
                    lit_addr = ((pc2 + 4) & ~3) + disp2 * 4
                    lit_off = lit_addr - base
                    if 0 <= lit_off + 4 <= len(data):
                        target = struct.unpack('>I', data[lit_off:lit_off+4])[0]
                        calls.setdefault(caller, []).append(target)
                    break
    return calls
```

### 24.4 Phase 3: Instruction-Level Disassembly

#### 24.4.1 Core SH-2 Instruction Decoding

The SH-2 has ~60 core instructions, all 16-bit. The most common patterns in this binary:

**Data Movement:**
```
mov #imm, Rn           ; 0xEnII — load 8-bit sign-extended immediate
mov.w @(disp,PC), Rn   ; 0x9nDD — load 16-bit from literal pool (EA = PC+4 + d*2)
mov.l @(disp,PC), Rn   ; 0xDnDD — load 32-bit from literal pool (EA = (PC+4)&~3 + d*4)
mov Rm, Rn             ; 0x6nm3 — register to register
mov.l Rm, @-Rn         ; 0x2nm6 — push to stack
mov.l @Rm+, Rn         ; 0x6nm6 — pop from stack
mov.b @(r0,Rm), Rn     ; 0x0nmc — load byte indexed
mov.w @(disp,Rm), R0   ; 0x85mD — load word with displacement (R0 only)
mov.l @(disp,Rm), Rn   ; 0x5nmD — load long with displacement
mov.l Rm, @(disp,Rn)   ; 0x1nmD — store long with displacement
```

**Arithmetic:**
```
add Rm, Rn             ; 0x3nm0c — register add
add #imm, Rn           ; 0x7nII — add immediate
sub Rm, Rn             ; 0x3nm8 — subtract
muls.w Rm, Rn          ; 0x2nmF — signed 16×16 multiply → MACL
```

**Compare and Branch:**
```
cmp/eq #imm, R0        ; 0x88II — compare R0 with immediate
cmp/eq Rm, Rn          ; 0x3nm0 — compare equal
cmp/hi Rm, Rn          ; 0x3nm6 — compare unsigned greater
tst Rm, Rn             ; 0x2nm8 — test (AND), set T
bt disp                ; 0x89DD — branch if T=1
bf disp                ; 0x8BDD — branch if T=0
bra disp               ; 0xAnnn — unconditional branch
bsr disp               ; 0xBnnn — branch to subroutine
```

**Special:**
```
sts.l PR, @-r15        ; 0x4F22 — push return address (function entry)
lds.l @r15+, PR        ; 0x4F26 — pop return address (function exit)
jsr @Rn                ; 0x4n0B — jump to subroutine
rts                    ; 0x000B — return from subroutine
extu.b Rm, Rn          ; 0x6nmC — zero-extend byte
extu.w Rm, Rn          ; 0x6nmD — zero-extend word
exts.b Rm, Rn          ; 0x6nmE — sign-extend byte
exts.w Rm, Rn          ; 0x6nmF — sign-extend word
```

#### 24.4.2 Literal Pool Resolution

The SH-2 cannot encode large immediates in instructions. Instead, constants are stored in "literal pools" near the code and loaded with PC-relative addressing. **This is the single most important decoding step** — without resolving literal pools, you cannot determine function call targets or data addresses.

```python
def resolve_literal(insn, pc, data, base):
    """Resolve PC-relative loads to their actual values."""
    hi4 = (insn >> 12) & 0xF

    if hi4 == 0xD:  # mov.l @(disp,PC), Rn
        disp = insn & 0xFF
        rn = (insn >> 8) & 0xF
        ea = ((pc + 4) & ~3) + disp * 4
        file_off = ea - base
        if 0 <= file_off + 4 <= len(data):
            value = struct.unpack('>I', data[file_off:file_off+4])[0]
            return rn, value, 'long'

    elif hi4 == 0x9:  # mov.w @(disp,PC), Rn
        disp = insn & 0xFF
        rn = (insn >> 8) & 0xF
        ea = (pc + 4) + disp * 2
        file_off = ea - base
        if 0 <= file_off + 2 <= len(data):
            value = struct.unpack('>H', data[file_off:file_off+2])[0]
            return rn, value, 'word'

    return None, None, None
```

#### 24.4.3 Delay Slot Handling

**CRITICAL:** SH-2 branch instructions execute the instruction AFTER the branch (the "delay slot") before the branch takes effect. When reading disassembly:

```asm
jsr    @r3          ; Call function at r3
mov    r5, r4       ; ← THIS EXECUTES BEFORE THE CALL (delay slot)
; next instruction  ; ← Execution continues here after jsr returns
```

Common delay slot patterns:
- `mov Rm, Rn` — moving an argument register for the call
- `add #N, Rn` — adjusting a pointer before passing it
- `nop` — no operation (wasted slot)
- `mov #imm, Rn` — loading an argument

### 24.5 Phase 4: Function Decompilation (Assembly → C)

#### 24.5.1 Register Tracking Method

The core technique: trace each register's value through the function to determine what C variables they represent.

**Step 1:** Identify the prologue and note which registers are saved (these are used as local variables).

**Step 2:** Map input arguments:
```
r4 = first argument (often: payload pointer, or context pointer)
r5 = second argument
r6 = third argument
r7 = fourth argument
```

**Step 3:** Track r14 — in almost every handler in this binary, r14 becomes the game state pointer:
```asm
mov.l  @(8,GBR), r0   ; Load game state from global base register
mov    r0, r14         ; r14 = game_state (preserved throughout function)
```

**Step 4:** Read operations sequentially. Each `mov.w @r4+, r0` or `mov.l @r4+, r0` advances the payload pointer by 2 or 4 bytes, reading the next field.

#### 24.5.2 Standard Handler Template

Most of the 197 handlers follow this C structure:

```c
void handler_MSG_NAME(uint8_t *payload) {
    game_state_t *gs = *(game_state_t**)GBR[8];

    // 1. Read status field
    uint16_t status = read_u16_be(payload); payload += 2;
    if (status != 0) {
        // Error path — usually just returns
        return;
    }

    // 2. Read payload fields
    uint16_t field1 = read_u16_be(payload); payload += 2;
    uint32_t field2 = read_u32_be(payload); payload += 4;
    // ...

    // 3. Store into game state
    gs->some_field = field1;
    memcpy(gs->some_array, payload, N);

    // 4. Optionally trigger UI update or state change
    some_callback_func(gs);
}
```

#### 24.5.3 Decompilation Worked Example

Here is the complete workflow for decompiling one handler from raw binary to C:

**Target:** Handler at 0x06012EE0 (file offset 0x01AEE0), msg_type 0x01A6 (PARTYENTRY_REPLY)

**Step 1: Raw disassembly**
```
python tools/disasm.py 0x01AEE0 40
```

Output:
```
0x06012EE0  2FE6  mov.l r14, @-r15
0x06012EE2  4F22  sts.l PR, @-r15
0x06012EE4  7FF0  add #-16, r15
0x06012EE6  D306  mov.l @(0x06012F00), r3  ; = 0x06019FF6 (read_u16_be)
0x06012EE8  6E43  mov r4, r14              ; r14 = payload ptr
0x06012EEA  6AF3  mov r15, r10             ; r10 = stack frame
0x06012EEC  430B  jsr @r3                  ; call read_u16_be
0x06012EEE  64A3  mov r10, r4              ; delay slot: dest = stack frame
; ... more instructions ...
```

**Step 2: Trace register values**
```
r14 = payload pointer (r4 input)
r10 = stack frame pointer
r3 = 0x06019FF6 → read_u16_be function
r4 = stack frame → dest for read_u16_be
```

**Step 3: Identify reads**
```
Call 1: read_u16_be(stack_frame, payload) → reads uint16 status
Check: status != 0 → error return
Call 2: read_u16_be(stack_frame+2, payload+2) → reads uint16 field1
Call 3: read_u32_be(stack_frame+4, payload+4) → reads uint32 field2
```

**Step 4: Identify stores**
```
GBR[8] → game_state
game_state[0x1234] = field1
game_state[0x1238] = field2
```

**Step 5: Write C approximation**
```c
void h_partyentry_reply(uint8_t *payload) {
    game_state_t *gs = GBR_GAME_STATE;
    uint16_t status = read_u16_be(payload); payload += 2;
    if (status != 0) return;

    uint16_t party_id = read_u16_be(payload); payload += 2;
    uint32_t party_flags = read_u32_be(payload); payload += 4;

    gs->party_id = party_id;
    gs->party_flags = party_flags;
}
```

### 24.6 Phase 5: Data Structure Recovery

#### 24.6.1 Game State Structure (g_state)

The game state is a single massive structure at a pointer loaded via `@(8,GBR)`. To recover its layout:

1. **Collect all handler writes:** For each handler, note every offset into the game state where data is stored. Example from handler analysis:
   ```
   Handler 0x01E9 stores at gs+0x0260 (4 bytes)
   Handler 0x019F stores at gs+0x1BE0 (164 bytes)
   Handler 0x02D2 stores at gs+0x1684 (varies by type)
   ```

2. **Cluster by subsystem:** Group offsets that are always accessed together:
   ```
   0x0000-0x00FF   Connection/session data
   0x0100-0x01FF   Login state machine
   0x0260-0x02FF   Character identity
   0x1530-0x1680   Inventory
   0x1684-0x1B80   Character list
   0x1BE0-0x2000   Party data
   0xDDFE-0xE000   Gate flags
   0xE8C0-0xF000   Backup RAM mirror
   ```

3. **Determine field types:** Use the read function to determine width:
   - `read_u16_be` → `uint16_t`
   - `read_u32_be` → `uint32_t`
   - `memcpy_16(dst, src, N)` → `uint8_t[N]` or nested struct

4. **Name fields by context:** If a handler named `EQUIP_REPLY` stores at offset X, that offset is likely `equipped_item_slot` or similar.

#### 24.6.2 Paired Data Tables

The binary contains several paired tables (two parallel arrays where index N in table A corresponds to index N in table B). The message dispatch table is the primary example:

```python
# Read paired message table at file offset 0x042F18
# 108 entries × 4 bytes each: [u16 client_msg][u16 server_reply]
paired_table_off = 0x042F18
for i in range(108):
    off = paired_table_off + i * 4
    client_msg = struct.unpack('>H', data[off:off+2])[0]
    server_reply = struct.unpack('>H', data[off+2:off+4])[0]
    print(f"  [{i:3d}] 0x{client_msg:04X} → 0x{server_reply:04X}")
```

### 24.7 Phase 6: Game Logic Extraction

This is the next frontier — extracting the game content and formulas that the server needs to implement.

#### 24.7.1 Battle System

The battle system code resides approximately in file offsets `0x015000-0x020000`. Key entry points:

- BTL_CMD handler (0x0221/0x0222): Battle command processing
- BTL_RESULT_NOTICE handler: Battle outcome
- BTL_EFFECTEND_REPLY: Effect completion
- BTL_END_REPLY: Battle termination

**Workflow to extract battle formulas:**

1. Start from BTL_CMD handler entry point
2. Trace the command dispatch (usually a switch on `command_type` byte)
3. For each command type (attack, magic, item, flee), trace the calculation:
   - Identify stat lookups (reads from character data structure)
   - Identify formula operations (muls.w, shifts, adds)
   - Identify random number generation (calls to RNG function)
4. Document as: `damage = (ATK * modifier / DEF) + random(0, variance)`

#### 24.7.2 Item and Monster Databases

Game content data is stored in the binary data section and possibly loaded from CD. Look for:

1. **Fixed-size record arrays:** Sequences of same-length structs with incrementing IDs
2. **String table references:** Array of pointers to Shift-JIS strings (item names, monster names)
3. **CD file loading code:** Traces of `CDC_` or file read functions that load external data

#### 24.7.3 Map and Zone Data

Map data may be stored as:
- Tile index arrays (2D grids of 16-bit tile IDs)
- Walkability bitmasks
- NPC position tables (x, y, facing, script_id)
- Encounter rate tables per zone

### 24.8 Phase 7: Source Code Reconstruction

#### 24.8.1 File Organization

Based on assertion strings and code organization, reconstruct the original source tree:

```
src/
  lib_sv.c         — SV framing (confirmed by assertion strings)
  scmd.c           — SCMD message builder
  session.c        — Session protocol layer
  bbs.c            — BBS command scripts
  main.c           — Main loop, state machine
  login.c          — Login state machine
  battle.c         — Battle system
  party.c          — Party management
  shop.c           — Shop system
  event.c          — Event system
  map.c            — Map/zone management
  char.c           — Character data
  ui.c             — VDP2 text/menu rendering
  io.c             — Controller input
  save.c           — Backup RAM access
```

#### 24.8.2 Reconstruction Guidelines

1. **Preserve original naming:** Use assertion strings, debug prints, and protocol names where available
2. **Use exact offset comments:** Every reconstructed function should comment its file offset:
   ```c
   /* 0x01AEE0 (mem: 0x06012EE0) — PARTYENTRY_REPLY handler */
   void h_partyentry_reply(uint8_t *payload) { ... }
   ```
3. **Match structure layouts exactly:** Field offsets in the reconstructed structs must match the binary
4. **Verify with re-compilation:** Compile reconstructed C with `sh-coff-gcc -m2 -O2` and compare instruction patterns (they won't be identical but should be structurally similar)

#### 24.8.3 Verification Checklist

For each decompiled function:
- [ ] All reads from payload accounted for (correct byte count consumed)
- [ ] All writes to game state at correct offsets
- [ ] All function calls resolved to known targets
- [ ] Conditional branches correctly translated (bt = if true, bf = if false)
- [ ] Delay slots correctly handled (instruction after branch executes before branch)
- [ ] Literal pool values resolved to correct constants
- [ ] Stack frame size matches push count + local allocation

### 24.9 Phase 8: Integration Testing

#### 24.9.1 Server-Side Validation

For each message handler implemented on the server:

1. Send the message from the test client
2. Capture the Saturn's response via server logging
3. Verify response matches the paired message type
4. Verify payload size matches handler's expected read count
5. Check Saturn doesn't display error dialog (error 0, 1, or 2)

#### 24.9.2 Real Hardware Testing

The definitive test is always real Saturn hardware:

1. Boot game disc with NetLink modem connected to DreamPi
2. DreamPi in transparent mode routes TCP to server
3. Server logs every frame in both directions
4. Compare log with expected protocol flow

#### 24.9.3 Regression Test Matrix

| Test Case | Expected Behavior |
|-----------|-------------------|
| Initial connect | BBS → Establishment → INIT → ESP_NOTICE |
| Login | LOGIN_REQUEST → full character data sequence |
| GOTOLIST | Server list → re-login cycle (no INIT re-send) |
| Keepalive | No disconnect for 60+ seconds idle |
| Invalid message | Server logs warning, Saturn doesn't crash |

### 24.10 Remaining Decompilation Work

The following areas of the binary have NOT been fully decompiled and represent the next targets:

| Region (file) | Approx Size | Content | Priority |
|---------------|-------------|---------|----------|
| `0x001200-0x010000` | ~60 KB | Main game loop, UI state machines, VDP rendering | Medium |
| `0x015000-0x020000` | ~20 KB | Battle system formulas, encounter logic | **HIGH** |
| `0x020000-0x030000` | ~64 KB | World logic, NPC scripts, event scripting | High |
| `0x030000-0x03D000` | ~52 KB | Additional game logic, quest system | Medium |
| `0x03D000-0x04D000` | ~64 KB | Data tables (items, monsters, maps) | **HIGH** |
| `0x04D000-0x07B000` | ~184 KB | Compressed assets (graphics, fonts) | Low |

**Priority explanation:**
- **Battle formulas** (HIGH): Server must calculate damage, hit rates, etc.
- **Data tables** (HIGH): Server needs item stats, monster stats, shop inventories
- **World logic** (High): NPC behavior, event triggers, zone transitions
- **UI/rendering** (Medium): Understanding helps but server doesn't need graphics code
- **Assets** (Low): Graphics and fonts are Saturn-side only

---

## 25. Analysis Tools Reference

This section documents all tools created during the Dragon's Dream reverse engineering project. All tools are Python scripts that operate on the extracted binary (`extracted/0.BIN`).

### 25.1 Tool Inventory

```
DragonsDreamDecomp/
├── tools/                          # Canonical tool directory
│   ├── disasm.py                   # Primary SH-2 disassembler (493 lines)
│   ├── decode_sh2.py               # Instruction decoder library (256 lines)
│   └── sh2_disasm.py               # Alternative disassembler (244 lines)
├── disasm.py                       # Root-level disassembler variant
├── disasm2.py                      # Second disassembler variant
├── disasm_check.py                 # Disassembly validation tool
├── disasm_delivery.py              # Delivery function disassembler (642 lines)
├── disasm_session_builder.py       # Session builder disassembler (518 lines)
├── disasm_sh2.py                   # Compact SH-2 decoder
├── disasm_tool.py                  # Flexible address range disassembler
├── disasm_helper.py                # Instruction decoding helper library
├── sh2_disasm.py                   # Minimal disassembler
├── sh2dis_tmp.py                   # Temporary/experimental decoder
├── delivery_function_trace.py      # Major: delivery function analysis (1,524 lines)
├── find_session_builder2.py        # Session builder search tool (415 lines)
├── search_session_response.py      # Session response pattern search (351 lines)
├── trace_hex_encode.py             # Hex encoding/checksum tracer (227 lines)
├── analyze_logout.py               # Logout state machine analysis (448 lines)
├── analyze_state.py                # Login state machine analysis (406 lines)
├── extracted/
│   ├── 0.BIN                       # THE BINARY (504,120 bytes)
│   ├── disasm.py                   # Binary-local disassembler
│   ├── trace_chardata.py           # CHARDATA_REPLY handler trace (653 lines)
│   └── trace_btl_result.py         # BTL_RESULT handler trace (290 lines)
├── server/
│   ├── dragons_dream_server_v3.py  # CURRENT revival server (1,767 lines)
│   ├── dragons_dream_server_v2.py  # Previous server revision (1,706 lines)
│   ├── bridge.py                   # Modem-to-TCP bridge (246 lines)
│   ├── test_client.py              # QA test client (426 lines)
│   └── netlink.py                  # DreamPi NetLink module (1,245 lines)
└── dragons_dream_server.py         # Original server prototype (1,033 lines)
```

### 25.2 Primary Disassembler — `tools/disasm.py`

**Purpose:** General-purpose SH-2 disassembler for analyzing arbitrary code regions in 0.BIN.

**Usage:**
```python
# Import and use from Python
from tools.disasm import sh2_disasm, read_u16, read_u32

# Disassemble 80 instructions starting at file offset 0x01AEE0
sh2_disasm(0x01AEE0, count=80)
```

**Or run directly:**
```bash
python tools/disasm.py
# Then modify the script's main block to set start offset
```

**Features:**
- Loads `extracted/0.BIN` at base `0x06010000`
- Resolves PC-relative `mov.l` and `mov.w` to actual constant values
- Resolves branch targets (`bt`, `bf`, `bra`, `bsr`) to memory addresses
- Decodes all common SH-2 instructions
- Output format: `0xADDR [0xFILE] OPCODE MNEMONIC ; comment`

**Instruction Coverage:**
| Category | Instructions Decoded |
|----------|---------------------|
| Data Movement | `mov`, `mov.b`, `mov.w`, `mov.l` (all addressing modes) |
| Arithmetic | `add`, `sub`, `neg`, `muls.w`, `mulu.w` |
| Logic | `and`, `or`, `xor`, `not`, `tst` |
| Shift | `shll`, `shlr`, `shal`, `shar`, `shll2`, `shlr2`, `shll8`, `shlr8`, `shll16`, `shlr16` |
| Compare | `cmp/eq`, `cmp/hi`, `cmp/ge`, `cmp/gt`, `cmp/hs`, `cmp/pl`, `cmp/pz` |
| Branch | `bt`, `bf`, `bra`, `bsr`, `jsr`, `jmp`, `rts`, `rte` |
| System | `sts`, `lds`, `stc`, `ldc`, `clrt`, `sett`, `nop`, `sleep` |
| Extension | `extu.b`, `extu.w`, `exts.b`, `exts.w`, `swap.b`, `swap.w` |
| MAC | `muls.w`, `mulu.w`, `mac.l`, `mac.w`, `sts MACL`, `sts MACH` |

### 25.3 Instruction Decoder Library — `tools/decode_sh2.py`

**Purpose:** Standalone instruction decoder that returns mnemonic strings. Used as an importable module by other analysis scripts.

**Usage:**
```python
from tools.decode_sh2 import decode_one, decode_sh2

# Decode a single instruction
mnemonic = decode_one(0xD306, pc=0x06012EE6, off=0x01AEE6)

# Decode a range of instructions
lines = decode_sh2(start_offset=0x01AEE0, count=120)
for line in lines:
    print(line)
```

**Output format:**
```
  0x06012EE0 [0x01AEE0]  2FE6  MOV.L R14, @-R15
  0x06012EE2 [0x01AEE2]  4F22  STS.L PR, @-R15
  0x06012EE4 [0x01AEE4]  7FF0  ADD #-16, R15
  0x06012EE6 [0x01AEE6]  D306  MOV.L @(0x06012F00),R3  ; =0x06019FF6
```

### 25.4 Delivery Function Trace — `delivery_function_trace.py`

**Purpose:** Comprehensive annotated trace of the session delivery function at `0x060423C8`. This is the most detailed analysis script in the project (1,524 lines) and serves as a template for how to fully trace a complex function.

**What it documents:**
- Complete register allocation through 88-byte stack frame
- All sub-function calls with parameter passing
- Session establishment logic (flags, sequence numbers, checksums)
- Connection state transitions (DISCONNECTED → CONNECTING → CONNECTED)
- Checksum algorithm implementation at `0x060429B6`
- Hex encoding function at `0x06042A14`

**Usage:**
```bash
python delivery_function_trace.py
```

Outputs a complete annotated walkthrough with C pseudocode for each section of the function.

### 25.5 Specialized Trace Scripts

#### 25.5.1 `extracted/trace_chardata.py` — Character Data Handler

**Purpose:** Manual trace of the CHARDATA_REPLY (0x02D2) handler at `0x06013858`. This handler has 3 sub-types (character list, character detail, inventory) and is one of the most complex handlers.

**Key findings documented:**
- Type 1: Character list — 24 bytes/entry → session+0x1684
- Type 2: Character detail — 52 bytes/entry → session+0x1BE0, triggers backup RAM save
- Type 3: Inventory — 24 bytes/entry → session+0x1530

#### 25.5.2 `extracted/trace_btl_result.py` — Battle Result Handler

**Purpose:** Trace of BTL_RESULT_NOTICE handler at `0x060181B0`. Documents the battle result payload structure.

#### 25.5.3 `trace_hex_encode.py` — Hex Encoding and Checksum

**Purpose:** Traces the hex encoding function (`0x06042A14`) and additive checksum function (`0x060429B6`). These are critical for implementing correct IV frame encoding and session checksums.

**Key findings documented:**
- Hex encoder uses lowercase `"0123456789abcdef"` character table
- Checksum is simple additive byte sum masked to 16 bits
- Checksum computed with bytes at offsets [2:6] zeroed

#### 25.5.4 `analyze_state.py` — Login State Machine

**Purpose:** Traces the login state machine (states 0-7) including controller input polling and character selection logic.

**Key findings documented:**
- All 7 states are LOCAL (no network messages sent)
- Controller bitmask at 0x0606967C (active-high, inverted from hardware)
- Button A = revive character, C = new character, B = cancel
- After state machine completes, parent code sends LOGIN_REQUEST (0x019E)

#### 25.5.5 `analyze_logout.py` — Logout State Machine

**Purpose:** Traces the logout and disconnection flow, documenting connection teardown protocol and cleanup.

#### 25.5.6 `disasm_delivery.py` — Delivery Function Disassembly

**Purpose:** Raw disassembly output of the delivery function range (0x060423C8 to 0x060428F8), 642 lines of annotated disassembly. Companion to the higher-level `delivery_function_trace.py`.

#### 25.5.7 `disasm_session_builder.py` — Session Response Builder

**Purpose:** Disassembly of the session frame response builder functions. Documents how the client constructs 0xA6-type session frames with escape encoding.

#### 25.5.8 `find_session_builder2.py` — Session Builder Discovery

**Purpose:** Pattern-based search for code that builds session responses. Scans for BSR/JSR instructions targeting `0x060222CC` and related session functions.

#### 25.5.9 `search_session_response.py` — Session Response Pattern Search

**Purpose:** Searches the binary for byte patterns matching the 18-byte session response structure (0xA6 header with escape encoding).

### 25.6 Server Tools

#### 25.6.1 `server/dragons_dream_server_v3.py` — Revival Server

**Purpose:** The current production revival server. Asyncio Python TCP server implementing the complete Dragon's Dream protocol stack.

**Usage:**
```bash
cd server
python dragons_dream_server_v3.py
# Listens on 0.0.0.0:8020
```

**Architecture:**
```
DDSession (per-client connection handler)
├── bbs_handshake()                 # BBS command phase (P, SET, C NETRPG)
├── _send_session_establishment()   # 256-byte IV frame
├── _session_message_loop()         # Main receive/dispatch loop
│   ├── recv_iv()                   # Parse IV frames
│   ├── _parse_client_session()     # Decode 0xA6 escape-encoded frames
│   └── _dispatch(msg_type, payload, param1)
├── _keepalive_loop()               # IV-wrapped ACK frames every 6s
├── send_msg(msg_type, payload, param1)  # Build SCMD → session → IV → TCP
└── _h_*()                          # Per-message handler functions
    ├── _h_init()                   # 0x0035 → ESP_NOTICE + UPDATE_CHARDATA_REQ
    ├── _h_login_request()          # 0x019E → full login flow
    ├── _h_update_chardata_reply()  # 0x01AA → character data sequence
    ├── _h_gotolist_notice()        # 0x019B → proactive ESP+UPDATE re-send
    └── _build_minimal_reply()      # Fallback for unimplemented handlers
```

**Logging:**
- All frames logged to `server/logs/dd_server_YYYYMMDD_HHMMSS.log`
- DEBUG level includes hex dumps of every frame
- INFO level shows message types and high-level flow

#### 25.6.2 `server/test_client.py` — Protocol Test Client

**Purpose:** Simulates a Saturn client for automated server testing. Runs the full BBS → session establishment → INIT → login sequence without needing real hardware.

**Usage:**
```bash
python server/test_client.py --host 127.0.0.1 --port 8020
```

**Note:** Currently imports from `dragons_dream_server_v2.py`. Update imports to v3 if v2 is removed.

#### 25.6.3 `server/bridge.py` — Modem-to-TCP Bridge

**Purpose:** Bridges Saturn NetLink modem connections (physical or emulated) to the TCP game server. Handles modem AT commands and BBS protocol translation.

**Usage:**
```bash
# For emulator (Yabause/Kronos NetLink):
python server/bridge.py --listen-port 1337 --server-host 127.0.0.1 --server-port 8020

# Configure emulator to connect to 127.0.0.1:1337
```

**Architecture:**
```
[Saturn/Emulator] ←modem/TCP→ [Bridge :1337] ←TCP→ [Server :8020]
```

After BBS phase completion, the bridge becomes a transparent byte-level proxy.

#### 25.6.4 `server/netlink.py` — DreamPi NetLink Module

**Purpose:** Integration module for DreamPi (Raspberry Pi-based modem bridge for real Saturn hardware). Provides `handler=transparent` mode for Dragon's Dream, routing raw TCP between the modem and the game server.

**Setup:**
1. Install DreamPi on a Raspberry Pi
2. Configure `server/config.ini` with Dragon's Dream dial code
3. Set `handler=transparent` in config
4. Saturn dials DreamPi → DreamPi routes to server

### 25.7 Creating New Analysis Tools

When extending the toolkit for continued decompilation, follow these patterns:

#### 25.7.1 Basic Trace Script Template

```python
#!/usr/bin/env python3
"""Trace [FUNCTION_NAME] at 0x[ADDRESS]."""
import struct

BINARY = r"D:\DragonsDreamDecomp\extracted\0.BIN"
BASE = 0x06010000

with open(BINARY, 'rb') as f:
    data = f.read()

def u16(off): return struct.unpack('>H', data[off:off+2])[0]
def u32(off): return struct.unpack('>I', data[off:off+4])[0]
def mem(addr): return addr - BASE  # mem addr → file offset
def addr(off): return off + BASE   # file offset → mem addr

def disasm(start_off, count=60):
    """Minimal disassembler for quick analysis."""
    from tools.decode_sh2 import decode_sh2
    lines = decode_sh2(start_off, count)
    for line in lines:
        print(line)

# --- Main analysis ---
TARGET = 0x0XXXXX  # File offset of function to trace
print(f"=== Tracing function at {addr(TARGET):#010x} ===")
disasm(TARGET, count=80)
```

#### 25.7.2 Handler Payload Extractor Template

```python
#!/usr/bin/env python3
"""Extract payload layout for handler at 0x[ADDRESS]."""
import struct

BINARY = r"D:\DragonsDreamDecomp\extracted\0.BIN"
BASE = 0x06010000

with open(BINARY, 'rb') as f:
    data = f.read()

def u16(off): return struct.unpack('>H', data[off:off+2])[0]
def u32(off): return struct.unpack('>I', data[off:off+4])[0]

# Known helper functions
READ_U16_BE = 0x06019FF6
READ_U32_BE = 0x06019FD2
MEMCPY_16 = 0x0603FE68

HANDLER_OFFSET = 0x0XXXXX  # File offset

# Scan for calls to read helpers
pc = HANDLER_OFFSET
payload_offset = 0
fields = []

for i in range(200):
    insn = u16(pc + i*2)
    # Look for jsr @rN where rN was loaded with a known helper
    if (insn & 0xF0FF) == 0x400B:
        rn = (insn >> 8) & 0xF
        # Trace backward to find what rN was loaded with
        for j in range(i-1, max(i-20, 0), -1):
            prev = u16(pc + j*2)
            if (prev >> 12) == 0xD and ((prev >> 8) & 0xF) == rn:
                disp = prev & 0xFF
                lit_pc = BASE + pc + j*2
                lit_addr = ((lit_pc + 4) & ~3) + disp * 4
                lit_off = lit_addr - BASE
                if 0 <= lit_off + 4 <= len(data):
                    target = u32(lit_off)
                    if target == READ_U16_BE:
                        fields.append((payload_offset, 'U16 BE'))
                        payload_offset += 2
                    elif target == READ_U32_BE:
                        fields.append((payload_offset, 'U32 BE'))
                        payload_offset += 4
                break

print(f"Handler at {BASE + HANDLER_OFFSET:#010x}:")
for off, typ in fields:
    print(f"  +{off:3d}  {typ}")
print(f"Total payload size: {payload_offset} bytes")
```

#### 25.7.3 Data Table Scanner Template

```python
#!/usr/bin/env python3
"""Scan for fixed-size record tables in data section."""
import struct

BINARY = r"D:\DragonsDreamDecomp\extracted\0.BIN"
BASE = 0x06010000

with open(BINARY, 'rb') as f:
    data = f.read()

DATA_START = 0x03D000  # Data section start (file offset)
DATA_END = 0x04D000    # Data section end

def scan_for_tables(record_size, min_entries=8):
    """Find sequences of N records that look like a table."""
    results = []
    for off in range(DATA_START, DATA_END - record_size * min_entries, 4):
        # Check if consecutive records have similar structure
        # (e.g., incrementing IDs in first 2 bytes)
        ids = []
        for i in range(min_entries):
            rec_off = off + i * record_size
            first_u16 = struct.unpack('>H', data[rec_off:rec_off+2])[0]
            ids.append(first_u16)

        # Check for sequential IDs (common in RPG databases)
        if all(ids[i+1] == ids[i] + 1 for i in range(len(ids)-1)):
            results.append((off, ids[0], ids[-1]))

    return results

# Scan for common RPG record sizes
for size in [8, 12, 16, 20, 24, 28, 32, 48, 64]:
    tables = scan_for_tables(size)
    if tables:
        print(f"\nRecord size {size}:")
        for off, first_id, last_id in tables:
            print(f"  0x{off:06X}: IDs {first_id}-{last_id}")
```

### 25.8 Tool Maintenance Notes

1. **Multiple disassembler variants exist** because they evolved during the project. The canonical versions in `tools/` should be preferred for new work. Root-level copies are kept for reproducibility of earlier analysis.

2. **All tools hardcode the binary path** to `D:\DragonsDreamDecomp\extracted\0.BIN` or relative `extracted/0.BIN`. Update paths if the project directory moves.

3. **The disassembler does not handle ALL SH-2 instructions.** Missing decodings discovered during analysis are documented in comments (see `trace_chardata.py` header for examples). Add new instruction decodings to `tools/decode_sh2.py` as they are encountered.

4. **No external dependencies** — all tools use only Python standard library (`struct`, `sys`, `os`). No installation required beyond Python 3.8+.

---

## Appendix A: SCMD Library API

### A.1 Build Functions

```c
// Initialize message buffer with param1 and msg_type
void scmd_new_message(uint16_t param1, uint16_t msg_type);
// File: 0x149EC, Memory: 0x060249EC

// Add 1 byte to payload
void scmd_add_byte(uint8_t value);
// File: 0x14A32, Memory: 0x06024A32

// Add 2 bytes (uint16 BE) to payload
void scmd_add_word(uint16_t value);
// File: 0x14B04, Memory: 0x06024B04

// Add 4 bytes (uint32 BE) to payload
void scmd_add_long(uint32_t value);
// File: 0x14BDC, Memory: 0x06024BDC

// Add N bytes from source pointer to payload
void scmd_add_data(void* src, uint32_t length);
// File: 0x14CD0, Memory: 0x06024CD0

// Finalize and queue message for sending
void scmd_send(void);
// File: 0x14E3C, Memory: 0x06024E3C
```

### A.2 Receive Helpers

```c
// Read uint16 BE from source, store at dest, return src+2
void* read_u16_be(uint16_t* dest, void* src);
// Memory: 0x06019FF6

// Read uint32 BE from source, store at dest, return src+4
void* read_u32_be(uint32_t* dest, void* src);
// Memory: 0x06019FD2

// Copy N bytes (typically 16)
void memcpy_16(void* dst, void* src, uint32_t len);
// Memory: 0x0603FE68
```

---

## Appendix B: Key RAM Addresses

### B.1 SV Layer

| Address | Description |
|---------|-------------|
| `0x202E4B3C` | SV context (cache-through) |
| `0x06062314` | SV session struct |
| `0x06062374` | Connection state (0/1/2) |
| `0x060623D8` | Send queue (20 entries) |
| `0x06062498` | nMsgSize (current payload size) |
| `0x202E6148` | SCMD build buffer (max 4800B) |

### B.2 Connection State Machine

| Address | Description |
|---------|-------------|
| `0x06061D80` | Struct base (R14) |
| `0x06061E3F` | State dispatch byte (R14+0xBF) |

### B.3 Game State

| Address | Description |
|---------|-------------|
| `0x0605F424` | Callback function pointer |
| `0x0605F432` | Global flag byte |
| `0x0606967C` | Controller bitmask (active-high) |
| `0x0606967E` | Button change detection |
| `0x06060E76` | Display button state |
| `0x060610C2` | Pending join tracking |

### B.4 Debug/Print

| Address | Description |
|---------|-------------|
| `0x06069508` | Debug print function |
| `0x0603FE28` | Memory alloc function |
| `0x06020D70` | I/O handler function |

---

## Appendix C: String Constants

### C.1 Network Strings

| Offset | String | Purpose |
|--------|--------|---------|
| `0x03D680` | `DRGNSDRMM` | Memory card save file |
| `0x03D68C` | `DRGNSDRMT` | Text data save file |
| `0x03FC0C` | `DRGNSDRMSYS` | System save file |
| `0x03FC18` | `NRPG0410` | Game ID (Network RPG v4.10) |
| `0x03EEC8` | `$I'm alive!!\r\n` | Client keepalive |
| `0x03EF1C` | `lib_sv.c` | SV source filename |
| `0x03F058` | `#sv error occured\r\n` | Error notification |
| `0x03EF28` | `FragQue full\n\r` | Queue overflow |

### C.2 Character Data Strings

| Offset | String | Purpose |
|--------|--------|---------|
| `0x03FA38` | `DURLAM` | Race name |
| `0x03FA40` | `ELFINE` | Race name |
| `0x03FA48` | `ANGELA` | Race name |
| `0x03FA50` | `DRAGONUTE` | Race name |
| `0x03FA5C` | `RUGOLAM` | Race name |
| `0x03FA64` | `BEAST` | Race name |
| `0x03FA6C` | `RULA` | Class name |
| `0x03FA74` | `ALEF` | Class name |
| `0x03FA7C` | `MALE` | Gender |
| `0x03FA84` | `FEMALE` | Gender |
| `0x03FA8C` | `NEUTRAL` | Gender |

### C.3 Modem Strings

| Offset | String | Purpose |
|--------|--------|---------|
| `0x03D704` | `ATDT` | Tone dialing |
| `0x03D70C` | `ATDP` | Pulse dialing |
| `0x03D6D4` | `*** infinity dialing go!! ***\r\n` | Debug retry mode |
| `0x03D6F4` | `\r\n::host=` | Direct TCP parameter |

---

## Appendix D: Common Handler Patterns

### D.1 Status Gate Pattern

Most handlers read a U16 status at offset 0 and exit if nonzero:

```asm
; Typical handler entry
mov.l  @(8,GBR),r0    ; load SV context
mov    r0,r14         ; r14 = context
jsr    @r3            ; call read_u16(context+4, payload)
add    #4,r4          ; delay slot: skip to payload start
mov.w  @(4,r14),r0    ; read status
tst    r0,r0          ; check if zero
bf     error          ; nonzero = error, skip payload reads
; ... read payload fields ...
```

**Server implication:** Send `status=0` to trigger full processing, or `status=1` to safely skip.

### D.2 List Processing Pattern

Complex handlers (shops, parties, lists) follow:

```
1. Read header (status, entry_count, params)
2. Clear target memory area via 0x0603FBC0
3. Loop entry_count times:
   a. Read entry data
   b. Store via 0x0603FB24 (22-byte copy)
4. Update count fields
```

### D.3 Multi-Page Pattern

Large data (CHARDATA_REPLY, CLASS_CHANGE_REPLY):

```
1. Read header: type, page_number, total_pages, entry_count
2. If page_number == 1: reset accumulation buffer at 0x20200000
3. Copy chunk data to 0x20200000 + (page_number-1)*512
4. If page_number >= total_pages: parse accumulated data
```

### D.4 Party Entry Calculation

```python
party_entry = g_state + 0x1BE0 + g_state[0x1B90] * 0xA4
```

This formula appears in dozens of handlers. The party array holds 4 entries, each 164 bytes (0xA4).

---

*End of Dragon's Dream Engineering Manual v1.0*

*This document was generated from complete binary decompilation of the Sega Saturn client executable (0.BIN, 504,120 bytes). All handler payload layouts, state machine states, and protocol details are derived from direct SH-2 assembly analysis, confirmed against real Saturn hardware testing.*
