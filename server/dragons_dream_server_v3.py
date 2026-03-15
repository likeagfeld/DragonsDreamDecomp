#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dragon's Dream Revival Server v3
Protocol-accurate server based on complete binary decompilation of 0.BIN (504,120 bytes)

Wire format: [2B param1][2B msg_type][4B payload_size][payload]
SV framing:  IV{size:03x}{~size&0xFFF:03x} + raw_payload (NO \\r\\n)
BBS phase:   " P\\r" -> "*\\r\\n", "SET\\r" -> "*\\r\\n", "C ...\\r" -> "COM\\r\\n"

Author: Claude Code (decompilation-driven)
Date: 2026-03-11
"""

import asyncio
import struct
import logging
import time
import os
import sys
import argparse
from datetime import datetime

# ============================================================
# Logging — console + rotating file log
# ============================================================
LOG_FORMAT = "%(asctime)s.%(msecs)03d [%(levelname)s] %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Create logs directory next to this script
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_LOG_DIR = os.path.join(_SCRIPT_DIR, "logs")
os.makedirs(_LOG_DIR, exist_ok=True)
_LOG_FILE = os.path.join(_LOG_DIR, f"dd_server_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

log = logging.getLogger("DD-Server")
log.setLevel(logging.DEBUG)

# Console handler (INFO level — less noise)
_ch = logging.StreamHandler()
_ch.setLevel(logging.INFO)
_ch.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT))
log.addHandler(_ch)

# File handler (DEBUG level — full detail for post-session review)
_fh = logging.FileHandler(_LOG_FILE, encoding='utf-8')
_fh.setLevel(logging.DEBUG)
_fh.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT))
log.addHandler(_fh)

log.info("=== Dragon's Dream Server v3 — log file: %s ===", _LOG_FILE)

# ============================================================
# Message Type Constants (from handler table at file 0x0435D8)
# ============================================================
# Server -> Client (what server sends, client handler processes)
MSG_LOGOUT_REQUEST      = 0x0043
MSG_REGIST_HANDLE_REQ   = 0x0046
MSG_SPEAK_REQUEST       = 0x0049
MSG_SPEAK_REPLY         = 0x004A
MSG_SPEAK_NOTICE        = 0x0076
MSG_ESP_REQUEST         = 0x006F
MSG_ESP_REPLY           = 0x006E
MSG_ESP_NOTICE          = 0x01E8
MSG_INFORMATION_NOTICE  = 0x019D
MSG_UPDATE_CHARDATA_REQ = 0x019F
MSG_CHARDATA_NOTICE     = 0x01AB
MSG_CHARDATA_REQUEST    = 0x02F9
MSG_CHARDATA_REPLY      = 0x02D2
MSG_CURREGION_NOTICE    = 0x01B9
MSG_PARTYID_REQUEST     = 0x01ED
MSG_CLR_KNOWNMAP_REQ    = 0x01EF
MSG_PARTYEXIT_REQUEST   = 0x01A8
MSG_GOTOLIST_REQUEST    = 0x019B
MSG_PARTYLIST_REQUEST   = 0x01A3
MSG_USERLIST_REQUEST    = 0x01A1
MSG_CAMP_IN_REQUEST     = 0x01AD
MSG_CAMP_OUT_REQUEST    = 0x01B4
MSG_MOVE1_REQUEST       = 0x01C4
MSG_MOVE2_REQUEST       = 0x01C5
MSG_MOVE2_NOTICE        = 0x02F3
MSG_SET_MOVEMODE_REQ    = 0x01E0
MSG_GIVEUP_REQUEST      = 0x02F8
MSG_SETPOS_REQUEST      = 0x01D4
MSG_TELEPORTLIST_REQ    = 0x01B0
MSG_AREA_LIST_REQUEST   = 0x023C
MSG_EXPLAIN_REQUEST     = 0x023F
MSG_EQUIP_REQUEST       = 0x0205
MSG_DISARM_REQUEST      = 0x026D
MSG_MAP_NOTICE          = 0x01DE
MSG_KNOWNMAP_NOTICE     = 0x01D2
MSG_ENCOUNTMONSTER_REQ  = 0x0244
MSG_BTL_CMD_REQUEST     = 0x0222
MSG_BTL_CHGMODE_REQ     = 0x0225
MSG_BTL_EFFECTEND_REQ   = 0x0297
MSG_BTL_END_REQUEST     = 0x01EB
MSG_CANCEL_ENCOUNT_REQ  = 0x01E4
MSG_SHOP_LIST_REQUEST   = 0x0203
MSG_SHOP_IN_REQUEST     = 0x01FF
MSG_SHOP_ITEM_REQUEST   = 0x01FD
MSG_SHOP_BUY_REQUEST    = 0x01F3
MSG_SHOP_SELL_REQUEST   = 0x01F5
MSG_SHOP_OUT_REQUEST    = 0x0201
MSG_STORE_LIST_REQUEST  = 0x0270
MSG_STORE_IN_REQUEST    = 0x0272
MSG_SAKAYA_LIST_REQUEST = 0x020D
MSG_SAKAYA_TBLLIST_REQ  = 0x01F9
MSG_SAKAYA_IN_REQUEST   = 0x0217
MSG_SAKAYA_EXIT_REQUEST = 0x01FB
MSG_SAKAYA_SIT_REQUEST  = 0x020F
MSG_SAKAYA_MEMLIST_REQ  = 0x024C
MSG_SAKAYA_FIND_REQUEST = 0x024F
MSG_SAKAYA_STAND_REQ    = 0x021A
MSG_SET_SIGN_REQUEST    = 0x0246
MSG_MOVE_SEAT_REQUEST   = 0x0255
MSG_SET_SEKIBAN_REQUEST = 0x0251
MSG_DIR_REQUEST         = 0x029E
MSG_SUBDIR_REQUEST      = 0x02A0
MSG_MEMODIR_REQUEST     = 0x02A2
MSG_NEWS_READ_REQUEST   = 0x02A4
MSG_NEWS_WRITE_REQUEST  = 0x02A6
MSG_NEWS_DEL_REQUEST    = 0x02A8
MSG_BB_MKDIR_REQUEST    = 0x02B2
MSG_BB_RMDIR_REQUEST    = 0x02B4
MSG_BB_MKSUBDIR_REQUEST = 0x02B6
MSG_BB_RMSUBDIR_REQUEST = 0x02B8
MSG_PARTYENTRY_REQUEST  = 0x022B
MSG_ALLOW_JOIN_REQUEST  = 0x01E7
MSG_CANCEL_JOIN_REQUEST = 0x025C
MSG_PARTYUNITE_REQUEST  = 0x022F
MSG_ALLOW_UNITE_REQUEST = 0x0231
MSG_FINDUSER_REQUEST    = 0x01B8
MSG_FINDUSER2_REQUEST   = 0x0241
MSG_MIRRORDUNGEON_REQ   = 0x0234
MSG_CLASS_LIST_REQUEST  = 0x0299
MSG_CLASS_CHANGE_REQ    = 0x029B
MSG_EXEC_EVENT_REQUEST  = 0x01D0
MSG_GIVE_ITEM_REQUEST   = 0x0294
MSG_USE_REQUEST         = 0x02D1
MSG_SELL_REQUEST        = 0x028D
MSG_BUY_REQUEST         = 0x028F
MSG_TRADE_CANCEL_REQ    = 0x0291
MSG_COMPOUND_REQUEST    = 0x02EE
MSG_CONFIRM_LVLUP_REQ   = 0x0276
MSG_LEVELUP_REQUEST     = 0x0278
MSG_SKILL_LIST_REQUEST  = 0x02BA
MSG_LEARN_SKILL_REQUEST = 0x02E1
MSG_SKILLUP_REQUEST     = 0x02E3
MSG_EQUIP_SKILL_REQUEST = 0x02E5
MSG_DISARM_SKILL_REQ    = 0x02E7
MSG_USE_SKILL_REQUEST   = 0x02E9
MSG_CHANGE_PARA_REQUEST = 0x02F6
MSG_SEL_THEME_REQUEST   = 0x0269
MSG_CHECK_THEME_REQUEST = 0x026B
MSG_MAIL_LIST_REQUEST   = 0x02AA
MSG_GET_MAIL_REQUEST    = 0x02AC
MSG_SEND_MAIL_REQUEST   = 0x02AE
MSG_DEL_MAIL_REQUEST    = 0x02B0
MSG_COLO_WAITING_REQ    = 0x02BC
MSG_COLO_EXIT_REQUEST   = 0x02BF
MSG_COLO_LIST_REQUEST   = 0x02C2
MSG_COLO_ENTRY_REQUEST  = 0x02C4
MSG_COLO_CANCEL_REQUEST = 0x02C6
MSG_COLO_FLDENT_REQUEST = 0x02C9
MSG_COLO_RANKING_REQ    = 0x02CE
MSG_CAST_DICE_REQUEST   = 0x02D5
MSG_CARD_REQUEST        = 0x02DC
MSG_ACTION_CHAT_REQUEST = 0x0260

# Client -> Server message types (what client sends)
MSG_INIT_C2S             = 0x0035
MSG_LOGIN_REQUEST_C2S    = 0x019E
MSG_UPDATE_CHARDATA_RPL  = 0x01AA
MSG_CHARDATA2_NOTICE_C2S = 0x0B6C
MSG_STANDARD_REPLY_C2S   = 0x0048
MSG_MOVE_C2S             = 0x01C1
MSG_LOGOUT_NOTICE_C2S    = 0x019A
MSG_GOTOLIST_NOTICE_C2S  = 0x019C
MSG_MAP_CHANGE_NOTICE_C2S = 0x01AC

# ============================================================
# Paired Message Table (108 entries from file 0x043424)
# Client sends -> Server replies
# ============================================================
PAIRED_TABLE = {
    0x0035: 0x01E8, 0x019E: 0x019F, 0x01AA: 0x02F9, 0x0B6C: 0x02F9,
    0x0048: 0x0049, 0x006D: 0x006F, 0x01EC: 0x01ED, 0x01EE: 0x01EF,
    0x01A7: 0x01A8, 0x025F: 0x0260, 0x02D4: 0x02D5, 0x02DB: 0x02DC,
    0x019A: 0x019B, 0x019C: 0x019D, 0x01B7: 0x01B8, 0x026F: 0x0270,
    0x0271: 0x0272, 0x020C: 0x020D, 0x0210: 0x0211, 0x0216: 0x0217,
    0x01A0: 0x01A1, 0x01F8: 0x01F9, 0x02FA: 0x01F9, 0x01FA: 0x01FB,
    0x020E: 0x020F, 0x024B: 0x024C, 0x024E: 0x024F, 0x0219: 0x021A,
    0x0245: 0x0246, 0x0254: 0x0255, 0x0250: 0x0251, 0x0202: 0x0203,
    0x01FE: 0x01FF, 0x01FC: 0x01FD, 0x01F2: 0x01F3, 0x01F4: 0x01F5,
    0x0200: 0x0201, 0x029D: 0x029E, 0x029F: 0x02A0, 0x02A1: 0x02A2,
    0x02A3: 0x02A4, 0x02A5: 0x02A6, 0x02A7: 0x02A8, 0x02B1: 0x02B2,
    0x02B3: 0x02B4, 0x02B5: 0x02B6, 0x02B7: 0x02B8, 0x01A2: 0x01A3,
    0x01A4: 0x022B, 0x01E6: 0x01E7, 0x025B: 0x025C, 0x022C: 0x022F,
    0x0230: 0x0231, 0x023B: 0x023C, 0x01AF: 0x01B0, 0x023E: 0x023F,
    0x04E0: 0x0046, 0x0233: 0x0234, 0x0240: 0x0241, 0x0298: 0x0299,
    0x029A: 0x029B, 0x01C1: 0x01C4, 0x01C2: 0x01C4, 0x01AC: 0x01AD,
    0x01DF: 0x01E0, 0x02F7: 0x02F8, 0x01D3: 0x01D4, 0x01D6: 0x02D8,
    0x02D9: 0x02DA, 0x01B3: 0x01B4, 0x0204: 0x0205, 0x026C: 0x026D,
    0x02E8: 0x02E9, 0x02F5: 0x02F6, 0x0243: 0x0244, 0x0221: 0x0222,
    0x0224: 0x0225, 0x0296: 0x0297, 0x01EA: 0x01EB, 0x01E3: 0x01E4,
    0x0235: 0x0236, 0x01CF: 0x01D0, 0x0293: 0x0294, 0x02D0: 0x02D1,
    0x0289: 0x028D, 0x028E: 0x028F, 0x0290: 0x0291, 0x02ED: 0x02EE,
    0x0275: 0x0276, 0x0277: 0x0278, 0x02B9: 0x02BA, 0x02E0: 0x02E1,
    0x02E2: 0x02E3, 0x02E4: 0x02E5, 0x02E6: 0x02E7, 0x0268: 0x0269,
    0x026A: 0x026B, 0x02A9: 0x02AA, 0x02AB: 0x02AC, 0x02AD: 0x02AE,
    0x02AF: 0x02B0, 0x02BB: 0x02BC, 0x02BE: 0x02BF, 0x02C1: 0x02C2,
    0x02C3: 0x02C4, 0x02C5: 0x02C6, 0x02C8: 0x02C9, 0x02CD: 0x02CE,
}

# ============================================================
# SV Framing Layer
# ============================================================

def sv_encode(payload: bytes) -> bytes:
    """Wrap payload in IV frame: 8-byte header + raw data. NO \\r\\n."""
    size = len(payload)
    if size > 4095:
        raise ValueError(f"IV payload too large: {size} > 4095")
    complement = (~size) & 0xFFF
    header = f"IV{size:03x}{complement:03x}".encode('ascii')
    return header + payload


def build_game_msg(msg_type: int, payload: bytes = b'', param1: int = 0) -> bytes:
    """Build game message: [2B param1][2B msg_type][4B payload_size][payload]"""
    header = struct.pack('>HHI', param1, msg_type, len(payload))
    return header + payload


def parse_game_msg(data: bytes):
    """Parse game message. Returns (msg_type, payload, param1) or (None,None,None)."""
    if len(data) < 8:
        return None, None, None
    param1, msg_type, payload_size = struct.unpack('>HHI', data[:8])
    payload = data[8:8 + payload_size]
    return msg_type, payload, param1


# ============================================================
# Utility
# ============================================================

def sjis_pad(text: str, size: int) -> bytes:
    """Encode text as Shift-JIS, pad/truncate to exact size with null bytes."""
    try:
        encoded = text.encode('shift_jis')
    except (UnicodeEncodeError, LookupError):
        encoded = text.encode('ascii', errors='replace')
    if len(encoded) >= size:
        return encoded[:size]
    return encoded + b'\x00' * (size - len(encoded))


def hexdump(data: bytes, prefix: str = "") -> str:
    """Short hex dump for logging."""
    if len(data) <= 32:
        return prefix + data.hex()
    return prefix + data[:32].hex() + f"... ({len(data)} bytes total)"


def full_hexdump(data: bytes, label: str = "") -> str:
    """Full multi-line hex dump with ASCII for protocol debugging."""
    lines = [f"--- {label} ({len(data)} bytes) ---"]
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = ' '.join(f'{b:02X}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"  {i:04X}: {hex_part:<48s}  {ascii_part}")
    return '\n'.join(lines)


# ============================================================
# Client Session
# ============================================================

class DDSession:
    """Handles a single Dragon's Dream client connection."""

    _next_id = 0

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        DDSession._next_id += 1
        self.sid = DDSession._next_id
        self.reader = reader
        self.writer = writer
        self.running = True
        self.keepalive_task = None
        self.login_phase = 0  # tracks login flow stage
        # All server→client data uses IV framing (SV_RecvFrame resets to state 0 after each delivery)

        # Session protocol state
        self.session_param = self.sid & 0xFFFF
        self.connection_id = self.sid & 0xFFFF
        self.send_seq = 0  # outgoing BYTE OFFSET (incremented by SCMD size, not by 1)
        self.client_seq = 0  # last received client byte offset (for logging)

        # Character state
        self.char_id = 0x00000001
        self.char_name = sjis_pad("Player", 16)
        self.char_class = 0   # 0=warrior
        self.char_level = 1
        self.char_race = 0
        self.char_gender = 0
        self.reconnect_flag = 0  # 0x0000=new char, 0xFFFF=revive
        self.gold = 1000
        self.exp = 0
        self.hp = 100
        self.mp = 50
        # 19 stats: HP, MP, STR, VIT, INT, MND, AGI, DEX, LUK, CHA, + 9 more
        self.base_stats = [100, 50, 15, 12, 10, 10, 12, 10,
                           10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10]

        # World state
        self.zone_id = 1
        self.map_id = 1

    # ----------------------------------------------------------
    # Transport: IV framing
    # ----------------------------------------------------------
    async def send_iv(self, payload: bytes):
        """Send one IV frame."""
        frame = sv_encode(payload)
        self.writer.write(frame)
        await self.writer.drain()

    async def send_msg(self, msg_type: int, payload: bytes = b'', param1: int = 0):
        """Build SCMD game message, wrap in 0x00-type session DATA frame, send as IV."""
        scmd = build_game_msg(msg_type, payload, param1)
        session_frame = self._build_session_data_frame(scmd)
        await self.send_iv(session_frame)
        log.info("[S%d] >> SEND 0x%04X (%d bytes payload, param1=0x%04X, send_seq=%d)",
                 self.sid, msg_type, len(payload), param1, self.send_seq)
        log.debug("[S%d] >> SCMD:\n%s", self.sid, full_hexdump(scmd, f"SCMD 0x{msg_type:04X}"))
        log.debug("[S%d] >> Session frame:\n%s", self.sid,
                  full_hexdump(session_frame, "Session DATA frame"))

    async def recv_iv(self) -> bytes:
        """Receive one complete IV frame. Handles keepalives transparently."""
        while True:
            b = await self.reader.read(1)
            if not b:
                raise ConnectionError("Connection closed")

            if b == b'$':
                # Keepalive from client: read until \n, discard
                buf = b''
                while True:
                    c = await self.reader.read(1)
                    if not c:
                        raise ConnectionError("Connection closed in keepalive")
                    buf += c
                    if c == b'\n':
                        break
                log.info("[S%d] Client keepalive received", self.sid)
                continue

            if b == b'I':
                b2 = await self.reader.read(1)
                if not b2:
                    raise ConnectionError("Connection closed")
                if b2 == b'V':
                    break
                # Got 'I' but not 'V' — log both bytes
                log.info("[S%d] recv_iv: got 'I' then 0x%02X (not 'V')", self.sid, b2[0])
                continue
            # Not 'I' or '$' — log every byte so we can see what the Saturn sends
            log.info("[S%d] recv_iv: 0x%02X '%s'",
                     self.sid, b[0], chr(b[0]) if 32 <= b[0] < 127 else '.')

        # Read 6 hex chars
        hex_bytes = await self._readexact(6)
        size_str = hex_bytes[0:3].decode('ascii', errors='replace')
        comp_str = hex_bytes[3:6].decode('ascii', errors='replace')
        log.info("[S%d] IV header: IV%s%s", self.sid, size_str, comp_str)

        try:
            size = int(size_str, 16)
            comp = int(comp_str, 16)
        except ValueError:
            log.warning("[S%d] Invalid IV hex: %s%s (raw: %s)",
                        self.sid, size_str, comp_str, hex_bytes.hex())
            return b''

        if (size ^ comp) != 0xFFF:
            log.warning("[S%d] IV integrity fail: 0x%03X ^ 0x%03X = 0x%03X (expected 0xFFF)",
                        self.sid, size, comp, size ^ comp)

        # Read payload
        if size > 0:
            payload = await self._readexact(size)
            log.debug("[S%d] IV payload (%d bytes): %s",
                      self.sid, size, hexdump(payload[:32]))
            return payload
        return b''

    async def _readexact(self, n: int) -> bytes:
        """Read exactly n bytes."""
        buf = b''
        while len(buf) < n:
            chunk = await self.reader.read(n - len(buf))
            if not chunk:
                raise ConnectionError("Connection closed during read")
            buf += chunk
        return buf

    # ----------------------------------------------------------
    # Session Protocol (delivery function at 0x060423C8)
    # ----------------------------------------------------------
    # Session frame format (256 bytes, wrapped in IV frame):
    #   [0]:    protocol byte (0x00=server→client, 0xA6=client→server with escape encoding)
    #   [1]:    frame flags: bit0=has_seq_data, bit1=has_data, bit6=alt_data
    #   [2:4]:  uint16 BE checksum (sum of all bytes with [2:6] zeroed, & 0xFFFF)
    #   [4:6]:  zeroed (part of checksum field, cleared during verification)
    #   [6:8]:  escape byte (for 0xA6 frames) / unused (for 0x00 frames)
    #   [8:10]: uint16 BE session flags: bit3=ESTABLISH (required for state=2 transition)
    #   [10:256]: session data (zeros for establishment)
    #
    # Delivery function sets [0x06062374]=2 (CONNECTED) when:
    #   1. frame flags bit 0 = 0 (new frame, not retransmit)
    #   2. session flags [8:10] bit 3 (0x0008) is set (ESTABLISH)
    #   3. session callback non-NULL (set by SV_Setup) or setup function succeeds
    # There is NO two-frame handshake — a single correct frame sets state=2.

    def _session_checksum(self, payload: bytearray) -> int:
        """Calculate session checksum: sum of all bytes with [2:6] zeroed, & 0xFFFF."""
        total = 0
        for i, b in enumerate(payload):
            if 2 <= i < 6:
                continue
            total += b
        return total & 0xFFFF

    def _build_session_data_frame(self, scmd_data: bytes) -> bytes:
        """
        Build a 0x00-type session DATA frame wrapping SCMD game data.

        Binary evidence (delivery function at 0x060423C8, DATA path at 0x06042508):
          [0]     = 0x00 type marker (server→client, no escape encoding)
          [1]     = 0x03 flags: bit0=has_seq_data (read seq/ack from frame), bit1=has_data
          [2:4]   = uint16 BE checksum (sum all bytes with [2:6] zeroed, & 0xFFFF)
          [4:6]   = 0x0000 (zeroed for checksum)
          [6:8]   = 0x0000 (reserved/padding)
          [8:12]  = uint32 BE data_seq BYTE OFFSET (queue insert key, dispatch expects == session[116])
          [12:16] = uint32 BE ack_num (must be > session[112], monotonically increasing)
          [16:18] = uint16 BE copy_length (SCMD byte count)
          [18:20] = 0x0000 (padding)
          [20:]   = SCMD data (copy_length bytes)

        CRITICAL: Sequence numbers are BYTE OFFSETS, not frame counters!
        Evidence from client 0xA6 frames: INIT(seq=0, 74B SCMD) → next frame seq=74.
        After dispatch, Saturn updates session[116] = seq + copy_length.
        So server's seq must be cumulative SCMD byte offset.

        CRITICAL: ack must be > session[112] (monotonically increasing, any scheme).
        We use send_seq + 1 (byte offset + 1) which always increases.
        """
        frame = bytearray(20 + len(scmd_data))
        frame[0] = 0x00           # server→client type marker
        frame[1] = 0x03           # flags: has_seq_data | has_data (MUST have bit 0!)
        # [2:6] left as zero for checksum computation
        # [6:8] reserved
        struct.pack_into('>I', frame, 8, self.send_seq)           # data seq = byte offset
        struct.pack_into('>I', frame, 12, self.send_seq + 1)   # ack (must be > session[112])
        struct.pack_into('>H', frame, 16, len(scmd_data))     # copy length
        # [18:20] padding
        frame[20:20 + len(scmd_data)] = scmd_data             # SCMD payload
        # Compute and store checksum
        checksum = self._session_checksum(frame)
        struct.pack_into('>H', frame, 2, checksum)
        seq = self.send_seq
        self.send_seq += len(scmd_data)  # advance by SCMD byte count (byte-offset sequence)
        log.info("[S%d] Built session DATA frame: %d bytes, seq=%d, scmd_len=%d, cksum=0x%04X, header=%s",
                 self.sid, len(frame), seq, len(scmd_data), checksum, frame[:20].hex())
        return bytes(frame)

    def _decode_0xa6_payload(self, raw: bytes) -> bytes:
        """
        Extract SCMD game data from a 0xA6 escape-encoded session frame.

        Binary evidence (delivery function 0xA6 path at 0x06042484):
          [0]     = 0xA6 type marker
          [1]     = flags (bit0=retransmit, bit1=has_data, bit3=establish, etc.)
          [2:6]   = 4 ASCII hex chars (checksum)
          [6]     = escape byte (typically 0x1C)
          [7]     = sub-flags
          [8:]    = escape-encoded data:
                    4 escape-decoded bytes → uint32 sequence (R10)
                    4 escape-decoded bytes → uint32 val2 (R11)
                    4 raw bytes skipped (R3 += 4 at 0x060424AA)
                    remaining → escape-decoded SCMD data

        Escape encoding: if byte == escape_byte, next_byte ^ 0x60 = original byte.
        Returns empty bytes if no data, otherwise the extracted SCMD bytes.
        """
        if len(raw) < 8 or raw[0] != 0xA6:
            return b''

        flags = raw[1]
        if not (flags & 0x02):  # bit1 = has_data
            log.info("[S%d] 0xA6 status frame (no data), flags=0x%02X", self.sid, flags)
            return b''

        escape_byte = raw[6]
        pos = 8

        def read_escaped():
            nonlocal pos
            if pos >= len(raw):
                return 0
            b = raw[pos]
            pos += 1
            if b == escape_byte and pos < len(raw):
                b = raw[pos] ^ 0x60
                pos += 1
            return b & 0xFF

        # Read sequence number (uint32, 4 escape-decoded bytes)
        seq = (read_escaped() << 24) | (read_escaped() << 16) | (read_escaped() << 8) | read_escaped()
        # Read second uint32
        val2 = (read_escaped() << 24) | (read_escaped() << 16) | (read_escaped() << 8) | read_escaped()

        # Track client's sequence for ack_num in our DATA frames
        self.client_seq = seq

        log.info("[S%d] 0xA6 data: seq=%d, val2=0x%08X, raw_pos=%d, remaining=%d",
                 self.sid, seq, val2, pos, len(raw) - pos)

        # Skip 4 raw bytes (binary: R3 = read_ptr; R3 += 4)
        pos += 4

        # Remaining bytes = escape-decoded SCMD data
        scmd = bytearray()
        while pos < len(raw):
            scmd.append(read_escaped())

        if scmd:
            log.info("[S%d] Extracted SCMD (%d bytes): %s",
                     self.sid, len(scmd), scmd[:32].hex() + ('...' if len(scmd) > 32 else ''))
        return bytes(scmd)

    async def _send_session_establishment(self):
        """
        Send the initial 256-byte session establishment IV frame.

        Binary analysis of delivery function at 0x060423C8:
        - [0]=0x00: normal frame path (not 0xA6 escape-encoded)
        - [1]=0x42: frame flags (bit1=has_data, bit6=alt_data, bit0=0 new)
        - [2:4]: uint16 BE checksum (binary, NOT ASCII hex)
        - [8:10]=0x0008: ESTABLISH flag (bit 3) — REQUIRED for state=2 transition
        - Without ESTABLISH flag: delivery processes data but never sets CONNECTED
        """
        payload = bytearray(256)
        payload[0] = 0x00     # server→client type marker
        payload[1] = 0x00     # frame flags: NO has_data (non-data path reads [8:10] as sub-flags)
        # [8:10] = sub-flags with ESTABLISH bit (bit 3) — read by non-data path at 0x06042520
        # With flags=0x00: delivery function goes through non-data path → [8:10] → SP+40
        # Then at 0x060427AA: bit3 of SP+40 triggers ESTABLISH processing → state=2
        # NOTE: bit4 (0x10) sets receive window from [10:12] — setting to 0 blocks client sends!
        # session[116] = session[168] (initialized from default, should be 0 for zeroed struct)
        struct.pack_into('>H', payload, 8, 0x0008)   # bit 3 only: ESTABLISH
        # Compute and store checksum as uint16 BE at [2:4]
        checksum = self._session_checksum(payload)
        struct.pack_into('>H', payload, 2, checksum)

        await self.send_iv(bytes(payload))
        log.info("[S%d] Sent session establishment (256 bytes, flags=0x00, subflags=0x0008, cksum=0x%04X)",
                 self.sid, checksum)
        log.debug("[S%d] Establishment frame:\n%s", self.sid,
                  full_hexdump(bytes(payload), "Session ESTABLISH"))

    async def _session_message_loop(self):
        """
        Unified session message loop (handles both handshake and game phases).

        All post-BBS IV payloads go through the session protocol layer:
        - 0xA6 frames (client→server): escape-decode to extract SCMD data
        - 0x00 frames: parse session header to extract SCMD data
        - Other: try as raw SCMD (fallback)

        Dispatches extracted SCMD messages to game handlers.
        """
        msg_num = 0

        while self.running:
            try:
                raw = await asyncio.wait_for(self.recv_iv(), timeout=60.0)
            except asyncio.TimeoutError:
                log.debug("[S%d] Recv timeout (%d msgs so far)", self.sid, msg_num)
                continue

            if not raw:
                continue

            msg_num += 1

            if raw[0] == 0xA6:
                # Client→server session frame (escape-encoded)
                flags = raw[1]
                log.info("[S%d] << RECV 0xA6 #%d (%d bytes, flags=0x%02X)",
                         self.sid, msg_num, len(raw), flags)
                log.debug("[S%d] << Raw 0xA6:\n%s", self.sid,
                          full_hexdump(raw, "Client 0xA6 frame"))

                # Extract SCMD data from data frames
                scmd_data = self._decode_0xa6_payload(raw)
                if scmd_data and len(scmd_data) >= 8:
                    msg_type, payload, param1 = parse_game_msg(scmd_data)
                    if msg_type is not None:
                        log.info("[S%d] << SCMD 0x%04X (%d bytes, param1=0x%04X)",
                                 self.sid, msg_type, len(payload), param1)
                        await self._dispatch(msg_type, payload, param1)
                    else:
                        log.warning("[S%d] Failed to parse SCMD from 0xA6 data: %s",
                                    self.sid, scmd_data[:16].hex())
                elif scmd_data:
                    log.info("[S%d] 0xA6 data too short for SCMD (%d bytes): %s",
                             self.sid, len(scmd_data), scmd_data.hex())
                # Status/ACK frames (no data) are logged by _decode_0xa6_payload

            elif raw[0] == 0x00:
                # 0x00-type frame from client (unusual but handle it)
                log.info("[S%d] Recv 0x00 #%d (%d bytes): %s",
                         self.sid, msg_num, len(raw), raw[:32].hex())
                if len(raw) >= 20 and (raw[1] & 0x02):
                    data_len = struct.unpack_from('>H', raw, 16)[0]
                    scmd_data = raw[20:20 + data_len]
                    if len(scmd_data) >= 8:
                        msg_type, payload, param1 = parse_game_msg(scmd_data)
                        if msg_type is not None:
                            log.info("[S%d] << SCMD 0x%04X (%d bytes)",
                                     self.sid, msg_type, len(payload))
                            await self._dispatch(msg_type, payload, param1)

            else:
                # Fallback: try parsing as raw SCMD (pre-session-layer messages)
                log.info("[S%d] Recv raw #%d (%d bytes, type=0x%02X): %s",
                         self.sid, msg_num, len(raw), raw[0], raw[:32].hex())
                msg_type, payload, param1 = parse_game_msg(raw)
                if msg_type is not None:
                    log.info("[S%d] << raw SCMD 0x%04X (%d bytes)", self.sid, msg_type, len(payload))
                    await self._dispatch(msg_type, payload, param1)

        log.info("[S%d] Message loop ended after %d messages", self.sid, msg_num)

    # ----------------------------------------------------------
    # BBS handshake
    # ----------------------------------------------------------
    async def bbs_handshake(self) -> bool:
        """Handle BBS command phase. Content-aware — matches by keyword, not line count."""
        try:
            got_p = False
            got_set = False
            got_hrpg = False

            while not got_hrpg:
                line = await asyncio.wait_for(self._read_bbs_line(), timeout=30.0)
                text = line.strip()
                log.info("[S%d] BBS: %r", self.sid, text)

                if not got_p:
                    if text in (b'P', b' P'):
                        self.writer.write(b'*\r\n')
                        await self.writer.drain()
                        got_p = True
                    # Ignore empty/whitespace lines before P
                    continue

                if not got_set:
                    if text.startswith(b'SET'):
                        self.writer.write(b'*\r\n')
                        await self.writer.drain()
                        got_set = True
                    continue

                if text.startswith(b'C '):
                    service = text[2:].decode('ascii', errors='replace')
                    # Saturn's BBS match engine scans for "COM" substring.
                    # Send minimal response to minimize leftover bytes in UART buffer.
                    self.writer.write(b'COM\r\n')
                    await self.writer.drain()
                    log.info("[S%d] BBS: Connected to service '%s'", self.sid, service)
                    got_hrpg = True

            return True

        except asyncio.TimeoutError:
            log.warning("[S%d] BBS handshake timeout (P=%s SET=%s HRPG=%s)",
                        self.sid, got_p, got_set, got_hrpg)
            return False

    async def _read_bbs_line(self) -> bytes:
        """Read bytes until \\r."""
        buf = b''
        while True:
            b = await self.reader.read(1)
            if not b:
                raise ConnectionError("Closed during BBS")
            buf += b
            if b == b'\r':
                return buf

    # ----------------------------------------------------------
    # Keepalive
    # ----------------------------------------------------------
    def _build_keepalive_frame(self) -> bytes:
        """Build a session ACK-only frame (no SCMD data) for keepalive.

        Binary evidence (SV_RecvFrame at 0x060226DA, state 0):
          ANY non-'I' byte while CONNECTED triggers error_dialog(1) = comm error.
          Therefore the server MUST NOT send raw bytes like "$I'm alive!!\\r\\n".
          Instead we send a valid IV-wrapped session frame with flags=0x01
          (has_seq only, no data), which:
          - Passes SV_RecvFrame state 0→1→2 (valid IV header + payload)
          - Resets sv_ctx[0x07F4] timeout counter at exit 0x060228F8
          - Delivery function processes flags=0x01 with copy_length=0 (no SCMD dispatch)
          - Does NOT advance send_seq (no data payload)
        """
        frame = bytearray(20)
        frame[0] = 0x00           # server→client type marker
        frame[1] = 0x01           # flags: bit0=has_seq_data only (NO bit1=has_data)
        # [2:4] checksum (computed below)
        # [4:6] zeros
        # [6:8] zeros
        struct.pack_into('>I', frame, 8, self.send_seq)       # seq (current, NOT incremented)
        struct.pack_into('>I', frame, 12, self.send_seq + 1)  # ack (monotonically > prev)
        struct.pack_into('>H', frame, 16, 0)                  # copy_length = 0 (no SCMD)
        # [18:20] zeros
        checksum = self._session_checksum(frame)
        struct.pack_into('>H', frame, 2, checksum)
        return bytes(frame)

    async def _keepalive_loop(self):
        """Send IV-wrapped session ACK frames every 6 seconds.

        Prevents the client's SV timeout (sv_ctx[0x07F4] reaching 0x04B0=1200 frames)
        without triggering the comm error that raw non-IV bytes cause.
        """
        try:
            while self.running:
                await asyncio.sleep(6.0)
                if self.running:
                    frame = self._build_keepalive_frame()
                    await self.send_iv(frame)
                    log.debug("[S%d] >> Keepalive (IV-wrapped session ACK, seq=%d)",
                              self.sid, self.send_seq)
        except (ConnectionError, asyncio.CancelledError):
            pass

    # ----------------------------------------------------------
    # Main handler
    # ----------------------------------------------------------
    async def handle(self):
        """Main entry point for a client session."""
        addr = self.writer.get_extra_info('peername')
        log.info("[S%d] Connected from %s", self.sid, addr)

        try:
            # BBS phase
            if not await self.bbs_handshake():
                return
            log.info("[S%d] BBS complete, starting session handshake", self.sid)

            # Brief delay: Saturn needs ~2 VBlank frames after BBS to call
            # SV_Setup (state 3) and start SV_Poll → SV_RecvFrame.
            await asyncio.sleep(0.5)

            # Phase 1: Session establishment (triggers [0x06062374] = 2)
            await self._send_session_establishment()

            # Phase 2: Start keepalives immediately (prevent SV timeout during handshake)
            self.keepalive_task = asyncio.ensure_future(self._keepalive_loop())

            # Phase 3: Unified session message loop (handles handshake + game messages)
            await self._session_message_loop()

        except (ConnectionError, asyncio.IncompleteReadError) as e:
            log.info("[S%d] Disconnected: %s", self.sid, e)
        except Exception as e:
            log.error("[S%d] Error: %s", self.sid, e, exc_info=True)
        finally:
            self.running = False
            if self.keepalive_task:
                self.keepalive_task.cancel()
            try:
                self.writer.close()
            except Exception:
                pass
            log.info("[S%d] Session closed", self.sid)

    # ----------------------------------------------------------
    # Message dispatch
    # ----------------------------------------------------------
    async def _dispatch(self, msg_type: int, payload: bytes, param1: int):
        """Route message to handler."""
        # Explicit handlers for known messages
        handlers = {
            # Login flow
            0x0035: self._h_init,
            0x019E: self._h_login_request,
            0x01AA: self._h_update_chardata_reply,
            0x0B6C: self._h_chardata2_notice,

            # Movement
            0x01C1: self._h_move,
            0x01C2: self._h_move,

            # General client messages (acknowledged with paired reply)
            0x0048: self._h_standard_reply,
            0x019A: self._h_logout,
            0x019C: self._h_gotolist_notice,
            0x01AC: self._h_map_change_notice,
            0x01A7: self._h_ack_simple,
            0x01EC: self._h_ack_simple,
            0x01EE: self._h_ack_simple,
            0x01CF: self._h_exec_event,
            0x01DF: self._h_camp_in,
            0x0204: self._h_ack_simple,
            0x01B3: self._h_ack_simple,
            0x01D3: self._h_ack_simple,
            0x025F: self._h_ack_simple,
            0x01E3: self._h_ack_simple,
            0x01E6: self._h_ack_simple,
            0x01EA: self._h_ack_simple,
            0x0221: self._h_btl_cmd,
            0x0224: self._h_ack_simple,
            0x0296: self._h_ack_simple,
            0x0200: self._h_ack_simple,
            0x01FC: self._h_ack_simple,
            0x01FE: self._h_ack_simple,
            0x01F2: self._h_ack_simple,
            0x01F4: self._h_ack_simple,
            0x0202: self._h_ack_simple,
            0x020C: self._h_ack_simple,
            0x0210: self._h_ack_simple,
            0x0216: self._h_ack_simple,
            0x0219: self._h_ack_simple,
            0x01FA: self._h_ack_simple,
            0x01F8: self._h_ack_simple,
            0x020E: self._h_ack_simple,
            0x024B: self._h_ack_simple,
            0x024E: self._h_ack_simple,
            0x0245: self._h_ack_simple,
            0x0250: self._h_ack_simple,
            0x0254: self._h_ack_simple,
            0x025B: self._h_ack_simple,
            0x02D4: self._h_ack_simple,
            0x02DB: self._h_ack_simple,
            0x0068: self._h_ack_simple,
            0x006D: self._h_ack_simple,
            0x02F5: self._h_change_para,
            0x02D0: self._h_ack_simple,
            0x0289: self._h_ack_simple,
            0x028E: self._h_ack_simple,
            0x0290: self._h_ack_simple,
            0x0293: self._h_ack_simple,
            0x02ED: self._h_ack_simple,
            0x029D: self._h_ack_simple,
            0x029F: self._h_ack_simple,
            0x02A1: self._h_ack_simple,
            0x02A3: self._h_ack_simple,
            0x02A5: self._h_ack_simple,
            0x02A7: self._h_ack_simple,
            0x02A9: self._h_ack_simple,
            0x02AB: self._h_ack_simple,
            0x02AD: self._h_ack_simple,
            0x02AF: self._h_ack_simple,
            0x02B1: self._h_ack_simple,
            0x02B3: self._h_ack_simple,
            0x02B5: self._h_ack_simple,
            0x02B7: self._h_ack_simple,
            0x02B9: self._h_ack_simple,
            0x02BB: self._h_ack_simple,
            0x02BE: self._h_ack_simple,
            0x02C1: self._h_ack_simple,
            0x02C3: self._h_ack_simple,
            0x02C5: self._h_ack_simple,
            0x02C8: self._h_ack_simple,
            0x02CD: self._h_ack_simple,
            0x026A: self._h_ack_simple,
            0x0268: self._h_disarm_skill_reply,
            0x026C: self._h_ack_simple,
            0x026F: self._h_ack_simple,
            0x0271: self._h_ack_simple,
            0x0275: self._h_ack_simple,
            0x0277: self._h_ack_simple,
            0x02E0: self._h_ack_simple,
            0x02E2: self._h_ack_simple,
            0x02E4: self._h_ack_simple,
            0x02E6: self._h_ack_simple,
            0x02E8: self._h_ack_simple,
            0x0230: self._h_ack_simple,
            0x022C: self._h_ack_simple,
            0x0243: self._h_ack_simple,
            0x0235: self._h_ack_simple,
            0x0233: self._h_ack_simple,
            0x0240: self._h_ack_simple,
            0x0298: self._h_ack_simple,
            0x029A: self._h_ack_simple,
            0x01A2: self._h_ack_simple,
            0x01A4: self._h_ack_simple,
            0x023B: self._h_ack_simple,
            0x01AF: self._h_ack_simple,
            0x023E: self._h_ack_simple,
            0x04E0: self._h_ack_simple,
            0x01D6: self._h_ack_simple,
            0x02D9: self._h_ack_simple,
            0x02F7: self._h_ack_simple,
            0x01A0: self._h_ack_simple,
            0x02FA: self._h_ack_simple,
        }

        handler = handlers.get(msg_type)
        if handler:
            await handler(msg_type, payload, param1)
        else:
            log.debug("[S%d] Unhandled 0x%04X, trying paired reply", self.sid, msg_type)
            reply_type = PAIRED_TABLE.get(msg_type)
            if reply_type:
                await self.send_msg(reply_type, self._build_minimal_reply(reply_type))
            else:
                log.warning("[S%d] No handler or paired entry for 0x%04X", self.sid, msg_type)

    # ==========================================================
    # LOGIN FLOW HANDLERS
    # ==========================================================

    async def _h_init(self, msg_type, payload, param1):
        """
        0x0035 -> ESP_NOTICE (0x01E8): 51 bytes
        First game message. Resets client state and sends server info.

        INIT payload (66 bytes, from builder at file 0x012BE0):
          [0:8]   version string (ASCII, e.g. "BV451234")
          [8:32]  reserved (zeros)
          [32:56] character name (24 bytes Shift-JIS)
          [56:60] sentinel 0xFFFFFFFF
          [60:62] reconnect_flag: 0xFFFF=revive existing, 0x0000=new character
          [62:64] login_mode
          [64:66] protocol_version

        Paired table entry 0: 0x0035 → 0x01E8. Server sends ONLY ESP_NOTICE here.
        The client's login state machine (file 0x02C100) then waits for controller
        input — bitmask at 0x06060E76 is CONTROLLER BUTTON STATE written by
        Saturn peripheral polling at 0x06040B22 (NOT set by server messages):
          PAD_A (0x0400) → result 2 → REVIVE existing character
          PAD_C (0x0200) → result 1 → NEW character
          PAD_B (0x0100) → result 0xFF → CANCEL
        After button press, client sends LOGIN_REQUEST (0x019E).
        """
        log.info("[S%d] INIT received (%d bytes payload)", self.sid, len(payload))

        # Parse INIT payload
        reconnect_flag = 0
        if len(payload) >= 62:
            version_str = payload[0:8].rstrip(b'\x00').decode('ascii', errors='replace')
            name_bytes = payload[32:56]
            self.char_name = name_bytes[:16]  # store first 16 bytes for later use
            reconnect_flag = struct.unpack('>H', payload[60:62])[0]
            login_mode = struct.unpack('>H', payload[62:64])[0] if len(payload) >= 64 else 0
            proto_ver = struct.unpack('>H', payload[64:66])[0] if len(payload) >= 66 else 0
            try:
                name_str = name_bytes.rstrip(b'\x00').decode('shift_jis', errors='replace')
            except Exception:
                name_str = name_bytes.hex()
            log.info("[S%d] INIT: version=%r, name=%r, reconnect=0x%04X, mode=%d, proto=%d",
                     self.sid, version_str, name_str, reconnect_flag, login_mode, proto_ver)
        self.reconnect_flag = reconnect_flag

        # Send ESP_NOTICE (0x01E8): 51 bytes — the ONLY response to 0x0035
        esp = bytearray(51)
        struct.pack_into('>H', esp, 0, 0)              # status = 0 (success)
        struct.pack_into('>H', esp, 2, self.session_param)  # session_param → g_state+0x0264
        struct.pack_into('>H', esp, 4, self.connection_id)  # connection_id → g_state+0xA2
        esp[6] = 0                                       # game_mode → g_state+0xA4
        esp[7] = 0                                       # sub_mode → g_state+0xA5
        struct.pack_into('>I', esp, 8, 1)               # server_id → g_state+0x94
        esp[12:28] = sjis_pad("DD Revival", 16)         # server_name → g_state+0xA6
        # [28:40] session_data → g_state+0x7C88 = zeros
        # [40:51] config_bytes → g_state+0x7C94..0x7C9F = zeros

        await self.send_msg(MSG_ESP_NOTICE, bytes(esp))

        # Also send UPDATE_CHARDATA_REQUEST (0x019F): 24 bytes
        # Binary evidence from handler at file 0x3578:
        #   Stores char_id at g_state+0x0260, party entry at g_state+0x1BE0.
        #   Does NOT set init flags (0x8E-0x91) — those are set by ESP_NOTICE above.
        # Empirically REQUIRED: without this frame, Saturn times out after ~66s
        # (SV timeout 0x07D0=2000 from session response). The additional IV frame
        # keeps the connection alive and initializes party data structures needed
        # before LOGIN_REQUEST can be sent.
        resp = bytearray(24)
        struct.pack_into('>H', resp, 0, 0)              # status = 0 (success)
        struct.pack_into('>H', resp, 2, 1)              # char_field
        struct.pack_into('>I', resp, 4, self.char_id)   # char_id → g_state+0x0260
        resp[8:24] = self.char_name[:16]                 # char_data → party_entry[4:20]

        await self.send_msg(MSG_UPDATE_CHARDATA_REQ, bytes(resp))
        self.login_phase = 1

    async def _h_login_request(self, msg_type, payload, param1):
        """
        0x019E -> UPDATE_CHARDATA_REQUEST (0x019F): 24 bytes
        Client sends login credentials. Server acknowledges with char data ref.
        Client payload: W(0), W(flag), D(name,16), B*N...
        """
        if len(payload) >= 20:
            name_bytes = payload[4:20]
            self.char_name = name_bytes
            try:
                name_str = name_bytes.rstrip(b'\x00').decode('shift_jis', errors='replace')
            except Exception:
                name_str = name_bytes.hex()
            log.info("[S%d] LOGIN: name=%r", self.sid, name_str)

        # UPDATE_CHARDATA_REQUEST (0x019F): 24 bytes
        resp = bytearray(24)
        struct.pack_into('>H', resp, 0, 0)       # status = 0 (success)
        struct.pack_into('>H', resp, 2, 1)       # char_field
        struct.pack_into('>I', resp, 4, self.char_id)  # char_id
        resp[8:24] = self.char_name[:16]          # char_data

        await self.send_msg(MSG_UPDATE_CHARDATA_REQ, bytes(resp))
        self.login_phase = 2

    async def _h_update_chardata_reply(self, msg_type, payload, param1):
        """
        0x01AA -> CHARDATA_REQUEST (0x02F9): 72 or 172 bytes
        Client payload: W(1), W(f0), W(f1), W(f2), W(f3), W(f4) = 12 bytes

        After CHARDATA_REQUEST, server pushes CHARDATA_REPLY (0x02D2) with all 3 types:
          TYPE 1 (char_list): 24B/entry → stored at session+0x1684, count at session+0x1925
          TYPE 2 (char_detail): 52B/entry → stored at session+0x1BE0, TRIGGERS SYSTEM FILE SAVE
          TYPE 3 (inventory): 24B/entry → stored at session+0x1530, count at session+0x1924
        TYPE 2 is CRITICAL: it calls save function at 0x0603AD2C which writes character
        data to backup RAM. Without this, login state machine cannot complete.
        Then server sends INFORMATION_NOTICE (0x019D) to finalize login.
        """
        log.info("[S%d] UPDATE_CHARDATA_REPLY received (login_phase=%d)", self.sid, self.login_phase)

        # Guard: only run CHARDATA sequence once. _h_init and _h_login both send
        # 0x019F which each trigger UPDATE_CHARDATA_REPLY — skip the duplicate.
        # MUST send paired reply 0x02F9 with session_check=0 (success) to satisfy
        # context[6] tracking. session_check=1 causes "data seems to be missing" error
        # because the client handler at file 0x3648 treats nonzero as data unavailable.
        if self.login_phase >= 3:
            log.info("[S%d] CHARDATA already sent (login_phase=%d), sending 0x02F9 only",
                     self.sid, self.login_phase)
            await self._send_chardata_request()  # session_check=0, idempotent
            return

        # 1) Paired reply: CHARDATA_REQUEST (0x02F9)
        await self._send_chardata_request()
        await asyncio.sleep(0.05)

        # 2) Push CHARDATA_REPLY type 1 (char_list)
        await self._send_chardata_reply()
        await asyncio.sleep(0.05)

        # 3) Push CHARDATA_REPLY type 2 (char_detail) — triggers system file save
        await self._send_chardata_reply_type2()
        await asyncio.sleep(0.05)

        # 4) Push CHARDATA_REPLY type 3 (inventory) — empty for now
        await self._send_chardata_reply_type3()
        await asyncio.sleep(0.05)

        # 5) INFORMATION_NOTICE to finalize login
        await self._send_information_notice()
        self.login_phase = 3

        # 6) MAP_NOTICE (0x01DE) — push map grid data for minimap display.
        # Server-initiated NOTICE (no client response expected).
        # Handler at file 0x6C38 stores bit-packed map grid in g_state.
        # Default: 48x48 all-walkable. Not required for login but provides minimap.
        await asyncio.sleep(0.05)
        await self._send_map_notice()

        # 7) KNOWNMAP_NOTICE (0x01D2) — push explored map overlay.
        # Server-initiated NOTICE (no client response expected).
        # Handler at file 0x6CDA sets "known map loaded" flag.
        await asyncio.sleep(0.05)
        await self._send_knownmap_notice()

        # 8) CHARDATA_NOTICE (0x01AB) — push player character into game world
        # This is a server-initiated NOTICE (no client response expected).
        # Handler at file 0x3B90 stores character data for world display.
        # Without this, the login state machine has no character in-world and times out.
        await asyncio.sleep(0.05)
        await self._send_chardata_notice()
        self.login_phase = 4

    async def _h_chardata2_notice(self, msg_type, payload, param1):
        """
        0x0B6C -> CHARDATA_REQUEST (0x02F9): 72 or 172 bytes
        Client payload: D(identity, 16) = 16 bytes
        Post-login character data update (NOT part of initial login flow).
        Paired table entry 3: 0x0B6C → 0x02F9.
        """
        log.info("[S%d] CHARDATA2_NOTICE received (%d bytes)", self.sid, len(payload))

        # Paired reply: CHARDATA_REQUEST
        await self._send_chardata_request()
        await asyncio.sleep(0.05)

        # Push updated character data (all 3 types)
        await self._send_chardata_reply()
        await asyncio.sleep(0.05)
        await self._send_chardata_reply_type2()
        await asyncio.sleep(0.05)
        await self._send_chardata_reply_type3()

        self.login_phase = 4
        log.info("[S%d] CHARDATA2 update complete", self.sid)

    async def _send_chardata_request(self):
        """
        Send CHARDATA_REQUEST (0x02F9) to client.

        Handler at file 0x3648 reads:
          [0:2]   session_check (must be 0)
          [2:4]   char_field
          [4:8]   char_id
          [8:24]  name (16B)
          [24:32] status_block_A (fn_A106): [24]=type, [25]=field, [26]=race(lookup),
                  [27]=gender(lookup), [28]=level_raw, [29:30]=pad, [31]=misc
          [32:36] experience
          [36:40] gold
          [40:56] skill_ids (8 x U16)
          [56:64] status_block_B (fn_A1EA): [58]=class(0-5), [63]=level(1-16)
          [65]    skill_flag (0=clear)
          [67]    status_flag (nonzero=has extended +100B)
          [69]    item_flag (0=clear)
          [71]    license_flag (0=clear)
          --- if status_flag != 0 ---
          [72:110]  base_stats (19 x U16)
          [110:148] current_stats (19 x U16)
          [148:156] appearance (5B + 3B pad)
          [156:172] skill_levels (8 x U16)
        """
        resp = bytearray(172)

        # Fixed section (72 bytes)
        struct.pack_into('>H', resp, 0, 0)             # session_check = 0 (proceed)
        struct.pack_into('>H', resp, 2, 1)             # char_field
        struct.pack_into('>I', resp, 4, self.char_id)  # character_id
        resp[8:24] = self.char_name[:16]               # character_name (16B)

        # status_block_A (8 bytes at offset 24) — processed by fn_A106
        resp[24] = 0                 # type → char_struct[21]
        resp[25] = 0                 # field → char_struct[23]
        resp[26] = self.char_race    # race (lookup) → char_struct[24]
        resp[27] = self.char_gender  # gender (lookup) → char_struct[22]
        resp[28] = self.char_level   # level_raw → char_struct[25]
        resp[29] = 0                 # padding
        resp[30] = 0
        resp[31] = 0                 # misc → char_struct[46]

        # field_A, field_B
        struct.pack_into('>I', resp, 32, self.exp)    # experience
        struct.pack_into('>I', resp, 36, self.gold)   # gold

        # skill_ids (8 x U16 = 16 bytes at offset 40) - all zeros (no skills)

        # status_block_B (8 bytes at offset 56) — processed by fn_A1EA
        # fn_A1EA reads: [58]=class(0-5 validated), [63]=level(1-16 validated)
        resp[58] = self.char_class   # class (0-5) → validated by fn_A1EA
        resp[63] = self.char_level   # level (1-16) → validated by fn_A1EA

        # Flags (offsets 64-71)
        resp[65] = 0   # skill_flag: 0 = clear skill area (no skills)
        resp[67] = 1   # status_flag: nonzero = has extended data
        resp[69] = 0   # item_flag: 0 = clear item area
        resp[71] = 0   # license_flag: 0 = clear license area

        # Extended section (100 bytes at offset 72)
        # base_stats: 19 x U16 BE (38 bytes)
        for i in range(19):
            val = self.base_stats[i] if i < len(self.base_stats) else 10
            struct.pack_into('>H', resp, 72 + i * 2, val)

        # current_stats: 19 x U16 BE (38 bytes) - same as base for now
        for i in range(19):
            val = self.base_stats[i] if i < len(self.base_stats) else 10
            struct.pack_into('>H', resp, 110 + i * 2, val)

        # appearance_data: 5 bytes + 3 padding (8 bytes at offset 148)
        # skill_levels: 8 x U16 (16 bytes at offset 156) - zeros

        await self.send_msg(MSG_CHARDATA_REQUEST, bytes(resp))

    async def _send_chardata_reply(self):
        """
        Send CHARDATA_REPLY (0x02D2) with character list.
        Header: char_type(1), page_num(1), total_pages(1), num_entries(1), chunk_size(4)
        Type 1 entries: name(16), exp(2), class(1), race(1), field(1), field(1), status(1), pad(1)
        """
        entry = bytearray(24)
        entry[0:16] = self.char_name[:16]
        struct.pack_into('>H', entry, 16, self.exp & 0xFFFF)
        entry[18] = self.char_class
        entry[19] = self.char_race
        entry[20] = self.char_gender
        entry[21] = self.char_level
        entry[22] = 0  # status
        entry[23] = 0  # padding

        header = bytearray(8)
        header[0] = 1   # char_type = char_list
        header[1] = 1   # page_number = 1
        header[2] = 1   # total_pages = 1
        header[3] = 1   # num_entries = 1
        struct.pack_into('>I', header, 4, len(entry))  # chunk_size

        await self.send_msg(MSG_CHARDATA_REPLY, bytes(header) + bytes(entry))

    async def _send_chardata_reply_type2(self):
        """
        Send CHARDATA_REPLY (0x02D2) TYPE 2: char_detail.
        Handler at file 0x3858, TYPE 2 branch.
        52 bytes per entry → stored at session+0x1BE0 (164B each after expansion).
        After processing, triggers system file save via 0x0603AD2C (backup RAM write).

        Entry format (52 bytes):
          [0:2]   char_slot_id (U16 BE)
          [2]     class
          [3]     sub_class
          [4:20]  char_name (16 bytes Shift-JIS)
          [20:22] experience (U16 BE)
          [22:30] stat_bytes[8] (STR,VIT,INT,MND,AGI,DEX,LUK,CHA)
          [30:32] padding
          [32:36] gold/HP (U32 BE)
          [36:52] equipment_slots (8 × U16 BE)
        """
        entry = bytearray(52)
        struct.pack_into('>H', entry, 0, 0)              # char_slot_id = 0
        entry[2] = self.char_class                        # class
        entry[3] = 0                                      # sub_class
        entry[4:20] = self.char_name[:16]                 # char_name
        struct.pack_into('>H', entry, 20, self.exp & 0xFFFF)  # experience
        # stat_bytes[8]: STR,VIT,INT,MND,AGI,DEX,LUK,CHA
        stat_indices = [2, 3, 4, 5, 6, 7, 8, 9]  # indices into base_stats
        for i, si in enumerate(stat_indices):
            val = self.base_stats[si] if si < len(self.base_stats) else 10
            entry[22 + i] = min(val, 255)
        # [30:32] padding = 0
        struct.pack_into('>I', entry, 32, self.gold)     # gold/HP
        # [36:52] equipment_slots = all zeros (no equipment)

        header = bytearray(8)
        header[0] = 2   # char_type = char_detail
        header[1] = 1   # page_number = 1 (resets accumulation buffer)
        header[2] = 1   # total_pages = 1 (parse immediately since 1 >= 1)
        header[3] = 1   # num_entries = 1
        struct.pack_into('>I', header, 4, len(entry))    # chunk_size = 52

        await self.send_msg(MSG_CHARDATA_REPLY, bytes(header) + bytes(entry))

    async def _send_chardata_reply_type3(self):
        """
        Send CHARDATA_REPLY (0x02D2) TYPE 3: inventory.
        Handler at file 0x3858, TYPE 3 branch.
        24 bytes per entry (16B item_data + 8B discarded).
        Stored at session+0x1530, count at session+0x1924.
        Send with 0 entries for empty inventory.
        """
        header = bytearray(8)
        header[0] = 3   # char_type = inventory
        header[1] = 1   # page_number = 1
        header[2] = 1   # total_pages = 1
        header[3] = 0   # num_entries = 0 (empty inventory)
        struct.pack_into('>I', header, 4, 0)             # chunk_size = 0

        await self.send_msg(MSG_CHARDATA_REPLY, bytes(header))

    async def _send_information_notice(self):
        """Send INFORMATION_NOTICE (0x019D): 8 bytes (status + info_type + info_value).
        Handler at 0x3DDA reads info_type[2:4] and info_value[4:8] when status==0."""
        await self.send_msg(MSG_INFORMATION_NOTICE, struct.pack('>HHI', 0, 0, 0))

    async def _send_map_notice(self, width=48, rows=48):
        """
        Send MAP_NOTICE (0x01DE): variable-length map grid data.
        Handler at file 0x6C38 (mem 0x06016C38).

        Payload format (from binary decompilation):
          [0]    U8    width - map width in bits (max 48, stored at g_state[0x826C])
          [1]    U8    rows  - number of rows (max 48, stored at g_state[0x826D])
          [2:4]  U16   (skipped by handler, unused padding)
          [4:8]  U32   decompressed_size (read by read_be32 at 0x06019FD2, stored on stack)
          [8:]   bytes map data - rows * ceil(width/8) bytes

        The handler:
        1. Stores width at g_state[0x826C], rows at g_state[0x826D]
        2. Skips 2 bytes, reads 4-byte BE32 (decompressed_size) — NOT actually used
        3. Computes row_bytes = (width + 7) / 8 via division at 0x0603F694
        4. Clears two 288-byte buffers at g_state[0x826F] and g_state[0x838F]
        5. Copies row data: for each row, memcpy(g_state+0x826F+row*6, data, row_bytes)
        6. Sets [0x0605F432] |= 0x02 (bit 1 - map grid loaded)
        7. Sets g_state[0x84AF] = 1 (map loaded flag)

        Map buffer: g_state[0x826F..0x838E] = 288 bytes = 48 rows * 6 bytes/row
        Each row stores a bitmask of walkable/visible tiles.
        With 6 bytes per row and width=48, each bit represents one tile.
        All-1s = all tiles accessible. All-0s = no tiles.

        MAP_NOTICE is NOT required for login flow or movement (the flag bits it
        sets are never tested by other handlers). It provides minimap display data.
        """
        row_bytes = (width + 7) // 8
        total_data = row_bytes * rows
        # Build map data: all 0xFF = all tiles walkable/visible
        map_data = b'\xFF' * total_data

        payload = bytearray(8 + total_data)
        payload[0] = width & 0xFF
        payload[1] = rows & 0xFF
        payload[2] = 0  # padding
        payload[3] = 0  # padding
        struct.pack_into('>I', payload, 4, total_data)  # decompressed_size
        payload[8:8 + total_data] = map_data

        await self.send_msg(MSG_MAP_NOTICE, bytes(payload))

    async def _send_knownmap_notice(self, map_flags=0):
        """
        Send KNOWNMAP_NOTICE (0x01D2): 2 bytes.
        Handler at file 0x6CDA (mem 0x06016CDA).

        Payload format:
          [0:2]  U16 BE  map_flags (read but main effect is setting bit 2 of [0x0605F432])

        The handler:
        1. Reads 2-byte BE16 map_flags via 0x06019FF6 (stored on stack, not used elsewhere)
        2. Sets [0x0605F432] |= 0x04 (bit 2 - known map loaded)

        Like MAP_NOTICE, this flag bit is never tested by other handlers.
        It provides "explored areas" overlay data for minimap display.
        """
        await self.send_msg(MSG_KNOWNMAP_NOTICE, struct.pack('>H', map_flags))

    async def _send_chardata_notice(self):
        """
        Send CHARDATA_NOTICE (0x01AB): 76 bytes minimum (no equipment).
        Handler at file 0x3B90 stores character data for world display.

        Layout (from handler decompilation):
          [0:2]   char_id (U16 BE)
          [2:24]  char_name (22 bytes, handler skips but must be present)
          [24:32] appearance (8 bytes, parsed by parse_appearance)
          [32:36] experience (U32 BE)
          [36:40] gold (U32 BE)
          [40:56] stat_array (8 × U16 BE: HP, MP, STR, VIT, INT, MND, AGI, DEX)
          [56:64] status (8 bytes, parsed by parse_status: [58]=class, [63]=level)
          [64]    unknown_64
          [65]    unknown_65
          [66]    unknown_66
          [67]    has_equip_stats (0=present, nonzero=absent)
          [68]    unknown_68
          [69]    unknown_69
          [70]    num_equip_items
          [71]    has_equip_items (0=present, nonzero=absent)
          [72:76] padding
        """
        payload = bytearray(76)

        # [0:2] char_id
        struct.pack_into('>H', payload, 0, self.char_id & 0xFFFF)

        # [2:24] char_name (22 bytes, not read by handler but must occupy space)
        payload[2:2 + min(16, len(self.char_name))] = self.char_name[:16]

        # [24:32] appearance (8 bytes) — same layout as status_block_A in CHARDATA_REQUEST
        payload[24] = 0                 # type
        payload[25] = 0                 # field
        payload[26] = self.char_race    # race
        payload[27] = self.char_gender  # gender
        payload[28] = self.char_level   # level_raw

        # [32:36] experience
        struct.pack_into('>I', payload, 32, self.exp)

        # [36:40] gold
        struct.pack_into('>I', payload, 36, self.gold)

        # [40:56] stat_array (8 × U16 BE)
        for i in range(8):
            val = self.base_stats[i] if i < len(self.base_stats) else 10
            struct.pack_into('>H', payload, 40 + i * 2, val)

        # [56:64] status (8 bytes) — same layout as status_block_B in CHARDATA_REQUEST
        payload[58] = self.char_class   # class (0-5)
        payload[63] = self.char_level   # level (1-16)

        # [64:76] flags and padding
        payload[67] = 1  # has_equip_stats = nonzero → skip equip stats section
        payload[71] = 1  # has_equip_items = nonzero → skip equip items section

        await self.send_msg(MSG_CHARDATA_NOTICE, bytes(payload))
        log.info("[S%d] Sent CHARDATA_NOTICE (76 bytes, char_id=%d)", self.sid, self.char_id & 0xFFFF)

    # ==========================================================
    # GAME HANDLERS
    # ==========================================================

    async def _h_standard_reply(self, msg_type, payload, param1):
        """0x0048 - STANDARD_REPLY from client (paired entry 4).
        Client sends 0x0048, expects 0x0049 (SPEAK_REQUEST) reply.
        Handler at file 0x3D42 reads status(U16), then if status==0: speak_data(U16).
        Send status=1 (nonzero) to skip speak processing cleanly."""
        await self.send_msg(0x0049, struct.pack('>H', 1))

    async def _h_move(self, msg_type, payload, param1):
        """
        0x01C1/0x01C2 - Movement from client.
        Paired reply: MOVE1_REQUEST (0x01C4): 16 bytes
        Layout: status(2), unknown(2), skip(2), move_bytes(3+skip), move_value(2), trailing(4)
        """
        direction = payload[0] if payload else 0
        log.debug("[S%d] MOVE dir=%d", self.sid, direction)

        resp = bytearray(16)
        struct.pack_into('>H', resp, 0, 0)   # status = 0 (success)
        struct.pack_into('>H', resp, 2, 0)   # unknown
        # skip 2 bytes (offsets 4-5)
        resp[6] = 0     # move_byte_0
        resp[7] = 0     # move_byte_1
        resp[8] = 0     # move_byte_2 (direction/position)
        # skip 1 byte (offset 9)
        struct.pack_into('>H', resp, 10, 0)  # move_value
        # trailing 4 bytes (offset 12-15)

        await self.send_msg(MSG_MOVE1_REQUEST, bytes(resp))

    async def _h_logout(self, msg_type, payload, param1):
        """
        0x019A - Client LOGOUT is NOT a disconnect — it's a protocol transition
        requesting a destination list. Paired table entry 12: 0x019A → 0x019B.
        After receiving GOTOLIST_REQUEST, client shows destination selection UI.
        User selects → client sends GOTOLIST_NOTICE (0x019C) → server confirms
        with INFORMATION_NOTICE (0x019D) → login flow continues.

        GOTOLIST_REQUEST handler at file 0x492E:
          HEADER (8 bytes):
            [0:2] result_code (0=success)
            [2:4] entry_count → g_state+0xB8
            [4:8] page_token
          PER ENTRY (28 bytes, stored at g_state+0xBC + i*28):
            [0:4]   char_id
            [4:6]   zone_id
            [6:8]   map_id
            [8:10]  position
            [10]    type_flag
            [11]    padding
            [12:28] char_name (16 bytes, null-terminated at [27])
        """
        log.info("[S%d] LOGOUT (destination list request)", self.sid)

        # Build GOTOLIST_REQUEST with 1 destination entry
        entry_count = 1
        resp = bytearray(8 + entry_count * 28)
        struct.pack_into('>H', resp, 0, 0)            # result_code = 0 (success)
        struct.pack_into('>H', resp, 2, entry_count)  # entry_count = 1
        struct.pack_into('>I', resp, 4, 0)            # page_token

        # Entry 0: starting city
        off = 8
        struct.pack_into('>I', resp, off + 0, self.char_id)  # char_id
        struct.pack_into('>H', resp, off + 4, 1)             # zone_id = 1
        struct.pack_into('>H', resp, off + 6, 1)             # map_id = 1
        struct.pack_into('>H', resp, off + 8, 0)             # position = 0
        resp[off + 10] = 0                                    # type_flag
        resp[off + 11] = 0                                    # padding
        name = self.char_name[:16]
        resp[off + 12:off + 12 + len(name)] = name
        resp[off + 27] = 0  # null terminator

        await self.send_msg(MSG_GOTOLIST_REQUEST, bytes(resp))
        # Do NOT set self.running = False — login flow continues

    async def _h_gotolist_notice(self, msg_type, payload, param1):
        """
        0x019C - Client selected a destination from GOTOLIST.
        Paired table entry 13: 0x019C -> 0x019D.
        Client payload: L(dest_id) = 4 bytes.

        CORRECTED ANALYSIS (2026-03-15, updated):

        After INFORMATION_NOTICE is received, the client AUTOMATICALLY
        transitions from game world (session[0x01AD]=3) back to login state
        (session[0x01AD]=2) within 1-2 frames via the gate mechanism:
        1. Game world per-frame function (0x0603BB6E) sets session[0x01BC]=1
        2. Gate function 0x0603B6F0(1) checks g_state[0xE8C2]==1
        3. Gate PASSES: session[0x01BC]=0, session[0x01AD]=2 (login state)

        CRITICAL: The connection state machine (file 0x0103C0) does NOT
        re-send 0x0035 (INIT) after GOTOLIST. INIT is only sent ONCE when
        the SV layer first reaches CONNECTED state (R14[0xBF] transitions
        3->4). After INIT is sent, bit 7 is set (R14[0xBF]=0x84) which
        permanently prevents re-sending. The previous assumption that the
        connection state machine "detects state changes" was WRONG.

        Therefore the server MUST proactively send ESP_NOTICE and
        UPDATE_CHARDATA_REQ after INFORMATION_NOTICE to restart the login
        flow, since the client will never send INIT again.
        """
        dest_id = 0
        if len(payload) >= 4:
            dest_id = struct.unpack('>I', payload[:4])[0]
        log.info("[S%d] GOTOLIST_NOTICE: dest_id=%d", self.sid, dest_id)

        # Reset login_phase for the full login sequence to run again
        self.login_phase = 0

        # Paired reply: INFORMATION_NOTICE (0x019D)
        await self._send_information_notice()

        # Server must proactively send ESP_NOTICE + UPDATE_CHARDATA_REQ
        # because the client will NOT re-send INIT (0x0035) after GOTOLIST.
        # The connection state machine's INIT-sending state (4) has bit 7
        # set permanently after the first INIT, preventing re-send.
        # Without these messages, the client's login state machine has no
        # server data and the screen goes black.

        # ESP_NOTICE (0x01E8): 51 bytes - same as _h_init
        esp = bytearray(51)
        struct.pack_into('>H', esp, 0, 0)              # status = 0
        struct.pack_into('>H', esp, 2, self.session_param)
        struct.pack_into('>H', esp, 4, self.connection_id)
        esp[6] = 0                                       # game_mode
        esp[7] = 0                                       # sub_mode
        struct.pack_into('>I', esp, 8, 1)               # server_id
        esp[12:28] = sjis_pad("DD Revival", 16)         # server_name

        await self.send_msg(MSG_ESP_NOTICE, bytes(esp))

        # UPDATE_CHARDATA_REQ (0x019F): 24 bytes - same as _h_init
        resp = bytearray(24)
        struct.pack_into('>H', resp, 0, 0)
        struct.pack_into('>H', resp, 2, 1)
        struct.pack_into('>I', resp, 4, self.char_id)
        resp[8:24] = self.char_name[:16]

        await self.send_msg(MSG_UPDATE_CHARDATA_REQ, bytes(resp))
        self.login_phase = 1
        log.info("[S%d] GOTOLIST: sent INFORMATION + ESP_NOTICE + UPDATE_CHARDATA_REQ for re-login", self.sid)

    async def _h_map_change_notice(self, msg_type, payload, param1):
        """0x01AC - Map change. Respond with CAMP_IN_REQUEST."""
        resp = struct.pack('>H', 0)  # status = 0
        await self.send_msg(MSG_CAMP_IN_REQUEST, resp)

    async def _h_camp_in(self, msg_type, payload, param1):
        """0x01DF - Camp in notice. Respond with SET_MOVEMODE_REQUEST."""
        resp = struct.pack('>H', 0)  # move_mode = 0
        await self.send_msg(MSG_SET_MOVEMODE_REQ, resp)

    async def _h_exec_event(self, msg_type, payload, param1):
        """0x01CF - Execute event. Respond with EXEC_EVENT_REQUEST.
        Handler reads 8+ bytes when status==0 (event_id + data_size + N bytes).
        Status=1 rejects safely."""
        resp = struct.pack('>H', 1)  # status = 1 (reject)
        await self.send_msg(MSG_EXEC_EVENT_REQUEST, resp)

    async def _h_btl_cmd(self, msg_type, payload, param1):
        """0x0221 - Battle command. Respond with BTL_CMD_REQUEST.
        Handler falls through to BTL_CMD_REPLY reading ~24 bytes when status==0.
        Status=1 rejects safely."""
        resp = struct.pack('>H', 1)  # status = 1 (reject)
        await self.send_msg(MSG_BTL_CMD_REQUEST, resp)

    async def _h_disarm_skill_reply(self, msg_type, payload, param1):
        """
        0x0268 - DISARM_SKILL_REPLY from client.
        Paired reply: SEL_THEME_REQUEST (0x0269) — 2 bytes, status=0.
        Client payload: L(arg) = 4 bytes.

        Handler at file 0x9758 reads one U16 (status), stores at context+4.
        No state transitions triggered by this handler alone.
        """
        # Send paired reply
        await self.send_msg(MSG_SEL_THEME_REQUEST, struct.pack('>H', 0))

    async def _h_change_para(self, msg_type, payload, param1):
        """0x02F5 - Full character state sync from client. Respond with CHANGE_PARA_REQUEST."""
        log.info("[S%d] CHANGE_PARA received (%d bytes)", self.sid, len(payload))
        resp = struct.pack('>H', 0)
        await self.send_msg(MSG_CHANGE_PARA_REQUEST, resp)

    async def _h_ack_simple(self, msg_type, payload, param1):
        """
        Generic handler for messages that just need a paired reply with status=0.
        Looks up the paired reply type and sends a minimal successful response.
        """
        reply_type = PAIRED_TABLE.get(msg_type)
        if reply_type:
            # Build response based on what the client handler expects
            resp = self._build_minimal_reply(reply_type)
            await self.send_msg(reply_type, resp)
        else:
            log.debug("[S%d] No paired reply for 0x%04X", self.sid, msg_type)

    def _build_minimal_reply(self, reply_type: int) -> bytes:
        """
        Build a minimal valid response for a given reply message type.
        Most handlers check status at offset 0 (U16 BE) and skip on nonzero.
        """
        # Messages with special payload requirements.
        # CRITICAL: Each payload MUST be at least as large as the handler reads.
        # The SCMD buffer at 0x202E6148 retains residual data from prior messages.
        # Short payloads cause buffer overreads → garbage data → Saturn errors.
        special = {
            # ── List messages: header with entry_count=0 ──
            MSG_GOTOLIST_REQUEST:    struct.pack('>HHI', 0, 0, 0),          # 8B
            MSG_PARTYLIST_REQUEST:   struct.pack('>HHII', 0, 0, 0, 0),     # 12B
            MSG_SHOP_LIST_REQUEST:   struct.pack('>HHI', 0, 0, 0),          # 8B
            MSG_SHOP_ITEM_REQUEST:   struct.pack('>HHI', 0, 0, 0),          # 8B
            MSG_STORE_LIST_REQUEST:  struct.pack('>HHI', 0, 0, 0),          # 8B
            MSG_SAKAYA_LIST_REQUEST: struct.pack('>HHI', 0, 0, 0),          # 8B
            MSG_SAKAYA_TBLLIST_REQ:  struct.pack('>HHHHI', 0, 0, 0, 0, 0), # 12B: handler reads 12-byte header
            MSG_AREA_LIST_REQUEST:   struct.pack('>HHI', 0, 0, 0),          # 8B
            MSG_TELEPORTLIST_REQ:    struct.pack('>HHHHI', 0, 0, 0, 0, 0), # 12B
            MSG_DIR_REQUEST:         struct.pack('>HHI', 0, 0, 0),          # 8B
            MSG_SUBDIR_REQUEST:      struct.pack('>HHI', 0, 0, 0),          # 8B
            MSG_MEMODIR_REQUEST:     struct.pack('>HHHI', 0, 0, 0, 0),     # 12B
            MSG_MAIL_LIST_REQUEST:   struct.pack('>HHIBBI', 0, 0, 0, 0, 0, 0),  # 12B
            MSG_COLO_LIST_REQUEST:   struct.pack('>HHI', 0, 0, 0),          # 8B: handler reads H+H+I (not H+B+I)
            MSG_COLO_RANKING_REQ:    struct.pack('>HBBI', 0, 0, 0, 0),     # 8B
            MSG_SKILL_LIST_REQUEST:  struct.pack('>HHI', 0, 0, 0),          # 8B
            MSG_SHOP_BUY_REQUEST:    struct.pack('>HHI', 0, 0, 0),          # 8B
            MSG_SHOP_SELL_REQUEST:   struct.pack('>HHI', 0, 0, 0),          # 8B

            # ── Status=0, handler reads more → full zeroed payload ──
            MSG_PARTYID_REQUEST:     struct.pack('>HHI', 0, 0, self.char_id),  # 8B: value[2:4] + party_id[4:8]
            MSG_SPEAK_REQUEST:       struct.pack('>HH', 0, 0),              # 4B: speak_data[2:4]
            MSG_CLR_KNOWNMAP_REQ:    struct.pack('>HH', 0, 0),              # 4B
            MSG_CONFIRM_LVLUP_REQ:   struct.pack('>HI', 0, 0),             # 6B: levelup_data[2:6]
            MSG_CAST_DICE_REQUEST:   struct.pack('>HI', 0, 0),             # 6B: dice_result + data
            MSG_SET_SIGN_REQUEST:    struct.pack('>HH', 0, 0),              # 4B: sign_param[2:4]
            MSG_MOVE_SEAT_REQUEST:   struct.pack('>HH', 0, 0),              # 4B: seat_param[2:4]
            MSG_SET_SEKIBAN_REQUEST: struct.pack('>HH', 0, 0),              # 4B: sekiban_param[2:4]
            MSG_ALLOW_UNITE_REQUEST: struct.pack('>HH', 0, 0),              # 4B: always reads 2 U16s

            # ── Status=0, handler reads much more → reject (status=1) to skip reads ──
            MSG_PARTYEXIT_REQUEST:   struct.pack('>H', 1),                   # reject → skips 22B reads
            MSG_ESP_REQUEST:         struct.pack('>H', 1),                   # reject → skips 34+B reads
            MSG_EXEC_EVENT_REQUEST:  struct.pack('>H', 1),                   # reject → skips event data
            MSG_FINDUSER_REQUEST:    struct.pack('>H', 1),                   # "not found" → skips 4B
            MSG_SHOP_IN_REQUEST:     struct.pack('>H', 1),                   # reject → skips shop data
            MSG_STORE_IN_REQUEST:    struct.pack('>H', 1),                   # reject → skips store flag
            MSG_SAKAYA_IN_REQUEST:   struct.pack('>H', 1),                   # reject → skips in_param
            MSG_SAKAYA_EXIT_REQUEST: struct.pack('>H', 1),                   # reject → skips exit data
            MSG_SAKAYA_SIT_REQUEST:  struct.pack('>H', 1),                   # reject → skips sit_param
            MSG_SAKAYA_MEMLIST_REQ:  struct.pack('>H', 1),                   # reject → skips member data
            MSG_SAKAYA_FIND_REQUEST: struct.pack('>H', 1),                   # reject → skips find data
            MSG_SAKAYA_STAND_REQ:    struct.pack('>H', 1),                   # reject → skips stand_param
            MSG_BTL_CMD_REQUEST:     struct.pack('>H', 1),                   # reject → prevents fallthrough

            # ── No status check — unconditionally reads full payload ──
            MSG_GIVEUP_REQUEST:      b'\x00' * 16,                           # 16B: handler reads 16 unconditionally

            # ── Always reads beyond status regardless of value → pad to full size ──
            MSG_PARTYENTRY_REQUEST:  struct.pack('>HH', 1, 0),              # 4B: always reads 2 U16s
            MSG_PARTYUNITE_REQUEST:  struct.pack('>HH', 1, 0),              # 4B: always reads 2 U16s
            MSG_LEVELUP_REQUEST:     struct.pack('>HI', 1, 0),              # 6B: always reads status + U32
            MSG_COLO_ENTRY_REQUEST:  struct.pack('>HBB', 1, 0, 0),          # 4B: always reads status + U8

            # ── Status=0, handler reads only 2 bytes → safe as-is ──
            MSG_CAMP_IN_REQUEST:     struct.pack('>H', 0),
            MSG_CAMP_OUT_REQUEST:    struct.pack('>H', 0),
            MSG_EQUIP_REQUEST:       struct.pack('>H', 0),
            MSG_DISARM_REQUEST:      struct.pack('>H', 0),
            MSG_SET_MOVEMODE_REQ:    struct.pack('>H', 0),
            MSG_SETPOS_REQUEST:      struct.pack('>H', 0),
            MSG_EXPLAIN_REQUEST:     struct.pack('>HH', 0, 0),              # 4B
            MSG_ENCOUNTMONSTER_REQ:  struct.pack('>H', 0),
            MSG_BTL_CHGMODE_REQ:     struct.pack('>H', 0),
            MSG_BTL_EFFECTEND_REQ:   struct.pack('>H', 0),
            MSG_BTL_END_REQUEST:     struct.pack('>H', 0),
            MSG_CANCEL_ENCOUNT_REQ:  struct.pack('>H', 0),
            MSG_SHOP_OUT_REQUEST:    struct.pack('>H', 0),
            MSG_NEWS_WRITE_REQUEST:  struct.pack('>H', 0),
            MSG_NEWS_DEL_REQUEST:    struct.pack('>H', 0),
            MSG_BB_MKDIR_REQUEST:    struct.pack('>H', 0),
            MSG_BB_RMDIR_REQUEST:    struct.pack('>H', 0),
            MSG_BB_MKSUBDIR_REQUEST: struct.pack('>H', 0),
            MSG_BB_RMSUBDIR_REQUEST: struct.pack('>H', 0),
            MSG_ALLOW_JOIN_REQUEST:  struct.pack('>H', 0),
            MSG_CANCEL_JOIN_REQUEST: struct.pack('>H', 0),
            MSG_CLASS_LIST_REQUEST:  struct.pack('>H', 0),
            MSG_CHANGE_PARA_REQUEST: struct.pack('>H', 0),
            MSG_SEL_THEME_REQUEST:   struct.pack('>H', 0),
            MSG_CHECK_THEME_REQUEST: struct.pack('>H', 0),
            MSG_DEL_MAIL_REQUEST:    struct.pack('>H', 0),
            MSG_COLO_WAITING_REQ:    struct.pack('>H', 0),
            MSG_COLO_EXIT_REQUEST:   struct.pack('>H', 0),
            MSG_COLO_CANCEL_REQUEST: struct.pack('>H', 0),
            MSG_COLO_FLDENT_REQUEST: struct.pack('>H', 0),
            MSG_CARD_REQUEST:        struct.pack('>H', 0),
            MSG_ACTION_CHAT_REQUEST: struct.pack('>H', 0),
            MSG_REGIST_HANDLE_REQ:   struct.pack('>H', 0),
            MSG_TRADE_CANCEL_REQ:    struct.pack('>H', 0),

            # ── Nonzero status (reject) — handler skips reads, safe at 2 bytes ──
            MSG_FINDUSER2_REQUEST:   struct.pack('>H', 1),
            MSG_MIRRORDUNGEON_REQ:   struct.pack('>H', 1),
            MSG_NEWS_READ_REQUEST:   struct.pack('>H', 1),
            MSG_CLASS_CHANGE_REQ:    struct.pack('>H', 1),
            MSG_GIVE_ITEM_REQUEST:   struct.pack('>H', 1),
            MSG_USE_REQUEST:         struct.pack('>H', 1),
            MSG_SELL_REQUEST:        struct.pack('>H', 1),
            MSG_BUY_REQUEST:         struct.pack('>H', 1),
            MSG_COMPOUND_REQUEST:    struct.pack('>H', 1),
            MSG_LEARN_SKILL_REQUEST: struct.pack('>H', 1),
            MSG_SKILLUP_REQUEST:     struct.pack('>H', 1),
            MSG_EQUIP_SKILL_REQUEST: struct.pack('>H', 1),
            MSG_DISARM_SKILL_REQ:    struct.pack('>H', 1),
            MSG_USE_SKILL_REQUEST:   struct.pack('>H', 1),
            MSG_GET_MAIL_REQUEST:    struct.pack('>H', 1),
            MSG_SEND_MAIL_REQUEST:   struct.pack('>H', 1),

            # ── Empty handlers (no reads at all) ──
            MSG_USERLIST_REQUEST:    b'',
            MSG_CURREGION_NOTICE:    b'',
        }

        resp = special.get(reply_type)
        if resp is not None:
            return resp

        # Default: 2-byte status = 0
        return struct.pack('>H', 0)


# ============================================================
# Server
# ============================================================

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    session = DDSession(reader, writer)
    await session.handle()


async def main(host: str = '0.0.0.0', port: int = 8020):
    server = await asyncio.start_server(handle_client, host, port)
    addrs = ', '.join(str(s.getsockname()) for s in server.sockets)
    log.info("Dragon's Dream Revival Server v3 listening on %s", addrs)

    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Dragon's Dream Revival Server v3")
    parser.add_argument('--host', default='0.0.0.0', help='Bind address')
    parser.add_argument('--port', type=int, default=8020, help='Bind port')
    args = parser.parse_args()

    try:
        asyncio.run(main(args.host, args.port))
    except KeyboardInterrupt:
        log.info("Server stopped")
