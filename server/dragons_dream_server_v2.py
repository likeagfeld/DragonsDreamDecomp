#!/usr/bin/env python3
"""
Dragon's Dream (ドラゴンズドリーム) Revival Server v2
Fujitsu × SEGA, Saturn MMORPG, December 1997

PROTOCOL STACK (verified from binary analysis of 0.BIN):
  +------------------------------------------+
  | Game Messages                            |
  | [2B msg_type BE][payload of msg_type-2]  |
  +------------------------------------------+
  | SV Fragmentation (lib_sv.c)              |
  | "IVsssccc\\r\\n" + binary payload (≤256B) |
  +------------------------------------------+
  | Text Line Transport                      |
  | Lines: IV=data, $=keepalive, #=error     |
  +------------------------------------------+
  | TCP / Modem                              |
  +------------------------------------------+

CONNECTION FLOW:
  1. TCP connection established
  2. Saturn sends " P\\r" -> server responds "*\\r\\n"
  3. Saturn sends "SET 1:0,2:0,...\\r" -> server responds "*\\r\\n"
  4. Saturn sends "C HRPG\\r" -> server responds "COM HRPG\\r\\n"
  5. SV framing begins — game messages inside IV fragments
  6. Client sends LOGIN_REQUEST as first game message
"""

import argparse
import asyncio
import logging
import os
import sqlite3
import struct
import sys
import time
import traceback
from typing import Optional

# ═══════════════════════════════════════════════════════════════════════════════
# PROTOCOL CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

SERVER_PORT = 8020

# Game message header: just 2 bytes (msg_type)
# Wire format: [2B msg_type BE][payload of (msg_type - 2) bytes]
# msg_type value = total wire size of the message
MSG_HEADER_SIZE = 2

# SV framing constants (from binary at 0x03EEB8)
SV_MAX_FRAG_DATA = 256   # Max payload per IV fragment
SV_HEADER_BUF = 16       # Internal header buffer (aligned)
SV_BUFFER_SIZE = 2048    # Send/receive buffer size

# SV keepalive (from binary at 0x03EEC8)
SV_KEEPALIVE = b"$I'm alive!!\r\n"

# BBS commands (from binary at 0x03D790)
BBS_SET_CMD = b'SET 1:0,2:0,3:0,4:1,5:0,7:0,8:0,9:0,10:0,12:0,13:0,14:0,15:0,18:0,19:0,20:0,21:0,22:0\r'
BBS_C_HRPG = b'C HRPG\r'
BBS_OFF = b'OFF\r'

# Result codes (from handler dispatch analysis)
# Handler code: mov.w @(4,r14),r0 / tst r0,r0 / bt <error_path>
# Zero = error/no data, non-zero = success
RESULT_OK = 1
RESULT_ERROR = 0

# Keepalive interval (SV timeout ~10s at 60fps, send well before)
KEEPALIVE_INTERVAL = 6.0

# ═══════════════════════════════════════════════════════════════════════════════
# COMPLETE MESSAGE TABLE (310 entries from binary 0x04612C)
# Wire size = msg_type value; payload_size = wire_size - 2
# ═══════════════════════════════════════════════════════════════════════════════

MSG_TABLE = {
    0x0000: "SELECT_REQUEST",
    0x0043: "LOGOUT_REQUEST",
    0x0044: "COLO_MEMBER_NOTICE",
    0x0046: "REGIST_HANDLE_REQUEST",
    0x0048: "STANDARD_REPLY",
    0x0049: "SPEAK_REQUEST",
    0x004A: "SPEAK_REPLY",
    0x0068: "CARD_NOTICE",
    0x006D: "SYSTEM_NOTICE",
    0x006E: "ESP_REPLY",
    0x006F: "ESP_REQUEST",
    0x0076: "SPEAK_NOTICE",
    0x019A: "LOGOUT_NOTICE",
    0x019B: "GOTOLIST_REQUEST",
    0x019C: "GOTOLIST_NOTICE",
    0x019D: "INFORMATION_NOTICE",
    0x019E: "LOGIN_REQUEST",
    0x019F: "UPDATE_CHARDATA_REQUEST",
    0x01A0: "SAKAYA_IN_NOTICE",
    0x01A1: "USERLIST_REQUEST",
    0x01A2: "BB_RMSUBDIR_REPLY",
    0x01A3: "PARTYLIST_REQUEST",
    0x01A4: "PARTYLIST_REPLY",
    0x01A5: "PARTYENTRY_ACCEPT_REPLY",
    0x01A6: "PARTYENTRY_REPLY",
    0x01A7: "CLR_KNOWNMAP_REPLY",
    0x01A8: "PARTYEXIT_REQUEST",
    0x01A9: "PARTYEXIT_REPLY",
    0x01AA: "UPDATE_CHARDATA_REPLY",
    0x01AB: "CHARDATA_NOTICE",
    0x01AC: "MAP_CHANGE_NOTICE",
    0x01AD: "CAMP_IN_REQUEST",
    0x01AE: "CAMP_IN_REPLY",
    0x01AF: "AREA_LIST_REPLY",
    0x01B0: "TELEPORTLIST_REQUEST",
    0x01B2: "TEXT_NOTICE",
    0x01B3: "ALLOW_SETLEADER_REPLY",
    0x01B4: "CAMP_OUT_REQUEST",
    0x01B5: "CAMP_OUT_REPLY",
    0x01B6: "CANCEL_JOIN_NOTICE",
    0x01B7: "REGIONCHANGE_REQUEST",
    0x01B8: "FINDUSER_REQUEST",
    0x01B9: "CURREGION_NOTICE",
    0x01BC: "CHAR_DISAPPEAR_NOTICE",
    0x01BD: "SELECT_NOTICE",
    0x01C0: "CLASS_CHANGE_REPLY",
    0x01C1: "OTHERPARTY_DATA_NOTICE",
    0x01C2: "MOVE1_NOTICE",
    0x01C4: "MOVE1_REQUEST",
    0x01C5: "MOVE2_REQUEST",
    0x01C6: "EVENT_ITEM_NOTICE",
    0x01C7: "BTLJOIN_NOTICE",
    0x01C8: "BTL_GOLD_NOTICE",
    0x01C9: "ENCOUNTMONSTER_REPLY",
    0x01CA: "ENCOUNTMONSTER_NOTICE",
    0x01CF: "EVENT_NOTICE",
    0x01D0: "EXEC_EVENT_REQUEST",
    0x01D1: "EXEC_EVENT_REPLY",
    0x01D2: "KNOWNMAP_NOTICE",
    0x01D3: "GIVEUP_REPLY",
    0x01D4: "SETPOS_REQUEST",
    0x01D5: "SETPOS_REPLY",
    0x01D6: "SETPOS_NOTICE",
    0x01D7: "SETLEADER_REQUEST",
    0x01D8: "SETLEADER_REPLY",
    0x01DA: "MONSTER_DEL_NOTICE",
    0x01DB: "VISION_NOTICE",
    0x01DC: "OBITUARY_NOTICE",
    0x01DE: "MAP_NOTICE",
    0x01DF: "CAMP_IN_NOTICE",
    0x01E0: "SET_MOVEMODE_REQUEST",
    0x01E1: "SET_MOVEMODE_REPLY",
    0x01E3: "ENCOUNTPARTY_NOTICE",
    0x01E4: "CANCEL_ENCOUNT_REQUEST",
    0x01E5: "CANCEL_ENCOUNT_REPLY",
    0x01E6: "INQUIRE_JOIN_NOTICE",
    0x01E7: "ALLOW_JOIN_REQUEST",
    0x01E8: "ESP_NOTICE",
    0x01EA: "BTL_EFFECTEND_REPLY",
    0x01EB: "BTL_END_REQUEST",
    0x01EC: "AVATA_NOID_NOTICE",
    0x01ED: "PARTYID_REQUEST",
    0x01EE: "PARTYID_REPLY",
    0x01EF: "CLR_KNOWNMAP_REQUEST",
    0x01F2: "SHOP_ITEM_REPLY",
    0x01F3: "SHOP_BUY_REQUEST",
    0x01F4: "SHOP_BUY_REPLY",
    0x01F5: "SHOP_SELL_REQUEST",
    0x01F8: "USERLIST_NOTICE",
    0x01F9: "SAKAYA_TBLLIST_REQUEST",
    0x01FA: "SAKAYA_TBLLIST2_REQUEST",
    0x01FB: "SAKAYA_EXIT_REQUEST",
    0x01FC: "SHOP_IN_REPLY",
    0x01FD: "SHOP_ITEM_REQUEST",
    0x01FE: "SHOP_LIST_REPLY",
    0x01FF: "SHOP_IN_REQUEST",
    0x0200: "SHOP_SELL_REPLY",
    0x0201: "SHOP_OUT_REQUEST",
    0x0202: "SEKIBAN_NOTICE",
    0x0203: "SHOP_LIST_REQUEST",
    0x0204: "CAMP_OUT_NOTICE",
    0x0205: "EQUIP_REQUEST",
    0x020C: "STORE_IN_NOTICE",
    0x020D: "SAKAYA_LIST_REQUEST",
    0x020E: "SAKAYA_EXIT_NOTICE",
    0x020F: "SAKAYA_SIT_REQUEST",
    0x0210: "SAKAYA_LIST_NOTICE",
    0x0211: "SAKABA_MOVE_REQUEST",
    0x0212: "SAKABA_MOVE_REPLY",
    0x0213: "SAKAYA_LIST_REPLY",
    0x0214: "SAKAYA_TBLLIST_REPLY",
    0x0215: "GOTOLIST_REPLY",
    0x0216: "SAKABA_MOVE_NOTICE",
    0x0217: "SAKAYA_IN_REQUEST",
    0x0218: "SAKAYA_IN_REPLY",
    0x0219: "SAKAYA_FIND_REPLY",
    0x021A: "SAKAYA_STAND_REQUEST",
    0x021B: "SAKAYA_EXIT_REPLY",
    0x021C: "USERLIST_REPLY",
    0x021E: "SAKAYA_STAND_REPLY",
    0x021F: "BATTLEMODE_NOTICE",
    0x0220: "BTL_MEMBER_NOTICE",
    0x0221: "BTL_MENU_NOTICE",
    0x0222: "BTL_CMD_REQUEST",
    0x0223: "BTL_CMD_REPLY",
    0x0224: "BTL_CMD_NOTICE",
    0x0225: "BTL_CHGMODE_REQUEST",
    0x0226: "BTL_CHGMODE_REPLY",
    0x0227: "BTL_RESULT_NOTICE",
    0x0228: "BTL_END_NOTICE",
    0x0229: "BTL_MASK_NOTICE",
    0x022B: "PARTYENTRY_REQUEST",
    0x022C: "MEMBERDATA_NOTICE",
    0x022D: "PARTYUNITE_ACCEPT_REPLY",
    0x022E: "PARTYUNITE_REPLY",
    0x022F: "PARTYUNITE_REQUEST",
    0x0230: "INQUIRE_UNITE_NOTICE",
    0x0231: "ALLOW_UNITE_REQUEST",
    0x0232: "PARTYEXIT_NOTICE",
    0x0233: "TELEPORT_NOTICE",
    0x0234: "MIRRORDUNGEON_REQUEST",
    0x0235: "CANCEL_ENCOUNT_NOTICE",
    0x0236: "BTLJOIN_REQUEST",
    0x0237: "BTLJOIN_REPLY",
    0x023B: "ALLOW_UNITE_REPLY",
    0x023C: "AREA_LIST_REQUEST",
    0x023E: "TELEPORTLIST_REPLY",
    0x023F: "EXPLAIN_REQUEST",
    0x0240: "MIRRORDUNGEON_REPLY",
    0x0241: "FINDUSER2_REQUEST",
    0x0242: "CHANGE_PARA_REPLY",
    0x0243: "MONSTERWARN_NOTICE",
    0x0244: "ENCOUNTMONSTER_REQUEST",
    0x0245: "SAKAYA_CHARLIST_NOTICE",
    0x0246: "SET_SIGN_REQUEST",
    0x0247: "SET_SIGN_REPLY",
    0x0248: "SETCLOCK0_NOTICE",
    0x0249: "EVENT_MAP_NOTICE",
    0x024A: "MONSTER_MAP_NOTICE",
    0x024B: "SAKAYA_SIT_REPLY",
    0x024C: "SAKAYA_MEMLIST_REQUEST",
    0x024D: "SAKAYA_MEMLIST_REPLY",
    0x024E: "SAKAYA_MEMLIST_NOTICE",
    0x024F: "SAKAYA_FIND_REQUEST",
    0x0250: "MOVE_SEAT_NOTICE",
    0x0251: "SET_SEKIBAN_REQUEST",
    0x0252: "SET_SEKIBAN_REPLY",
    0x0253: "SET_SEKIBAN_NOTICE",
    0x0254: "SET_SIGN_NOTICE",
    0x0255: "MOVE_SEAT_REQUEST",
    0x0256: "MOVE_SEAT_REPLY",
    0x0257: "MISSPARTY_NOTICE",
    0x025A: "PARTYENTRY_NOTICE",
    0x025B: "ALLOW_JOIN_REPLY",
    0x025C: "CANCEL_JOIN_REQUEST",
    0x025D: "CANCEL_JOIN_REPLY",
    0x025E: "PARTYUNITE_NOTICE",
    0x025F: "PARTY_BREAKUP_NOTICE",
    0x0260: "ACTION_CHAT_REQUEST",
    0x0261: "ACTION_CHAT_REPLY",
    0x0263: "EQUIP_REPLY",
    0x0268: "DISARM_SKILL_REPLY",
    0x0269: "SEL_THEME_REQUEST",
    0x026A: "SEL_THEME_REPLY",
    0x026B: "CHECK_THEME_REQUEST",
    0x026C: "EQUIP_NOTICE",
    0x026D: "DISARM_REQUEST",
    0x026E: "DISARM_REPLY",
    0x026F: "FINDUSER_REPLY",
    0x0270: "STORE_LIST_REQUEST",
    0x0271: "STORE_LIST_REPLY",
    0x0272: "STORE_IN_REQUEST",
    0x0273: "STORE_IN_REPLY",
    0x0274: "ACTION_CHAT_NOTICE",
    0x0275: "COMPOUND_REPLY",
    0x0276: "CONFIRM_LVLUP_REQUEST",
    0x0277: "CONFIRM_LVLUP_REPLY",
    0x0278: "LEVELUP_REQUEST",
    0x0289: "USE_NOTICE",
    0x028A: "BUY_REPLY",
    0x028B: "TRADE_DONE_NOTICE",
    0x028C: "SELL_REPLY",
    0x028D: "SELL_REQUEST",
    0x028E: "INQUIRE_BUY_NOTICE",
    0x028F: "BUY_REQUEST",
    0x0290: "TRADE_NOTICE",
    0x0291: "TRADE_CANCEL_REQUEST",
    0x0292: "TRADE_CANCEL_REPLY",
    0x0293: "EVENT_MOVE_NOTICE",
    0x0294: "GIVE_ITEM_REQUEST",
    0x0295: "GIVE_ITEM_REPLY",
    0x0296: "BTL_ACTIONCOUNT_NOTICE",
    0x0297: "BTL_EFFECTEND_REQUEST",
    0x0298: "FINDUSER2_REPLY",
    0x0299: "CLASS_LIST_REQUEST",
    0x029A: "CLASS_LIST_REPLY",
    0x029B: "CLASS_CHANGE_REQUEST",
    0x029D: "SHOP_OUT_REPLY",
    0x029E: "DIR_REQUEST",
    0x029F: "DIR_REPLY",
    0x02A0: "SUBDIR_REQUEST",
    0x02A1: "SUBDIR_REPLY",
    0x02A2: "MEMODIR_REQUEST",
    0x02A3: "MEMODIR_REPLY",
    0x02A4: "NEWS_READ_REQUEST",
    0x02A5: "NEWS_READ_REPLY",
    0x02A6: "NEWS_WRITE_REQUEST",
    0x02A7: "NEWS_WRITE_REPLY",
    0x02A8: "NEWS_DEL_REQUEST",
    0x02A9: "CHECK_THEME_REPLY",
    0x02AA: "MAIL_LIST_REQUEST",
    0x02AB: "MAIL_LIST_REPLY",
    0x02AC: "GET_MAIL_REQUEST",
    0x02AD: "GET_MAIL_REPLY",
    0x02AE: "SEND_MAIL_REQUEST",
    0x02AF: "SEND_MAIL_REPLY",
    0x02B0: "DEL_MAIL_REQUEST",
    0x02B1: "NEWS_DEL_REPLY",
    0x02B2: "BB_MKDIR_REQUEST",
    0x02B3: "BB_MKDIR_REPLY",
    0x02B4: "BB_RMDIR_REQUEST",
    0x02B5: "BB_RMDIR_REPLY",
    0x02B6: "BB_MKSUBDIR_REQUEST",
    0x02B7: "BB_MKSUBDIR_REPLY",
    0x02B8: "BB_RMSUBDIR_REQUEST",
    0x02B9: "LEVELUP_REPLY",
    0x02BA: "SKILL_LIST_REQUEST",
    0x02BB: "DEL_MAIL_REPLY",
    0x02BC: "COLO_WAITING_REQUEST",
    0x02BD: "COLO_WAITING_REPLY",
    0x02BE: "COLO_WAITING_NOTICE",
    0x02BF: "COLO_EXIT_REQUEST",
    0x02C0: "COLO_EXIT_REPLY",
    0x02C1: "COLO_EXIT_NOTICE",
    0x02C2: "COLO_LIST_REQUEST",
    0x02C3: "COLO_LIST_REPLY",
    0x02C4: "COLO_ENTRY_REQUEST",
    0x02C5: "COLO_ENTRY_NOTICE",
    0x02C6: "COLO_CANCEL_REQUEST",
    0x02C7: "COLO_CANCEL_NOTICE",
    0x02C8: "COLO_BATTLE_NOTICE",
    0x02C9: "COLO_FLDENT_REQUEST",
    0x02CC: "COLO_FLDENT_NOTICE",
    0x02CD: "COLO_RESULT_NOTICE",
    0x02CE: "COLO_RANKING_REQUEST",
    0x02CF: "COLO_FLDENT_REPLY",
    0x02D0: "GIVE_ITEM_NOTICE",
    0x02D1: "USE_REQUEST",
    0x02D2: "CHARDATA_REPLY",
    0x02D3: "USE_REPLY",
    0x02D4: "CMD_BLOCK_REPLY",
    0x02D5: "CAST_DICE_REQUEST",
    0x02D6: "CAST_DICE_REPLY",
    0x02D7: "SETLEADER_NOTICE",
    0x02D8: "INQUIRE_LEADER_NOTICE",
    0x02D9: "SETLEADER_ACCEPT_REPLY",
    0x02DA: "ALLOW_SETLEADER_REQUEST",
    0x02DB: "CAST_DICE_NOTICE",
    0x02DC: "CARD_REQUEST",
    0x02DD: "CARD_REPLY",
    0x02E0: "SKILL_LIST_REPLY",
    0x02E1: "LEARN_SKILL_REQUEST",
    0x02E2: "LEARN_SKILL_REPLY",
    0x02E3: "SKILLUP_REQUEST",
    0x02E4: "SKILLUP_REPLY",
    0x02E5: "EQUIP_SKILL_REQUEST",
    0x02E6: "EQUIP_SKILL_REPLY",
    0x02E7: "DISARM_SKILL_REQUEST",
    0x02E8: "DISARM_NOTICE",
    0x02E9: "USE_SKILL_REQUEST",
    0x02EA: "USE_SKILL_REPLY",
    0x02EB: "COLO_ENTRY_REPLY",
    0x02EC: "COLO_CANCEL_REPLY",
    0x02ED: "TRADE_CANCEL_NOTICE",
    0x02EE: "COMPOUND_REQUEST",
    0x02EF: "EXEC_EVENT_NOTICE",
    0x02F0: "EVENT_EFFECT_NOTICE",
    0x02F1: "WAIT_EVENT_NOTICE",
    0x02F2: "COLO_RANKING_REPLY",
    0x02F3: "MOVE2_NOTICE",
    0x02F4: "BTL_END_REPLY",
    0x02F5: "USE_SKILL_NOTICE",
    0x02F6: "CHANGE_PARA_REQUEST",
    0x02F7: "SET_MOVEMODE_NOTICE",
    0x02F8: "GIVEUP_REQUEST",
    0x02F9: "CHARDATA_REQUEST",
    0x02FA: "SAKAYA_TBLLIST_NOTICE",
    0x04E0: "EXPLAIN_REPLY",
    0x04E1: "TELEPORT_REQUEST",
    0x0B6C: "CHARDATA2_NOTICE",
}

# Build reverse lookups
MSG_ID_BY_NAME = {name: mid for mid, name in MSG_TABLE.items()}

# Auto-generate REQUEST -> REPLY mapping
REQUEST_REPLY_MAP = {}
for _mid, _name in MSG_TABLE.items():
    if _name.endswith('_REQUEST'):
        _reply_name = _name.replace('_REQUEST', '_REPLY')
        _reply_mid = MSG_ID_BY_NAME.get(_reply_name)
        if _reply_mid:
            REQUEST_REPLY_MAP[_mid] = _reply_mid


def msg_name(msg_type: int) -> str:
    return MSG_TABLE.get(msg_type, f'UNKNOWN_0x{msg_type:04X}')


def payload_size(msg_type: int) -> int:
    return max(0, msg_type - MSG_HEADER_SIZE)


# ═══════════════════════════════════════════════════════════════════════════════
# LOGGING
# ═══════════════════════════════════════════════════════════════════════════════

LOG_PATH = 'dragons_dream_v2.log'

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_PATH, encoding='utf-8'),
    ]
)
log = logging.getLogger('DDv2')


def hexdump(data: bytes, width: int = 16, max_bytes: int = 512) -> str:
    lines = []
    for i in range(0, min(len(data), max_bytes), width):
        chunk = data[i:i+width]
        hex_part = ' '.join(f'{b:02X}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'  {i:04X}  {hex_part:<{width*3}}  {ascii_part}')
    if len(data) > max_bytes:
        lines.append(f'  ... ({len(data) - max_bytes} more bytes)')
    return '\n'.join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# SV FRAMING LAYER (lib_sv.c)
#
# Fragment wire format:
#   "IV" + 3 hex chars (size) + 3 hex chars (checksum) + "\r\n" + binary payload
#   Example: "IV048xxx\r\n" + 72 bytes
#
# Checksum: sum of payload bytes, masked to 12 bits (& 0x0FFF)
# Max fragment payload: 256 bytes
# Keepalive: "$I'm alive!!\r\n" (raw text, outside IV framing)
# ═══════════════════════════════════════════════════════════════════════════════

class SVFraming:
    """SV protocol framing layer for Dragon's Dream."""

    MAX_FRAG = SV_MAX_FRAG_DATA  # 256

    def __init__(self):
        self._recv_buf = bytearray()
        self._reassembly_buf = bytearray()

    @staticmethod
    def checksum(data: bytes) -> int:
        """Compute 12-bit checksum: additive byte sum & 0x0FFF."""
        return sum(data) & 0x0FFF

    def encode_fragment(self, payload: bytes) -> bytes:
        """Encode a single fragment with IV header."""
        size = len(payload)
        cksum = self.checksum(payload) if size > 0 else 0
        header = f"IV{size:03X}{cksum:03X}\r\n".encode('ascii')
        return header + payload

    def encode_message(self, game_msg: bytes) -> bytes:
        """Encode a complete game message into IV-framed fragments."""
        if not game_msg:
            return self.encode_fragment(b'')

        output = bytearray()
        offset = 0
        while offset < len(game_msg):
            chunk = game_msg[offset:offset + self.MAX_FRAG]
            output.extend(self.encode_fragment(chunk))
            offset += self.MAX_FRAG
        return bytes(output)

    def feed(self, data: bytes):
        """Feed raw TCP bytes into the receive buffer."""
        self._recv_buf.extend(data)

    def iter_events(self):
        """
        Parse the receive buffer and yield events:
          ('keepalive',)     — keepalive received
          ('fragment', payload_bytes) — IV fragment received
          ('error', msg_str) — error notification received
        """
        while True:
            if not self._recv_buf:
                break

            first = self._recv_buf[0]

            # '$' prefix = keepalive line
            if first == 0x24:
                nl = self._recv_buf.find(b'\n')
                if nl < 0:
                    break  # incomplete line
                self._recv_buf = self._recv_buf[nl + 1:]
                yield ('keepalive',)
                continue

            # '#' prefix = error notification
            if first == 0x23:
                nl = self._recv_buf.find(b'\n')
                if nl < 0:
                    break
                line = bytes(self._recv_buf[1:nl]).decode('ascii', errors='replace').strip()
                self._recv_buf = self._recv_buf[nl + 1:]
                yield ('error', line)
                continue

            # 'I' = possible IV header
            if first == 0x49:
                if len(self._recv_buf) < 2:
                    break
                if self._recv_buf[1] != 0x56:  # 'V'
                    self._recv_buf = self._recv_buf[1:]
                    continue

                # Need "IVsssccc\r\n" = 10 bytes minimum
                if len(self._recv_buf) < 10:
                    break

                # Validate \r\n at positions 8,9
                if self._recv_buf[8] != 0x0D or self._recv_buf[9] != 0x0A:
                    self._recv_buf = self._recv_buf[1:]
                    continue

                # Parse hex fields
                try:
                    size_str = self._recv_buf[2:5].decode('ascii')
                    cksum_str = self._recv_buf[5:8].decode('ascii')
                    frag_size = int(size_str, 16)
                    expected_cksum = int(cksum_str, 16)
                except (ValueError, UnicodeDecodeError):
                    self._recv_buf = self._recv_buf[1:]
                    continue

                # Sanity check size
                if frag_size > 4095:
                    self._recv_buf = self._recv_buf[1:]
                    continue

                # Check if we have the full payload
                total_frame = 10 + frag_size
                if len(self._recv_buf) < total_frame:
                    break  # incomplete, wait for more data

                # Extract payload
                frag_payload = bytes(self._recv_buf[10:total_frame])
                self._recv_buf = self._recv_buf[total_frame:]

                # Verify checksum
                computed = self.checksum(frag_payload)
                if computed != expected_cksum:
                    log.warning('SV checksum mismatch: expected 0x%03X got 0x%03X (%d bytes)',
                                expected_cksum, computed, frag_size)

                yield ('fragment', frag_payload)
                continue

            # Skip whitespace/noise
            if first in (0x0D, 0x0A, 0x20):
                self._recv_buf = self._recv_buf[1:]
                continue

            # Unknown byte, skip
            self._recv_buf = self._recv_buf[1:]

    def process_fragment(self, frag_payload: bytes):
        """Add fragment payload to reassembly buffer."""
        if frag_payload:
            self._reassembly_buf.extend(frag_payload)

    def iter_messages(self):
        """Yield complete game messages from the reassembly buffer."""
        while len(self._reassembly_buf) >= MSG_HEADER_SIZE:
            msg_type = struct.unpack('>H', self._reassembly_buf[:2])[0]

            if msg_type < MSG_HEADER_SIZE:
                # Invalid — clear buffer
                self._reassembly_buf.clear()
                break

            if msg_type > 8192:
                # Sanity — discard
                log.warning('SV reassembly: msg_type 0x%04X too large, clearing', msg_type)
                self._reassembly_buf.clear()
                break

            if len(self._reassembly_buf) < msg_type:
                break  # need more fragments

            # Complete message
            msg = bytes(self._reassembly_buf[:msg_type])
            self._reassembly_buf = bytearray(self._reassembly_buf[msg_type:])
            yield msg


# ═══════════════════════════════════════════════════════════════════════════════
# GAME MESSAGE BUILDERS (2-byte header: [msg_type BE][payload])
# ═══════════════════════════════════════════════════════════════════════════════

def build_game_msg(msg_type: int, payload: bytes = b'') -> bytes:
    """
    Build a game message: [2B msg_type][payload].
    Payload is padded/truncated to (msg_type - 2) bytes.
    """
    expected = payload_size(msg_type)
    if len(payload) != expected:
        if len(payload) < expected:
            payload = payload + b'\x00' * (expected - len(payload))
        else:
            payload = payload[:expected]
    return struct.pack('>H', msg_type) + payload


def build_standard_reply(result: int = RESULT_OK, extra: bytes = b'') -> bytes:
    """STANDARD_REPLY (0x0048) — 72 bytes total, 70 bytes payload."""
    pld = bytearray(payload_size(0x0048))
    struct.pack_into('>H', pld, 0, result)
    if extra:
        copy_len = min(len(extra), len(pld) - 2)
        pld[2:2+copy_len] = extra[:copy_len]
    return build_game_msg(0x0048, bytes(pld))


def build_chardata_reply(char: dict, status: int = 2) -> bytes:
    """
    CHARDATA_REPLY (0x02D2) — 722 bytes total, 720 bytes payload.
    Status: 1=new character, 2=existing character.
    Payload layout from binary handler analysis at 0x003858:
      +0x00: result/status (2B)
      +0x10: header block
      +0x44: character name region
      +0x58-0x62: stats
    """
    pld = bytearray(payload_size(0x02D2))
    struct.pack_into('>H', pld, 0, status)

    # Character name at offset 0x44 (relative to payload)
    handle = char.get('handle', '').encode('ascii', errors='replace')[:31]
    pld[0x44:0x44+len(handle)] = handle

    # Member ID at offset 0x10
    member_id = char.get('member_id', '').encode('ascii', errors='replace')[:63]
    pld[0x10:0x10+len(member_id)] = member_id

    # Stats (bytes at 0x58-0x62)
    pld[0x58] = min(255, char.get('level', 1))
    pld[0x59] = min(255, char.get('race', 0))
    pld[0x5A] = min(255, char.get('class_id', 0))
    pld[0x5B] = min(255, char.get('gender', 0))

    # 32-bit stats starting at 0x5C
    struct.pack_into('>I', pld, 0x5C, char.get('hp_cur', 50))
    struct.pack_into('>I', pld, 0x60, char.get('hp_max', 50))
    struct.pack_into('>I', pld, 0x64, char.get('mp_cur', 20))
    struct.pack_into('>I', pld, 0x68, char.get('mp_max', 20))
    struct.pack_into('>I', pld, 0x6C, char.get('str_', 10))
    struct.pack_into('>I', pld, 0x70, char.get('agi', 10))
    struct.pack_into('>I', pld, 0x74, char.get('int_', 10))
    struct.pack_into('>I', pld, 0x78, char.get('vit', 10))
    struct.pack_into('>I', pld, 0x7C, char.get('luc', 10))
    struct.pack_into('>I', pld, 0x80, char.get('def_', 10))
    struct.pack_into('>I', pld, 0x84, char.get('spd', 10))
    struct.pack_into('>I', pld, 0x88, char.get('atk', 10))

    # Experience
    struct.pack_into('>I', pld, 0x8C, char.get('exp', 0))

    # Gold
    struct.pack_into('>I', pld, 0x90, char.get('gold', 100))

    # Position data
    struct.pack_into('>I', pld, 0xA0, char.get('dungeon_id', 0))
    struct.pack_into('>I', pld, 0xA4, char.get('floor', 0))
    struct.pack_into('>I', pld, 0xA8, char.get('pos_x', 0))
    struct.pack_into('>I', pld, 0xAC, char.get('pos_y', 0))
    struct.pack_into('>I', pld, 0xB0, char.get('facing', 0))

    return build_game_msg(0x02D2, bytes(pld))


def build_chardata2_notice(players: list) -> bytes:
    """CHARDATA2_NOTICE (0x0B6C) — 2924 bytes total. Nearby player list."""
    pld = bytearray(payload_size(0x0B6C))
    struct.pack_into('>H', pld, 0, RESULT_OK)
    struct.pack_into('>I', pld, 2, int(time.time()))
    struct.pack_into('>I', pld, 6, len(players))
    return build_game_msg(0x0B6C, bytes(pld))


def build_map_notice(dungeon_id: int = 0, floor: int = 0) -> bytes:
    """MAP_NOTICE (0x01DE) — 478 bytes total."""
    pld = bytearray(payload_size(0x01DE))
    struct.pack_into('>H', pld, 0, RESULT_OK)
    struct.pack_into('>I', pld, 2, dungeon_id)
    struct.pack_into('>I', pld, 6, floor)
    return build_game_msg(0x01DE, bytes(pld))


def build_curregion_notice(region_id: int = 0) -> bytes:
    """CURREGION_NOTICE (0x01B9) — 441 bytes total."""
    pld = bytearray(payload_size(0x01B9))
    struct.pack_into('>H', pld, 0, RESULT_OK)
    struct.pack_into('>I', pld, 2, region_id)
    return build_game_msg(0x01B9, bytes(pld))


def build_information_notice(text: str = '') -> bytes:
    """INFORMATION_NOTICE (0x019D) — 413 bytes total."""
    pld = bytearray(payload_size(0x019D))
    struct.pack_into('>H', pld, 0, RESULT_OK)
    enc = text.encode('ascii', errors='replace')[:payload_size(0x019D) - 3]
    pld[2:2+len(enc)] = enc
    return build_game_msg(0x019D, bytes(pld))


def build_speak_notice(handle: str, text: str) -> bytes:
    """SPEAK_NOTICE (0x0076) — 118 bytes total, 116 bytes payload."""
    pld = bytearray(payload_size(0x0076))
    struct.pack_into('>H', pld, 0, RESULT_OK)
    h_enc = handle.encode('ascii', errors='replace')[:31]
    pld[2:2+len(h_enc)] = h_enc
    t_enc = text.encode('ascii', errors='replace')[:79]
    pld[34:34+len(t_enc)] = t_enc
    return build_game_msg(0x0076, bytes(pld))


def build_logout_notice(member_id: str) -> bytes:
    """LOGOUT_NOTICE (0x019A) — 410 bytes total."""
    pld = bytearray(payload_size(0x019A))
    struct.pack_into('>H', pld, 0, RESULT_OK)
    enc = member_id.encode('ascii', errors='replace')[:63]
    pld[2:2+len(enc)] = enc
    return build_game_msg(0x019A, bytes(pld))


def build_setclock0_notice() -> bytes:
    """SETCLOCK0_NOTICE (0x0248) — 584 bytes total. Server time/clock."""
    pld = bytearray(payload_size(0x0248))
    struct.pack_into('>H', pld, 0, RESULT_OK)
    struct.pack_into('>I', pld, 2, int(time.time()))
    return build_game_msg(0x0248, bytes(pld))


def build_knownmap_notice() -> bytes:
    """KNOWNMAP_NOTICE (0x01D2) — 466 bytes total. Explored map data."""
    pld = bytearray(payload_size(0x01D2))
    struct.pack_into('>H', pld, 0, RESULT_OK)
    return build_game_msg(0x01D2, bytes(pld))


def build_typed_reply(reply_type: int, result: int = RESULT_OK) -> bytes:
    """Build a generic reply of any type with result code at payload[0:2]."""
    pld = bytearray(payload_size(reply_type))
    struct.pack_into('>H', pld, 0, result)
    return build_game_msg(reply_type, bytes(pld))


# ═══════════════════════════════════════════════════════════════════════════════
# PAYLOAD PARSERS
# ═══════════════════════════════════════════════════════════════════════════════

def _read_cstr(buf: bytes, off: int, maxlen: int) -> str:
    end = buf.find(b'\x00', off, off + maxlen)
    if end < 0:
        end = off + maxlen
    return buf[off:end].decode('ascii', errors='replace')


def parse_login_request(payload: bytes) -> dict:
    return {
        'member_id': _read_cstr(payload, 0, 64),
        'game_version': _read_cstr(payload, 128, 16) if len(payload) >= 144 else '',
    }


def parse_speak_request(payload: bytes) -> dict:
    return {'text': _read_cstr(payload, 0, min(len(payload), 71))}


def parse_regist_handle(payload: bytes) -> dict:
    return {'handle': _read_cstr(payload, 0, min(len(payload), 64))}


# ═══════════════════════════════════════════════════════════════════════════════
# DATABASE
# ═══════════════════════════════════════════════════════════════════════════════

DB_PATH = 'dragons_dream_v2.db'


class Database:
    def __init__(self, path: str = DB_PATH):
        self.path = path
        self._conn = None
        self._init_schema()

    @property
    def conn(self) -> sqlite3.Connection:
        if not self._conn:
            self._conn = sqlite3.connect(self.path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute('PRAGMA journal_mode=WAL')
        return self._conn

    def _init_schema(self):
        c = sqlite3.connect(self.path)
        c.executescript("""
            CREATE TABLE IF NOT EXISTS characters (
                member_id  TEXT PRIMARY KEY,
                handle     TEXT DEFAULT '',
                level      INTEGER DEFAULT 1,
                race       INTEGER DEFAULT 0,
                class_id   INTEGER DEFAULT 0,
                gender     INTEGER DEFAULT 0,
                exp        INTEGER DEFAULT 0,
                hp_cur     INTEGER DEFAULT 50,
                hp_max     INTEGER DEFAULT 50,
                mp_cur     INTEGER DEFAULT 20,
                mp_max     INTEGER DEFAULT 20,
                str_       INTEGER DEFAULT 10,
                agi        INTEGER DEFAULT 10,
                int_       INTEGER DEFAULT 10,
                vit        INTEGER DEFAULT 10,
                luc        INTEGER DEFAULT 10,
                def_       INTEGER DEFAULT 10,
                spd        INTEGER DEFAULT 10,
                atk        INTEGER DEFAULT 10,
                dungeon_id INTEGER DEFAULT 0,
                floor      INTEGER DEFAULT 0,
                pos_x      INTEGER DEFAULT 0,
                pos_y      INTEGER DEFAULT 0,
                facing     INTEGER DEFAULT 0,
                gold       INTEGER DEFAULT 100,
                created_at INTEGER DEFAULT (strftime('%s','now'))
            );
            CREATE TABLE IF NOT EXISTS mail (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                from_id    TEXT NOT NULL,
                to_id      TEXT NOT NULL,
                subject    TEXT DEFAULT '',
                body       TEXT DEFAULT '',
                read       INTEGER DEFAULT 0,
                created_at INTEGER DEFAULT (strftime('%s','now'))
            );
            CREATE TABLE IF NOT EXISTS bulletin (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                author_id  TEXT NOT NULL,
                dir_name   TEXT DEFAULT 'general',
                title      TEXT DEFAULT '',
                body       TEXT DEFAULT '',
                created_at INTEGER DEFAULT (strftime('%s','now'))
            );
        """)
        c.commit()
        c.close()

    def get_or_create_character(self, member_id: str) -> dict:
        row = self.conn.execute(
            'SELECT * FROM characters WHERE member_id=?', (member_id,)
        ).fetchone()
        if row:
            return dict(row)
        self.conn.execute(
            'INSERT INTO characters(member_id, handle) VALUES(?,?)',
            (member_id, member_id)
        )
        self.conn.commit()
        return self.get_or_create_character(member_id)

    def update_character(self, member_id: str, fields: dict):
        allowed = {
            'handle', 'level', 'race', 'class_id', 'gender', 'exp',
            'hp_cur', 'hp_max', 'mp_cur', 'mp_max',
            'str_', 'agi', 'int_', 'vit', 'luc', 'def_', 'spd', 'atk',
            'dungeon_id', 'floor', 'pos_x', 'pos_y', 'facing', 'gold',
        }
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return
        set_clause = ', '.join(f'{k}=?' for k in updates)
        vals = list(updates.values()) + [member_id]
        self.conn.execute(
            f"UPDATE characters SET {set_clause} WHERE member_id=?", vals
        )
        self.conn.commit()

    def register_handle(self, member_id: str, handle: str) -> bool:
        taken = self.conn.execute(
            'SELECT member_id FROM characters WHERE handle=? AND member_id!=?',
            (handle, member_id)
        ).fetchone()
        if taken:
            return False
        self.update_character(member_id, {'handle': handle})
        return True

    def get_mail_list(self, member_id: str) -> list:
        rows = self.conn.execute(
            'SELECT id, from_id, subject, read, created_at FROM mail WHERE to_id=? ORDER BY id DESC LIMIT 20',
            (member_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_mail(self, mail_id: int) -> Optional[dict]:
        row = self.conn.execute('SELECT * FROM mail WHERE id=?', (mail_id,)).fetchone()
        if row:
            self.conn.execute('UPDATE mail SET read=1 WHERE id=?', (mail_id,))
            self.conn.commit()
            return dict(row)
        return None

    def send_mail(self, from_id: str, to_id: str, subject: str, body: str) -> bool:
        self.conn.execute(
            'INSERT INTO mail(from_id, to_id, subject, body) VALUES(?,?,?,?)',
            (from_id, to_id, subject, body)
        )
        self.conn.commit()
        return True

    def delete_mail(self, mail_id: int, member_id: str) -> bool:
        self.conn.execute('DELETE FROM mail WHERE id=? AND to_id=?', (mail_id, member_id))
        self.conn.commit()
        return True


# ═══════════════════════════════════════════════════════════════════════════════
# ONLINE REGISTRY
# ═══════════════════════════════════════════════════════════════════════════════

class OnlineRegistry:
    def __init__(self):
        self._clients = {}   # member_id -> ClientSession
        self._lock = asyncio.Lock()

    async def add(self, member_id: str, session):
        async with self._lock:
            self._clients[member_id] = session

    async def remove(self, member_id: str):
        async with self._lock:
            self._clients.pop(member_id, None)

    async def get_online_list(self) -> list:
        async with self._lock:
            return list(self._clients.keys())

    async def get_session(self, member_id: str):
        async with self._lock:
            return self._clients.get(member_id)

    async def broadcast(self, game_msg: bytes, exclude: str = None):
        """Broadcast a game message to all connected clients via SV framing."""
        async with self._lock:
            for mid, session in list(self._clients.items()):
                if mid != exclude:
                    try:
                        await session.send_game_msg(game_msg)
                    except Exception:
                        pass

    async def broadcast_raw(self, data: bytes, exclude: str = None):
        """Broadcast raw (already SV-framed) data."""
        async with self._lock:
            for mid, session in list(self._clients.items()):
                if mid != exclude:
                    try:
                        session.writer.write(data)
                        await session.writer.drain()
                    except Exception:
                        pass


# ═══════════════════════════════════════════════════════════════════════════════
# CLIENT SESSION
# ═══════════════════════════════════════════════════════════════════════════════

class ClientSession:
    """Manages one connected Saturn client through BBS -> SV -> game protocol."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 db: Database, registry: OnlineRegistry):
        self.reader = reader
        self.writer = writer
        self.db = db
        self.registry = registry
        self.sv = SVFraming()
        self.member_id = None
        self.handle = None
        self.char = None
        addr = writer.get_extra_info('peername')
        self.addr_str = f'{addr[0]}:{addr[1]}' if addr else 'unknown'
        self.log = logging.getLogger(f'DDv2/{self.addr_str}')
        self._keepalive_task = None
        self._connected = False

    async def send_raw(self, data: bytes):
        """Send raw bytes over TCP."""
        self.writer.write(data)
        await self.writer.drain()

    async def send_game_msg(self, game_msg: bytes):
        """Send a game message through SV framing."""
        framed = self.sv.encode_message(game_msg)
        self.log.debug('SEND game msg 0x%04X (%d bytes) -> %d framed bytes',
                       struct.unpack('>H', game_msg[:2])[0] if len(game_msg) >= 2 else 0,
                       len(game_msg), len(framed))
        await self.send_raw(framed)

    # ── BBS Phase ─────────────────────────────────────────────────────────

    async def do_bbs_phase(self) -> bool:
        """
        Handle NIFTY-Serve BBS connection phase.
        Server WAITS for client to speak first.
        Returns True if BBS phase succeeded -> enter SV/game mode.
        """
        self.log.info('BBS phase: waiting for client to speak first...')
        buf = bytearray()

        while True:
            try:
                data = await asyncio.wait_for(self.reader.read(1024), timeout=60.0)
            except asyncio.TimeoutError:
                self.log.warning('BBS phase: 60s timeout, no data from client')
                return False

            if not data:
                self.log.info('BBS phase: client disconnected')
                return False

            buf.extend(data)
            self.log.debug('BBS recv (%d bytes total):\n%s', len(buf), hexdump(bytes(buf)))

            # Process line-by-line (\r terminated)
            while b'\r' in buf:
                cr_pos = buf.index(b'\r')
                line = bytes(buf[:cr_pos])
                del buf[:cr_pos + 1]
                # Consume optional \n after \r
                if buf and buf[0:1] == b'\n':
                    del buf[:1]

                line_str = line.decode('ascii', errors='replace').strip()
                self.log.info('BBS command: "%s"', line_str)

                if b'C HRPG' in line or b'C NETRPG' in line:
                    # Connect to game service — send COM response and enter SV mode
                    self.log.info('BBS: C HRPG -> responding "COM HRPG\\r\\n"')
                    await self.send_raw(b'COM HRPG\r\n')
                    # Any remaining data goes to SV layer
                    if buf:
                        self.sv.feed(bytes(buf))
                        buf.clear()
                    return True

                elif b'SET ' in line:
                    # Terminal settings — respond with * prompt
                    self.log.info('BBS: SET -> responding "*\\r\\n"')
                    await self.send_raw(b'*\r\n')

                elif b'OFF' in line:
                    self.log.info('BBS: OFF -> disconnecting')
                    return False

                else:
                    # Initial " P\r" or any other command — respond with * prompt
                    self.log.info('BBS: "%s" -> responding "*\\r\\n"', line_str)
                    await self.send_raw(b'*\r\n')

            # Check for possible direct SV data (no BBS phase)
            if len(buf) >= 2 and buf[:2] == b'IV':
                self.log.info('BBS: detected IV header — client skipped BBS, entering SV mode')
                self.sv.feed(bytes(buf))
                buf.clear()
                return True

            # Safety: very large buffer without \r means something is wrong
            if len(buf) > 4096:
                self.log.warning('BBS: >4KB without CR — forcing SV mode')
                self.sv.feed(bytes(buf))
                buf.clear()
                return True

    # ── Keepalive ─────────────────────────────────────────────────────────

    async def _keepalive_loop(self):
        """Send periodic SV keepalive to prevent timeout."""
        try:
            while True:
                await asyncio.sleep(KEEPALIVE_INTERVAL)
                self.writer.write(SV_KEEPALIVE)
                await self.writer.drain()
                self.log.debug('Sent keepalive')
        except (ConnectionError, asyncio.CancelledError):
            pass

    # ── Message Handlers ──────────────────────────────────────────────────

    async def handle_login(self, payload: bytes):
        """Handle LOGIN_REQUEST (0x019E)."""
        info = parse_login_request(payload)
        member_id = info['member_id'].strip('\x00').strip()
        self.log.info('LOGIN_REQUEST: member_id=%r version=%r',
                      member_id, info['game_version'])

        if not member_id:
            member_id = f'GUEST_{self.addr_str}'

        self.member_id = member_id
        self.char = self.db.get_or_create_character(member_id)
        self.handle = self.char.get('handle', member_id)

        await self.registry.add(member_id, self)

        # Send login response sequence
        await self.send_game_msg(build_standard_reply(RESULT_OK))
        await self.send_game_msg(build_chardata_reply(self.char, status=2))
        await self.send_game_msg(build_curregion_notice(0))
        await self.send_game_msg(build_map_notice(0, 0))
        await self.send_game_msg(build_knownmap_notice())
        await self.send_game_msg(build_setclock0_notice())
        await self.send_game_msg(build_chardata2_notice([]))
        await self.send_game_msg(build_information_notice('Welcome to Dragons Dream!'))

        self.log.info('Login complete: %s (%s)', member_id, self.handle)

    async def handle_logout(self, payload: bytes):
        """Handle LOGOUT_REQUEST (0x0043)."""
        self.log.info('LOGOUT_REQUEST from %s', self.member_id)
        if self.member_id:
            await self.registry.broadcast(
                build_logout_notice(self.member_id), exclude=self.member_id)
            await self.registry.remove(self.member_id)
        raise ConnectionError('Client logout')

    async def handle_speak(self, payload: bytes):
        """Handle SPEAK_REQUEST (0x0049)."""
        info = parse_speak_request(payload)
        text = info['text']
        self.log.info('SPEAK: [%s] %s', self.handle, text)

        # Send SPEAK_REPLY to speaker
        await self.send_game_msg(build_typed_reply(0x004A, RESULT_OK))

        # Broadcast SPEAK_NOTICE to all
        notice = build_speak_notice(self.handle or self.member_id or 'Unknown', text)
        await self.registry.broadcast(notice)

    async def handle_regist_handle(self, payload: bytes):
        """Handle REGIST_HANDLE_REQUEST (0x0046)."""
        info = parse_regist_handle(payload)
        handle = info['handle'].strip('\x00').strip()
        self.log.info('REGIST_HANDLE: %s -> %s', self.member_id, handle)

        if self.member_id and handle:
            ok = self.db.register_handle(self.member_id, handle)
            if ok:
                self.handle = handle
            await self.send_game_msg(build_standard_reply(RESULT_OK if ok else RESULT_ERROR))
        else:
            await self.send_game_msg(build_standard_reply(RESULT_ERROR))

    async def handle_chardata_request(self, payload: bytes):
        """Handle CHARDATA_REQUEST (0x02F9)."""
        req_member = _read_cstr(payload, 0, 64) if len(payload) >= 64 else ''
        req_member = req_member.strip('\x00').strip() or self.member_id
        self.log.info('CHARDATA_REQUEST for %s', req_member)

        if req_member:
            char = self.db.get_or_create_character(req_member)
            await self.send_game_msg(build_chardata_reply(char, status=2))
        else:
            await self.send_game_msg(build_typed_reply(0x02D2, RESULT_ERROR))

    async def handle_update_chardata(self, payload: bytes):
        """Handle UPDATE_CHARDATA_REQUEST (0x019F)."""
        self.log.info('UPDATE_CHARDATA_REQUEST from %s', self.member_id)
        # Client is sending updated character data — save it
        if self.member_id and len(payload) >= 0x62:
            fields = {}
            if len(payload) >= 0x59:
                fields['level'] = payload[0x58]
            if len(payload) >= 0x5A:
                fields['race'] = payload[0x59]
            if len(payload) >= 0x5B:
                fields['class_id'] = payload[0x5A]
            if len(payload) >= 0x5C:
                fields['gender'] = payload[0x5B]
            self.db.update_character(self.member_id, fields)
            self.char = self.db.get_or_create_character(self.member_id)

        await self.send_game_msg(build_typed_reply(0x01AA, RESULT_OK))

    async def handle_area_list(self, payload: bytes):
        """Handle AREA_LIST_REQUEST (0x023C)."""
        self.log.info('AREA_LIST_REQUEST')
        pld = bytearray(payload_size(0x01AF))
        struct.pack_into('>H', pld, 0, RESULT_OK)
        struct.pack_into('>I', pld, 2, 1)  # 1 area available

        # Area entry: name + ID
        area_name = b'Starter Town'
        pld[6:6+len(area_name)] = area_name

        await self.send_game_msg(build_game_msg(0x01AF, bytes(pld)))

    async def handle_gotolist(self, payload: bytes):
        """Handle GOTOLIST_REQUEST (0x019B)."""
        self.log.info('GOTOLIST_REQUEST')
        await self.send_game_msg(build_typed_reply(0x0215, RESULT_OK))

    async def handle_userlist(self, payload: bytes):
        """Handle USERLIST_REQUEST (0x01A1)."""
        online = await self.registry.get_online_list()
        self.log.info('USERLIST_REQUEST: %d online', len(online))

        pld = bytearray(payload_size(0x021C))
        struct.pack_into('>H', pld, 0, RESULT_OK)
        struct.pack_into('>I', pld, 2, len(online))

        # Pack user entries (handle strings)
        offset = 6
        for i, mid in enumerate(online[:10]):  # max 10 in reply
            char = self.db.get_or_create_character(mid)
            h = char.get('handle', mid).encode('ascii', errors='replace')[:31]
            if offset + 32 <= len(pld):
                pld[offset:offset+len(h)] = h
                offset += 32

        await self.send_game_msg(build_game_msg(0x021C, bytes(pld)))

    async def handle_partyid(self, payload: bytes):
        """Handle PARTYID_REQUEST (0x01ED)."""
        self.log.info('PARTYID_REQUEST')
        await self.send_game_msg(build_typed_reply(0x01EE, RESULT_OK))

    async def handle_partylist(self, payload: bytes):
        """Handle PARTYLIST_REQUEST (0x01A3)."""
        self.log.info('PARTYLIST_REQUEST')
        await self.send_game_msg(build_typed_reply(0x01A4, RESULT_OK))

    async def handle_camp_in(self, payload: bytes):
        """Handle CAMP_IN_REQUEST (0x01AD)."""
        self.log.info('CAMP_IN_REQUEST')
        await self.send_game_msg(build_typed_reply(0x01AE, RESULT_OK))

    async def handle_camp_out(self, payload: bytes):
        """Handle CAMP_OUT_REQUEST (0x01B4)."""
        self.log.info('CAMP_OUT_REQUEST')
        await self.send_game_msg(build_typed_reply(0x01B5, RESULT_OK))

    async def handle_setpos(self, payload: bytes):
        """Handle SETPOS_REQUEST (0x01D4)."""
        self.log.info('SETPOS_REQUEST')
        if self.member_id and len(payload) >= 16:
            fields = {}
            if len(payload) >= 4:
                fields['pos_x'] = struct.unpack_from('>I', payload, 0)[0]
            if len(payload) >= 8:
                fields['pos_y'] = struct.unpack_from('>I', payload, 4)[0]
            if len(payload) >= 12:
                fields['facing'] = struct.unpack_from('>I', payload, 8)[0]
            self.db.update_character(self.member_id, fields)
        await self.send_game_msg(build_typed_reply(0x01D5, RESULT_OK))

    async def handle_move(self, msg_type: int, payload: bytes):
        """Handle MOVE1_REQUEST (0x01C4) and MOVE2_REQUEST (0x01C5)."""
        move_type = 'MOVE1' if msg_type == 0x01C4 else 'MOVE2'
        self.log.debug('%s_REQUEST', move_type)

        # Extract position from payload if available
        if self.member_id and len(payload) >= 12:
            fields = {
                'pos_x': struct.unpack_from('>I', payload, 0)[0],
                'pos_y': struct.unpack_from('>I', payload, 4)[0],
                'facing': struct.unpack_from('>I', payload, 8)[0],
            }
            self.db.update_character(self.member_id, fields)

        # Broadcast movement to other players
        notice_type = 0x01C2 if msg_type == 0x01C4 else 0x02F3
        notice_pld = bytearray(payload_size(notice_type))
        struct.pack_into('>H', notice_pld, 0, RESULT_OK)
        # Copy member_id into notice
        if self.member_id:
            mid_enc = self.member_id.encode('ascii', errors='replace')[:63]
            notice_pld[2:2+len(mid_enc)] = mid_enc
        # Copy position data
        if len(payload) >= 12:
            notice_pld[66:66+12] = payload[:12]

        notice = build_game_msg(notice_type, bytes(notice_pld))
        await self.registry.broadcast(notice, exclude=self.member_id)

    async def handle_regionchange(self, payload: bytes):
        """Handle REGIONCHANGE_REQUEST (0x01B7)."""
        region_id = 0
        if len(payload) >= 4:
            region_id = struct.unpack_from('>I', payload, 0)[0]
        self.log.info('REGIONCHANGE_REQUEST: region=%d', region_id)

        await self.send_game_msg(build_standard_reply(RESULT_OK))
        await self.send_game_msg(build_curregion_notice(region_id))
        await self.send_game_msg(build_map_notice(0, 0))

    async def handle_teleportlist(self, payload: bytes):
        """Handle TELEPORTLIST_REQUEST (0x01B0)."""
        self.log.info('TELEPORTLIST_REQUEST')
        await self.send_game_msg(build_typed_reply(0x023E, RESULT_OK))

    async def handle_teleport(self, payload: bytes):
        """Handle TELEPORT_REQUEST (0x04E1)."""
        self.log.info('TELEPORT_REQUEST')
        dest_id = 0
        if len(payload) >= 4:
            dest_id = struct.unpack_from('>I', payload, 0)[0]

        await self.send_game_msg(build_standard_reply(RESULT_OK))
        await self.send_game_msg(build_curregion_notice(dest_id))
        await self.send_game_msg(build_map_notice(dest_id, 0))
        await self.send_game_msg(build_chardata2_notice([]))

    async def handle_esp(self, payload: bytes):
        """Handle ESP_REQUEST (0x006F) — whisper/private message."""
        self.log.info('ESP_REQUEST (whisper)')
        target = _read_cstr(payload, 0, 32) if len(payload) >= 32 else ''
        text = _read_cstr(payload, 32, 64) if len(payload) >= 96 else ''
        self.log.info('ESP: %s -> %s: %s', self.handle, target, text)

        # Send ESP_REPLY to sender
        await self.send_game_msg(build_typed_reply(0x006E, RESULT_OK))

        # Send ESP_NOTICE to target
        target_session = await self.registry.get_session(target)
        if target_session:
            esp_pld = bytearray(payload_size(0x01E8))
            struct.pack_into('>H', esp_pld, 0, RESULT_OK)
            sender = (self.handle or self.member_id or '').encode('ascii', errors='replace')[:31]
            esp_pld[2:2+len(sender)] = sender
            text_enc = text.encode('ascii', errors='replace')[:63]
            esp_pld[34:34+len(text_enc)] = text_enc
            await target_session.send_game_msg(build_game_msg(0x01E8, bytes(esp_pld)))

    async def handle_action_chat(self, payload: bytes):
        """Handle ACTION_CHAT_REQUEST (0x0260)."""
        self.log.info('ACTION_CHAT_REQUEST')
        await self.send_game_msg(build_typed_reply(0x0261, RESULT_OK))
        # Broadcast ACTION_CHAT_NOTICE
        notice_pld = bytearray(payload_size(0x0274))
        struct.pack_into('>H', notice_pld, 0, RESULT_OK)
        if self.member_id:
            mid_enc = self.member_id.encode('ascii', errors='replace')[:63]
            notice_pld[2:2+len(mid_enc)] = mid_enc
        if len(payload) >= 64:
            copy_len = min(len(payload), len(notice_pld) - 66)
            notice_pld[66:66+copy_len] = payload[:copy_len]
        await self.registry.broadcast(
            build_game_msg(0x0274, bytes(notice_pld)), exclude=self.member_id)

    async def handle_shop_list(self, payload: bytes):
        """Handle SHOP_LIST_REQUEST (0x0203)."""
        self.log.info('SHOP_LIST_REQUEST')
        pld = bytearray(payload_size(0x01FE))
        struct.pack_into('>H', pld, 0, RESULT_OK)
        struct.pack_into('>I', pld, 2, 0)  # 0 shops
        await self.send_game_msg(build_game_msg(0x01FE, bytes(pld)))

    async def handle_shop_in(self, payload: bytes):
        """Handle SHOP_IN_REQUEST (0x01FF)."""
        self.log.info('SHOP_IN_REQUEST')
        await self.send_game_msg(build_typed_reply(0x01FC, RESULT_OK))

    async def handle_shop_out(self, payload: bytes):
        """Handle SHOP_OUT_REQUEST (0x0201)."""
        self.log.info('SHOP_OUT_REQUEST')
        await self.send_game_msg(build_typed_reply(0x029D, RESULT_OK))

    async def handle_equip(self, payload: bytes):
        """Handle EQUIP_REQUEST (0x0205)."""
        self.log.info('EQUIP_REQUEST')
        await self.send_game_msg(build_typed_reply(0x0263, RESULT_OK))

    async def handle_disarm(self, payload: bytes):
        """Handle DISARM_REQUEST (0x026D)."""
        self.log.info('DISARM_REQUEST')
        await self.send_game_msg(build_typed_reply(0x026E, RESULT_OK))

    async def handle_finduser(self, payload: bytes):
        """Handle FINDUSER_REQUEST (0x01B8)."""
        target = _read_cstr(payload, 0, 64) if len(payload) >= 64 else ''
        self.log.info('FINDUSER_REQUEST: %s', target)
        pld = bytearray(payload_size(0x026F))
        struct.pack_into('>H', pld, 0, RESULT_OK)
        # Check if target is online
        online = await self.registry.get_online_list()
        if target.strip('\x00').strip() in online:
            struct.pack_into('>H', pld, 2, 1)  # found
        else:
            struct.pack_into('>H', pld, 2, 0)  # not found
        await self.send_game_msg(build_game_msg(0x026F, bytes(pld)))

    async def handle_explain(self, payload: bytes):
        """Handle EXPLAIN_REQUEST (0x023F)."""
        self.log.info('EXPLAIN_REQUEST')
        pld = bytearray(payload_size(0x04E0))
        struct.pack_into('>H', pld, 0, RESULT_OK)
        desc = b'A mysterious land awaits...'
        pld[2:2+len(desc)] = desc
        await self.send_game_msg(build_game_msg(0x04E0, bytes(pld)))

    async def handle_class_list(self, payload: bytes):
        """Handle CLASS_LIST_REQUEST (0x0299)."""
        self.log.info('CLASS_LIST_REQUEST')
        pld = bytearray(payload_size(0x029A))
        struct.pack_into('>H', pld, 0, RESULT_OK)
        struct.pack_into('>I', pld, 2, 2)  # 2 classes: Rula, Alef
        pld[6:6+4] = b'Rula'
        pld[38:38+4] = b'Alef'
        await self.send_game_msg(build_game_msg(0x029A, bytes(pld)))

    async def handle_skill_list(self, payload: bytes):
        """Handle SKILL_LIST_REQUEST (0x02BA)."""
        self.log.info('SKILL_LIST_REQUEST')
        pld = bytearray(payload_size(0x02E0))
        struct.pack_into('>H', pld, 0, RESULT_OK)
        struct.pack_into('>I', pld, 2, 0)  # 0 skills available
        await self.send_game_msg(build_game_msg(0x02E0, bytes(pld)))

    async def handle_mail_list(self, payload: bytes):
        """Handle MAIL_LIST_REQUEST (0x02AA)."""
        self.log.info('MAIL_LIST_REQUEST')
        mails = self.db.get_mail_list(self.member_id) if self.member_id else []
        pld = bytearray(payload_size(0x02AB))
        struct.pack_into('>H', pld, 0, RESULT_OK)
        struct.pack_into('>I', pld, 2, len(mails))
        await self.send_game_msg(build_game_msg(0x02AB, bytes(pld)))

    async def handle_store_list(self, payload: bytes):
        """Handle STORE_LIST_REQUEST (0x0270)."""
        self.log.info('STORE_LIST_REQUEST')
        pld = bytearray(payload_size(0x0271))
        struct.pack_into('>H', pld, 0, RESULT_OK)
        struct.pack_into('>I', pld, 2, 0)  # 0 stored items
        await self.send_game_msg(build_game_msg(0x0271, bytes(pld)))

    async def handle_sakaya_list(self, payload: bytes):
        """Handle SAKAYA_LIST_REQUEST (0x020D) — tavern list."""
        self.log.info('SAKAYA_LIST_REQUEST')
        pld = bytearray(payload_size(0x0213))
        struct.pack_into('>H', pld, 0, RESULT_OK)
        struct.pack_into('>I', pld, 2, 0)  # 0 taverns
        await self.send_game_msg(build_game_msg(0x0213, bytes(pld)))

    async def handle_dir_request(self, payload: bytes):
        """Handle DIR_REQUEST (0x029E) — bulletin board directory."""
        self.log.info('DIR_REQUEST')
        pld = bytearray(payload_size(0x029F))
        struct.pack_into('>H', pld, 0, RESULT_OK)
        struct.pack_into('>I', pld, 2, 0)  # 0 directories
        await self.send_game_msg(build_game_msg(0x029F, bytes(pld)))

    async def handle_colo_list(self, payload: bytes):
        """Handle COLO_LIST_REQUEST (0x02C2) — colosseum list."""
        self.log.info('COLO_LIST_REQUEST')
        pld = bytearray(payload_size(0x02C3))
        struct.pack_into('>H', pld, 0, RESULT_OK)
        struct.pack_into('>I', pld, 2, 0)  # 0 colosseum entries
        await self.send_game_msg(build_game_msg(0x02C3, bytes(pld)))

    async def handle_giveup(self, payload: bytes):
        """Handle GIVEUP_REQUEST (0x02F8)."""
        self.log.info('GIVEUP_REQUEST')
        await self.send_game_msg(build_typed_reply(0x01D3, RESULT_OK))
        # Restore HP
        if self.member_id:
            self.db.update_character(self.member_id, {'hp_cur': self.char.get('hp_max', 50)})
            self.char = self.db.get_or_create_character(self.member_id)

    # ── Main Dispatch ─────────────────────────────────────────────────────

    SPECIFIC_HANDLERS = None  # set in __init_handlers

    @classmethod
    def _init_handlers(cls):
        """Build the specific handler dispatch table."""
        cls.SPECIFIC_HANDLERS = {
            0x019E: 'handle_login',
            0x0043: 'handle_logout',
            0x0049: 'handle_speak',
            0x0046: 'handle_regist_handle',
            0x02F9: 'handle_chardata_request',
            0x019F: 'handle_update_chardata',
            0x023C: 'handle_area_list',
            0x019B: 'handle_gotolist',
            0x01A1: 'handle_userlist',
            0x01ED: 'handle_partyid',
            0x01A3: 'handle_partylist',
            0x01AD: 'handle_camp_in',
            0x01B4: 'handle_camp_out',
            0x01D4: 'handle_setpos',
            0x01C4: 'handle_move',
            0x01C5: 'handle_move',
            0x01B7: 'handle_regionchange',
            0x01B0: 'handle_teleportlist',
            0x04E1: 'handle_teleport',
            0x006F: 'handle_esp',
            0x0260: 'handle_action_chat',
            0x0203: 'handle_shop_list',
            0x01FF: 'handle_shop_in',
            0x0201: 'handle_shop_out',
            0x0205: 'handle_equip',
            0x026D: 'handle_disarm',
            0x01B8: 'handle_finduser',
            0x023F: 'handle_explain',
            0x0299: 'handle_class_list',
            0x02BA: 'handle_skill_list',
            0x02AA: 'handle_mail_list',
            0x0270: 'handle_store_list',
            0x020D: 'handle_sakaya_list',
            0x029E: 'handle_dir_request',
            0x02C2: 'handle_colo_list',
            0x02F8: 'handle_giveup',
        }

    async def dispatch(self, msg_type: int, payload: bytes):
        """Dispatch a received game message to the appropriate handler."""
        name = msg_name(msg_type)
        self.log.info('<- %s (0x%04X) payload=%d bytes', name, msg_type, len(payload))

        if self.SPECIFIC_HANDLERS is None:
            self._init_handlers()

        handler_name = self.SPECIFIC_HANDLERS.get(msg_type)
        if handler_name:
            handler = getattr(self, handler_name)
            # MOVE handlers need msg_type
            if handler_name == 'handle_move':
                await handler(msg_type, payload)
            else:
                await handler(payload)
            return

        # Auto-reply: if REQUEST type has a matching REPLY, send it
        if name.endswith('_REQUEST'):
            reply_type = REQUEST_REPLY_MAP.get(msg_type)
            if reply_type:
                self.log.info('Auto-reply: %s -> %s (0x%04X)',
                              name, msg_name(reply_type), reply_type)
                await self.send_game_msg(build_typed_reply(reply_type, RESULT_OK))
            else:
                self.log.info('Auto-reply: %s -> STANDARD_REPLY', name)
                await self.send_game_msg(build_standard_reply(RESULT_OK))
            return

        # ACCEPT_REPLY types (client confirmations) — just acknowledge
        if name.endswith('_ACCEPT_REPLY'):
            self.log.info('Received confirmation: %s — acknowledged', name)
            return

        # Everything else — log but don't reply
        self.log.info('Received %s — no handler, ignoring', name)

    # ── Main Loop ─────────────────────────────────────────────────────────

    async def run(self):
        """Main session loop: BBS phase -> SV framing -> game dispatch."""
        try:
            # Phase 1: BBS commands
            if not await self.do_bbs_phase():
                self.log.info('BBS phase failed — closing connection')
                return

            self.log.info('=== BBS phase complete — entering SV/game protocol ===')
            self._connected = True

            # Start keepalive
            self._keepalive_task = asyncio.create_task(self._keepalive_loop())

            # Phase 2: SV framing + game protocol
            while True:
                raw = await asyncio.wait_for(self.reader.read(4096), timeout=30.0)
                if not raw:
                    raise ConnectionError('Client disconnected (EOF)')

                self.log.debug('TCP RECV %d bytes', len(raw))

                # Feed to SV framing layer
                self.sv.feed(raw)

                # Process SV events
                for event in self.sv.iter_events():
                    if event[0] == 'keepalive':
                        self.log.debug('Received keepalive from client')
                    elif event[0] == 'error':
                        self.log.warning('SV error from client: %s', event[1])
                    elif event[0] == 'fragment':
                        frag_payload = event[1]
                        if not frag_payload:
                            # Empty fragment (SV handshake) — respond with empty fragment
                            self.log.info('Received empty SV fragment (handshake)')
                            await self.send_raw(self.sv.encode_fragment(b''))
                            continue
                        self.sv.process_fragment(frag_payload)

                # Process complete game messages
                for msg in self.sv.iter_messages():
                    if len(msg) < MSG_HEADER_SIZE:
                        continue
                    msg_type = struct.unpack('>H', msg[:2])[0]
                    msg_payload = msg[MSG_HEADER_SIZE:]
                    await self.dispatch(msg_type, msg_payload)

        except asyncio.TimeoutError:
            self.log.warning('Read timeout (30s) — closing')
        except (ConnectionError, asyncio.IncompleteReadError) as e:
            self.log.info('Connection closed: %s', e)
        except Exception as e:
            self.log.exception('Unhandled error: %s', e)
        finally:
            if self._keepalive_task:
                self._keepalive_task.cancel()
            if self.member_id:
                await self.registry.broadcast(
                    build_logout_notice(self.member_id), exclude=self.member_id)
                await self.registry.remove(self.member_id)
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception:
                pass
            self.log.info('Session ended: member=%s', self.member_id)


# ═══════════════════════════════════════════════════════════════════════════════
# SERVER
# ═══════════════════════════════════════════════════════════════════════════════

class DreamServerV2:
    def __init__(self, port: int = SERVER_PORT):
        self.port = port
        self.db = Database(DB_PATH)
        self.registry = OnlineRegistry()

    async def handle_client(self, reader: asyncio.StreamReader,
                            writer: asyncio.StreamWriter):
        addr = writer.get_extra_info('peername')
        log.info('New connection from %s:%d', addr[0], addr[1])
        session = ClientSession(reader, writer, self.db, self.registry)
        await session.run()

    async def start(self):
        server = await asyncio.start_server(
            self.handle_client, '0.0.0.0', self.port
        )
        log.info('=' * 60)
        log.info("Dragon's Dream Revival Server v2")
        log.info('=' * 60)
        log.info('TCP port: %d', self.port)
        log.info('Protocol: BBS -> SV IV-framing -> [2B msg_type][payload]')
        log.info('BBS flow: " P\\r" -> "*", SET -> "*", C HRPG -> "COM HRPG"')
        log.info('SV framing: IVsssccc\\r\\n + binary payload (max 256B)')
        log.info('Checksum: sum(payload) & 0x0FFF')
        log.info('Keepalive: "$I\'m alive!!\\r\\n" every %.0fs', KEEPALIVE_INTERVAL)
        log.info('Messages: 310 types, %d auto-reply mappings', len(REQUEST_REPLY_MAP))
        log.info('=' * 60)

        async with server:
            await server.serve_forever()


def main():
    ap = argparse.ArgumentParser(
        description="Dragon's Dream Revival Server v2"
    )
    ap.add_argument('--port', type=int, default=SERVER_PORT,
                    help=f'TCP port (default: {SERVER_PORT})')
    ap.add_argument('--db', type=str, default=DB_PATH,
                    help=f'Database path (default: {DB_PATH})')
    args = ap.parse_args()

    db_path = args.db
    dream = DreamServerV2(port=args.port)
    dream.db = Database(db_path)
    try:
        asyncio.run(dream.start())
    except KeyboardInterrupt:
        log.info('Server shutting down')


if __name__ == '__main__':
    main()
