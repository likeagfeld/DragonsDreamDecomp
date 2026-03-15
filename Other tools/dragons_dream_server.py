#!/usr/bin/env python3
"""
dragons_dream_server.py — Dragon's Dream (ドラゴンズドリーム) Online Revival Server
Fujitsu × SEGA, Saturn / Windows PC MMORPG, December 1997
Original servers closed September 1999.

TCP Port: 8020  |  Modem: 2400 bps via Saturn NetLink (MK-80118 / L39 controller)

══════════════════════════════════════════════════════════════════════════════════
PROTOCOL RECONSTRUCTION
══════════════════════════════════════════════════════════════════════════════════

Phase 1 — IV Handshake (server speaks first, always):

  S→C  8 bytes    INIT_HEADER  "IV100000"
  S→C  256 bytes  SESSION_CHALLENGE  (RSA-512 public key + session nonce)
  C→S  8 bytes    CLIENT_ACK   "IV012fed"
  S→C  8 bytes    SECOND_HEADER "IV012fed"
  S→C  18 bytes   SESSION_CONFIRM  (field8=0x00000008 marks session active)

Phase 2 — Data phase (message-framed packets):

  Packet wire format:
    [2B big-endian]  msg_type
    [2B big-endian]  payload_length   (bytes following this 4B header)
    [payload_length] payload

  Login exchange:
    C→S  MSG_LOGIN_REQUEST (0x019E)
         member_id[64]  + rsa_enc_password[64] + version[16] +
         caps[4] + nonce_echo[64] + reserved (fills to declared length)
    S→C  MSG_LOGIN_REPLY (0x01A0)
         result[1] + session_token[16] + server_time[4] + reserved

  Handle registration:
    C→S  MSG_REGIST_HANDLE_REQUEST (0x0046)  handle[64] + flags[2]
    S→C  MSG_REGIST_HANDLE_REPLY   (0x0047)  result[1] + reserved[3]

  Character data:
    C→S  MSG_CHARDATA_REQUEST       (0x02F9)  member_id[64] + params[693]
    S→C  MSG_CHARDATA_REPLY         (0x02D2)  character record (see CharData)
    S→C  MSG_CHARDATA_NOTICE        (0x01AB)  compact char notice
    S→C  MSG_CHARDATA2_NOTICE       (0x0B6C)  extended char data (2920B payload)
    C→S  MSG_UPDATE_CHARDATA_REQUEST (0x019F) updated character record
    S→C  MSG_UPDATE_CHARDATA_REPLY   (0x01AA) result[1] + reserved[3]

══════════════════════════════════════════════════════════════════════════════════
RSA NOTES
══════════════════════════════════════════════════════════════════════════════════

The game uses Fujitsu's RSA32 library (RSA32.dll on PC; native SH2 code on Saturn).
Session challenge bytes [18:82] carry the server RSA-512 public key modulus (64 B).
Bytes [82:86] carry the public exponent (4 B little-endian; typically 0x10001).

Two operating modes (--rsa-mode flag):

  bypass  (default)
    Accept every login without RSA verification. Use while analysing login
    packet layout or before the original key has been factored.

  own-key
    Generate (or load) our own RSA-512 keypair, embed the public key in the
    SESSION_CHALLENGE, and decrypt what the client sends. Requires the Saturn
    disc to be patched so it reads the server's key from the challenge packet
    instead of using a hardcoded value.  Use --dump-pubkey to get the hex you
    need to patch into the game binary (search for the original 64-byte modulus,
    replace with ours).

  original-key
    Provide the factored original private key via --privkey-file <pem>.
    The original server used a 512-bit key (factoring takes seconds with YAFU/
    msieve on any modern CPU). Extract the public key modulus from the disc
    (it will appear as a 64-byte big-endian integer in the data segment) and
    factor it to obtain the private key, then pass it here.

Sources:
  Normmatt partial server  https://gist.github.com/Normmatt/b806349214c2cd195a68294d9128860b
  Network message list     (disassembly screenshot — network_message_list_01/02)
  saturn_uart16550.h / modem.h (NetLink driver headers, modem at 2400 bps)
  Bo / Rings of Saturn     https://32bits.substack.com/p/bonus-dragons-dream
  Registration: TeleParc/G NIFTY-Serve member IDs (gmsnet.or.jp, defunct)
"""

import argparse
import hashlib
import logging
import os
import sqlite3
import struct
import sys
import threading
import time
from io import BytesIO
from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR

# ── Optional RSA support ─────────────────────────────────────────────────────
try:
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    from cryptography.hazmat.primitives.asymmetric import padding as _pad
    from cryptography.hazmat.primitives import serialization as _ser
    from cryptography.hazmat.primitives import hashes as _hash
    from cryptography.hazmat.backends import default_backend as _backend
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

# ═══════════════════════════════════════════════════════════════════════════════
# PROTOCOL CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

SERVER_PORT   = 8020
DB_PATH       = 'dragons_dream.db'
LOG_PATH      = 'dragons_dream.log'
KEYPAIR_PATH  = 'dd_server_keypair.pem'

# IV handshake magic (8-byte markers)
INIT_HEADER   = b'IV100000'   # server → client, connection open
CLIENT_ACK    = b'IV012fed'   # client → server, handshake ack
SECOND_HEADER = b'IV012fed'   # server → client, before SESSION_CONFIRM

# Session challenge (256 B) layout offsets
SESS_OFF_FLAGS   = 1    # 0x42 (bits checked by game: &0x01, &0x08, &0x40, &0x42)
SESS_OFF_CHKSUM  = 2    # uint16_le  16-bit sum of all 256 bytes
SESS_OFF_FIELD8  = 8    # uint32_le  0 in challenge, 8 in confirm
SESS_OFF_FIELD12 = 12   # uint32_le  0
SESS_OFF_DLEN    = 16   # uint16_le  byte count of nonce+key in [18:]
SESS_OFF_NONCE   = 18   # 64-byte session nonce
SESS_OFF_PUBMOD  = 82   # 64-byte RSA-512 public key modulus (big-endian)
SESS_OFF_PUBEXP  = 146  # 4-byte RSA public exponent (little-endian)
SESSION_FLAG     = 0x42

# 18-byte SESSION_CONFIRM layout
CONF_OFF_FIELD8  = 8    # uint32_le = 0x00000008  (marks session active)

# ── Message type IDs (from network_message_list_01/02 disassembly) ───────────
#  Each game packet starts with [uint16 big-endian msg_type][uint16 BE length]
MSG_LOGIN_REQUEST           = 0x019E
MSG_UPDATE_CHARDATA_REQUEST = 0x019F
MSG_UPDATE_CHARDATA_REPLY   = 0x01AA
MSG_CHARDATA_REQUEST        = 0x02F9
MSG_CHARDATA_REPLY          = 0x02D2
MSG_CHARDATA_NOTICE         = 0x01AB
MSG_CHARDATA2_NOTICE        = 0x0B6C
MSG_REGIST_HANDLE_REQUEST   = 0x0046

# Server-originated response types (inferred from naming conventions)
MSG_LOGIN_REPLY             = 0x01A0  # follows MSG_LOGIN_REQUEST
MSG_REGIST_HANDLE_REPLY     = 0x0047  # follows MSG_REGIST_HANDLE_REQUEST

# Result codes
RESULT_OK    = 0x00
RESULT_ERROR = 0x01

# ═══════════════════════════════════════════════════════════════════════════════
# LOGGING
# ═══════════════════════════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_PATH, encoding='utf-8'),
    ]
)
log = logging.getLogger('DD')

def hexdump(data: bytes, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_part  = ' '.join(f'{b:02X}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'  {i:04X}  {hex_part:<{width*3}}  {ascii_part}')
    return '\n'.join(lines)

# ═══════════════════════════════════════════════════════════════════════════════
# RSA HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

class RSAEngine:
    """
    Manages the server's RSA-512 keypair used in the session challenge.

    Three modes:
      bypass     — skip RSA entirely; accept all logins (default)
      own-key    — generate/load our own keypair; game must be patched
      original   — use the factored original private key from a PEM file
    """

    def __init__(self, mode: str = 'bypass', privkey_file: str = None):
        self.mode = mode
        self._private_key = None
        self._public_key  = None
        self.pub_modulus   = bytes(64)   # 64-byte big-endian modulus placeholder
        self.pub_exponent  = 0x10001

        if mode == 'bypass':
            log.warning('RSA mode: BYPASS — all logins accepted without verification')
            return

        if not HAVE_CRYPTO:
            log.error('cryptography library missing; falling back to bypass mode')
            self.mode = 'bypass'
            return

        if mode == 'own-key':
            self._load_or_generate(KEYPAIR_PATH)
        elif mode == 'original':
            if not privkey_file:
                raise ValueError('--privkey-file required with --rsa-mode original')
            self._load_pem(privkey_file)
        else:
            raise ValueError(f'Unknown RSA mode: {mode}')

    def _load_or_generate(self, path: str):
        if os.path.exists(path):
            log.info('Loading existing keypair from %s', path)
            self._load_pem(path)
        else:
            log.info('Generating new RSA-512 keypair → %s', path)
            self._private_key = _rsa.generate_private_key(
                public_exponent=0x10001,
                key_size=512,
                backend=_backend()
            )
            pem = self._private_key.private_bytes(
                encoding=_ser.Encoding.PEM,
                format=_ser.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=_ser.NoEncryption()
            )
            with open(path, 'wb') as f:
                f.write(pem)
            log.info('Keypair saved to %s', path)
            self._extract_pubkey_bytes()

    def _load_pem(self, path: str):
        with open(path, 'rb') as f:
            pem_data = f.read()
        self._private_key = _ser.load_pem_private_key(pem_data, password=None, backend=_backend())
        self._extract_pubkey_bytes()
        log.info('RSA key loaded, modulus: %s...', self.pub_modulus.hex()[:16])

    def _extract_pubkey_bytes(self):
        pub = self._private_key.public_key()
        nums = pub.public_key().public_numbers() if hasattr(pub, 'public_key') else pub.public_numbers()
        n = nums.n
        e = nums.e
        # 64-byte big-endian modulus
        self.pub_modulus  = n.to_bytes(64, 'big')
        self.pub_exponent = e

    def dump_pubkey_hex(self) -> str:
        """Return hex of public modulus for use in game binary patching."""
        return self.pub_modulus.hex().upper()

    def decrypt_login_blob(self, ciphertext: bytes) -> bytes:
        """
        Decrypt 64-byte RSA-encrypted login blob from client.
        Returns plaintext or b'' on failure / bypass mode.
        """
        if self.mode == 'bypass':
            return b''
        try:
            plaintext = self._private_key.decrypt(
                ciphertext,
                _pad.PKCS1v15()
            )
            return plaintext
        except Exception as exc:
            log.warning('RSA decrypt failed: %s', exc)
            return b''


# ═══════════════════════════════════════════════════════════════════════════════
# PACKET BUILDERS
# ═══════════════════════════════════════════════════════════════════════════════

def _checksum16(data: bytes) -> int:
    """16-bit unsigned sum of all bytes (Normmatt's observed checksum)."""
    return sum(data) & 0xFFFF


def build_session_challenge(nonce: bytes, rsa: RSAEngine) -> bytes:
    """
    Build the 256-byte SESSION_CHALLENGE packet.

    [0]     unknown0     = 0x00
    [1]     flags        = 0x42  (SESSION_FLAG)
    [2:4]   checksum     = uint16_le  sum of all 256 bytes
    [4:8]   unknown4..7  = 0x00
    [8:12]  field8       = uint32_le 0
    [12:16] field12      = uint32_le 0
    [16:18] data_length  = uint16_le  len(nonce) + len(pubmod) + 4
    [18:82] nonce        = 64-byte session nonce
    [82:146] pub_modulus = 64-byte RSA-512 modulus (big-endian)
    [146:150] pub_exp    = uint32_le RSA public exponent
    [150:256] padding    = 0x00
    """
    pkt = bytearray(256)
    pkt[0] = 0x00
    pkt[SESS_OFF_FLAGS] = SESSION_FLAG

    struct.pack_into('<I', pkt, SESS_OFF_FIELD8,  0)
    struct.pack_into('<I', pkt, SESS_OFF_FIELD12, 0)

    # payload section: nonce (64) + modulus (64) + exponent (4) = 132 bytes
    data_len = 64 + 64 + 4
    struct.pack_into('<H', pkt, SESS_OFF_DLEN, data_len)

    pkt[SESS_OFF_NONCE:SESS_OFF_NONCE+64]   = nonce[:64]
    pkt[SESS_OFF_PUBMOD:SESS_OFF_PUBMOD+64] = rsa.pub_modulus[:64]
    struct.pack_into('<I', pkt, SESS_OFF_PUBEXP, rsa.pub_exponent)

    # compute and fill checksum after all fields are set
    checksum = _checksum16(bytes(pkt))
    struct.pack_into('<H', pkt, SESS_OFF_CHKSUM, checksum)
    return bytes(pkt)


def build_session_confirm() -> bytes:
    """
    Build the 18-byte SESSION_CONFIRM packet (sent after CLIENT_ACK).

    [0]     unknown0     = 0x00
    [1]     flags        = 0x00   (cleared after challenge, session live)
    [2:4]   checksum     = uint16_le
    [4:8]   unknown4..7  = 0x00
    [8:12]  field8       = uint32_le 0x00000008  (signals session active)
    [12:16] field12      = uint32_le 0x00000000
    [16:18] field16      = uint16_le 0x0000
    """
    pkt = bytearray(18)
    pkt[0] = 0x00
    pkt[1] = 0x00
    struct.pack_into('<I', pkt, CONF_OFF_FIELD8, 0x00000008)
    struct.pack_into('<I', pkt, 12, 0)
    struct.pack_into('<H', pkt, 16, 0)

    checksum = _checksum16(bytes(pkt))
    struct.pack_into('<H', pkt, 2, checksum)
    return bytes(pkt)


def build_game_packet(msg_type: int, payload: bytes) -> bytes:
    """Wrap a payload in the data-phase packet header."""
    hdr = struct.pack('>HH', msg_type, len(payload))
    return hdr + payload


def build_login_reply(result: int = RESULT_OK, session_token: bytes = None) -> bytes:
    """
    MSG_LOGIN_REPLY (0x01A0) payload:
      [0]      result        0x00 = OK, 0x01 = error
      [1:17]   session_token 16-byte opaque token
      [17:21]  server_time   uint32_le UNIX timestamp
      [21:]    reserved (0)  pad to reasonable length (32 bytes total payload)
    """
    if session_token is None:
        session_token = os.urandom(16)
    payload = bytearray(32)
    payload[0] = result & 0xFF
    payload[1:17] = session_token[:16]
    struct.pack_into('<I', payload, 17, int(time.time()) & 0xFFFFFFFF)
    return build_game_packet(MSG_LOGIN_REPLY, bytes(payload))


def build_chardata_reply(char: dict) -> bytes:
    """
    MSG_CHARDATA_REPLY (0x02D2) — 718-byte payload (total packet 722B).
    Encodes a player character record.
    Layout (all strings are null-padded to stated widths):
      [0:64]   member_id       NIFTY-Serve member ID
      [64:96]  handle          display handle
      [96:100] level           uint32_le
      [100:104] exp            uint32_le
      [104:108] hp             uint32_le
      [108:112] mp             uint32_le
      [112:116] str            uint32_le
      [116:120] def            uint32_le
      [120:124] agi            uint32_le
      [124:128] int_           uint32_le
      [128:132] class_id       uint32_le  (0=Fighter,1=Mage,2=Thief,3=Cleric)
      [132:196] equip_ids      16×uint32_le equipment slot IDs
      [196:260] item_ids       16×uint32_le inventory item IDs
      [260:718] reserved       zero-padded
    """
    payload = bytearray(718)

    def pack_str(buf, off, s, maxlen):
        enc = s.encode('ascii', errors='replace')[:maxlen-1]
        buf[off:off+len(enc)] = enc

    pack_str(payload,  0, char.get('member_id', ''), 64)
    pack_str(payload, 64, char.get('handle', ''), 32)
    struct.pack_into('<I', payload, 96,  char.get('level', 1))
    struct.pack_into('<I', payload, 100, char.get('exp',   0))
    struct.pack_into('<I', payload, 104, char.get('hp',    50))
    struct.pack_into('<I', payload, 108, char.get('mp',    20))
    struct.pack_into('<I', payload, 112, char.get('str',   10))
    struct.pack_into('<I', payload, 116, char.get('def',   10))
    struct.pack_into('<I', payload, 120, char.get('agi',   10))
    struct.pack_into('<I', payload, 124, char.get('int_',  10))
    struct.pack_into('<I', payload, 128, char.get('class_id', 0))
    return build_game_packet(MSG_CHARDATA_REPLY, bytes(payload))


def build_update_chardata_reply(result: int = RESULT_OK) -> bytes:
    """MSG_UPDATE_CHARDATA_REPLY (0x01AA) — 4-byte payload."""
    payload = struct.pack('>I', result)
    return build_game_packet(MSG_UPDATE_CHARDATA_REPLY, payload)


def build_regist_handle_reply(result: int = RESULT_OK) -> bytes:
    """MSG_REGIST_HANDLE_REPLY (0x0047) — 4-byte payload."""
    payload = struct.pack('>I', result)
    return build_game_packet(MSG_REGIST_HANDLE_REPLY, payload)


# ═══════════════════════════════════════════════════════════════════════════════
# DATABASE
# ═══════════════════════════════════════════════════════════════════════════════

class Database:
    """SQLite-backed user and character store."""

    def __init__(self, path: str = DB_PATH):
        self.path = path
        self._local = threading.local()
        self._init_schema()
        log.info('Database ready: %s', path)

    @property
    def conn(self) -> sqlite3.Connection:
        if not getattr(self._local, 'conn', None):
            self._local.conn = sqlite3.connect(self.path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def _init_schema(self):
        c = sqlite3.connect(self.path)
        c.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                member_id  TEXT PRIMARY KEY,
                handle     TEXT,
                pw_hash    TEXT,
                created_at INTEGER DEFAULT (strftime('%s','now')),
                last_login INTEGER
            );
            CREATE TABLE IF NOT EXISTS characters (
                member_id  TEXT PRIMARY KEY,
                handle     TEXT,
                level      INTEGER DEFAULT 1,
                exp        INTEGER DEFAULT 0,
                hp         INTEGER DEFAULT 50,
                mp         INTEGER DEFAULT 20,
                str        INTEGER DEFAULT 10,
                def        INTEGER DEFAULT 10,
                agi        INTEGER DEFAULT 10,
                int_       INTEGER DEFAULT 10,
                class_id   INTEGER DEFAULT 0,
                equip_json TEXT    DEFAULT '[]',
                item_json  TEXT    DEFAULT '[]',
                updated_at INTEGER DEFAULT (strftime('%s','now'))
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token      TEXT PRIMARY KEY,
                member_id  TEXT,
                created_at INTEGER DEFAULT (strftime('%s','now')),
                expires_at INTEGER
            );
        """)
        c.commit()
        c.close()

    # ── Users ─────────────────────────────────────────────────────────────────

    def upsert_user(self, member_id: str, handle: str = None, pw_hash: str = None):
        """Create or update a user record (auto-create on first login)."""
        existing = self.conn.execute(
            'SELECT member_id FROM users WHERE member_id=?', (member_id,)
        ).fetchone()
        if existing:
            if handle:
                self.conn.execute(
                    'UPDATE users SET handle=? WHERE member_id=?', (handle, member_id)
                )
            self.conn.execute(
                'UPDATE users SET last_login=strftime(\'%s\',\'now\') WHERE member_id=?',
                (member_id,)
            )
        else:
            self.conn.execute(
                'INSERT INTO users(member_id, handle, pw_hash) VALUES(?,?,?)',
                (member_id, handle or member_id, pw_hash or '')
            )
        self.conn.commit()

    def get_user(self, member_id: str) -> sqlite3.Row:
        return self.conn.execute(
            'SELECT * FROM users WHERE member_id=?', (member_id,)
        ).fetchone()

    # ── Characters ────────────────────────────────────────────────────────────

    def get_or_create_character(self, member_id: str) -> dict:
        row = self.conn.execute(
            'SELECT * FROM characters WHERE member_id=?', (member_id,)
        ).fetchone()
        if row:
            return dict(row)
        # Auto-create starter character
        self.conn.execute(
            'INSERT INTO characters(member_id, handle) VALUES(?,?)',
            (member_id, member_id)
        )
        self.conn.commit()
        return self.get_or_create_character(member_id)

    def update_character(self, member_id: str, fields: dict):
        allowed = {'handle','level','exp','hp','mp','str','def','agi','int_',
                   'class_id','equip_json','item_json'}
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return
        set_clause = ', '.join(f'{k}=?' for k in updates)
        vals = list(updates.values()) + [member_id]
        self.conn.execute(
            f'UPDATE characters SET {set_clause}, updated_at=strftime(\'%s\',\'now\')'
            f' WHERE member_id=?',
            vals
        )
        self.conn.commit()

    def register_handle(self, member_id: str, handle: str) -> bool:
        """Register a display handle. Returns False if handle already taken."""
        taken = self.conn.execute(
            'SELECT member_id FROM characters WHERE handle=? AND member_id!=?',
            (handle, member_id)
        ).fetchone()
        if taken:
            return False
        self.update_character(member_id, {'handle': handle})
        self.upsert_user(member_id, handle=handle)
        return True

    # ── Sessions ──────────────────────────────────────────────────────────────

    def create_session(self, member_id: str) -> bytes:
        token = os.urandom(16)
        token_hex = token.hex()
        expires = int(time.time()) + 86400  # 24 h
        self.conn.execute(
            'INSERT OR REPLACE INTO sessions(token, member_id, expires_at) VALUES(?,?,?)',
            (token_hex, member_id, expires)
        )
        self.conn.commit()
        return token

    def resolve_session(self, token: bytes) -> str:
        row = self.conn.execute(
            'SELECT member_id, expires_at FROM sessions WHERE token=?',
            (token.hex(),)
        ).fetchone()
        if row and row['expires_at'] > int(time.time()):
            return row['member_id']
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# PACKET PARSER
# ═══════════════════════════════════════════════════════════════════════════════

class PacketParser:
    """
    Incrementally reads data-phase game packets from a byte stream.
    Wire format: [uint16 BE msg_type][uint16 BE payload_len][payload_len bytes]
    """

    def __init__(self):
        self._buf = bytearray()

    def feed(self, data: bytes):
        self._buf.extend(data)

    def packets(self):
        """Yield (msg_type, payload) tuples for every complete packet in buffer."""
        while len(self._buf) >= 4:
            msg_type, payload_len = struct.unpack_from('>HH', self._buf, 0)
            total = 4 + payload_len
            if len(self._buf) < total:
                break
            payload = bytes(self._buf[4:total])
            del self._buf[:total]
            yield msg_type, payload


# ═══════════════════════════════════════════════════════════════════════════════
# LOGIN REQUEST PARSER
# ═══════════════════════════════════════════════════════════════════════════════

def parse_login_request(payload: bytes) -> dict:
    """
    Decode MSG_LOGIN_REQUEST (0x019E) payload.

    Inferred layout (total wire packet = 414 bytes → payload = 410 bytes):
      [0:64]   member_id       null-terminated NIFTY-Serve / TeleParc/G ID
      [64:128] rsa_enc_blob    64-byte RSA-512 encrypted block
                               (contains password hash + nonce echo when decrypted)
      [128:144] game_version   null-terminated version string (16 bytes)
      [144:148] client_caps    uint32_le capability flags
      [148:212] nonce_echo     64-byte echo of server challenge nonce
      [212:410] reserved
    """
    def read_cstr(buf, off, maxlen) -> str:
        end = buf.find(b'\x00', off, off + maxlen)
        if end < 0:
            end = off + maxlen
        return buf[off:end].decode('ascii', errors='replace')

    result = {
        'member_id':    read_cstr(payload, 0,   64),
        'rsa_enc_blob': payload[64:128] if len(payload) >= 128 else b'',
        'game_version': read_cstr(payload, 128, 16) if len(payload) >= 144 else '',
        'client_caps':  struct.unpack_from('<I', payload, 144)[0] if len(payload) >= 148 else 0,
        'nonce_echo':   payload[148:212] if len(payload) >= 212 else b'',
        'raw_len':      len(payload),
    }
    return result


def parse_update_chardata_request(payload: bytes) -> dict:
    """
    Decode MSG_UPDATE_CHARDATA_REQUEST (0x019F) payload.
    Layout mirrors CHARDATA_REPLY (server→client direction of same struct).
    """
    def read_cstr(buf, off, maxlen) -> str:
        end = buf.find(b'\x00', off, off + maxlen)
        if end < 0:
            end = off + maxlen
        return buf[off:end].decode('ascii', errors='replace')

    r = {'member_id': read_cstr(payload, 0, 64)}
    if len(payload) >= 132:
        r['level']    = struct.unpack_from('<I', payload, 96)[0]
        r['exp']      = struct.unpack_from('<I', payload, 100)[0]
        r['hp']       = struct.unpack_from('<I', payload, 104)[0]
        r['mp']       = struct.unpack_from('<I', payload, 108)[0]
        r['str']      = struct.unpack_from('<I', payload, 112)[0]
        r['def']      = struct.unpack_from('<I', payload, 116)[0]
        r['agi']      = struct.unpack_from('<I', payload, 120)[0]
        r['int_']     = struct.unpack_from('<I', payload, 124)[0]
        r['class_id'] = struct.unpack_from('<I', payload, 128)[0]
    return r


def parse_regist_handle_request(payload: bytes) -> dict:
    """
    Decode MSG_REGIST_HANDLE_REQUEST (0x0046) payload.
    Layout (total wire packet = 70 bytes → payload = 66 bytes):
      [0:64]  handle   null-terminated display name
      [64:66] flags    uint16_le
    """
    end = payload.find(b'\x00', 0, 64)
    handle = payload[:end if end >= 0 else 64].decode('ascii', errors='replace')
    flags  = struct.unpack_from('<H', payload, 64)[0] if len(payload) >= 66 else 0
    return {'handle': handle, 'flags': flags}


# ═══════════════════════════════════════════════════════════════════════════════
# CLIENT HANDLER
# ═══════════════════════════════════════════════════════════════════════════════

class ClientHandler:
    """
    Manages one connected Saturn client through the full protocol lifecycle:
    IV handshake → login → character data → gameplay messages.
    """

    def __init__(self, sock: socket, addr, db: Database, rsa_engine: RSAEngine):
        self.sock       = sock
        self.addr       = addr
        self.db         = db
        self.rsa        = rsa_engine
        self.log        = logging.getLogger(f'DD/{addr[0]}:{addr[1]}')
        self.nonce      = os.urandom(64)
        self.member_id  = None
        self.session_token = None
        self.parser     = PacketParser()

    # ── Low-level I/O ─────────────────────────────────────────────────────────

    def recv_exact(self, n: int) -> bytes:
        buf = b''
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError('Client disconnected')
            buf += chunk
        return buf

    def send(self, data: bytes):
        self.sock.sendall(data)
        self.log.debug('SEND %d bytes\n%s', len(data), hexdump(data))

    def recv(self, n: int = 4096) -> bytes:
        data = self.recv_exact(n)
        self.log.debug('RECV %d bytes\n%s', len(data), hexdump(data))
        return data

    # ── Phase 1: IV Handshake ─────────────────────────────────────────────────

    def do_iv_handshake(self):
        """
        Execute the 5-step IV handshake:
          S→C  INIT_HEADER (8B)
          S→C  SESSION_CHALLENGE (256B)
          C→S  CLIENT_ACK (8B)     expect b'IV012fed'
          S→C  SECOND_HEADER (8B)  = b'IV012fed'
          S→C  SESSION_CONFIRM (18B)
        """
        self.log.info('Starting IV handshake')

        # Step 1+2: server sends init header + session challenge
        challenge = build_session_challenge(self.nonce, self.rsa)
        self.send(INIT_HEADER + challenge)

        # Step 3: wait for client ack
        ack = self.recv_exact(8)
        if ack != CLIENT_ACK:
            self.log.warning('Unexpected client ack: %s (expected %s)', ack.hex(), CLIENT_ACK.hex())
            # Continue anyway — the game might have sent a variant
        else:
            self.log.info('Client ack received OK: %s', ack.decode('ascii', errors='replace'))

        # Step 4+5: server sends second header + session confirm
        confirm = build_session_confirm()
        self.send(SECOND_HEADER + confirm)
        self.log.info('IV handshake complete')

    # ── Phase 2+3: Data phase message dispatch ────────────────────────────────

    def recv_data_packet(self) -> tuple:
        """
        Read one framed data-phase packet from the socket.
        Returns (msg_type, payload) or raises ConnectionError.
        Feeds the PacketParser with raw socket data until a full packet is ready.
        """
        while True:
            for msg_type, payload in self.parser.packets():
                return msg_type, payload
            raw = self.sock.recv(4096)
            if not raw:
                raise ConnectionError('Client disconnected')
            self.log.debug('RAW RECV %d bytes\n%s', len(raw), hexdump(raw))
            self.parser.feed(raw)

    def handle_login_request(self, payload: bytes) -> bool:
        info = parse_login_request(payload)
        member_id = info['member_id'].strip('\x00').strip()

        self.log.info('LOGIN_REQUEST: member_id=%r version=%r caps=0x%X raw_len=%d',
                      member_id, info['game_version'], info['client_caps'], info['raw_len'])

        if not member_id:
            self.log.warning('Empty member_id in login request — rejecting')
            self.send(build_login_reply(RESULT_ERROR))
            return False

        # RSA verification
        if self.rsa.mode != 'bypass' and info['rsa_enc_blob']:
            plaintext = self.rsa.decrypt_login_blob(info['rsa_enc_blob'])
            self.log.debug('RSA decrypt result (%d bytes): %s', len(plaintext), plaintext.hex())
            # In a strict server we'd verify nonce_echo matches self.nonce here.
            # For revival purposes, accept any successful decrypt.

        # Nonce echo verification (bypass mode: skip)
        if self.rsa.mode != 'bypass' and info['nonce_echo']:
            if info['nonce_echo'][:64] != self.nonce[:64]:
                self.log.warning('Nonce echo mismatch — possible replay attack')
                # Don't reject; log for protocol analysis

        # Accept the login and create/update user record
        self.db.upsert_user(member_id)
        self.session_token = self.db.create_session(member_id)
        self.member_id = member_id

        self.log.info('Login accepted: %s (session %s)', member_id, self.session_token.hex())
        self.send(build_login_reply(RESULT_OK, self.session_token))
        return True

    def handle_regist_handle_request(self, payload: bytes):
        info = parse_regist_handle_request(payload)
        self.log.info('REGIST_HANDLE_REQUEST: handle=%r flags=0x%X', info['handle'], info['flags'])

        if not self.member_id:
            self.log.warning('REGIST_HANDLE before login — ignoring')
            self.send(build_regist_handle_reply(RESULT_ERROR))
            return

        ok = self.db.register_handle(self.member_id, info['handle'])
        result = RESULT_OK if ok else RESULT_ERROR
        if ok:
            self.log.info('Handle registered: %s → %r', self.member_id, info['handle'])
        else:
            self.log.warning('Handle %r already taken', info['handle'])
        self.send(build_regist_handle_reply(result))

    def handle_chardata_request(self, payload: bytes):
        def read_cstr(buf, off, maxlen):
            end = buf.find(b'\x00', off, off + maxlen)
            return buf[off:end if end >= 0 else off+maxlen].decode('ascii', errors='replace')

        req_member = read_cstr(payload, 0, 64) if len(payload) >= 64 else self.member_id
        self.log.info('CHARDATA_REQUEST for member_id=%r', req_member)

        char = self.db.get_or_create_character(req_member or self.member_id)
        self.send(build_chardata_reply(char))

    def handle_update_chardata_request(self, payload: bytes):
        info = parse_update_chardata_request(payload)
        member_id = info.get('member_id', '').strip() or self.member_id
        self.log.info('UPDATE_CHARDATA_REQUEST: member_id=%r level=%s',
                      member_id, info.get('level'))

        if member_id != self.member_id:
            self.log.warning('Client trying to update different member — ignoring')
            self.send(build_update_chardata_reply(RESULT_ERROR))
            return

        # Remove member_id from update dict
        update_fields = {k: v for k, v in info.items() if k != 'member_id'}
        self.db.update_character(self.member_id, update_fields)
        self.send(build_update_chardata_reply(RESULT_OK))

    def dispatch(self, msg_type: int, payload: bytes):
        name_map = {
            MSG_LOGIN_REQUEST:           'LOGIN_REQUEST',
            MSG_REGIST_HANDLE_REQUEST:   'REGIST_HANDLE_REQUEST',
            MSG_CHARDATA_REQUEST:        'CHARDATA_REQUEST',
            MSG_UPDATE_CHARDATA_REQUEST: 'UPDATE_CHARDATA_REQUEST',
            MSG_UPDATE_CHARDATA_REPLY:   'UPDATE_CHARDATA_REPLY',
        }
        name = name_map.get(msg_type, f'UNKNOWN_0x{msg_type:04X}')
        self.log.info('← %s  payload=%d bytes', name, len(payload))

        if msg_type == MSG_LOGIN_REQUEST:
            self.handle_login_request(payload)
        elif msg_type == MSG_REGIST_HANDLE_REQUEST:
            self.handle_regist_handle_request(payload)
        elif msg_type == MSG_CHARDATA_REQUEST:
            self.handle_chardata_request(payload)
        elif msg_type == MSG_UPDATE_CHARDATA_REQUEST:
            self.handle_update_chardata_request(payload)
        else:
            self.log.warning('Unhandled msg_type 0x%04X (%d bytes) — logging raw',
                             msg_type, len(payload))
            if payload:
                self.log.debug('Unknown payload:\n%s', hexdump(payload))

    # ── Main entry ────────────────────────────────────────────────────────────

    def run(self):
        try:
            self.do_iv_handshake()
            self.log.info('Entering data phase')
            while True:
                msg_type, payload = self.recv_data_packet()
                self.dispatch(msg_type, payload)
        except ConnectionError as e:
            self.log.info('Connection closed: %s', e)
        except Exception as e:
            self.log.exception('Unhandled error in client handler: %s', e)
        finally:
            try:
                self.sock.close()
            except Exception:
                pass
            self.log.info('Handler exiting for %s member=%s',
                          f'{self.addr[0]}:{self.addr[1]}', self.member_id)


# ═══════════════════════════════════════════════════════════════════════════════
# SERVER
# ═══════════════════════════════════════════════════════════════════════════════

class DragonsServerDream:

    def __init__(self, port: int = SERVER_PORT, rsa_mode: str = 'bypass',
                 privkey_file: str = None):
        self.port   = port
        self.db     = Database(DB_PATH)
        self.rsa    = RSAEngine(mode=rsa_mode, privkey_file=privkey_file)
        self._sock  = None

    def start(self):
        self._sock = socket(AF_INET, SOCK_STREAM)
        self._sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self._sock.bind(('0.0.0.0', self.port))
        self._sock.listen(10)
        log.info('Dragon\'s Dream revival server listening on TCP port %d', self.port)
        log.info('RSA mode: %s', self.rsa.mode)
        if self.rsa.mode == 'own-key':
            log.info('Server public key (patch this into the Saturn disc):')
            log.info('  Modulus (hex): %s', self.rsa.dump_pubkey_hex())

        while True:
            try:
                client_sock, addr = self._sock.accept()
                log.info('Connection from %s:%d', addr[0], addr[1])
                handler = ClientHandler(client_sock, addr, self.db, self.rsa)
                t = threading.Thread(target=handler.run, daemon=True,
                                     name=f'client-{addr[0]}:{addr[1]}')
                t.start()
            except KeyboardInterrupt:
                log.info('Server shutting down')
                break
            except Exception as e:
                log.exception('Accept error: %s', e)


# ═══════════════════════════════════════════════════════════════════════════════
# UTILITY: Game binary patching helpers
# ═══════════════════════════════════════════════════════════════════════════════

def find_rsa_pubkey_in_binary(bin_path: str, key_size_bytes: int = 64):
    """
    Scan a Dragon's Dream disc binary for RSA public key candidates.
    Heuristic: look for 64-byte (512-bit) big-endian integers where:
      - High bit is set (valid RSA modulus is always odd and high-bit set)
      - Last bit is set (RSA modulus is always odd)
      - Value is plausible for a 512-bit RSA modulus
    Prints offsets of candidates to stdout.
    """
    with open(bin_path, 'rb') as f:
        data = f.read()

    log.info('Scanning %s (%d bytes) for RSA-512 public key candidates...', bin_path, len(data))
    candidates = []
    for i in range(0, len(data) - key_size_bytes, 4):
        chunk = data[i:i+key_size_bytes]
        if (chunk[0] & 0x80) and (chunk[-1] & 0x01):
            n = int.from_bytes(chunk, 'big')
            bit_len = n.bit_length()
            if 500 <= bit_len <= 520:
                candidates.append((i, chunk.hex()))
                log.info('Candidate at offset 0x%X: %s...', i, chunk.hex()[:32])
    if not candidates:
        log.info('No candidates found — key may be 1024-bit or stored differently')
    return candidates


def patch_binary_pubkey(bin_path: str, old_modulus_hex: str, new_modulus_hex: str,
                        out_path: str = None):
    """
    Replace the server's RSA public key modulus in the game binary.
    Use after generating a new keypair with --gen-keypair.
    """
    old_bytes = bytes.fromhex(old_modulus_hex)
    new_bytes = bytes.fromhex(new_modulus_hex)
    assert len(old_bytes) == len(new_bytes), 'Key lengths must match'

    with open(bin_path, 'rb') as f:
        data = bytearray(f.read())

    idx = data.find(old_bytes)
    if idx < 0:
        log.error('Old modulus not found in binary')
        return False

    data[idx:idx+len(old_bytes)] = new_bytes
    out = out_path or (bin_path + '.patched')
    with open(out, 'wb') as f:
        f.write(data)
    log.info('Patched binary written to %s (offset 0x%X)', out, idx)
    return True


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRYPOINT
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        description='Dragon\'s Dream (ドラゴンズドリーム) revival server — TCP 8020'
    )
    ap.add_argument('--port',        type=int, default=SERVER_PORT,
                    help='TCP port to listen on (default 8020)')
    ap.add_argument('--rsa-mode',    choices=['bypass','own-key','original'],
                    default='bypass',
                    help='RSA authentication mode (default: bypass)')
    ap.add_argument('--privkey-file', default=None,
                    help='Path to PEM private key (required for --rsa-mode original)')
    ap.add_argument('--gen-keypair', action='store_true',
                    help='Generate a new RSA-512 keypair and exit')
    ap.add_argument('--dump-pubkey', action='store_true',
                    help='Print current server public key hex and exit')
    ap.add_argument('--find-rsa',    metavar='BIN',
                    help='Scan a game binary for RSA public key candidates')
    ap.add_argument('--patch-binary', nargs=3,
                    metavar=('BIN', 'OLD_MOD_HEX', 'NEW_MOD_HEX'),
                    help='Patch game binary to use a new RSA public key')
    args = ap.parse_args()

    if args.find_rsa:
        find_rsa_pubkey_in_binary(args.find_rsa)
        return

    if args.patch_binary:
        bin_path, old_hex, new_hex = args.patch_binary
        patch_binary_pubkey(bin_path, old_hex, new_hex)
        return

    rsa_engine = RSAEngine(mode=args.rsa_mode, privkey_file=args.privkey_file)

    if args.gen_keypair or args.dump_pubkey:
        if rsa_engine.mode == 'bypass':
            print('ERROR: --gen-keypair/--dump-pubkey require --rsa-mode own-key')
            sys.exit(1)
        print('Server public key modulus (hex):')
        print(rsa_engine.dump_pubkey_hex())
        return

    server = DragonsServerDream(
        port=args.port,
        rsa_mode=args.rsa_mode,
        privkey_file=args.privkey_file,
    )
    server.start()


if __name__ == '__main__':
    main()
