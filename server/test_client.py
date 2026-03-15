#!/usr/bin/env python3
"""
Dragon's Dream — Test Client / QA Validator (v2 Protocol)

Simulates a Saturn client connecting to the revival server:
  1. BBS phase: " P\r" -> SET -> "C HRPG"
  2. SV framing: IV-prefixed fragments with checksums
  3. Game messages: [2B msg_type][payload of msg_type-2 bytes]

Usage:
  python test_client.py [--host 127.0.0.1] [--port 8020]
"""

import argparse
import asyncio
import os
import struct
import sys
import time

# Import from server module
sys.path.insert(0, os.path.dirname(__file__))
from dragons_dream_server_v2 import (
    MSG_TABLE, MSG_HEADER_SIZE, SVFraming, SV_KEEPALIVE,
    RESULT_OK, RESULT_ERROR, msg_name, payload_size, hexdump,
)

# Message type constants
MSG_LOGIN_REQUEST           = 0x019E
MSG_LOGOUT_REQUEST          = 0x0043
MSG_STANDARD_REPLY          = 0x0048
MSG_REGIST_HANDLE_REQUEST   = 0x0046
MSG_CHARDATA_REQUEST        = 0x02F9
MSG_CHARDATA_REPLY          = 0x02D2
MSG_CHARDATA2_NOTICE        = 0x0B6C
MSG_SPEAK_REQUEST           = 0x0049
MSG_SPEAK_REPLY             = 0x004A
MSG_SPEAK_NOTICE            = 0x0076
MSG_INFORMATION_NOTICE      = 0x019D
MSG_MAP_NOTICE              = 0x01DE
MSG_CURREGION_NOTICE        = 0x01B9
MSG_KNOWNMAP_NOTICE         = 0x01D2
MSG_SETCLOCK0_NOTICE        = 0x0248
MSG_PARTYID_REQUEST         = 0x01ED
MSG_PARTYID_REPLY           = 0x01EE
MSG_AREA_LIST_REQUEST       = 0x023C
MSG_AREA_LIST_REPLY         = 0x01AF
MSG_USERLIST_REQUEST        = 0x01A1
MSG_USERLIST_REPLY          = 0x021C
MSG_GOTOLIST_REQUEST        = 0x019B
MSG_GOTOLIST_REPLY          = 0x0215
MSG_MOVE1_REQUEST           = 0x01C4
MSG_CAMP_IN_REQUEST         = 0x01AD
MSG_CAMP_IN_REPLY           = 0x01AE


class TestResult:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = []

    def check(self, name: str, condition: bool, detail: str = ''):
        if condition:
            self.passed += 1
            print(f'  [PASS] {name}')
        else:
            self.failed += 1
            msg = f'{name}: {detail}' if detail else name
            self.errors.append(msg)
            print(f'  [FAIL] {msg}')

    def summary(self):
        total = self.passed + self.failed
        print(f'\n{"="*60}')
        print(f'QA RESULTS: {self.passed}/{total} passed, {self.failed} failed')
        if self.errors:
            print(f'\nFailures:')
            for e in self.errors:
                print(f'  - {e}')
        print(f'{"="*60}')
        return self.failed == 0


def build_game_msg(msg_type: int, payload: bytes = b'') -> bytes:
    """Build game message: [2B msg_type][payload padded to msg_type-2]."""
    expected = payload_size(msg_type)
    if len(payload) < expected:
        payload = payload + b'\x00' * (expected - len(payload))
    elif len(payload) > expected:
        payload = payload[:expected]
    return struct.pack('>H', msg_type) + payload


def build_login_request(member_id: str, version: str = 'NRPG0410') -> bytes:
    """Build LOGIN_REQUEST (0x019E)."""
    pld = bytearray(payload_size(MSG_LOGIN_REQUEST))
    mid = member_id.encode('ascii')[:63]
    pld[:len(mid)] = mid
    ver = version.encode('ascii')[:15]
    pld[128:128+len(ver)] = ver
    return build_game_msg(MSG_LOGIN_REQUEST, bytes(pld))


def build_regist_handle_request(handle: str) -> bytes:
    """Build REGIST_HANDLE_REQUEST (0x0046)."""
    pld = bytearray(payload_size(MSG_REGIST_HANDLE_REQUEST))
    h = handle.encode('ascii')[:63]
    pld[:len(h)] = h
    return build_game_msg(MSG_REGIST_HANDLE_REQUEST, bytes(pld))


def build_chardata_request(member_id: str) -> bytes:
    """Build CHARDATA_REQUEST (0x02F9)."""
    pld = bytearray(payload_size(MSG_CHARDATA_REQUEST))
    mid = member_id.encode('ascii')[:63]
    pld[:len(mid)] = mid
    return build_game_msg(MSG_CHARDATA_REQUEST, bytes(pld))


def build_speak_request(text: str) -> bytes:
    """Build SPEAK_REQUEST (0x0049)."""
    pld = bytearray(payload_size(MSG_SPEAK_REQUEST))
    t = text.encode('ascii')[:70]
    pld[:len(t)] = t
    return build_game_msg(MSG_SPEAK_REQUEST, bytes(pld))


def build_simple_request(msg_type: int) -> bytes:
    """Build a request with zero payload."""
    return build_game_msg(msg_type)


def build_logout_request() -> bytes:
    """Build LOGOUT_REQUEST (0x0043)."""
    return build_game_msg(MSG_LOGOUT_REQUEST)


class SVClient:
    """SV framing client — encodes outgoing and decodes incoming."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self.sv = SVFraming()
        self._pending_msgs = []

    async def send_game_msg(self, game_msg: bytes):
        """Send a game message via SV framing."""
        framed = self.sv.encode_message(game_msg)
        self.writer.write(framed)
        await self.writer.drain()

    async def recv_messages(self, timeout: float = 5.0) -> list:
        """Receive and decode game messages, returns list of (msg_type, payload)."""
        messages = []
        deadline = time.time() + timeout

        while time.time() < deadline:
            remaining = max(0.1, deadline - time.time())
            try:
                data = await asyncio.wait_for(
                    self.reader.read(4096), timeout=remaining)
            except asyncio.TimeoutError:
                break

            if not data:
                break

            self.sv.feed(data)

            for event in self.sv.iter_events():
                if event[0] == 'fragment':
                    self.sv.process_fragment(event[1])
                elif event[0] == 'keepalive':
                    pass  # ignore keepalives in test

            for msg in self.sv.iter_messages():
                if len(msg) >= 2:
                    msg_type = struct.unpack('>H', msg[:2])[0]
                    msg_payload = msg[2:]
                    messages.append((msg_type, msg_payload))

            # After receiving some messages, keep draining with short timeouts
            # until no more data arrives (handles multi-fragment large messages)
            if messages:
                while time.time() < deadline:
                    try:
                        data2 = await asyncio.wait_for(self.reader.read(4096), timeout=0.5)
                        if not data2:
                            break
                        self.sv.feed(data2)
                        for event in self.sv.iter_events():
                            if event[0] == 'fragment':
                                self.sv.process_fragment(event[1])
                        for msg in self.sv.iter_messages():
                            if len(msg) >= 2:
                                msg_type = struct.unpack('>H', msg[:2])[0]
                                messages.append((msg_type, msg[2:]))
                    except asyncio.TimeoutError:
                        break
                break

        return messages


async def run_tests(host: str, port: int):
    results = TestResult()
    member_id = f'test_{int(time.time()) % 100000:05d}'

    print(f'\nDragon\'s Dream QA Test Suite (v2 Protocol)')
    print(f'Server: {host}:{port}')
    print(f'Test member_id: {member_id}')
    print(f'{"="*60}')

    # ── Test 1: TCP Connection ────────────────────────────────────────────
    print(f'\n[Test 1] TCP Connection')
    try:
        reader, writer = await asyncio.open_connection(host, port)
        results.check('TCP connect', True)
    except Exception as e:
        results.check('TCP connect', False, str(e))
        return results.summary()

    # ── Test 2: BBS Phase ─────────────────────────────────────────────────
    print(f'\n[Test 2] BBS Phase (NIFTY-Serve)')

    # Send " P\r" (initial prompt)
    writer.write(b' P\r')
    await writer.drain()
    try:
        resp = await asyncio.wait_for(reader.read(256), timeout=5.0)
        results.check('BBS: " P\\r" -> got response', len(resp) > 0, f'{len(resp)} bytes')
        results.check('BBS: response contains "*"', b'*' in resp, repr(resp))
    except asyncio.TimeoutError:
        results.check('BBS: " P\\r" response', False, 'timeout')
        writer.close()
        return results.summary()

    # Send SET command
    set_cmd = b'SET 1:0,2:0,3:0,4:1,5:0,7:0,8:0,9:0,10:0,12:0,13:0,14:0,15:0,18:0,19:0,20:0,21:0,22:0\r'
    writer.write(set_cmd)
    await writer.drain()
    try:
        resp = await asyncio.wait_for(reader.read(256), timeout=5.0)
        results.check('BBS: SET -> got response', len(resp) > 0, f'{len(resp)} bytes')
        results.check('BBS: SET response contains "*"', b'*' in resp, repr(resp))
    except asyncio.TimeoutError:
        results.check('BBS: SET response', False, 'timeout')
        writer.close()
        return results.summary()

    # Send C HRPG
    writer.write(b'C HRPG\r')
    await writer.drain()
    try:
        resp = await asyncio.wait_for(reader.read(256), timeout=5.0)
        results.check('BBS: "C HRPG" -> got response', len(resp) > 0, f'{len(resp)} bytes')
        results.check('BBS: response contains "COM"', b'COM' in resp, repr(resp))
    except asyncio.TimeoutError:
        results.check('BBS: C HRPG response', False, 'timeout')
        writer.close()
        return results.summary()

    print('  BBS phase complete — entering SV/game protocol')

    # Create SV client for game protocol
    sv_client = SVClient(reader, writer)

    # ── Test 3: Login ─────────────────────────────────────────────────────
    print(f'\n[Test 3] Login Request (SV framed)')
    login_msg = build_login_request(member_id)
    await sv_client.send_game_msg(login_msg)

    packets = await sv_client.recv_messages(timeout=8.0)
    results.check('Received response packets',
                  len(packets) > 0,
                  f'got {len(packets)} packets')

    # Find STANDARD_REPLY
    std_replies = [p for p in packets if p[0] == MSG_STANDARD_REPLY]
    results.check('STANDARD_REPLY received', len(std_replies) > 0)
    if std_replies:
        pld = std_replies[0][1]
        results.check('STANDARD_REPLY payload size',
                      len(pld) == payload_size(MSG_STANDARD_REPLY),
                      f'expected {payload_size(MSG_STANDARD_REPLY)}, got {len(pld)}')
        if len(pld) >= 2:
            result_code = struct.unpack_from('>H', pld, 0)[0]
            results.check('Login result = OK',
                          result_code == RESULT_OK,
                          f'got 0x{result_code:04X}')

    # Check for CHARDATA_REPLY
    chardata_replies = [p for p in packets if p[0] == MSG_CHARDATA_REPLY]
    results.check('CHARDATA_REPLY received', len(chardata_replies) > 0)
    if chardata_replies:
        pld = chardata_replies[0][1]
        results.check('CHARDATA_REPLY payload size',
                      len(pld) == payload_size(MSG_CHARDATA_REPLY),
                      f'expected {payload_size(MSG_CHARDATA_REPLY)}, got {len(pld)}')

    # Check for other initial state packets
    for expected_type, expected_name in [
        (MSG_CURREGION_NOTICE, 'CURREGION_NOTICE'),
        (MSG_MAP_NOTICE, 'MAP_NOTICE'),
        (MSG_CHARDATA2_NOTICE, 'CHARDATA2_NOTICE'),
        (MSG_INFORMATION_NOTICE, 'INFORMATION_NOTICE'),
    ]:
        found = [p for p in packets if p[0] == expected_type]
        results.check(f'{expected_name} received', len(found) > 0)

    print(f'\n  Received {len(packets)} packets after login:')
    for mt, pld in packets:
        print(f'    {msg_name(mt)} (0x{mt:04X}) — {len(pld)} bytes payload')

    # ── Test 4: Handle Registration ───────────────────────────────────────
    print(f'\n[Test 4] Handle Registration')
    test_handle = f'Drg{int(time.time()) % 1000:03d}'
    await sv_client.send_game_msg(build_regist_handle_request(test_handle))

    packets = await sv_client.recv_messages(timeout=3.0)
    std_replies = [p for p in packets if p[0] == MSG_STANDARD_REPLY]
    results.check('STANDARD_REPLY for handle', len(std_replies) > 0)
    if std_replies and len(std_replies[0][1]) >= 2:
        result = struct.unpack_from('>H', std_replies[0][1], 0)[0]
        results.check('Handle registration OK', result == RESULT_OK,
                      f'result=0x{result:04X}')

    # ── Test 5: Character Data Request ────────────────────────────────────
    print(f'\n[Test 5] Character Data Request')
    await sv_client.send_game_msg(build_chardata_request(member_id))

    packets = await sv_client.recv_messages(timeout=3.0)
    chardata = [p for p in packets if p[0] == MSG_CHARDATA_REPLY]
    results.check('CHARDATA_REPLY received', len(chardata) > 0)

    # ── Test 6: Speak (Chat) ──────────────────────────────────────────────
    print(f'\n[Test 6] Chat (Speak)')
    await sv_client.send_game_msg(build_speak_request('Hello Dragon World!'))

    packets = await sv_client.recv_messages(timeout=3.0)
    # Should get SPEAK_REPLY and/or SPEAK_NOTICE
    speak_replies = [p for p in packets if p[0] in (MSG_SPEAK_REPLY, MSG_SPEAK_NOTICE)]
    results.check('SPEAK response received', len(speak_replies) > 0)

    # ── Test 7: Party ID Request ──────────────────────────────────────────
    print(f'\n[Test 7] Party ID Request')
    await sv_client.send_game_msg(build_simple_request(MSG_PARTYID_REQUEST))

    packets = await sv_client.recv_messages(timeout=3.0)
    party_replies = [p for p in packets if p[0] == MSG_PARTYID_REPLY]
    results.check('PARTYID_REPLY received', len(party_replies) > 0)

    # ── Test 8: Area List Request ─────────────────────────────────────────
    print(f'\n[Test 8] Area List Request')
    await sv_client.send_game_msg(build_simple_request(MSG_AREA_LIST_REQUEST))

    packets = await sv_client.recv_messages(timeout=3.0)
    area_replies = [p for p in packets if p[0] == MSG_AREA_LIST_REPLY]
    results.check('AREA_LIST_REPLY received', len(area_replies) > 0)

    # ── Test 9: User List Request ─────────────────────────────────────────
    print(f'\n[Test 9] User List Request')
    await sv_client.send_game_msg(build_simple_request(MSG_USERLIST_REQUEST))

    packets = await sv_client.recv_messages(timeout=3.0)
    user_replies = [p for p in packets if p[0] == MSG_USERLIST_REPLY]
    results.check('USERLIST_REPLY received', len(user_replies) > 0)

    # ── Test 10: Goto List Request ────────────────────────────────────────
    print(f'\n[Test 10] Goto List Request')
    await sv_client.send_game_msg(build_simple_request(MSG_GOTOLIST_REQUEST))

    packets = await sv_client.recv_messages(timeout=3.0)
    goto_replies = [p for p in packets if p[0] == MSG_GOTOLIST_REPLY]
    results.check('GOTOLIST_REPLY received', len(goto_replies) > 0)

    # ── Test 11: Camp In Request ──────────────────────────────────────────
    print(f'\n[Test 11] Camp In Request')
    await sv_client.send_game_msg(build_simple_request(MSG_CAMP_IN_REQUEST))

    packets = await sv_client.recv_messages(timeout=3.0)
    camp_replies = [p for p in packets if p[0] == MSG_CAMP_IN_REPLY]
    results.check('CAMP_IN_REPLY received', len(camp_replies) > 0)

    # ── Test 12: Wire Size Validation ─────────────────────────────────────
    print(f'\n[Test 12] Wire Size Validation')
    # Verify payload sizes match (msg_type - 2) for all received messages
    # We already checked individual ones above, do a summary check
    results.check('MSG_HEADER_SIZE = 2', MSG_HEADER_SIZE == 2)
    results.check('STANDARD_REPLY wire size = 72',
                  0x0048 == 72 and payload_size(0x0048) == 70)
    results.check('LOGIN_REQUEST wire size = 414',
                  0x019E == 414 and payload_size(0x019E) == 412)
    results.check('CHARDATA_REPLY wire size = 722',
                  0x02D2 == 722 and payload_size(0x02D2) == 720)
    results.check('CHARDATA2_NOTICE wire size = 2924',
                  0x0B6C == 2924 and payload_size(0x0B6C) == 2922)

    # ── Cleanup: Logout ───────────────────────────────────────────────────
    print(f'\n[Cleanup] Logout')
    await sv_client.send_game_msg(build_logout_request())
    await asyncio.sleep(0.5)

    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass

    return results.summary()


def main():
    ap = argparse.ArgumentParser(description="Dragon's Dream QA test client (v2)")
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=8020)
    args = ap.parse_args()

    success = asyncio.run(run_tests(args.host, args.port))
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
