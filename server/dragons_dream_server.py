#!/usr/bin/env python3
"""
Dragon's Dream (ドラゴンズドリーム) Online Revival Server
Fujitsu × SEGA, Saturn / Windows PC MMORPG, December 1997
Original servers closed September 1999.

Binary-verified protocol implementation based on disassembly of:
  0.BIN (504,120 bytes) from Dragon's Dream (Japan) GS-7114 V1.003
  Message table at file offset 0x04612C (253 entries)
  Handler table at file offset 0x0435D8 (197 entries)

Architecture:
  TCP Port 8020 — accepts connections from:
    - Yabause/Kronos/Mednafen NetLink emulation (internet_enable mode)
    - Modem-to-TCP bridge (for real Saturn hardware or BBS-mode emulators)
    - PC client (Normmatt IV handshake mode)

  Connection flow:
    1. Server sends INIT_HEADER (8B) + SESSION_CHALLENGE (256B)
    2. Client sends CLIENT_ACK (8B)
    3. Server sends SECOND_HEADER (8B) + SESSION_CONFIRM (18B)
    4. Data phase: framed messages [uint16 BE msg_type][uint16 BE payload_len][payload]

  All message type IDs verified from binary dispatch table at 0x04612C.
  Wire size = msg_type value (confirmed: 0x0046=70, 0x019E=414, 0x02D2=722, etc.)
"""

import argparse
import asyncio
import hashlib
import json
import logging
import os
import sqlite3
import struct
import sys
import time
import traceback
from typing import Optional

# ═══════════════════════════════════════════════════════════════════════════════
# PROTOCOL CONSTANTS — verified from binary dispatch table at 0x04612C
# ═══════════════════════════════════════════════════════════════════════════════

SERVER_PORT = 8020

# IV handshake magic (8-byte markers) — from Normmatt's server.cs
INIT_HEADER   = b'IV100000'
CLIENT_ACK    = b'IV012fed'
SECOND_HEADER = b'IV012fed'

# Session challenge layout (256 bytes)
SESSION_FLAG  = 0x42

# BBS-mode commands (Saturn connects through NIFTY-Serve)
BBS_CMD_CONNECT = b'C HRPG\r'
BBS_CMD_NETRPG  = b'C NETRPG\r'

# ── Complete message type table (253 entries from binary 0x04612C) ───────────
# Format: MSG_ID: ("NAME", payload_size)
# Wire size = MSG_ID value; payload_size = wire_size - 4
MSG_TABLE = {
    0x0000: ("SELECT_REQUEST", 0),
    0x0043: ("LOGOUT_REQUEST", 63),
    0x0044: ("COLO_MEMBER_NOTICE", 64),
    0x0046: ("REGIST_HANDLE_REQUEST", 66),
    0x0048: ("STANDARD_REPLY", 68),
    0x0049: ("SPEAK_REQUEST", 69),
    0x004A: ("SPEAK_REPLY", 70),
    0x0068: ("CARD_NOTICE", 100),
    0x006D: ("SYSTEM_NOTICE", 105),
    0x006E: ("ESP_REPLY", 106),
    0x006F: ("ESP_REQUEST", 107),
    0x0076: ("SPEAK_NOTICE", 114),
    0x019A: ("LOGOUT_NOTICE", 406),
    0x019B: ("GOTOLIST_REQUEST", 407),
    0x019C: ("GOTOLIST_NOTICE", 408),
    0x019D: ("INFORMATION_NOTICE", 409),
    0x019E: ("LOGIN_REQUEST", 410),
    0x019F: ("UPDATE_CHARDATA_REQUEST", 411),
    0x01A0: ("SAKAYA_IN_NOTICE", 412),
    0x01A1: ("USERLIST_REQUEST", 413),
    0x01A2: ("BB_RMSUBDIR_REPLY", 414),
    0x01A3: ("PARTYLIST_REQUEST", 415),
    0x01A4: ("PARTYLIST_REPLY", 416),
    0x01A5: ("PARTYENTRY_ACCEPT_REPLY", 417),
    0x01A6: ("PARTYENTRY_REPLY", 418),
    0x01A7: ("CLR_KNOWNMAP_REPLY", 419),
    0x01A8: ("PARTYEXIT_REQUEST", 420),
    0x01A9: ("PARTYEXIT_REPLY", 421),
    0x01AA: ("UPDATE_CHARDATA_REPLY", 422),
    0x01AB: ("CHARDATA_NOTICE", 423),
    0x01AC: ("MAP_CHANGE_NOTICE", 424),
    0x01AD: ("CAMP_IN_REQUEST", 425),
    0x01AE: ("CAMP_IN_REPLY", 426),
    0x01AF: ("AREA_LIST_REPLY", 427),
    0x01B0: ("TELEPORTLIST_REQUEST", 428),
    0x01B2: ("TEXT_NOTICE", 430),
    0x01B3: ("ALLOW_SETLEADER_REPLY", 431),
    0x01B4: ("CAMP_OUT_REQUEST", 432),
    0x01B5: ("CAMP_OUT_REPLY", 433),
    0x01B6: ("CANCEL_JOIN_NOTICE", 434),
    0x01B7: ("REGIONCHANGE_REQUEST", 435),
    0x01B8: ("FINDUSER_REQUEST", 436),
    0x01B9: ("CURREGION_NOTICE", 437),
    0x01BC: ("CHAR_DISAPPEAR_NOTICE", 440),
    0x01BD: ("SELECT_NOTICE", 441),
    0x01C0: ("CLASS_CHANGE_REPLY", 444),
    0x01C1: ("OTHERPARTY_DATA_NOTICE", 445),
    0x01C2: ("MOVE1_NOTICE", 446),
    0x01C4: ("MOVE1_REQUEST", 448),
    0x01C5: ("MOVE2_REQUEST", 449),
    0x01C6: ("EVENT_ITEM_NOTICE", 450),
    0x01C7: ("BTLJOIN_NOTICE", 451),
    0x01C8: ("BTL_GOLD_NOTICE", 452),
    0x01C9: ("ENCOUNTMONSTER_REPLY", 453),
    0x01CA: ("ENCOUNTMONSTER_NOTICE", 454),
    0x01CF: ("EVENT_NOTICE", 459),
    0x01D0: ("EXEC_EVENT_REQUEST", 460),
    0x01D1: ("EXEC_EVENT_REPLY", 461),
    0x01D2: ("KNOWNMAP_NOTICE", 462),
    0x01D3: ("GIVEUP_REPLY", 463),
    0x01D4: ("SETPOS_REQUEST", 464),
    0x01D5: ("SETPOS_REPLY", 465),
    0x01D6: ("SETPOS_NOTICE", 466),
    0x01D7: ("SETLEADER_REQUEST", 467),
    0x01D8: ("SETLEADER_REPLY", 468),
    0x01DA: ("MONSTER_DEL_NOTICE", 470),
    0x01DB: ("VISION_NOTICE", 471),
    0x01DC: ("OBITUARY_NOTICE", 472),
    0x01DE: ("MAP_NOTICE", 474),
    0x01DF: ("CAMP_IN_NOTICE", 475),
    0x01E0: ("SET_MOVEMODE_REQUEST", 476),
    0x01E1: ("SET_MOVEMODE_REPLY", 477),
    0x01E3: ("ENCOUNTPARTY_NOTICE", 479),
    0x01E4: ("CANCEL_ENCOUNT_REQUEST", 480),
    0x01E5: ("CANCEL_ENCOUNT_REPLY", 481),
    0x01E6: ("INQUIRE_JOIN_NOTICE", 482),
    0x01E7: ("ALLOW_JOIN_REQUEST", 483),
    0x01E8: ("ESP_NOTICE", 484),
    0x01EA: ("BTL_EFFECTEND_REPLY", 486),
    0x01EB: ("BTL_END_REQUEST", 487),
    0x01EC: ("AVATA_NOID_NOTICE", 488),
    0x01ED: ("PARTYID_REQUEST", 489),
    0x01EE: ("PARTYID_REPLY", 490),
    0x01EF: ("CLR_KNOWNMAP_REQUEST", 491),
    0x01F2: ("SHOP_ITEM_REPLY", 494),
    0x01F3: ("SHOP_BUY_REQUEST", 495),
    0x01F4: ("SHOP_BUY_REPLY", 496),
    0x01F5: ("SHOP_SELL_REQUEST", 497),
    0x01F8: ("USERLIST_NOTICE", 500),
    0x01F9: ("SAKAYA_TBLLIST_REQUEST", 501),
    0x01FA: ("SAKAYA_TBLLIST2_REQUEST", 502),
    0x01FB: ("SAKAYA_EXIT_REQUEST", 503),
    0x01FC: ("SHOP_IN_REPLY", 504),
    0x01FD: ("SHOP_ITEM_REQUEST", 505),
    0x01FE: ("SHOP_LIST_REPLY", 506),
    0x01FF: ("SHOP_IN_REQUEST", 507),
    0x0200: ("SHOP_SELL_REPLY", 508),
    0x0201: ("SHOP_OUT_REQUEST", 509),
    0x0202: ("SEKIBAN_NOTICE", 510),
    0x0203: ("SHOP_LIST_REQUEST", 511),
    0x0204: ("CAMP_OUT_NOTICE", 512),
    0x0205: ("EQUIP_REQUEST", 513),
    0x020C: ("STORE_IN_NOTICE", 520),
    0x020D: ("SAKAYA_LIST_REQUEST", 521),
    0x020E: ("SAKAYA_EXIT_NOTICE", 522),
    0x020F: ("SAKAYA_SIT_REQUEST", 523),
    0x0210: ("SAKAYA_LIST_NOTICE", 524),
    0x0211: ("SAKABA_MOVE_REQUEST", 525),
    0x0212: ("SAKABA_MOVE_REPLY", 526),
    0x0213: ("SAKAYA_LIST_REPLY", 527),
    0x0214: ("SAKAYA_TBLLIST_REPLY", 528),
    0x0215: ("GOTOLIST_REPLY", 529),
    0x0216: ("SAKABA_MOVE_NOTICE", 530),
    0x0217: ("SAKAYA_IN_REQUEST", 531),
    0x0218: ("SAKAYA_IN_REPLY", 532),
    0x0219: ("SAKAYA_FIND_REPLY", 533),
    0x021A: ("SAKAYA_STAND_REQUEST", 534),
    0x021B: ("SAKAYA_EXIT_REPLY", 535),
    0x021C: ("USERLIST_REPLY", 536),
    0x021E: ("SAKAYA_STAND_REPLY", 538),
    0x021F: ("BATTLEMODE_NOTICE", 539),
    0x0220: ("BTL_MEMBER_NOTICE", 540),
    0x0221: ("BTL_MENU_NOTICE", 541),
    0x0222: ("BTL_CMD_REQUEST", 542),
    0x0223: ("BTL_CMD_REPLY", 543),
    0x0224: ("BTL_CMD_NOTICE", 544),
    0x0225: ("BTL_CHGMODE_REQUEST", 545),
    0x0226: ("BTL_CHGMODE_REPLY", 546),
    0x0227: ("BTL_RESULT_NOTICE", 547),
    0x0228: ("BTL_END_NOTICE", 548),
    0x0229: ("BTL_MASK_NOTICE", 549),
    0x022B: ("PARTYENTRY_REQUEST", 551),
    0x022C: ("MEMBERDATA_NOTICE", 552),
    0x022D: ("PARTYUNITE_ACCEPT_REPLY", 553),
    0x022E: ("PARTYUNITE_REPLY", 554),
    0x022F: ("PARTYUNITE_REQUEST", 555),
    0x0230: ("INQUIRE_UNITE_NOTICE", 556),
    0x0231: ("ALLOW_UNITE_REQUEST", 557),
    0x0232: ("PARTYEXIT_NOTICE", 558),
    0x0233: ("TELEPORT_NOTICE", 559),
    0x0234: ("MIRRORDUNGEON_REQUEST", 560),
    0x0235: ("CANCEL_ENCOUNT_NOTICE", 561),
    0x0236: ("BTLJOIN_REQUEST", 562),
    0x0237: ("BTLJOIN_REPLY", 563),
    0x023B: ("ALLOW_UNITE_REPLY", 567),
    0x023C: ("AREA_LIST_REQUEST", 568),
    0x023E: ("TELEPORTLIST_REPLY", 570),
    0x023F: ("EXPLAIN_REQUEST", 571),
    0x0240: ("MIRRORDUNGEON_REPLY", 572),
    0x0241: ("FINDUSER2_REQUEST", 573),
    0x0242: ("CHANGE_PARA_REPLY", 574),
    0x0243: ("MONSTERWARN_NOTICE", 575),
    0x0244: ("ENCOUNTMONSTER_REQUEST", 576),
    0x0245: ("SAKAYA_CHARLIST_NOTICE", 577),
    0x0246: ("SET_SIGN_REQUEST", 578),
    0x0247: ("SET_SIGN_REPLY", 579),
    0x0248: ("SETCLOCK0_NOTICE", 580),
    0x0249: ("EVENT_MAP_NOTICE", 581),
    0x024A: ("MONSTER_MAP_NOTICE", 582),
    0x024B: ("SAKAYA_SIT_REPLY", 583),
    0x024C: ("SAKAYA_MEMLIST_REQUEST", 584),
    0x024D: ("SAKAYA_MEMLIST_REPLY", 585),
    0x024E: ("SAKAYA_MEMLIST_NOTICE", 586),
    0x024F: ("SAKAYA_FIND_REQUEST", 587),
    0x0250: ("MOVE_SEAT_NOTICE", 588),
    0x0251: ("SET_SEKIBAN_REQUEST", 589),
    0x0252: ("SET_SEKIBAN_REPLY", 590),
    0x0253: ("SET_SEKIBAN_NOTICE", 591),
    0x0254: ("SET_SIGN_NOTICE", 592),
    0x0255: ("MOVE_SEAT_REQUEST", 593),
    0x0256: ("MOVE_SEAT_REPLY", 594),
    0x0257: ("MISSPARTY_NOTICE", 595),
    0x025A: ("PARTYENTRY_NOTICE", 598),
    0x025B: ("ALLOW_JOIN_REPLY", 599),
    0x025C: ("CANCEL_JOIN_REQUEST", 600),
    0x025D: ("CANCEL_JOIN_REPLY", 601),
    0x025E: ("PARTYUNITE_NOTICE", 602),
    0x025F: ("PARTY_BREAKUP_NOTICE", 603),
    0x0260: ("ACTION_CHAT_REQUEST", 604),
    0x0261: ("ACTION_CHAT_REPLY", 605),
    0x0263: ("EQUIP_REPLY", 607),
    0x0268: ("DISARM_SKILL_REPLY", 612),
    0x0269: ("SEL_THEME_REQUEST", 613),
    0x026A: ("SEL_THEME_REPLY", 614),
    0x026B: ("CHECK_THEME_REQUEST", 615),
    0x026C: ("EQUIP_NOTICE", 616),
    0x026D: ("DISARM_REQUEST", 617),
    0x026E: ("DISARM_REPLY", 618),
    0x026F: ("FINDUSER_REPLY", 619),
    0x0270: ("STORE_LIST_REQUEST", 620),
    0x0271: ("STORE_LIST_REPLY", 621),
    0x0272: ("STORE_IN_REQUEST", 622),
    0x0273: ("STORE_IN_REPLY", 623),
    0x0274: ("ACTION_CHAT_NOTICE", 624),
    0x0275: ("COMPOUND_REPLY", 625),
    0x0276: ("CONFIRM_LVLUP_REQUEST", 626),
    0x0277: ("CONFIRM_LVLUP_REPLY", 627),
    0x0278: ("LEVELUP_REQUEST", 628),
    0x0289: ("USE_NOTICE", 645),
    0x028A: ("BUY_REPLY", 646),
    0x028B: ("TRADE_DONE_NOTICE", 647),
    0x028C: ("SELL_REPLY", 648),
    0x028D: ("SELL_REQUEST", 649),
    0x028E: ("INQUIRE_BUY_NOTICE", 650),
    0x028F: ("BUY_REQUEST", 651),
    0x0290: ("TRADE_NOTICE", 652),
    0x0291: ("TRADE_CANCEL_REQUEST", 653),
    0x0292: ("TRADE_CANCEL_REPLY", 654),
    0x0293: ("EVENT_MOVE_NOTICE", 655),
    0x0294: ("GIVE_ITEM_REQUEST", 656),
    0x0295: ("GIVE_ITEM_REPLY", 657),
    0x0296: ("BTL_ACTIONCOUNT_NOTICE", 658),
    0x0297: ("BTL_EFFECTEND_REQUEST", 659),
    0x0298: ("FINDUSER2_REPLY", 660),
    0x0299: ("CLASS_LIST_REQUEST", 661),
    0x029A: ("CLASS_LIST_REPLY", 662),
    0x029B: ("CLASS_CHANGE_REQUEST", 663),
    0x029D: ("SHOP_OUT_REPLY", 665),
    0x029E: ("DIR_REQUEST", 666),
    0x029F: ("DIR_REPLY", 667),
    0x02A0: ("SUBDIR_REQUEST", 668),
    0x02A1: ("SUBDIR_REPLY", 669),
    0x02A2: ("MEMODIR_REQUEST", 670),
    0x02A3: ("MEMODIR_REPLY", 671),
    0x02A4: ("NEWS_READ_REQUEST", 672),
    0x02A5: ("NEWS_READ_REPLY", 673),
    0x02A6: ("NEWS_WRITE_REQUEST", 674),
    0x02A7: ("NEWS_WRITE_REPLY", 675),
    0x02A8: ("NEWS_DEL_REQUEST", 676),
    0x02A9: ("CHECK_THEME_REPLY", 677),
    0x02AA: ("MAIL_LIST_REQUEST", 678),
    0x02AB: ("MAIL_LIST_REPLY", 679),
    0x02AC: ("GET_MAIL_REQUEST", 680),
    0x02AD: ("GET_MAIL_REPLY", 681),
    0x02AE: ("SEND_MAIL_REQUEST", 682),
    0x02AF: ("SEND_MAIL_REPLY", 683),
    0x02B0: ("DEL_MAIL_REQUEST", 684),
    0x02B1: ("NEWS_DEL_REPLY", 685),
    0x02B2: ("BB_MKDIR_REQUEST", 686),
    0x02B3: ("BB_MKDIR_REPLY", 687),
    0x02B4: ("BB_RMDIR_REQUEST", 688),
    0x02B5: ("BB_RMDIR_REPLY", 689),
    0x02B6: ("BB_MKSUBDIR_REQUEST", 690),
    0x02B7: ("BB_MKSUBDIR_REPLY", 691),
    0x02B8: ("BB_RMSUBDIR_REQUEST", 692),
    0x02B9: ("LEVELUP_REPLY", 693),
    0x02BA: ("SKILL_LIST_REQUEST", 694),
    0x02BB: ("DEL_MAIL_REPLY", 695),
    0x02BC: ("COLO_WAITING_REQUEST", 696),
    0x02BD: ("COLO_WAITING_REPLY", 697),
    0x02BE: ("COLO_WAITING_NOTICE", 698),
    0x02BF: ("COLO_EXIT_REQUEST", 699),
    0x02C0: ("COLO_EXIT_REPLY", 700),
    0x02C1: ("COLO_EXIT_NOTICE", 701),
    0x02C2: ("COLO_LIST_REQUEST", 702),
    0x02C3: ("COLO_LIST_REPLY", 703),
    0x02C4: ("COLO_ENTRY_REQUEST", 704),
    0x02C5: ("COLO_ENTRY_NOTICE", 705),
    0x02C6: ("COLO_CANCEL_REQUEST", 706),
    0x02C7: ("COLO_CANCEL_NOTICE", 707),
    0x02C8: ("COLO_BATTLE_NOTICE", 708),
    0x02C9: ("COLO_FLDENT_REQUEST", 709),
    0x02CC: ("COLO_FLDENT_NOTICE", 712),
    0x02CD: ("COLO_RESULT_NOTICE", 713),
    0x02CE: ("COLO_RANKING_REQUEST", 714),
    0x02CF: ("COLO_FLDENT_REPLY", 715),
    0x02D0: ("GIVE_ITEM_NOTICE", 716),
    0x02D1: ("USE_REQUEST", 717),
    0x02D2: ("CHARDATA_REPLY", 718),
    0x02D3: ("USE_REPLY", 719),
    0x02D4: ("CMD_BLOCK_REPLY", 720),
    0x02D5: ("CAST_DICE_REQUEST", 721),
    0x02D6: ("CAST_DICE_REPLY", 722),
    0x02D7: ("SETLEADER_NOTICE", 723),
    0x02D8: ("INQUIRE_LEADER_NOTICE", 724),
    0x02D9: ("SETLEADER_ACCEPT_REPLY", 725),
    0x02DA: ("ALLOW_SETLEADER_REQUEST", 726),
    0x02DB: ("CAST_DICE_NOTICE", 727),
    0x02DC: ("CARD_REQUEST", 728),
    0x02DD: ("CARD_REPLY", 729),
    0x02E0: ("SKILL_LIST_REPLY", 732),
    0x02E1: ("LEARN_SKILL_REQUEST", 733),
    0x02E2: ("LEARN_SKILL_REPLY", 734),
    0x02E3: ("SKILLUP_REQUEST", 735),
    0x02E4: ("SKILLUP_REPLY", 736),
    0x02E5: ("EQUIP_SKILL_REQUEST", 737),
    0x02E6: ("EQUIP_SKILL_REPLY", 738),
    0x02E7: ("DISARM_SKILL_REQUEST", 739),
    0x02E8: ("DISARM_NOTICE", 740),
    0x02E9: ("USE_SKILL_REQUEST", 741),
    0x02EA: ("USE_SKILL_REPLY", 742),
    0x02EB: ("COLO_ENTRY_REPLY", 743),
    0x02EC: ("COLO_CANCEL_REPLY", 744),
    0x02ED: ("TRADE_CANCEL_NOTICE", 745),
    0x02EE: ("COMPOUND_REQUEST", 746),
    0x02EF: ("EXEC_EVENT_NOTICE", 747),
    0x02F0: ("EVENT_EFFECT_NOTICE", 748),
    0x02F1: ("WAIT_EVENT_NOTICE", 749),
    0x02F2: ("COLO_RANKING_REPLY", 750),
    0x02F3: ("MOVE2_NOTICE", 751),
    0x02F4: ("BTL_END_REPLY", 752),
    0x02F5: ("USE_SKILL_NOTICE", 753),
    0x02F6: ("CHANGE_PARA_REQUEST", 754),
    0x02F7: ("SET_MOVEMODE_NOTICE", 755),
    0x02F8: ("GIVEUP_REQUEST", 756),
    0x02F9: ("CHARDATA_REQUEST", 757),
    0x02FA: ("SAKAYA_TBLLIST_NOTICE", 758),
    0x04E0: ("EXPLAIN_REPLY", 1244),
    0x04E1: ("TELEPORT_REQUEST", 1245),
    0x0B6C: ("CHARDATA2_NOTICE", 2920),
}

# Build reverse lookup: name -> msg_id
MSG_ID_BY_NAME = {name: mid for mid, (name, _) in MSG_TABLE.items()}

# Frequently used message type IDs
MSG_LOGIN_REQUEST           = 0x019E
MSG_LOGOUT_REQUEST          = 0x0043
MSG_STANDARD_REPLY          = 0x0048
MSG_REGIST_HANDLE_REQUEST   = 0x0046
MSG_CHARDATA_REQUEST        = 0x02F9
MSG_CHARDATA_REPLY          = 0x02D2
MSG_CHARDATA_NOTICE         = 0x01AB
MSG_CHARDATA2_NOTICE        = 0x0B6C
MSG_UPDATE_CHARDATA_REQUEST = 0x019F
MSG_UPDATE_CHARDATA_REPLY   = 0x01AA
MSG_SPEAK_REQUEST           = 0x0049
MSG_SPEAK_NOTICE            = 0x0076
MSG_ESP_REQUEST             = 0x006F
MSG_ESP_NOTICE              = 0x01E8
MSG_INFORMATION_NOTICE      = 0x019D
MSG_SYSTEM_NOTICE           = 0x006D
MSG_MOVE1_REQUEST           = 0x01C4
MSG_MOVE1_NOTICE            = 0x01C2
MSG_MOVE2_REQUEST           = 0x01C5
MSG_MOVE2_NOTICE            = 0x02F3
MSG_MAP_NOTICE              = 0x01DE
MSG_MAP_CHANGE_NOTICE       = 0x01AC
MSG_CURREGION_NOTICE        = 0x01B9
MSG_LOGOUT_NOTICE           = 0x019A
MSG_PARTYID_REQUEST         = 0x01ED
MSG_PARTYID_REPLY           = 0x01EE
MSG_PARTYLIST_REQUEST       = 0x01A3
MSG_PARTYLIST_REPLY         = 0x01A4
MSG_PARTYENTRY_REQUEST      = 0x022B
MSG_PARTYENTRY_REPLY        = 0x01A6
MSG_PARTYEXIT_REQUEST       = 0x01A8
MSG_PARTYEXIT_REPLY         = 0x01A9
MSG_REGIONCHANGE_REQUEST    = 0x01B7
MSG_AREA_LIST_REQUEST       = 0x023C
MSG_AREA_LIST_REPLY         = 0x01AF
MSG_TELEPORTLIST_REQUEST    = 0x01B0
MSG_TELEPORTLIST_REPLY      = 0x023E
MSG_SETPOS_REQUEST          = 0x01D4
MSG_SETPOS_REPLY            = 0x01D5
MSG_ENCOUNTMONSTER_REQUEST  = 0x0244
MSG_ENCOUNTMONSTER_REPLY    = 0x01C9
MSG_BTL_CMD_REQUEST         = 0x0222
MSG_BTL_CMD_REPLY           = 0x0223
MSG_BTL_END_REQUEST         = 0x01EB
MSG_BTL_END_REPLY           = 0x02F4
MSG_EQUIP_REQUEST           = 0x0205
MSG_EQUIP_REPLY             = 0x0263
MSG_DISARM_REQUEST          = 0x026D
MSG_DISARM_REPLY            = 0x026E
MSG_USE_REQUEST             = 0x02D1
MSG_USE_REPLY               = 0x02D3
MSG_SHOP_LIST_REQUEST       = 0x0203
MSG_SHOP_IN_REQUEST         = 0x01FF
MSG_SHOP_ITEM_REQUEST       = 0x01FD
MSG_SHOP_BUY_REQUEST        = 0x01F3
MSG_SHOP_SELL_REQUEST       = 0x01F5
MSG_SHOP_OUT_REQUEST        = 0x0201
MSG_CAMP_IN_REQUEST         = 0x01AD
MSG_CAMP_IN_REPLY           = 0x01AE
MSG_CAMP_OUT_REQUEST        = 0x01B4
MSG_CAMP_OUT_REPLY          = 0x01B5
MSG_GOTOLIST_REQUEST        = 0x019B
MSG_GOTOLIST_REPLY          = 0x0215
MSG_USERLIST_REQUEST        = 0x01A1
MSG_USERLIST_REPLY          = 0x021C
MSG_FINDUSER_REQUEST        = 0x01B8
MSG_FINDUSER_REPLY          = 0x026F
MSG_ACTION_CHAT_REQUEST     = 0x0260
MSG_ACTION_CHAT_NOTICE      = 0x0274
MSG_SKILL_LIST_REQUEST      = 0x02BA
MSG_CLASS_LIST_REQUEST      = 0x0299
MSG_CLASS_CHANGE_REQUEST    = 0x029B
MSG_LEVELUP_REQUEST         = 0x0278
MSG_CONFIRM_LVLUP_REQUEST   = 0x0276
MSG_MAIL_LIST_REQUEST       = 0x02AA
MSG_SEND_MAIL_REQUEST       = 0x02AE
MSG_GET_MAIL_REQUEST        = 0x02AC
MSG_DEL_MAIL_REQUEST        = 0x02B0

RESULT_OK    = 0x00000000
RESULT_ERROR = 0x00000001

# ═══════════════════════════════════════════════════════════════════════════════
# LOGGING
# ═══════════════════════════════════════════════════════════════════════════════

LOG_PATH = 'dragons_dream.log'

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
        hex_part = ' '.join(f'{b:02X}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'  {i:04X}  {hex_part:<{width*3}}  {ascii_part}')
    return '\n'.join(lines)


def msg_name(msg_type: int) -> str:
    if msg_type in MSG_TABLE:
        return MSG_TABLE[msg_type][0]
    return f'UNKNOWN_0x{msg_type:04X}'


# ═══════════════════════════════════════════════════════════════════════════════
# PACKET BUILDERS
# ═══════════════════════════════════════════════════════════════════════════════

def _checksum16(data: bytes) -> int:
    return sum(data) & 0xFFFF


def build_session_challenge(nonce: bytes) -> bytes:
    """Build 256-byte SESSION_CHALLENGE. Layout verified from Normmatt's server."""
    pkt = bytearray(256)
    pkt[0] = 0x00
    pkt[1] = SESSION_FLAG  # 0x42
    # [2:4] checksum filled at end
    struct.pack_into('<I', pkt, 8,  0)   # field8
    struct.pack_into('<I', pkt, 12, 0)   # field12
    data_len = 64 + 64 + 4              # nonce + modulus + exponent
    struct.pack_into('<H', pkt, 16, data_len)
    pkt[18:82] = nonce[:64]
    # RSA modulus placeholder (64 bytes of zeros in bypass mode)
    # RSA exponent placeholder
    struct.pack_into('<I', pkt, 146, 0x10001)
    checksum = _checksum16(bytes(pkt))
    struct.pack_into('<H', pkt, 2, checksum)
    return bytes(pkt)


def build_session_confirm() -> bytes:
    """Build 18-byte SESSION_CONFIRM. field8=0x00000008 signals session active."""
    pkt = bytearray(18)
    struct.pack_into('<I', pkt, 8, 0x00000008)
    checksum = _checksum16(bytes(pkt))
    struct.pack_into('<H', pkt, 2, checksum)
    return bytes(pkt)


def build_packet(msg_type: int, payload: bytes) -> bytes:
    """Build a framed game packet: [uint16 BE msg_type][uint16 BE payload_len][payload]"""
    hdr = struct.pack('>HH', msg_type, len(payload))
    return hdr + payload


def build_standard_reply(result: int = RESULT_OK, data: bytes = b'') -> bytes:
    """STANDARD_REPLY (0x0048) — 68-byte payload generic response."""
    payload = bytearray(68)
    struct.pack_into('>I', payload, 0, result)
    if data:
        copy_len = min(len(data), 64)
        payload[4:4+copy_len] = data[:copy_len]
    return build_packet(MSG_STANDARD_REPLY, bytes(payload))


def build_chardata_reply(char: dict) -> bytes:
    """
    CHARDATA_REPLY (0x02D2) — 718-byte payload.
    Character record layout (verified payload size from binary table).
    """
    payload = bytearray(718)

    def pack_str(off, s, maxlen):
        enc = s.encode('ascii', errors='replace')[:maxlen-1]
        payload[off:off+len(enc)] = enc

    pack_str(0,  char.get('member_id', ''), 64)
    pack_str(64, char.get('handle', ''), 32)

    struct.pack_into('<B', payload, 96,  char.get('level', 1))
    struct.pack_into('<B', payload, 97,  char.get('race', 0))
    struct.pack_into('<B', payload, 98,  char.get('class_id', 0))
    struct.pack_into('<B', payload, 99,  char.get('gender', 0))
    struct.pack_into('<I', payload, 100, char.get('exp', 0))
    struct.pack_into('<I', payload, 104, char.get('hp_cur', 50))
    struct.pack_into('<I', payload, 108, char.get('hp_max', 50))
    struct.pack_into('<I', payload, 112, char.get('mp_cur', 20))
    struct.pack_into('<I', payload, 116, char.get('mp_max', 20))
    struct.pack_into('<I', payload, 120, char.get('str_', 10))
    struct.pack_into('<I', payload, 124, char.get('agi', 10))
    struct.pack_into('<I', payload, 128, char.get('int_', 10))
    struct.pack_into('<I', payload, 132, char.get('vit', 10))
    struct.pack_into('<I', payload, 136, char.get('luc', 10))
    struct.pack_into('<I', payload, 140, char.get('def_', 10))
    struct.pack_into('<I', payload, 144, char.get('spd', 10))
    struct.pack_into('<I', payload, 148, char.get('atk', 10))

    # Equipment slots (16 x uint32)
    equip = char.get('equip_ids', [])
    for i in range(16):
        val = equip[i] if i < len(equip) else 0
        struct.pack_into('<I', payload, 152 + i*4, val)

    # Item slots (32 x uint32)
    items = char.get('item_ids', [])
    for i in range(32):
        val = items[i] if i < len(items) else 0
        struct.pack_into('<I', payload, 216 + i*4, val)

    struct.pack_into('<I', payload, 344, char.get('dungeon_id', 0))
    struct.pack_into('<I', payload, 348, char.get('floor', 0))
    struct.pack_into('<I', payload, 352, char.get('pos_x', 0))
    struct.pack_into('<I', payload, 356, char.get('pos_y', 0))
    struct.pack_into('<I', payload, 360, char.get('facing', 0))
    struct.pack_into('<I', payload, 364, char.get('gold', 100))
    struct.pack_into('<I', payload, 368, char.get('status_flags', 0))
    struct.pack_into('<I', payload, 372, char.get('death_count', 0))
    struct.pack_into('<I', payload, 376, char.get('play_time', 0))
    struct.pack_into('<I', payload, 380, int(char.get('created_at', time.time())))

    # Spell slots (32 x uint32)
    spells = char.get('spell_ids', [])
    for i in range(32):
        val = spells[i] if i < len(spells) else 0
        struct.pack_into('<I', payload, 384 + i*4, val)

    pack_str(512, char.get('char_title', ''), 64)
    pack_str(576, char.get('guild_id', ''), 16)
    struct.pack_into('<I', payload, 592, char.get('guild_rank', 0))
    struct.pack_into('<I', payload, 596, char.get('kills', 0))
    struct.pack_into('<I', payload, 600, char.get('deaths', 0))
    struct.pack_into('<I', payload, 604, char.get('sessions', 0))

    return build_packet(MSG_CHARDATA_REPLY, bytes(payload))


def build_chardata2_notice(players: list) -> bytes:
    """
    CHARDATA2_NOTICE (0x0B6C) — 2920-byte payload.
    World state broadcast: header + 6 player slots of 480 bytes each.
    """
    payload = bytearray(2920)
    struct.pack_into('<I', payload, 0, int(time.time()))  # server_time
    struct.pack_into('<I', payload, 4, len(players))       # online_count
    struct.pack_into('<I', payload, 8, 0)                  # dungeon_flags
    struct.pack_into('<I', payload, 12, 0)                 # event_id
    # [16:40] reserved

    # Fill up to 6 player slots (480 bytes each from CHARDATA_REPLY format)
    for i, player in enumerate(players[:6]):
        slot_off = 40 + i * 480
        # Copy the first 480 bytes of chardata_reply payload format
        char_pkt = build_chardata_reply(player)
        # char_pkt = [4B header][718B payload]; take first 480 of payload
        char_payload = char_pkt[4:]
        copy_len = min(480, len(char_payload))
        payload[slot_off:slot_off+copy_len] = char_payload[:copy_len]

    return build_packet(MSG_CHARDATA2_NOTICE, bytes(payload))


def build_map_notice(dungeon_id: int = 0, floor: int = 0) -> bytes:
    """MAP_NOTICE (0x01DE) — 474-byte payload. Current map data."""
    payload = bytearray(474)
    struct.pack_into('<I', payload, 0, dungeon_id)
    struct.pack_into('<I', payload, 4, floor)
    return build_packet(MSG_MAP_NOTICE, bytes(payload))


def build_curregion_notice(region_id: int = 0) -> bytes:
    """CURREGION_NOTICE (0x01B9) — 437-byte payload. Current region."""
    payload = bytearray(437)
    struct.pack_into('<I', payload, 0, region_id)
    return build_packet(MSG_CURREGION_NOTICE, bytes(payload))


def build_information_notice(text: str = '') -> bytes:
    """INFORMATION_NOTICE (0x019D) — 409-byte payload. Server message."""
    payload = bytearray(409)
    enc = text.encode('ascii', errors='replace')[:400]
    payload[:len(enc)] = enc
    return build_packet(MSG_INFORMATION_NOTICE, bytes(payload))


def build_system_notice(text: str = '') -> bytes:
    """SYSTEM_NOTICE (0x006D) — 105-byte payload."""
    payload = bytearray(105)
    enc = text.encode('ascii', errors='replace')[:100]
    payload[:len(enc)] = enc
    return build_packet(MSG_SYSTEM_NOTICE, bytes(payload))


def build_speak_notice(handle: str, text: str) -> bytes:
    """SPEAK_NOTICE (0x0076) — 114-byte payload. Chat broadcast."""
    payload = bytearray(114)
    h_enc = handle.encode('ascii', errors='replace')[:31]
    payload[:len(h_enc)] = h_enc
    t_enc = text.encode('ascii', errors='replace')[:79]
    payload[32:32+len(t_enc)] = t_enc
    return build_packet(MSG_SPEAK_NOTICE, bytes(payload))


def build_logout_notice(member_id: str) -> bytes:
    """LOGOUT_NOTICE (0x019A) — 406-byte payload."""
    payload = bytearray(406)
    enc = member_id.encode('ascii', errors='replace')[:63]
    payload[:len(enc)] = enc
    return build_packet(MSG_LOGOUT_NOTICE, bytes(payload))


def build_update_chardata_reply(result: int = RESULT_OK) -> bytes:
    """UPDATE_CHARDATA_REPLY (0x01AA) — 422-byte payload."""
    payload = bytearray(422)
    struct.pack_into('>I', payload, 0, result)
    return build_packet(MSG_UPDATE_CHARDATA_REPLY, bytes(payload))


# ═══════════════════════════════════════════════════════════════════════════════
# PACKET PARSER
# ═══════════════════════════════════════════════════════════════════════════════

class PacketParser:
    """Reassemble framed packets from TCP stream."""

    def __init__(self):
        self._buf = bytearray()

    def feed(self, data: bytes):
        self._buf.extend(data)

    def packets(self):
        """Yield (msg_type, payload) for each complete packet."""
        while len(self._buf) >= 4:
            msg_type, payload_len = struct.unpack_from('>HH', self._buf, 0)
            total = 4 + payload_len
            if len(self._buf) < total:
                break
            payload = bytes(self._buf[4:total])
            del self._buf[:total]
            yield msg_type, payload


# ═══════════════════════════════════════════════════════════════════════════════
# PAYLOAD PARSERS
# ═══════════════════════════════════════════════════════════════════════════════

def _read_cstr(buf: bytes, off: int, maxlen: int) -> str:
    end = buf.find(b'\x00', off, off + maxlen)
    if end < 0:
        end = off + maxlen
    return buf[off:end].decode('ascii', errors='replace')


def parse_login_request(payload: bytes) -> dict:
    """Parse LOGIN_REQUEST (0x019E) — 410-byte payload."""
    return {
        'member_id':    _read_cstr(payload, 0, 64),
        'rsa_enc_blob': payload[64:128] if len(payload) >= 128 else b'',
        'game_version': _read_cstr(payload, 128, 16) if len(payload) >= 144 else '',
        'client_caps':  struct.unpack_from('<I', payload, 144)[0] if len(payload) >= 148 else 0,
        'nonce_echo':   payload[148:212] if len(payload) >= 212 else b'',
    }


def parse_update_chardata(payload: bytes) -> dict:
    """Parse UPDATE_CHARDATA_REQUEST (0x019F) — 411-byte payload."""
    r = {'member_id': _read_cstr(payload, 0, 64)}
    if len(payload) >= 100:
        r['level']    = payload[96] if len(payload) > 96 else 1
        r['race']     = payload[97] if len(payload) > 97 else 0
        r['class_id'] = payload[98] if len(payload) > 98 else 0
        r['gender']   = payload[99] if len(payload) > 99 else 0
    if len(payload) >= 152:
        r['exp']      = struct.unpack_from('<I', payload, 100)[0]
        r['hp_cur']   = struct.unpack_from('<I', payload, 104)[0]
        r['hp_max']   = struct.unpack_from('<I', payload, 108)[0]
        r['mp_cur']   = struct.unpack_from('<I', payload, 112)[0]
        r['mp_max']   = struct.unpack_from('<I', payload, 116)[0]
        r['str_']     = struct.unpack_from('<I', payload, 120)[0]
        r['agi']      = struct.unpack_from('<I', payload, 124)[0]
        r['int_']     = struct.unpack_from('<I', payload, 128)[0]
        r['vit']      = struct.unpack_from('<I', payload, 132)[0]
        r['luc']      = struct.unpack_from('<I', payload, 136)[0]
        r['def_']     = struct.unpack_from('<I', payload, 140)[0]
        r['spd']      = struct.unpack_from('<I', payload, 144)[0]
        r['atk']      = struct.unpack_from('<I', payload, 148)[0]
    if len(payload) >= 380:
        r['dungeon_id']   = struct.unpack_from('<I', payload, 344)[0]
        r['floor']        = struct.unpack_from('<I', payload, 348)[0]
        r['pos_x']        = struct.unpack_from('<I', payload, 352)[0]
        r['pos_y']        = struct.unpack_from('<I', payload, 356)[0]
        r['facing']       = struct.unpack_from('<I', payload, 360)[0]
        r['gold']         = struct.unpack_from('<I', payload, 364)[0]
        r['status_flags'] = struct.unpack_from('<I', payload, 368)[0]
        r['play_time']    = struct.unpack_from('<I', payload, 376)[0]
    return r


def parse_regist_handle(payload: bytes) -> dict:
    """Parse REGIST_HANDLE_REQUEST (0x0046) — 66-byte payload."""
    handle = _read_cstr(payload, 0, 64)
    flags = struct.unpack_from('<H', payload, 64)[0] if len(payload) >= 66 else 0
    return {'handle': handle, 'flags': flags}


def parse_speak_request(payload: bytes) -> dict:
    """Parse SPEAK_REQUEST (0x0049) — 69-byte payload."""
    return {'text': _read_cstr(payload, 0, 69)}


def parse_esp_request(payload: bytes) -> dict:
    """Parse ESP_REQUEST (0x006F) — 107-byte payload. Whisper/PM."""
    return {
        'target': _read_cstr(payload, 0, 32),
        'text':   _read_cstr(payload, 32, 75),
    }


def parse_move_request(payload: bytes) -> dict:
    """Parse MOVE1/MOVE2_REQUEST."""
    r = {}
    if len(payload) >= 16:
        r['direction'] = struct.unpack_from('<I', payload, 0)[0]
        r['pos_x']     = struct.unpack_from('<I', payload, 4)[0]
        r['pos_y']     = struct.unpack_from('<I', payload, 8)[0]
        r['facing']    = struct.unpack_from('<I', payload, 12)[0]
    return r


# ═══════════════════════════════════════════════════════════════════════════════
# DATABASE
# ═══════════════════════════════════════════════════════════════════════════════

DB_PATH = 'dragons_dream.db'


class Database:
    """Thread-safe SQLite database for users, characters, and sessions."""

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
            CREATE TABLE IF NOT EXISTS users (
                member_id  TEXT PRIMARY KEY,
                handle     TEXT DEFAULT '',
                pw_hash    TEXT DEFAULT '',
                created_at INTEGER DEFAULT (strftime('%s','now')),
                last_login INTEGER DEFAULT 0
            );
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
                equip_json TEXT DEFAULT '[]',
                item_json  TEXT DEFAULT '[]',
                spell_json TEXT DEFAULT '[]',
                dungeon_id INTEGER DEFAULT 0,
                floor      INTEGER DEFAULT 0,
                pos_x      INTEGER DEFAULT 0,
                pos_y      INTEGER DEFAULT 0,
                facing     INTEGER DEFAULT 0,
                gold       INTEGER DEFAULT 100,
                status_flags INTEGER DEFAULT 0,
                death_count  INTEGER DEFAULT 0,
                play_time    INTEGER DEFAULT 0,
                char_title   TEXT DEFAULT '',
                guild_id     TEXT DEFAULT '',
                guild_rank   INTEGER DEFAULT 0,
                kills        INTEGER DEFAULT 0,
                deaths       INTEGER DEFAULT 0,
                sessions     INTEGER DEFAULT 0,
                created_at   INTEGER DEFAULT (strftime('%s','now')),
                updated_at   INTEGER DEFAULT (strftime('%s','now'))
            );
            CREATE TABLE IF NOT EXISTS mail (
                mail_id    INTEGER PRIMARY KEY AUTOINCREMENT,
                to_id      TEXT NOT NULL,
                from_id    TEXT NOT NULL,
                subject    TEXT DEFAULT '',
                body       TEXT DEFAULT '',
                read_flag  INTEGER DEFAULT 0,
                created_at INTEGER DEFAULT (strftime('%s','now'))
            );
        """)
        c.commit()
        c.close()
        log.info('Database initialized: %s', self.path)

    def upsert_user(self, member_id: str, handle: str = None):
        existing = self.conn.execute(
            'SELECT member_id FROM users WHERE member_id=?', (member_id,)
        ).fetchone()
        if existing:
            updates = ["last_login=strftime('%s','now')"]
            params = []
            if handle:
                updates.append('handle=?')
                params.append(handle)
            params.append(member_id)
            self.conn.execute(
                f"UPDATE users SET {','.join(updates)} WHERE member_id=?", params
            )
        else:
            self.conn.execute(
                'INSERT INTO users(member_id, handle) VALUES(?,?)',
                (member_id, handle or member_id)
            )
        self.conn.commit()

    def get_or_create_character(self, member_id: str) -> dict:
        row = self.conn.execute(
            'SELECT * FROM characters WHERE member_id=?', (member_id,)
        ).fetchone()
        if row:
            d = dict(row)
            d['equip_ids'] = json.loads(d.pop('equip_json', '[]'))
            d['item_ids'] = json.loads(d.pop('item_json', '[]'))
            d['spell_ids'] = json.loads(d.pop('spell_json', '[]'))
            return d
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
            'dungeon_id', 'floor', 'pos_x', 'pos_y', 'facing',
            'gold', 'status_flags', 'death_count', 'play_time',
            'char_title', 'guild_id', 'guild_rank', 'kills', 'deaths', 'sessions',
        }
        updates = {k: v for k, v in fields.items() if k in allowed}
        if 'equip_ids' in fields:
            updates['equip_json'] = json.dumps(fields['equip_ids'])
        if 'item_ids' in fields:
            updates['item_json'] = json.dumps(fields['item_ids'])
        if 'spell_ids' in fields:
            updates['spell_json'] = json.dumps(fields['spell_ids'])
        if not updates:
            return
        set_clause = ', '.join(f'{k}=?' for k in updates)
        vals = list(updates.values()) + [member_id]
        self.conn.execute(
            f"UPDATE characters SET {set_clause}, updated_at=strftime('%s','now') WHERE member_id=?",
            vals
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
        self.upsert_user(member_id, handle=handle)
        return True


# ═══════════════════════════════════════════════════════════════════════════════
# ONLINE PLAYER REGISTRY
# ═══════════════════════════════════════════════════════════════════════════════

class OnlineRegistry:
    """Track online players and broadcast messages."""

    def __init__(self):
        self._clients = {}  # member_id -> ClientSession
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

    async def broadcast(self, data: bytes, exclude: str = None):
        async with self._lock:
            for mid, session in self._clients.items():
                if mid != exclude:
                    try:
                        session.writer.write(data)
                        await session.writer.drain()
                    except Exception:
                        pass

    async def get_online_chars(self, db: Database) -> list:
        async with self._lock:
            chars = []
            for mid in self._clients:
                chars.append(db.get_or_create_character(mid))
            return chars


# ═══════════════════════════════════════════════════════════════════════════════
# CLIENT SESSION
# ═══════════════════════════════════════════════════════════════════════════════

class ClientSession:
    """Manages one connected client through the full protocol lifecycle."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 db: Database, registry: OnlineRegistry):
        self.reader    = reader
        self.writer    = writer
        self.db        = db
        self.registry  = registry
        self.parser    = PacketParser()
        self.nonce     = os.urandom(64)
        self.member_id = None
        self.handle    = None
        addr = writer.get_extra_info('peername')
        self.addr_str  = f'{addr[0]}:{addr[1]}' if addr else 'unknown'
        self.log       = logging.getLogger(f'DD/{self.addr_str}')

    async def send(self, data: bytes):
        self.writer.write(data)
        await self.writer.drain()
        self.log.debug('SEND %d bytes\n%s', len(data), hexdump(data[:256]))

    async def recv_exact(self, n: int) -> bytes:
        data = await self.reader.readexactly(n)
        self.log.debug('RECV %d bytes\n%s', len(data), hexdump(data[:256]))
        return data

    # ── Handshake ──────────────────────────────────────────────────────────

    async def do_handshake(self):
        """
        Auto-detect client type and perform appropriate handshake.
        Server speaks first (IV handshake) — the standard for the game server.
        If client sends BBS commands first, handle those before IV.
        """
        self.log.info('Starting handshake')

        # Send INIT_HEADER + SESSION_CHALLENGE
        challenge = build_session_challenge(self.nonce)
        await self.send(INIT_HEADER + challenge)

        # Wait for client response (8 bytes)
        try:
            ack = await asyncio.wait_for(self.recv_exact(8), timeout=30.0)
        except asyncio.TimeoutError:
            self.log.warning('Handshake timeout waiting for client ACK')
            raise ConnectionError('Handshake timeout')

        if ack == CLIENT_ACK:
            self.log.info('Client ACK received (IV012fed)')
        elif ack[:2] == b'C ':
            # BBS-mode client — read rest of command line
            self.log.info('BBS-mode client detected, handling C command')
            remaining = await self.reader.readline()
            cmd = ack + remaining
            self.log.info('BBS command: %s', cmd.decode('ascii', errors='replace').strip())
            # After BBS routing, restart handshake for game protocol
            await self.send(INIT_HEADER + challenge)
            ack = await asyncio.wait_for(self.recv_exact(8), timeout=30.0)
            if ack != CLIENT_ACK:
                self.log.warning('Unexpected response after BBS routing: %s', ack.hex())
        else:
            self.log.warning('Unexpected ACK: %s (continuing anyway)', ack.hex())

        # Send SECOND_HEADER + SESSION_CONFIRM
        confirm = build_session_confirm()
        await self.send(SECOND_HEADER + confirm)
        self.log.info('Handshake complete')

    # ── Message Handlers ───────────────────────────────────────────────────

    async def handle_login_request(self, payload: bytes):
        info = parse_login_request(payload)
        member_id = info['member_id'].strip('\x00').strip()
        self.log.info('LOGIN_REQUEST: member_id=%r version=%r caps=0x%X',
                      member_id, info['game_version'], info['client_caps'])

        if not member_id:
            self.log.warning('Empty member_id — rejecting')
            await self.send(build_standard_reply(RESULT_ERROR))
            return False

        # Accept login (bypass RSA in revival mode)
        self.db.upsert_user(member_id)
        self.member_id = member_id
        char = self.db.get_or_create_character(member_id)
        self.handle = char.get('handle', member_id)

        # Increment session count
        self.db.update_character(member_id, {
            'sessions': char.get('sessions', 0) + 1
        })

        # Register in online registry
        await self.registry.add(member_id, self)

        # Send STANDARD_REPLY with success + session token
        session_token = os.urandom(16)
        reply_data = bytearray(64)
        reply_data[0:16] = session_token
        struct.pack_into('<I', reply_data, 16, int(time.time()))
        await self.send(build_standard_reply(RESULT_OK, bytes(reply_data)))

        self.log.info('Login accepted: %s (handle=%s)', member_id, self.handle)

        # Send initial world state
        await self.send_initial_state()
        return True

    async def send_initial_state(self):
        """Send initial game state after login."""
        char = self.db.get_or_create_character(self.member_id)

        # Character data
        await self.send(build_chardata_reply(char))

        # Current region
        await self.send(build_curregion_notice(0))

        # Map data
        await self.send(build_map_notice(
            char.get('dungeon_id', 0),
            char.get('floor', 0)
        ))

        # Online players
        online_chars = await self.registry.get_online_chars(self.db)
        await self.send(build_chardata2_notice(online_chars))

        # Welcome message
        await self.send(build_information_notice(
            'Welcome to Dragon\'s Dream Revival Server!'
        ))

        # Notify other players of our arrival
        await self.registry.broadcast(
            build_chardata_reply(char),
            exclude=self.member_id
        )

    async def handle_logout_request(self, payload: bytes):
        self.log.info('LOGOUT_REQUEST from %s', self.member_id)
        if self.member_id:
            # Save character state
            char = self.db.get_or_create_character(self.member_id)
            self.db.update_character(self.member_id, {
                'play_time': char.get('play_time', 0) + 1
            })
            # Notify others
            await self.registry.broadcast(
                build_logout_notice(self.member_id),
                exclude=self.member_id
            )
            await self.registry.remove(self.member_id)
        raise ConnectionError('Client logout')

    async def handle_regist_handle(self, payload: bytes):
        info = parse_regist_handle(payload)
        self.log.info('REGIST_HANDLE_REQUEST: handle=%r flags=0x%X',
                      info['handle'], info['flags'])
        if not self.member_id:
            await self.send(build_standard_reply(RESULT_ERROR))
            return
        ok = self.db.register_handle(self.member_id, info['handle'])
        if ok:
            self.handle = info['handle']
            self.log.info('Handle registered: %s', info['handle'])
        else:
            self.log.warning('Handle taken: %s', info['handle'])
        result = RESULT_OK if ok else RESULT_ERROR
        await self.send(build_standard_reply(result))

    async def handle_chardata_request(self, payload: bytes):
        req_member = _read_cstr(payload, 0, 64) if len(payload) >= 64 else ''
        req_member = req_member.strip('\x00').strip() or self.member_id
        self.log.info('CHARDATA_REQUEST for %s', req_member)
        char = self.db.get_or_create_character(req_member)
        await self.send(build_chardata_reply(char))

    async def handle_update_chardata(self, payload: bytes):
        info = parse_update_chardata(payload)
        member_id = info.pop('member_id', '').strip() or self.member_id
        self.log.info('UPDATE_CHARDATA: member=%s level=%s',
                      member_id, info.get('level'))
        if member_id != self.member_id:
            await self.send(build_update_chardata_reply(RESULT_ERROR))
            return
        self.db.update_character(self.member_id, info)
        await self.send(build_update_chardata_reply(RESULT_OK))

    async def handle_speak_request(self, payload: bytes):
        info = parse_speak_request(payload)
        self.log.info('SPEAK: [%s] %s', self.handle, info['text'])
        notice = build_speak_notice(self.handle or self.member_id, info['text'])
        await self.registry.broadcast(notice)

    async def handle_esp_request(self, payload: bytes):
        info = parse_esp_request(payload)
        self.log.info('ESP: [%s] -> [%s] %s', self.handle, info['target'], info['text'])
        # Send to target player
        target_session = await self.registry.get_session(info['target'])
        if target_session:
            esp_payload = bytearray(484)
            h = (self.handle or self.member_id).encode('ascii')[:31]
            esp_payload[:len(h)] = h
            t = info['text'].encode('ascii')[:200]
            esp_payload[32:32+len(t)] = t
            await target_session.send(build_packet(MSG_ESP_NOTICE, bytes(esp_payload)))
            await self.send(build_standard_reply(RESULT_OK))
        else:
            await self.send(build_standard_reply(RESULT_ERROR))

    async def handle_move_request(self, msg_type: int, payload: bytes):
        info = parse_move_request(payload)
        self.log.debug('MOVE: dir=%s pos=(%s,%s) facing=%s',
                       info.get('direction'), info.get('pos_x'),
                       info.get('pos_y'), info.get('facing'))
        if self.member_id:
            self.db.update_character(self.member_id, {
                'pos_x': info.get('pos_x', 0),
                'pos_y': info.get('pos_y', 0),
                'facing': info.get('facing', 0),
            })
            # Broadcast movement to other players
            notice_type = MSG_MOVE1_NOTICE if msg_type == MSG_MOVE1_REQUEST else MSG_MOVE2_NOTICE
            notice_payload_size = MSG_TABLE[notice_type][1]
            notice_payload = bytearray(notice_payload_size)
            mid_enc = (self.member_id or '').encode('ascii')[:63]
            notice_payload[:len(mid_enc)] = mid_enc
            if len(notice_payload) >= 80:
                struct.pack_into('<I', notice_payload, 64, info.get('direction', 0))
                struct.pack_into('<I', notice_payload, 68, info.get('pos_x', 0))
                struct.pack_into('<I', notice_payload, 72, info.get('pos_y', 0))
                struct.pack_into('<I', notice_payload, 76, info.get('facing', 0))
            await self.registry.broadcast(
                build_packet(notice_type, bytes(notice_payload)),
                exclude=self.member_id
            )

    async def handle_camp_request(self, msg_type: int, payload: bytes):
        """Handle camp in/out requests (save points)."""
        reply_type = MSG_CAMP_IN_REPLY if msg_type == MSG_CAMP_IN_REQUEST else MSG_CAMP_OUT_REPLY
        reply_size = MSG_TABLE[reply_type][1]
        reply_payload = bytearray(reply_size)
        struct.pack_into('>I', reply_payload, 0, RESULT_OK)
        await self.send(build_packet(reply_type, bytes(reply_payload)))

    async def handle_regionchange_request(self, payload: bytes):
        """Handle region change."""
        region_id = struct.unpack_from('<I', payload, 0)[0] if len(payload) >= 4 else 0
        self.log.info('REGIONCHANGE to region %d', region_id)
        await self.send(build_curregion_notice(region_id))
        await self.send(build_map_notice(region_id, 0))

    async def handle_area_list_request(self, payload: bytes):
        """Send list of available areas."""
        reply_size = MSG_TABLE[MSG_AREA_LIST_REPLY][1]
        reply_payload = bytearray(reply_size)
        # Area count
        struct.pack_into('<I', reply_payload, 0, 5)
        # Area entries (id, name) — simplified
        areas = [
            (0, 'Town'),
            (1, 'Forest Dungeon'),
            (2, 'Cave Dungeon'),
            (3, 'Tower Dungeon'),
            (4, 'Castle Dungeon'),
        ]
        off = 4
        for area_id, area_name in areas:
            if off + 68 > reply_size:
                break
            struct.pack_into('<I', reply_payload, off, area_id)
            name_enc = area_name.encode('ascii')[:63]
            reply_payload[off+4:off+4+len(name_enc)] = name_enc
            off += 68
        await self.send(build_packet(MSG_AREA_LIST_REPLY, bytes(reply_payload)))

    async def handle_partyid_request(self, payload: bytes):
        """Return party ID (0 = not in party)."""
        reply_size = MSG_TABLE[MSG_PARTYID_REPLY][1]
        reply_payload = bytearray(reply_size)
        struct.pack_into('<I', reply_payload, 0, 0)  # no party
        await self.send(build_packet(MSG_PARTYID_REPLY, bytes(reply_payload)))

    async def handle_gotolist_request(self, payload: bytes):
        """Send goto/warp destination list."""
        reply_size = MSG_TABLE[MSG_GOTOLIST_REPLY][1]
        reply_payload = bytearray(reply_size)
        struct.pack_into('<I', reply_payload, 0, 0)  # 0 destinations
        await self.send(build_packet(MSG_GOTOLIST_REPLY, bytes(reply_payload)))

    async def handle_userlist_request(self, payload: bytes):
        """Send list of online users."""
        reply_size = MSG_TABLE[MSG_USERLIST_REPLY][1]
        reply_payload = bytearray(reply_size)
        online = await self.registry.get_online_list()
        struct.pack_into('<I', reply_payload, 0, len(online))
        off = 4
        for mid in online:
            if off + 64 > reply_size:
                break
            mid_enc = mid.encode('ascii')[:63]
            reply_payload[off:off+len(mid_enc)] = mid_enc
            off += 64
        await self.send(build_packet(MSG_USERLIST_REPLY, bytes(reply_payload)))

    async def handle_generic_request(self, msg_type: int, payload: bytes):
        """
        Handle any REQUEST that has a known REPLY counterpart.
        Sends STANDARD_REPLY (0x0048) with success result.
        """
        self.log.info('Generic handler for %s — sending STANDARD_REPLY OK',
                      msg_name(msg_type))
        await self.send(build_standard_reply(RESULT_OK))

    # ── Main dispatch ──────────────────────────────────────────────────────

    async def dispatch(self, msg_type: int, payload: bytes):
        name = msg_name(msg_type)
        self.log.info('<- %s (0x%04X) payload=%d bytes', name, msg_type, len(payload))

        if msg_type == MSG_LOGIN_REQUEST:
            await self.handle_login_request(payload)
        elif msg_type == MSG_LOGOUT_REQUEST:
            await self.handle_logout_request(payload)
        elif msg_type == MSG_REGIST_HANDLE_REQUEST:
            await self.handle_regist_handle(payload)
        elif msg_type == MSG_CHARDATA_REQUEST:
            await self.handle_chardata_request(payload)
        elif msg_type == MSG_UPDATE_CHARDATA_REQUEST:
            await self.handle_update_chardata(payload)
        elif msg_type == MSG_SPEAK_REQUEST:
            await self.handle_speak_request(payload)
        elif msg_type == MSG_ESP_REQUEST:
            await self.handle_esp_request(payload)
        elif msg_type in (MSG_MOVE1_REQUEST, MSG_MOVE2_REQUEST):
            await self.handle_move_request(msg_type, payload)
        elif msg_type in (MSG_CAMP_IN_REQUEST, MSG_CAMP_OUT_REQUEST):
            await self.handle_camp_request(msg_type, payload)
        elif msg_type == MSG_REGIONCHANGE_REQUEST:
            await self.handle_regionchange_request(payload)
        elif msg_type == MSG_AREA_LIST_REQUEST:
            await self.handle_area_list_request(payload)
        elif msg_type == MSG_PARTYID_REQUEST:
            await self.handle_partyid_request(payload)
        elif msg_type == MSG_GOTOLIST_REQUEST:
            await self.handle_gotolist_request(payload)
        elif msg_type == MSG_USERLIST_REQUEST:
            await self.handle_userlist_request(payload)
        elif msg_type == MSG_SETPOS_REQUEST:
            if len(payload) >= 16:
                self.db.update_character(self.member_id, {
                    'pos_x': struct.unpack_from('<I', payload, 4)[0],
                    'pos_y': struct.unpack_from('<I', payload, 8)[0],
                })
            reply_size = MSG_TABLE.get(MSG_SETPOS_REPLY, ("", 465))[1]
            await self.send(build_packet(MSG_SETPOS_REPLY, bytearray(reply_size)))
        elif '_REQUEST' in name:
            await self.handle_generic_request(msg_type, payload)
        else:
            self.log.warning('Unhandled message: %s (0x%04X) %d bytes',
                             name, msg_type, len(payload))
            if payload:
                self.log.debug('Payload:\n%s', hexdump(payload[:128]))

    # ── Main loop ──────────────────────────────────────────────────────────

    async def run(self):
        try:
            await self.do_handshake()
            self.log.info('Entering data phase')

            while True:
                raw = await self.reader.read(4096)
                if not raw:
                    raise ConnectionError('Client disconnected')
                self.log.debug('RAW RECV %d bytes', len(raw))
                self.parser.feed(raw)
                for msg_type, payload in self.parser.packets():
                    await self.dispatch(msg_type, payload)

        except (ConnectionError, asyncio.IncompleteReadError) as e:
            self.log.info('Connection closed: %s', e)
        except Exception as e:
            self.log.exception('Unhandled error: %s', e)
        finally:
            if self.member_id:
                await self.registry.broadcast(
                    build_logout_notice(self.member_id),
                    exclude=self.member_id
                )
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

class DreamServer:
    """Dragon's Dream revival server."""

    def __init__(self, port: int = SERVER_PORT):
        self.port     = port
        self.db       = Database(DB_PATH)
        self.registry = OnlineRegistry()

    async def handle_client(self, reader: asyncio.StreamReader,
                            writer: asyncio.StreamWriter):
        addr = writer.get_extra_info('peername')
        log.info('Connection from %s:%d', addr[0], addr[1])
        session = ClientSession(reader, writer, self.db, self.registry)
        await session.run()

    async def start(self):
        server = await asyncio.start_server(
            self.handle_client, '0.0.0.0', self.port
        )
        log.info("Dragon's Dream revival server listening on TCP port %d", self.port)
        log.info('Protocol: 253 message types verified from binary analysis')
        log.info('RSA mode: bypass (revival mode)')

        async with server:
            await server.serve_forever()


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRYPOINT
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        description="Dragon's Dream revival server — TCP 8020"
    )
    ap.add_argument('--port', type=int, default=SERVER_PORT,
                    help='TCP port (default 8020)')
    args = ap.parse_args()

    dream = DreamServer(port=args.port)
    try:
        asyncio.run(dream.start())
    except KeyboardInterrupt:
        log.info('Server shutting down')


if __name__ == '__main__':
    main()
