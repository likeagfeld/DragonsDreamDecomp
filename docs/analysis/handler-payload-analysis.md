# Handler Payload Analysis — All 197 Handlers

## Binary: `D:\DragonsDreamDecomp\extracted\0.BIN` (504,120 bytes, SH-2 big-endian)
## Wire format: 8-byte header [2B param1][2B msg_type][4B payload_size] + payload
## Payload size = msg_type - 8
## Date: 2026-03-11

---

## SCMD Library Functions (confirmed)

| Address (mem) | Address (file) | Function | Description |
|---------------|----------------|----------|-------------|
| 0x060249EC | 0x149EC | scmd_new_message | Init msg buffer: buffer[0:2]=param1, buffer[2:4]=msg_type, buffer[4:8]=0, nMsgSize=0 |
| 0x06024A32 | 0x14A32 | scmd_add_byte | Add 1 byte at buffer[8+nMsgSize], assert nMsgSize+1 < 4800 |
| 0x06024B04 | 0x14B04 | scmd_add_word | Add 2 bytes (uint16 BE) at buffer[8+nMsgSize], assert nMsgSize+2 < 4800 |
| 0x06024BDC | 0x14BDC | scmd_add_long | Add 4 bytes (uint32 BE) at buffer[8+nMsgSize], assert nMsgSize+4 < 4800 |
| 0x06024CD0 | 0x14CD0 | scmd_add_data | Add N bytes from ptr at buffer[8+nMsgSize], assert nMsgSize+N < 4800 |
| 0x06024E3C | 0x14E3C | scmd_send | Set buffer[4:8]=nMsgSize, send buffer with size=nMsgSize+8 |

Buffer base: 0x202E6148 (Work RAM-L, cache-through)
nMsgSize global: 0x06062498

## Helper Functions (receive side)

| Address (mem) | Address (file) | Function | Description |
|---------------|----------------|----------|-------------|
| 0x06019FF6 | 0x09FF6 | read_u16_be | Reads 2B BE from src to dest, returns src+2 |
| 0x06019FD2 | 0x09FD2 | read_u32_be | Reads 4B BE from src to dest, returns src+4 |
| 0x0603FE68 | 0x3FE68 | memcpy_16 | Copies r6 bytes from r5 to r4 (typically 16B chunks) |

---

## Handler Categories

### EMPTY Handlers (rts only — 22 handlers)
These do absolutely nothing with the payload. Server can send any data (or zeros).

| msg_type | Name | Payload Size |
|----------|------|-------------|
| 0x01B9 | CURREGION_NOTICE | 433 |
| 0x01A1 | USERLIST_REQUEST | 409 |
| 0x021C | USERLIST_REPLY | 532 |
| 0x021E | SAKAYA_STAND_REPLY | 534 |
| 0x0252 | SET_SEKIBAN_REPLY | 586 |
| 0x0253 | SET_SEKIBAN_NOTICE | 587 |
| 0x0249 | EVENT_MAP_NOTICE | 577 |
| 0x024A | MONSTER_MAP_NOTICE | 578 |
| 0x01DB | VISION_NOTICE | 467 |
| 0x01DC | OBITUARY_NOTICE | 468 |
| 0x0263 | EQUIP_REPLY | 603 |
| 0x026E | DISARM_REPLY | 614 |
| 0x0220 | BTL_MEMBER_NOTICE | 536 |
| 0x0225 | BTL_CHGMODE_REQUEST | 541 |
| 0x0228 | BTL_END_NOTICE | 544 |
| 0x0229 | BTL_MASK_NOTICE | 545 |
| 0x0297 | BTL_EFFECTEND_REQUEST | 655 |
| 0x0236 | BTLJOIN_REQUEST | 558 |
| 0x0237 | BTLJOIN_REPLY | 559 |
| 0x02EC | COLO_CANCEL_REPLY | 740 |

### Complex Handlers (sorted by read complexity)

| msg_type | Name | Payload | Reads |
|----------|------|---------|-------|
| 0x02D2 | CHARDATA_REPLY | 714B | 19B + 4xU16 + 2xU32 + 1xMEMCPY |
| 0x0227 | BTL_RESULT_NOTICE | 543B | 14B + 11xU16 + 1xU32 + 1xMEMCPY |
| 0x01E8 | ESP_NOTICE | 480B | 10B + 3xU16 + 1xU32 + 2xMEMCPY |
| 0x0295 | GIVE_ITEM_REPLY | 653B | 10B + 5xU16 + 3xU32 + 2xMEMCPY |
| 0x0226 | BTL_CHGMODE_REPLY | 542B | 1B + 7xU16 + 4xU32 |
| 0x02EE | COMPOUND_REQUEST | 742B | 8B + 1xMEMCPY |
| 0x02AC | GET_MAIL_REQUEST | 676B | 7B + 1xMEMCPY |
| 0x01C8 | BTL_GOLD_NOTICE | 448B | 6B + 3xU16 + 2xU32 + 1xMEMCPY |
| 0x01C5 | MOVE2_REQUEST | 445B | 5B + 1xU16 + 1xU32 |
| 0x02F9 | CHARDATA_REQUEST | 753B | 4B + 4xU16 + 3xU32 + 2xMEMCPY |
| 0x01C0 | CLASS_CHANGE_REPLY | 440B | 11B + 2xU16 + 1xU32 + 1xMEMCPY |

### Send Functions (client builds these — 13 call sites)

| Literal Pool | Call Site | msg_type | Name |
|-------------|-----------|----------|------|
| 0x12C94 | 0x12BE4 | 0x0035 | (unknown/internal) |
| 0x12C94 | 0x12C40 | 0x019E | LOGIN_REQUEST |
| 0x12E48 | 0x12DF4 | 0x0010 | (internal control) |
| 0x12F54 | 0x12F18 | 0x02D4 | CMD_BLOCK_REPLY |
| 0x13064 | 0x12F80 | 0x02DB | CAST_DICE_NOTICE |
| 0x131C0 | 0x13184 | 0x01B7 | REGIONCHANGE_REQUEST |
| 0x13314 | 0x13298 | 0x0010 | (internal control) |
| 0x13464 | 0x13434 | 0x0254 | SET_SIGN_NOTICE |
| 0x135D0 | 0x1358C | 0x0200 | SHOP_SELL_REPLY |
| 0x1372C | 0x13640 | 0x02A1 | SUBDIR_REPLY |
| 0x1372C | 0x13690 | 0x02A3 | MEMODIR_REPLY |
| 0x1389C | 0x13874 | 0x01A4 | PARTYLIST_REPLY |
| 0x13A08 | 0x1396C | 0x0014 | (internal control) |
| 0x13B74 | 0x13B14 | 0x01AC | MAP_CHANGE_NOTICE |
| 0x13CB0 | 0x13B8C | 0x02F7 | SET_MOVEMODE_NOTICE |

NOTE: Many of these are REPLY/NOTICE messages built by the CLIENT code.
This suggests the client contains dual-mode code (can act as both client and server,
or handles local BBS operations like bulletin boards).

---

## LOGIN_REQUEST Build Code (file 0x12C3C)

Function takes r4=data_ptr, r5=byte_value:

```
scmd_new_message(param1=SV_context[0x0264], msg_type=0x019E)
scmd_add_word(0)                        // 2B: always 0
scmd_add_word(byte_value)               // 2B: the function's r5 arg (zero-extended)
scmd_add_data(data_ptr+4, 16)           // 16B: data from offset 4
scmd_add_byte(data_ptr[21])             // 1B: field from data[21]
scmd_add_byte(data_ptr[23])             // 1B: field from data[23]
// conditional on data[24] value...
// many more fields follow (total payload = 406 bytes)
```

---

## Full Handler Read Pattern Table

(See automated scan output for complete results)
