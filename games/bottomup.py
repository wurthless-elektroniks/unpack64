'''
Bottom Up, Japan's finest purveyor of Japanese N64 shovelware
'''

import logging

from bffi import BffiBuilder, Bffi
from n64rom import N64Rom
from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi
from signature import SignatureBuilder, WILDCARD

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------------
#
# 64 Oozumo
#
# This game calls osPiStartDma() directly to load its segments.
# The call pattern should be the same every time.
#
# --------------------------------------------------------------------------------

OSPISTARTDMA_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xd8,         # addiu      sp,sp,-0x28
        0x3c, 0x0e, 0x80, WILDCARD,     # lui        t6,0x8003
        0x8d, 0xce, WILDCARD, WILDCARD, # lw         t6,-0x7690(t6)=>DAT_80028970
        0xaf, 0xbf, 0x00, 0x1c,         # sw         ra,local_c(sp)
        0xaf, 0xa4, 0x00, 0x28,         # sw         a0,local_res0(sp)
        0xaf, 0xa5, 0x00, 0x2c,         # sw         a1,local_res4(sp)
        0xaf, 0xa6, 0x00, 0x30,         # sw         a2,local_res8(sp)
        0xaf, 0xa7, 0x00, 0x34,         # sw         a3,local_resc(sp)
        0xaf, 0xb1, 0x00, 0x18,         # sw         s1,local_10(sp)
        0x15, 0xc0, 0x00, 0x03,         # bne        t6,zero,LAB_8000da34
        0xaf, 0xb0, 0x00, 0x14,         # _sw        s0,local_14(sp)
        0x10, 0x00, 0x00, 0x32,         # b          LAB_8000daf8
        0x24, 0x02, 0xff, 0xff,         # _li        v0,-0x1
        0x8f, 0xaf, 0x00, 0x30,         # lw         t7,local_res8(sp)
        0x15, 0xe0, 0x00, 0x05,         # bne        t7,zero,LAB_8000da50
        0x00, 0x00, 0x00, 0x00,         # _nop
        0x8f, 0xb9, 0x00, 0x28,         # lw         t9,local_res0(sp)
        0x24, 0x18, 0x00, 0x0b,         # li         t8,0xb
        0x10, 0x00, 0x00, 0x04,         # b          LAB_8000da5c
        0xa7, 0x38, 0x00, 0x00,         # _sh        t8,0x0(t9)
    ]) \
    .build()

PISTARTDMA_CALL_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x08, WILDCARD, WILDCARD,     # +0x00 lui        t0,0x24
        0x3c, 0x0a, WILDCARD, WILDCARD,     # +0x04 lui        t2,0x28
        0x25, 0x4a, WILDCARD, WILDCARD,     # +0x08 addiu      t2,t2,0x23e0   <-- ROM start address
        0x25, 0x08, WILDCARD, WILDCARD,     # +0x0C addiu      t0,t0,0x27a0   <-- ROM end address
        0x3c, 0x09, 0x80, WILDCARD,         # +0x10 lui        t1,0x800b
        0x3c, 0x0c, 0x80, WILDCARD,         # +0x14 lui        t4,0x8003      <-- PI message queue
        0x25, 0x8c, WILDCARD, WILDCARD,     # +0x18 addiu      t4,t4,0x2000
        0x25, 0x29, WILDCARD, WILDCARD,     # +0x1C addiu      t1,t1,0x2400   <-- RAM destination address
        0x00, WILDCARD, WILDCARD, 0x23,     # +0x20 subu       t3,t2,t0
        0xac, WILDCARD, 0x00, 0x14,         # +0x24 sw         t3,0x14(sp)
        0xac, WILDCARD, 0x00, 0x10,         # +0x28 sw         t1,0x10(sp)
        0xac, WILDCARD, 0x00, 0x18,         # +0x2C sw         t4,0x14(sp)
        0x01, 0x00, 0x38, 0x25,             # +0x30 or         a3,t0,zero
        0x27, 0xa4, WILDCARD, WILDCARD,     # +0x34 addiu      a0,sp,0x30
        0x00, 0x00, 0x28, 0x25,             # +0x38 or         a1,zero,zero
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x3C jal        osPiStartDma
        0x00, 0x00, 0x30, 0x25,             # +0x40 _or        a2,zero,zero
    ]) \
    .modify_andmask(0x00, bytes([0b11111100, 0x00])) \
    .modify_andmask(0x04, bytes([0b11111100, 0x00])) \
    .modify_andmask(0x08, bytes([0b11111100, 0x00])) \
    .modify_andmask(0x0C, bytes([0b11111100, 0x00])) \
    .modify_andmask(0x10, bytes([0b11111100, 0x00])) \
    .modify_andmask(0x14, bytes([0b11111100, 0x00])) \
    .modify_andmask(0x18, bytes([0b11111100, 0x00])) \
    .modify_andmask(0x1C, bytes([0b11111100, 0x00])) \
    .modify_andmask(0x20, bytes([0b11111100, 0x00, 0x00, 0b00111111])) \
    .modify_andmask(0x24, bytes([0b11111100, 0x00])) \
    .modify_andmask(0x28, bytes([0b11111100, 0x00])) \
    .modify_andmask(0x2C, bytes([0b11111100, 0x00])) \
    .modify_andmask(0x30, bytes([0b11111100, 0b00011111, 0x00, 0b00111111])) \
    .const_op32_hi16("rom_start_address", 0x00) \
    .const_op32_hi16("rom_end_address", 0x04) \
    .const_op32_lo16("rom_end_address", 0x08) \
    .const_op32_lo16("rom_start_address", 0x0C) \
    .const_op32_hi16("ram_destination_address", 0x10) \
    .const_op32_hi16("pi_mesg_queue", 0x14) \
    .const_op32_lo16("pi_mesg_queue", 0x18) \
    .const_op32_lo16("ram_destination_address", 0x1C) \
    .xref_j_imm26("osPiStartDma_address", 0x3C) \
    .build()


def sumo_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    builder = BffiBuilder()
    earliest_bss_address, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)

    bootexe = rom.boot_exe()[:earliest_bss_address-ipc]

    ospistartdma_offset = None
    ospistartdma_offset = OSPISTARTDMA_PATTERN.find(bootexe)

    if ospistartdma_offset is None:
        return None
    
    ospistartdma_address = ipc + ospistartdma_offset
    logger.info("found osPiStartDma() at 0x%08x, scanning for calls to it...", ospistartdma_address)

    offset = 0
    ripped = []
    while True:
        offset = PISTARTDMA_CALL_PATTERN.find(bootexe, offset)
        if offset is None:
            break

        xrefs = PISTARTDMA_CALL_PATTERN.xrefs(ipc, bootexe, offset)
        if xrefs["osPiStartDma_address"].get_address() != ospistartdma_address:
            continue

        consts = PISTARTDMA_CALL_PATTERN.consts(ipc, bootexe, offset)

        offset += 4

        rom_start_address       = consts["rom_start_address"].get_value()
        rom_end_address         = consts["rom_end_address"].get_value()
        ram_destination_address = consts["ram_destination_address"].get_value()
        pi_mesg_queue           = consts["pi_mesg_queue"].get_value()

        if (rom_start_address, rom_end_address, ram_destination_address) in ripped:
            logger.info("segment already loaded: in ROM 0x%08x~0x%08x -> 0x%08x",
            rom_start_address,
            rom_end_address,
            ram_destination_address)
            continue
        
        ripped.append( (rom_start_address, rom_end_address, ram_destination_address) )

        logger.info("new segment found: ROM 0x%08x~0x%08x -> 0x%08x",
            rom_start_address,
            rom_end_address,
            ram_destination_address)
        
        segment = rom.read_bytes(rom_start_address, rom_end_address-rom_start_address)
        builder.seg(ram_destination_address, segment)
    
    builder.fix(ipc, bootexe)
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    return builder.build()


# --------------------------------------------------------------------------------
#
# 64 Trump Collection - Alice no Wakuwaku Trump World
#
# Alice in Wonderland and playing cards... Very inspired!!!
#
# As with 64 Oozumo it loads segments in with osPiStartDma(), but through a wrapper
# function this time. To make things more annoying, n64sym choked on this one and
# it couldn't find osPiStartDma().
#
# Same routine used on 64 Oozumo 2 and Onegai Monsters
#
# --------------------------------------------------------------------------------

# takes parameters: a0 = rom address, a1 = ram address, a2 = sizeof
ALICE_READ_CART_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0x98,     #addiu      sp,sp,-0x68
        0xaf, 0xb5, 0x00, 0x5c,     #sw         s5,local_c(sp)
        0x00, 0x80, 0xa8, 0x21,     #move       s5,a0
        0xaf, 0xb2, 0x00, 0x50,     #sw         s2,local_18(sp)
        0x00, 0xa0, 0x90, 0x21,     #move       s2,a1
        0xaf, 0xb4, 0x00, 0x58,     #sw         s4,local_10(sp)
        0x00, 0xc0, 0xa0, 0x21,     #move       s4,a2
        0xaf, 0xbf, 0x00, 0x60,     #sw         ra,local_8(sp)
        0xaf, 0xb3, 0x00, 0x54,     #sw         s3,local_14(sp)
        0xaf, 0xb1, 0x00, 0x4c,     #sw         s1,local_1c(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD,     #jal        FUN_800edb40
        0xaf, 0xb0, 0x00, 0x48,     #_sw        s0,local_20(sp)
        0x27, 0xb0, 0x00, 0x28,     #addiu      s0,sp,0x28
        0x02, 0x00, 0x20, 0x21,     #move       a0,s0
        0x27, 0xb3, 0x00, 0x40,     #addiu      s3,sp,0x40
        0x02, 0x60, 0x28, 0x21,     #move       a1,s3
        0x24, 0x06, 0x00, 0x01,     #li         a2,0x1
        0x0c, WILDCARD, WILDCARD, WILDCARD,     #jal        osCreateMesgQueue
        0x00, 0x40, 0x88, 0x21,     #_move      s1,v0
        0x02, 0x40, 0x20, 0x21,     #move       a0,s2
        0x0c, WILDCARD, WILDCARD, WILDCARD,     #jal        osInvaliDCache
        0x02, 0x80, 0x28, 0x21,     #_move      a1,s4
        0x02, 0x20, 0x20, 0x21,     #move       a0,s1
        0x27, 0xa5, 0x00, 0x10,     #addiu      a1,sp,0x10
        0x00, 0x00, 0x30, 0x21,     #clear      a2
        0xa3, 0xa0, 0x00, 0x12,     #sb         zero,local_56(sp)
        0xaf, 0xb0, 0x00, 0x14,     #sw         s0,local_54(sp)
        0xaf, 0xb2, 0x00, 0x18,     #sw         s2,local_50(sp)
        0xaf, 0xb5, 0x00, 0x1c,     #sw         s5,local_4c(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD,     #jal        osPiStartDma?
        0xaf, 0xb4, 0x00, 0x20,     #_sw        s4,local_48(sp)
        0x02, 0x00, 0x20, 0x21,     #move       a0,s0
        0x02, 0x60, 0x28, 0x21,     #move       a1,s3
        0x0c, WILDCARD, WILDCARD, WILDCARD,     #jal        osRecvMesg
        0x24, 0x06, 0x00, 0x01,     #_li        a2,0x1
        0x8f, 0xbf, 0x00, 0x60,     #lw         ra,local_8(sp)
        0x8f, 0xb5, 0x00, 0x5c,     #lw         s5,local_c(sp)
        0x8f, 0xb4, 0x00, 0x58,     #lw         s4,local_10(sp)
        0x8f, 0xb3, 0x00, 0x54,     #lw         s3,local_14(sp)
        0x8f, 0xb2, 0x00, 0x50,     #lw         s2,local_18(sp)
        0x8f, 0xb1, 0x00, 0x4c,     #lw         s1,local_1c(sp)
        0x8f, 0xb0, 0x00, 0x48,     #lw         s0,local_20(sp)
        0x03, 0xe0, 0x00, 0x08,     #jr         ra
    ]) \
    .build()

# ReadCart() calls are the same on Alice and Oozumo 2
ALICE_CALL_READ_CART_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x02, WILDCARD, WILDCARD,     # +0x00 lui   v0,0x1f
        0x24, 0x42, WILDCARD, WILDCARD,     # +0x04 addiu v0,v0,
        0x3c, 0x03, WILDCARD, WILDCARD,     # +0x08 lui   v1,0x1e
        0x24, 0x63, WILDCARD, WILDCARD,     # +0x0C addiu v1,v1,-0x49b0
        0x00, 0x43, 0x10, 0x23,             # +0x10 subu  v0,v0,v1
        0x3c, 0x04, WILDCARD, WILDCARD,     # +0x14 lui   a0,0x1e
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x18 addiu a0,a0,-0x49b0
        0x3c, 0x05, 0x80, WILDCARD,         # +0x1C lui   a1,0x8018
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x20 addiu a1,a1,0x1cf0
        0x00, 0x40, 0x30, 0x21,             # +0x24 move  a2,v0
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x28 jal   ReadCart
        0x00, 0x00, 0x00, 0x00,             # +0x2C _nop
    ]) \
    .const_op32_hi16("rom_end_address", 0x00) \
    .const_op32_lo16("rom_end_address", 0x04) \
    .const_op32_hi16("rom_start_address", 0x08) \
    .const_op32_lo16("rom_start_address", 0x0C) \
    .const_op32_hi16("ram_destination_address", 0x1C) \
    .const_op32_lo16("ram_destination_address", 0x20) \
    .xref_j_imm26("readcart_address", 0x28) \
    .build()

# Onegai Monsters can load its segments in chunks so as to not hold up the PI bus.
# this must have been a C macro that got out of hand because they repeat this
# load loop a million times
ONEGAI_CALL_READ_CART_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x10, 0x80, WILDCARD,         # +0x00 lui        s0,0x8020      <-- RAM destination address
        0x26, 0x10, WILDCARD, WILDCARD,     # +0x04 addiu      s0,s0,-0x3280
        0x02, 0x00, 0x20, 0x21,             # +0x08 move       a0,s0
        0x3c, 0x11, WILDCARD, WILDCARD,     # +0x0C lui        s1,0x17        <-- ROM end address
        0x26, 0x31, WILDCARD, WILDCARD,     # +0x10 addiu      s1,s1,0x5bf0
        0x3c, 0x12, WILDCARD, WILDCARD,     # +0x14 lui        s2,0x17        <-- ROM start address
        0x26, 0x52, WILDCARD, WILDCARD,     # +0x18 addiu      s2,s2,0x4380
        0x02, 0x32, 0x88, 0x23,             # +0x1C subu       s1,s1,s2
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x20 jal  osInvalICache
        0x02, 0x20, 0x28, 0x21,             # +0x24 _move      a1,s1
        0x12, 0x20, 0x00, 0x11,             # +0x28 beq        s1,zero,LAB_801015ac
        0x02, 0xb1, 0x10, 0x2b,             # +0x2C _sltu      v0,s5,s1
        0x14, 0x40, 0x00, 0x06,             # +0x30 bne        v0,zero,LAB_80101588
        0x02, 0x40, 0x20, 0x21,             # +0x34 _move      a0,s2
        0x02, 0x00, 0x28, 0x21,             # +0x38 move       a1,s0
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x3C jal        ReadCart
    ]) \
    .const_op32_hi16("ram_destination_address", 0x00) \
    .const_op32_lo16("ram_destination_address", 0x04) \
    .const_op32_hi16("rom_end_address", 0x0C) \
    .const_op32_lo16("rom_end_address", 0x10) \
    .const_op32_hi16("rom_start_address", 0x14) \
    .const_op32_lo16("rom_start_address", 0x18) \
    .xref_j_imm26("readcart_address", 0x3C) \
    .build()

def _bottomup_unpack_common(rom: N64Rom,
                            ipc: int,
                            readcart_call_pattern) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    builder = BffiBuilder()
    earliest_bss_address, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)

    bootexe = rom.boot_exe()[:earliest_bss_address-ipc]

    readcart_offset = ALICE_READ_CART_PATTERN.find(bootexe)
    if readcart_offset is None:
        return None
    
    readcart_address = readcart_offset + ipc
    logger.info("found Bottom Up readcart routine at 0x%08x", readcart_address)

    offset = 0
    ripped = []
    while True:
        offset = readcart_call_pattern.find(bootexe, offset)
        if offset is None:
            break

        xrefs = readcart_call_pattern.xrefs(ipc, bootexe, offset)
        if xrefs["readcart_address"].get_address() != readcart_address:
            offset += 4
            continue

        consts = readcart_call_pattern.consts(ipc, bootexe, offset)

        offset += 4

        rom_start_address       = consts["rom_start_address"].get_value()
        rom_end_address         = consts["rom_end_address"].get_value()
        ram_destination_address = consts["ram_destination_address"].get_value()

        if (rom_start_address, rom_end_address, ram_destination_address) in ripped:
            logger.info("segment already loaded: in ROM 0x%08x~0x%08x -> 0x%08x",
            rom_start_address,
            rom_end_address,
            ram_destination_address)
            continue
        
        ripped.append( (rom_start_address, rom_end_address, ram_destination_address) )

        logger.info("new segment found: ROM 0x%08x~0x%08x -> 0x%08x",
            rom_start_address,
            rom_end_address,
            ram_destination_address)
        
        segment = rom.read_bytes(rom_start_address, rom_end_address-rom_start_address)
        builder.seg(ram_destination_address, segment)
    
    builder.fix(ipc, bootexe)
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    return builder.build()

def alice_unpack(rom: N64Rom, ipc: int) -> Bffi:
    return _bottomup_unpack_common(rom, ipc, ALICE_CALL_READ_CART_PATTERN)

def onegai_unpack(rom: N64Rom, ipc: int) -> Bffi:
    return _bottomup_unpack_common(rom, ipc, ONEGAI_CALL_READ_CART_PATTERN)
