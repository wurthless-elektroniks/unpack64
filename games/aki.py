'''
Aki Corporation's output of pro wrestling games
'''

import logging
import struct

from bffi import BffiBuilder, Bffi
from n64rom import N64Rom
from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi
from signature import SignatureBuilder, WILDCARD
from sigutil import pick_pattern

logger = logging.getLogger(__name__)


def _aki_dump_overlays(rom: N64Rom,
                       bootexe: bytes,
                       overlay_table_offset: int,
                       builder: BffiBuilder):
    
    for i in range(999):
        overlay_entry_offset = overlay_table_offset + (i * 0x24)

        # don't care about code/data ranges when dumping. maybe we will in the future though
        rom_start, rom_end, load_address, _, _, _, _, bss_start, bss_end = \
            struct.unpack(">IIIIIIIII", bootexe[overlay_entry_offset:overlay_entry_offset+0x24])
        
        if (load_address >> 24) != 0x80:
            break

        if rom_start == rom_end:
            break

        logger.info("overlay: ROM 0x%08x-0x%08x -> RAM 0x%08x (bss 0x%08x-0x%08x)",
                    rom_start,
                    rom_end,
                    load_address,
                    bss_start,
                    bss_end)

        seg = rom.read_bytes(rom_start, rom_end - rom_start)
        builder.seg(load_address, seg)

# ------------------------------------------------
#
# WWF No Mercy
#
# 8000073c swaps overlays. The main thread is at 80026918 and will
# swap overlays in a loop depending on the game state.
#
# Though this game has an overlay table it passes the data directly to
# the overlay swapper. The table starts at 80052e40 and is in this format:
#
# - +0x00 [0] 4 bytes ROM start address
# - +0x04 [1] 4 bytes ROM end address
# - +0x08 [2] 4 bytes RAM load address
# - +0x0C [3] 4 bytes code start address
# - +0x10 [4] 4 bytes code end address
# - +0x14 [5] 4 bytes data start address
# - +0x18 [6] 4 bytes data end address
# - +0x1C [7] 4 bytes bss start address
# - +0x20 [8] 4 bytes bss end address
#
# Immediately following the last overlay (at 0x001bd1b0) is compressed data.
# This game is known to use compressed text and textures, probably not code though.
#
# ------------------------------------------------

WWFNOMERCY_MAINLOOP_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x14, 0x80, WILDCARD,     # lui        s4,0x8005 <-- start of overlay table, plus 0x10
        0x26, 0x94, WILDCARD, WILDCARD, # addiu      s4,s4,0x2e50
        0x3c, 0x13, 0x80, WILDCARD,     # lui        s3,0x8005
        0x26, 0x73, WILDCARD, WILDCARD, # addiu      s3,s3,0x2e74
        0x3c, 0x12, 0x80, WILDCARD,     # lui        s2,0x8005
        0x26, 0x52, WILDCARD, WILDCARD, # addiu      s2,s2,0x2e98
        0x3c, 0x11, 0x80, WILDCARD,     # lui        s1,0x8005
        0x26, 0x31, WILDCARD, WILDCARD, # addiu      s1,s1,0x2ee0
        0x3c, 0x10, 0x80, WILDCARD,     # lui        s0,0x8005
        0x26, 0x10, WILDCARD, WILDCARD, # addiu      s0,s0,0x2ebc
        0x3c, 0x01, 0x80, WILDCARD,     # lui        at,0x800a
        0xac, 0x20, WILDCARD, WILDCARD, # sw         zero,offset DAT_800a25e0(at)
        0x3c, 0x01, 0x80, WILDCARD,     # lui        at,0x800a
        0xa0, 0x20, WILDCARD, WILDCARD, # sb         zero,-0x6af8(at)=>DAT_80099508
        0x8e, 0x84, 0xff, 0xf0,         # lw         a0,-0x10(s4)
    ]) \
    .const_op32_hi16("overlay_table_address", 0x00) \
    .const_op32_lo16("overlay_table_address", 0x04) \
    .build()

# WCW/nWo Revenge can be grouped into the same driver
# as it does the same -0x10 offset thing
WCWNWOREVENGE_MAINLOOP_PATTERN = SignatureBuilder() \
    .pattern([ 
        0x27, 0xbd, 0xff, 0xc8,             # +0x00 addiu      sp,sp,-0x38
        0x24, 0x04, 0x01, 0xe0,             # +0x04 li         a0,0x1e0
        0xaf, 0xbf, 0x00, 0x30,             # +0x08 sw         ra,local_8(sp)
        0xaf, 0xb1, 0x00, 0x2c,             # +0x0C sw         s1,local_c(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x10 jal        FUN_80001260
        0xaf, 0xb0, 0x00, 0x28,             # +0x14 _sw        s0,local_10(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x18 jal        FUN_80003120
        0x00, 0x00, 0x00, 0x00,             # +0x1C _nop
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x20 jal        FUN_80003d20
        0x00, 0x00, 0x00, 0x00,             # +0x24 _nop
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x28 jal        FUN_800034a0
        0x00, 0x00, 0x00, 0x00,             # +0x2C _nop
        0x3c, 0x11, 0x80, WILDCARD,         # +0x30 lui        s1,0x8003
        0x26, 0x31, WILDCARD, WILDCARD,     # +0x34 addiu      s1,s1,0x6e40
        0x3c, 0x10, 0x80, WILDCARD,         # +0x38 lui        s0,0x8003
        0x26, 0x10, WILDCARD, WILDCARD,     # +0x3C addiu      s0,s0,0x6e64
        0x8e, 0x24, 0xff, 0xf0,             # +0x40 lw         a0,-0x10(s1)
    ]) \
    .const_op32_hi16("overlay_table_address", 0x30) \
    .const_op32_lo16("overlay_table_address", 0x34) \
    .build()

# from Virtual Pro Wrestling 2, also matches Wrestlemania 2000
VPW2_MAINLOOP_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x13, 0x80, WILDCARD,     # lui        s3,0x8004
        0x26, 0x73, WILDCARD, WILDCARD, # addiu      s3,s3,0x7cd0
        0x3c, 0x12, 0x80, WILDCARD,     # lui        s2,0x8004
        0x26, 0x52, WILDCARD, WILDCARD, # addiu      s2,s2,0x7cf4
        0x3c, 0x11, 0x80, WILDCARD,     # lui        s1,0x8004
        0x26, 0x31, WILDCARD, WILDCARD, # addiu      s1,s1,0x7d18
        0x3c, 0x10, 0x80, WILDCARD,     # lui        s0,0x8004
        0x26, 0x10, WILDCARD, WILDCARD, # addiu      s0,s0,0x7d3c
        0x8e, 0x64, 0xff, 0xf0,         # lw         a0,-0x10(s3)
    ]) \
    .const_op32_hi16("overlay_table_address", 0x00) \
    .const_op32_lo16("overlay_table_address", 0x04) \
    .build()

def wwfnomercy_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    builder = BffiBuilder()
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    bootexe = rom.boot_exe()[:earliest_bss-ipc]

    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.fix(ipc, bootexe)

    mainloop_pattern, mainloop_offset = pick_pattern(bootexe,
                                                     [ WWFNOMERCY_MAINLOOP_PATTERN, 
                                                       WCWNWOREVENGE_MAINLOOP_PATTERN,
                                                       VPW2_MAINLOOP_PATTERN
                                                    ])

    if mainloop_offset is None:
        return None
    
    logger.info("found Aki Corporation -0x10-style mainloop")

    consts = mainloop_pattern.consts(ipc, bootexe, mainloop_offset)

    # remember, this offset is +0x10, so subtract that before reading the table!
    overlay_table_address = consts["overlay_table_address"].get_value() - 0x10

    overlay_table_offset = overlay_table_address - ipc
    _aki_dump_overlays(rom, bootexe, overlay_table_offset, builder)
    
    return builder.build()

# ------------------------------------------------
#
# Virtual Pro Wrestling 64
# WCW vs nWo: World Tour
#
# Oldest version of the Aki engine on the N64
#
# Same overlay table structure, different mainloop pattern,
# and does not add -0x10 to the overlay table offset
#
# ------------------------------------------------

WCWNWOWORLDTOUR_MAINLOOP_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xc8,             # +0x00 addiu      sp,sp,-0x38
        0xaf, 0xbf, 0x00, 0x34,             # +0x04 sw         ra,local_4(sp)
        0xaf, 0xa4, 0x00, 0x38,             # +0x08 sw         a0,local_res0(sp)
        0xaf, 0xb1, 0x00, 0x30,             # +0x0C sw         s1,local_8(sp)
        0xaf, 0xb0, 0x00, 0x2c,             # +0x10 sw         s0,local_c(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x14 jal        FUN_800014b0
        0x24, 0x04, 0x01, 0xe0,             # +0x18 _li        a0,0x1e0
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x1C jal        FUN_80003700
        0x00, 0x00, 0x00, 0x00,             # +0x20 _nop
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x24 jal        FUN_800052b0
        0x00, 0x00, 0x00, 0x00,             # +0x28 _nop
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x2C jal        FUN_80004c10
        0x00, 0x00, 0x00, 0x00,             # +0x30 _nop
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x34 jal        FUN_8000d888
        0x00, 0x00, 0x00, 0x00,             # +0x38 _nop
        0x3c, 0x11, 0x80, WILDCARD,         # +0x3C lui        s1,0x8003
        0x3c, 0x10, 0x80, WILDCARD,         # +0x40 lui        s0,0x8003 <-- overlay table start
        0x26, 0x10, WILDCARD, WILDCARD,     # +0x44 addiu      s0,s0,0x2ba0
    ]) \
    .const_op32_hi16("overlay_table_address", 0x40) \
    .const_op32_lo16("overlay_table_address", 0x44) \
    .build()

def wcwnwoworldtour_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    builder = BffiBuilder()
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    bootexe = rom.boot_exe()[:earliest_bss-ipc]

    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.fix(ipc, bootexe)

    mainloop_offset = WCWNWOWORLDTOUR_MAINLOOP_PATTERN.find(bootexe)
    if mainloop_offset is None:
        return None
    
    logger.info("found WCW/nWo World Tour mainloop")

    consts = WCWNWOWORLDTOUR_MAINLOOP_PATTERN.consts(ipc, bootexe, mainloop_offset)
    overlay_table_address = consts["overlay_table_address"].get_value()

    overlay_table_offset = overlay_table_address - ipc
    _aki_dump_overlays(rom, bootexe, overlay_table_offset, builder)
    
    return builder.build()
