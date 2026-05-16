'''
Human Entertainment
'''

import logging
import struct

from bffi import BffiBuilder, Bffi
from n64rom import N64Rom
from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi
from signature import SignatureBuilder, WILDCARD

logger = logging.getLogger(__name__)

# ----------------------------------------------------------
#
# Airboarder 64
#
# Massive overlay table at 0x8004c834. Entry format is:
#
# - +0x00 code section start
# - +0x04 code section end
# - +0x08 data section start
# - +0x0C data section end
# - +0x10 RAM load address
# - +0x14 ROM start address
# - +0x18 ROM end address
# - +0x1C BSS start address (0 if no BSS)
# - +0x20 BSS end address (0 if no BSS)
#
# ----------------------------------------------------------

AIRBOARDERS_OVERLAY_LOADER_PATTERN = SignatureBuilder() \
    .pattern([
        0x00, 0x04, 0x70, 0xc0,             # +0x00 sll        t6,a0,0x3
        0x27, 0xbd, 0xff, 0xe0,             # +0x04 addiu      sp,sp,-0x20
        0x01, 0xc4, 0x70, 0x21,             # +0x08 addu       t6,t6,a0
        0x3c, 0x0f, 0x80, WILDCARD,         # +0x0C lui        t7,0x8005       <-- overlay table address
        0xaf, 0xb0, 0x00, 0x18,             # +0x10 sw         s0,local_8(sp)
        0x25, 0xef, WILDCARD, WILDCARD,     # +0x14 addiu      t7,t7,-0x37cc
        0x00, 0x0e, 0x70, 0x80,             # sll        t6,t6,0x2
        0x01, 0xcf, 0x80, 0x21,             # addu       s0,t6,t7
        0x8e, 0x04, 0x00, 0x00,             # lw         a0,0x0(s0)
        0x8e, 0x18, 0x00, 0x04,             # lw         t8,0x4(s0)
        0xaf, 0xbf, 0x00, 0x1c,             # sw         ra,local_4(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # jal        FUN_800338a0
        0x03, 0x04, 0x28, 0x23,             # _subu      a1,t8,a0
    ]) \
    .const_op32_hi16("overlay_table_address", 0x0C) \
    .const_op32_lo16("overlay_table_address", 0x14) \
    .build()

def airboarders_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    builder = BffiBuilder()
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    bootexe = rom.boot_exe()[:earliest_bss-ipc]

    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.fix(ipc, bootexe)

    overlay_loader_offset = AIRBOARDERS_OVERLAY_LOADER_PATTERN.find(bootexe)
    if overlay_loader_offset is None:
        return None
    
    logger.info("found Human Entertainment Airboarder 64 overlay loader")

    consts = AIRBOARDERS_OVERLAY_LOADER_PATTERN.consts(ipc, bootexe, overlay_loader_offset)
    overlay_table_address = consts["overlay_table_address"].get_value()

    overlay_table_offset = overlay_table_address - ipc
    while True:
        code_start, code_end, \
        data_start, data_end, \
        load_address, \
        rom_start, rom_end, \
        bss_start, bss_end = struct.unpack(">IIIIIIIII", bootexe[overlay_table_offset:overlay_table_offset+(9*4)])

        if 0 in [code_start, code_end, load_address]:
            break

        overlay_table_offset += (9*4)

        logger.info(\
"""overlay: ROM 0x%08x-0x%08x, loads to 0x%08x
- code section: 0x%08x-0x%08x
- data section: 0x%08x-0x%08x
- bss section: 0x%08x-0x%08x""", rom_start, rom_end, load_address, code_start, code_end, data_start, data_end, bss_start, bss_end)
        
        segment = rom.read_bytes(rom_start, rom_end-rom_start)

        builder.seg(load_address, segment)
    
    # TODO: output BFFI looks lightweight, maybe 670k, there may be more code
    # segments at large... but the game code could be that small
    return builder.build()

# ----------------------------------------------------------
#
# F-1 Pole Position 64 / Human Grand Prix - New Generation
# Might be a single-load game
# 
# Big resource hunks start with the magic "FLV2"
# Routine at 0x80008bf0 reads 'em
#
# Generic readcart routine at 80001d3c takes parameters
# $a0 = RAM address, $a1 = ROM address, $a2 = sizeof
#
# ----------------------------------------------------------
