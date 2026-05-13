'''
Seta games

Many of these games use "S1" and "B1" archives that will only be covered here
if they turn out to contain code.
'''

import logging
import struct

from bffi import Bffi, BffiBuilder
from n64rom import N64Rom
from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi
from signature import SignatureBuilder, WILDCARD

logger = logging.getLogger(__name__)

from signature import SignatureBuilder, WILDCARD

# ----------------------------------------------------------------
#
# Saikyo Habu Shogi
#
# This was a launch title, and it looked more like a high grade shovelware title
# than a serious selling point for the console. This perfectly set the tone for much
# of the N64's library.
#
# This game has several overlay swappers and tables.
#
# The "small overlay" loader takes a ROM segment (2 words in table at 0x800268a0)
# and loads it to a RAM segment (2 words in table at 0x80026940).
# This loads to a region with a fixed size (27200 bytes) which is cleared to 0
# before loading, so any unoccupied space in this region can be treated as BSS.
#
# TODO: the rest of the overlays aren't loaded yet. there's a lot of code
# following the end of the bootexe, but i don't know what loads it yet
#
# ----------------------------------------------------------------

SHSHOGI_SMALL_OVERLAY_SWAPPER_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x18, 0x80, WILDCARD,         # +0x00 lui    t8,0x8002    <-- RAM range table
        0x00, 0x11, 0x10, 0xc0,             # +0x04 sll    v0,s1,0x3
        0x27, 0x18, WILDCARD, WILDCARD,     # +0x08 addiu  t8,t8,0x6940
        0x00, 0x58, 0x30, 0x21,             # +0x0C addu   a2,v0,t8
        0x3c, 0x0f, 0x80, WILDCARD,         # +0x10 lui    t7,0x8002    <-- ROM range table
        0x8c, 0xd9, 0x00, 0x04,             # +0x14 lw     t9,0x4(a2)   +4 RAM end address
        0x8c, 0xc8, 0x00, 0x00,             # +0x18 lw     t0,0x0(a2)   +0 RAM start address
        0x25, 0xef, WILDCARD, WILDCARD,     # +0x1C addiu  t7,t7,0x68a0 
        0x00, 0x4f, 0x18, 0x21,             # +0x20 addu   v1,v0,t7
        0x8c, 0x72, 0x00, 0x00,             # +0x24 lw     s2,0x0(v1)   +0 ROM start address
        0x8c, 0x74, 0x00, 0x04,             # +0x28 lw     s4,0x4(v1)   +4 ROM end address
        0x8e, 0x64, 0x00, 0x00,             # +0x2C lw     a0,0x0(s3)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x30 jal    FUN_800137d0 clear cache thing
        0x03, 0x28, 0x28 ,0x23,             # +0x34 _subu  a1,t9,t0
    ]) \
    .const_op32_hi16("small_overlay_ram_table", 0x00) \
    .const_op32_lo16("small_overlay_ram_table", 0x08) \
    .const_op32_hi16("small_overlay_rom_table", 0x10) \
    .const_op32_lo16("small_overlay_rom_table", 0x1C) \
    .build()

def shshogi_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None

    builder = BffiBuilder()
    earliest_bss_section, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    bootexe = rom.boot_exe()[:earliest_bss_section-ipc]

    builder.fix(ipc, bootexe)
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())

    small_overlay_swapper_offset = SHSHOGI_SMALL_OVERLAY_SWAPPER_PATTERN.find(bootexe)
    if small_overlay_swapper_offset is None:
        return None
    
    logger.info("found Seta Saikyo Habu Shogi overlay swapper")

    # TODO: many overlays remain undumped; code that loads them isn't found yet

    consts = SHSHOGI_SMALL_OVERLAY_SWAPPER_PATTERN.consts(ipc, bootexe, small_overlay_swapper_offset)

    small_overlay_rom_table = consts["small_overlay_rom_table"].get_value()
    small_overlay_ram_table = consts["small_overlay_ram_table"].get_value()

    small_overlay_rom_table_offset = small_overlay_rom_table - ipc
    small_overlay_ram_table_offset = small_overlay_ram_table - ipc
    
    while True:
        rom_start_address, rom_end_address = struct.unpack(">II", bootexe[small_overlay_rom_table_offset:small_overlay_rom_table_offset+8])
        ram_start_address, ram_end_address = struct.unpack(">II", bootexe[small_overlay_ram_table_offset:small_overlay_ram_table_offset+8])
        
        if 0 in [rom_start_address, rom_end_address, ram_start_address, ram_end_address]:
            break

        logger.info("small overlay: ROM 0x%08x-0x%08x -> RAM 0x%08x-0x%08x",
                    rom_start_address,
                    rom_end_address,
                    ram_start_address,
                    ram_end_address)
        
        seg = rom.read_bytes(rom_start_address, rom_end_address-rom_start_address)
        builder.seg(ram_start_address, seg)

        small_overlay_rom_table_offset += 8
        small_overlay_ram_table_offset += 8
    
    return builder.build()

# ----------------------------------------------------------------
#
# Tetris 64
#
# Single read_cart routine at 0x8000e840 which takes parameters
# $a0=ROM address, $a1=RAM destination, $a2=sizeof.
#
# There are several ELF files embedded into the ROM.
# Whether the game loads them or not is a mystery to be solved later.
# If they don't, then there's a chance this is a single load game,
# as there's no other code sections besides the bootexe and the ELF files.
#
# ----------------------------------------------------------------
