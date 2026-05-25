'''
Eurocom games

All use EDL compression to some extent, none seem to clear caches correctly
'''

import logging
import struct


from bffi import Bffi, BffiBuilder
from n64rom import N64Rom
from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi
from signature import SignatureBuilder, WILDCARD

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------
#
# Mortal Kombat 4
#
# This looks like a two-load game. The main thread will load more code
# and data from an overlay immediately following the boot segment in ROM.
# However the readcart routine doesn't invalidate the instruction caches,
# making this another case where the game boots based on pure luck.
#
# ----------------------------------------------------------------

MK4_MAIN_SEGMENT_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x04, 0x80, WILDCARD,         # +0x00 lui        a0,0x8013
        0x34, 0x84, WILDCARD, WILDCARD,     # +0x04 ori        a0,a0,0x2000
        0x3c, 0x05, 0x00, WILDCARD,         # +0x08 lui        a1,0x5
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x0C addiu      a1,a1,0x1400
        0x3c, 0x06, 0x00, WILDCARD,         # +0x10 lui        a2,0x13
        0x24, 0xc6, WILDCARD, WILDCARD,     # +0x14 addiu      a2,a2,-0x5360
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x18 jal        readcart
        0x00, 0xc5, 0x30, 0x23,             # +0x1C _subu      a2,a2,a1
        
        # copy build datetime somewhere else in RAM
        0x3c, 0x04, 0x80, WILDCARD,         # +0x20 lui        a0,0x8010
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x24 addiu      a0,a0,-0x7858
        0x3c, 0x05, 0x00, WILDCARD,         # +0x28 lui        a1,0x25
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x2C addiu      a1,a1,-0x6cf0
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x30 jal        readcart
        0x24, 0x06, 0x00, 0x18,             # +0x34 _li        a2,0x18
    ]) \
    .const_op32_hi16("ram_load_address", 0x00) \
    .const_op32_lo16("ram_load_address", 0x04) \
    .const_op32_hi16("rom_start_address", 0x08) \
    .const_op32_lo16("rom_start_address", 0x0C) \
    .const_op32_hi16("rom_end_address", 0x10) \
    .const_op32_lo16("rom_end_address", 0x14) \
    .build()

def mk4_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None

    builder = BffiBuilder()
    earliest_bss_section, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    bootexe = rom.boot_exe()[:earliest_bss_section-ipc]

    builder.fix(ipc, bootexe)
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())

    mk4_main_segment_load_offset = MK4_MAIN_SEGMENT_LOAD_PATTERN.find(bootexe)
    if mk4_main_segment_load_offset is None:
        return None
    
    logger.info("found Mortal Kombat 4 main segment loader")

    consts = MK4_MAIN_SEGMENT_LOAD_PATTERN.consts(ipc, bootexe, mk4_main_segment_load_offset)
    ram_load_address  = consts["ram_load_address"].get_value()
    rom_start_address = consts["rom_start_address"].get_value()
    rom_end_address   = consts["rom_end_address"].get_value()

    logger.info("main segment: ROM 0x%08x-0x%08x -> RAM 0x%08x",
                rom_start_address,
                rom_end_address,
                ram_load_address)
    
    mainseg = rom.read_bytes(rom_start_address, rom_end_address-rom_start_address)
    builder.fix(ram_load_address, mainseg)

    return builder.build()

# ----------------------------------------------------------------
#
# Cruis'n World
#
# Eurocom's programmers really don't know what an instruction cache is
# and why it should be cleared. On top of all this is a ratsnest of logic
# with tables initialized later during the boot, overlays loading in random
# places, and the final insult is, there's another compression method that
# has to be added...
#
# ----------------------------------------------------------------
