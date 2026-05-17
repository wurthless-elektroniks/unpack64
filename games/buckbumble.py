'''
Buck Bumble from Argonaut Software

Looks like a two-load game; one OS segment and one engine segment.
'''


import logging

from bffi import BffiBuilder, Bffi
from n64rom import N64Rom
from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi
from signature import SignatureBuilder, WILDCARD
from sigutil import find_all_instances

logger = logging.getLogger(__name__)

# ----------------------------------------------------

BUCKBUMBLE_MAIN_OVERLAY_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x02, 0xb0, WILDCARD,         # +0x00 lui        v0,0xb00e
        0x24, 0x42, WILDCARD, WILDCARD,     # +0x04 addiu      v0,v0,-0x2c00
        0x3c, 0x06, 0xb0, WILDCARD,         # +0x08 lui        a2,0xb002
        0x24, 0xc6, WILDCARD, WILDCARD,     # +0x0C addiu      a2,a2,0x5b0
        0x00, 0xc0, 0x20, 0x21,             # +0x10 move       a0,a2
        0x3c, 0x05, 0x80, WILDCARD,         # +0x14 lui        a1,0x8004
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x18 addiu      a1,a1,0x3970
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x1C jal        readcart
        0x00, 0x46, 0x30, 0x23,             # +0x20 _subu      a2,v0,a2
    ]) \
    .const_op32_hi16("rom_end_address", 0x00) \
    .const_op32_lo16("rom_end_address", 0x04) \
    .const_op32_hi16("rom_start_address", 0x08) \
    .const_op32_lo16("rom_start_address", 0x0C) \
    .const_op32_hi16("ram_address", 0x14) \
    .const_op32_lo16("ram_address", 0x18) \
    .build()

def buckbumble_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None

    builder = BffiBuilder()
    earliest_bss_section, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    bootexe = rom.boot_exe()[:earliest_bss_section-ipc]

    builder.fix(ipc, bootexe)
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())

    overlay_loads = find_all_instances(bootexe, BUCKBUMBLE_MAIN_OVERLAY_LOAD_PATTERN)
    if not overlay_loads:
        return None
    
    logger.info("found Buck Bumble overlay load(s)")
    for overlay_load_offset in overlay_loads:
        consts = BUCKBUMBLE_MAIN_OVERLAY_LOAD_PATTERN.consts(ipc, bootexe, overlay_load_offset)

        rom_start_address = consts["rom_start_address"].get_value() & 0x03FFFFFF
        rom_end_address = consts["rom_end_address"].get_value() & 0x03FFFFFF
        ram_address = consts["ram_address"].get_value()
        
        logger.info("overlay: ROM 0x%08x-0x%08x -> RAM 0x%08x",
                    rom_start_address,
                    rom_end_address,
                    ram_address)
        
        seg = rom.read_bytes(rom_start_address, rom_end_address-rom_start_address)
        builder.seg(ram_address, seg)

    return builder.build()
