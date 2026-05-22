'''
South Park Rally
Another Mr. Hankey-themed piece of N64 shovelware

This is a conversion of a PSX game so there is a lot of filesystem code that tries
to wrap PSX filesystem stuff to a custom handler. The filesystem is in ROM at
0xB2E90 in the US version but is in a non-trivial format to reverse engineer.
If it turns out to have overlays then it'll be taken care of...

The main overlay read function is at 0x80024380. Three things call it:
- 0x8002441C is an overlay table handler which will drop overlays into RAM
  at 0x80099470. 
- 0x8002445C loads ROM 0x987a0 -> 0x8009B340
- 0x80024490 loads ROM 0xB2E90 -> 0x8009B340

IMPORTANT! This game requires $gp to be set at startup.
However, all threads the game spawns should set $gp themselves.
'''

import logging
import struct

from bffi import Bffi,BffiBuilder,BffiSectionType
from n64rom import N64Rom
from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi
from signature import SignatureBuilder, WILDCARD
from sigutil import find_all_instances
from strutil import extract_cstring

logger = logging.getLogger(__name__)

# ----------------------------------------------------------

# both 0x8002445C and 0x80024490 should match this
SPARKRALLY_SECONDARY_OVERLAY_LOADER_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xe8,             # +0x00 addiu      sp,sp,-0x18
        0x3c, 0x04, 0x80, WILDCARD,         # +0x04 lui        a0,0x800a <-- load address
        0x3c, 0x05, 0xb0, WILDCARD,         # +0x08 lui        a1,0xb00a <-- ROM start address
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x0C addiu      a1,a1,-0x7860
        0x3c, 0x06, 0xb0, WILDCARD,         # +0x10 lui        a2,0xb00a <-- ROM end address
        0x24, 0xc6, WILDCARD, WILDCARD,     # +0x14 addiu      a2,a2,0x5e50
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x18 addiu      a0,a0,-0x4cc0
        0xaf, 0xbf, 0x00, 0x10,             # +0x1C sw         ra,local_8(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x20 jal        read_overlay
        0x00, 0xc5, 0x30, 0x23,             # +0x24 _subu      a2,a2,a1
        0x8f, 0xbf, 0x00, 0x10,             # +0x28 lw         ra,local_8(sp)
        0x03, 0xe0, 0x00, 0x08,             # +0x2C jr         ra
        0x27, 0xbd, 0x00, 0x18,             # +0x30 _addiu     sp,sp,0x18
    ]) \
    .const_op32_hi16("load_address", 0x04) \
    .const_op32_lo16("load_address", 0x18) \
    .const_op32_hi16("rom_start_address", 0x08) \
    .const_op32_lo16("rom_start_address", 0x0C) \
    .const_op32_hi16("rom_end_address", 0x10) \
    .const_op32_lo16("rom_end_address", 0x14) \
    .build()

SPARKRALLY_OVERLAY_TABLE_LOADER_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xe8,             # +0x00 addiu      sp,sp,-0x18
        0x3c, 0x05, 0x80, WILDCARD,         # +0x04 lui        a1,0x800a <-- load address
        0x3c, 0x02, 0x80, WILDCARD,         # +0x08 lui        v0,0x8008 <-- overlay table address
        0x24, 0x42, WILDCARD, WILDCARD,     # +0x0C addiu      v0,v0,0xc10
        0x00, 0x04, 0x20, 0xc0,             # +0x10 sll        a0,a0,0x3
        0x00, 0x82, 0x18, 0x21,             # +0x14 addu       v1,a0,v0
        0x00, 0x44, 0x10, 0x21,             # +0x18 addu       v0,v0,a0
        0x24, 0xa4, WILDCARD, WILDCARD,     # +0x1C addiu      a0,a1,-0x6b90
        0xaf, 0xbf, 0x00, 0x10,             # +0x20 sw         ra,local_8(sp)
        0x8c, 0x65, 0x00, 0x00,             # +0x24 lw         a1,0x0(v1)
        0x8c, 0x46, 0x00, 0x04,             # +0x28 lw         a2,0x4(v0)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x2C jal        read_overlay
        0x00, 0xc5, 0x30, 0x23,             # +0x30 _subu      a2,a2,a1
        0x8f, 0xbf, 0x00, 0x10,             # +0x34 lw         ra,local_8(sp)
        0x03, 0xe0, 0x00, 0x08,             # +0x38 jr         ra
        0x27, 0xbd, 0x00, 0x18,             # +0x3C _addiu     sp,sp,0x18
    ]) \
    .const_op32_hi16("load_address", 0x04) \
    .const_op32_lo16("load_address", 0x1C) \
    .const_op32_hi16("overlay_table_address", 0x08) \
    .const_op32_lo16("overlay_table_address", 0x0C) \
    .build()

def sparkrally_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None

    builder = BffiBuilder()
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    bootexe = rom.boot_exe()[:earliest_bss-ipc]

    overlay_table_load_offset = SPARKRALLY_OVERLAY_TABLE_LOADER_PATTERN.find(bootexe)
    if overlay_table_load_offset is None:
        return None
    
    secondary_overlay_loads = find_all_instances(bootexe, SPARKRALLY_SECONDARY_OVERLAY_LOADER_PATTERN)
    if not secondary_overlay_loads:
        return None
    
    logger.info("found South Park Rally overlay loaders")

    consts = SPARKRALLY_OVERLAY_TABLE_LOADER_PATTERN.consts(ipc, bootexe, overlay_table_load_offset)
    load_address = consts["load_address"].get_value()
    overlay_table_address = consts["overlay_table_address"].get_value()

    loaded_overlays = []

    overlay_table_offset = overlay_table_address-ipc
    while True:
        rom_start_address, rom_end_address = struct.unpack(">II", bootexe[overlay_table_offset:overlay_table_offset+0x08])
        overlay_table_offset += 8
        if rom_start_address == rom_end_address:
            continue

        if (rom_start_address >> 24) != 0xB0 or (rom_end_address >> 24) != 0xB0:
            break

        t = (rom_start_address, rom_end_address)
        if t in loaded_overlays:
            continue
        loaded_overlays.append(t)

        rom_start_address &= 0x03FFFFFF
        rom_end_address &= 0x03FFFFFF

        logger.info("main overlay table loads ROM 0x%08x-0x%08x -> RAM 0x%08x",
                    rom_start_address,
                    rom_end_address,
                    load_address)
        
        overlay = rom.read_bytes(rom_start_address, rom_end_address-rom_start_address)
        builder.seg(load_address, overlay)
    
    for secondary_load_offset in secondary_overlay_loads:
        consts = SPARKRALLY_SECONDARY_OVERLAY_LOADER_PATTERN.consts(ipc, bootexe, secondary_load_offset)
        load_address = consts["load_address"].get_value()
        rom_start_address = consts["rom_start_address"].get_value() & 0x03FFFFFF
        rom_end_address = consts["rom_end_address"].get_value() & 0x03FFFFFF

        logger.info("secondary overlay load: ROM 0x%08x-0x%08x -> RAM 0x%08x",
                    rom_start_address,
                    rom_end_address,
                    load_address)
        
        overlay = rom.read_bytes(rom_start_address, rom_end_address-rom_start_address)
        builder.seg(load_address, overlay)

    # TODO: set $gp
    # builder.initial_global_pointer(preamble.)

    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())
    return builder.build()
