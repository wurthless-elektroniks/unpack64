'''
DMA Design
'''

import logging
import struct

from bffi import BffiBuilder, Bffi
from n64rom import N64Rom
from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi
from signature import SignatureBuilder, WILDCARD
from sigutil import find_all_instances

logger = logging.getLogger(__name__)

# ------------------------------------------------
#
# Space Station Silicon Valley
#
# This game uses two huge code overlays, probably one for ingame
# and the other for menus. Each has their own bss segment.
#
# ------------------------------------------------

SSSV_OVERLAY_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x04, WILDCARD, WILDCARD,        # +0x00 lui        a0,0x6a
        0x3c, WILDCARD, WILDCARD, WILDCARD,    # +0x04 lui        tX,0x7d
        0x24, 0x84, WILDCARD, WILDCARD,        # +0x08 addiu      a0,a0,0x6500
        0x24, WILDCARD, WILDCARD, WILDCARD,    # +0x0C addiu      tX,tX,0x1ad0
        0x3c, 0x05, 0x80, WILDCARD,            # +0x10 lui        a1,0x8029
        0x24, 0xa5, WILDCARD, WILDCARD,        # +0x14 addiu      a1,a1,0x4e50
        0x0c, WILDCARD, WILDCARD, WILDCARD,    # +0x18 jal        FUN_80129290
        0x00, 0x04, 0x30, 0x23,                # +0x1C _subu      a2,t8,a0
        0x3c, 0x04, 0x80, WILDCARD,            # +0x20 lui        a0,0x803c
        0x3c, WILDCARD, 0x80, WILDCARD,        # +0x24 lui        t9,0x8040
        0x24, 0x84, WILDCARD, WILDCARD,        # +0x28 addiu      a0,a0,0x420
        0x24, WILDCARD, WILDCARD, WILDCARD,    # +0x2C addiu      t9,t9,-0x2140
        0x0c, WILDCARD, WILDCARD, WILDCARD,    # +0x30 jal        FUN_80139530
        0x00, 0x24, 0x28, 0x23,                # +0x34 _subu      a1,t9,a0
    ]) \
    .modify_andmask(0x0C, bytes([0b11111100])) \
    .modify_andmask(0x1C, bytes([0b11111100, 0b00001111])) \
    .modify_andmask(0x2C, bytes([0b11111100])) \
    .modify_andmask(0x34, bytes([0b11111100, 0b00001111])) \
    .const_op32_hi16("rom_start_address", 0x00) \
    .const_op32_lo16("rom_start_address", 0x08) \
    .const_op32_hi16("rom_end_address", 0x04) \
    .const_op32_lo16("rom_end_address", 0x0C) \
    .const_op32_hi16("ram_load_address", 0x10) \
    .const_op32_lo16("ram_load_address", 0x14) \
    .const_op32_hi16("bss_start_address", 0x20) \
    .const_op32_lo16("bss_start_address", 0x28) \
    .const_op32_hi16("bss_end_address", 0x24) \
    .const_op32_lo16("bss_end_address", 0x2C) \
    .build()

# TODO: inline in sssv_unpack() - recursion is not needed
def _dump_all_segments(segment, segment_load_address, pattern, rom, builder):
    overlay_loads = find_all_instances(segment, pattern)
    if not overlay_loads:
        return
    
    for offset in overlay_loads:
        consts = pattern.consts(segment_load_address, segment, offset)

        rom_start_address = consts["rom_start_address"].get_value()
        rom_end_address = consts["rom_end_address"].get_value()
        ram_load_address = consts["ram_load_address"].get_value()
        bss_start_address = consts["bss_start_address"].get_value()
        bss_end_address = consts["bss_end_address"].get_value()
        
        logger.info("segment: ROM 0x%08x-0x%08x -> 0x%08x / bss 0x%08x-0x%08x",
                    rom_start_address,
                    rom_end_address,
                    ram_load_address,
                    bss_start_address,
                    bss_end_address)
        
        segcode = rom.read_bytes(rom_start_address, rom_end_address-rom_start_address)

        builder.seg(ram_load_address, segcode)

        _dump_all_segments(segcode, ram_load_address, pattern, rom, builder)

def sssv_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    builder = BffiBuilder()
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)

    bootexe = rom.boot_exe()[:earliest_bss-ipc]

    builder.fix(ipc, bootexe)
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.initial_stack_pointer(preamble.initial_stack_pointer())

    if not SSSV_OVERLAY_LOAD_PATTERN.find(bootexe):
        return None

    overlay_loads = find_all_instances(bootexe, SSSV_OVERLAY_LOAD_PATTERN)
    if not overlay_loads:
        return None
    
    logger.info("found DMA Design SSSV-style overlay loading code")
    
    _dump_all_segments(bootexe, ipc, SSSV_OVERLAY_LOAD_PATTERN, rom, builder)

    return builder.build()


# ------------------------------------------------
#
# Body Harvest
#
# Much more complicated version of SSSV:
#
# - Two main segments with bss
# - One main segment WITHOUT bss
# - Five per-level segments
#
# ------------------------------------------------

# basically the same as SSSV's but the segment load routine
# takes the arguments in a different order
BODYHARVEST_MAIN_OVERLAY_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x02, WILDCARD, WILDCARD,     # +0x00 lui   v0,0x4  <-- ROM start
        0x3c, 0x18, WILDCARD, WILDCARD,     # +0x04 lui   t8,0x8  <-- ROM end
        0x24, 0x45, WILDCARD, WILDCARD,     # +0x08 addiu a1,v0,0x720
        0x27, 0x18, WILDCARD, WILDCARD,     # +0x0C addiu t8,t8,-0xde0
        0x3c, 0x04, 0x80, WILDCARD,         # +0x10 lui   a0,0x8007  <-- RAM load address
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x14 addiu a0,a0,0x270
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x18 jal   FUN_800101f0
        0x03, 0x05, 0x30, 0x23,             # +0x1C _subu a2,t8,a1
    ]) \
    .const_op32_hi16("rom_start_address", 0x00) \
    .const_op32_lo16("rom_start_address", 0x08) \
    .const_op32_hi16("rom_end_address", 0x04) \
    .const_op32_lo16("rom_end_address", 0x0C) \
    .const_op32_hi16("ram_load_address", 0x10) \
    .const_op32_lo16("ram_load_address", 0x14) \
    .build()

# should follow each of the above, or we assume there is no BSS for that section
BODYHARVEST_AFTER_LOAD_OVERLAY_CLEAR_BSS_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x04, 0x80, WILDCARD,         # +0x00 lui   a0,0x800b <-- BSS start
        0x3c, 0x19, 0x80, WILDCARD,         # +0x04 lui   t9,0x800e <-- BSS end
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x08 addiu a0,a0,-0x1290
        0x27, 0x39, WILDCARD, WILDCARD,     # +0x0C addiu t9,t9,0x1d70
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x10 jal   FUN_8001e920
        0x03, 0x24, 0x28, 0x23              # +0x14 _subu a1,t9,a0
    ]) \
    .const_op32_hi16("bss_start_address", 0x00) \
    .const_op32_lo16("bss_start_address", 0x08) \
    .const_op32_hi16("bss_end_address", 0x04) \
    .const_op32_lo16("bss_end_address", 0x0C) \
    .build()
    
BODYHARVEST_LEVEL_OVERLAY_LOADER_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xc8,             # +0x00 addiu      sp,sp,-0x38
        0xaf, 0xa4, 0x00, 0x38,             # +0x04 sw         a0,local_res0(sp)
        0x30, 0x85, 0x00, 0xff,             # +0x08 andi       a1,a0,0xff
        0xaf, 0xbf, 0x00, 0x1c,             # +0x0C sw         ra,local_1c(sp)
        0x3c, 0x04, 0x80, WILDCARD,         # +0x10 lui        a0,0x8004
        0xaf, 0xb0, 0x00, 0x18,             # +0x14 sw         s0,local_20(sp)
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x18 addiu      a0,a0,-0x8000            = "Loading level %d code\n"
        0x00, 0xa0, 0x38, 0x25,             # +0x1C or         a3,a1,zero
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x20 jal        debugmsg 
        0xaf, 0xa5, 0x00, 0x34,             # +0x24 _sw        a1,local_4(sp)
        0x8f, 0xa7, 0x00, 0x34,             # +0x28 lw         a3,local_4(sp)
        0x3c, 0x0f, 0x80, WILDCARD,         # +0x2C lui        t7,0x8003       <-- overlay ROM start addresses table
        0x25, 0xef, WILDCARD, WILDCARD,     # +0x30 addiu      t7,t7,0x1c18
        0x3c, 0x18, 0x80, WILDCARD,         # +0x34 lui        t8,0x8003       <-- overlay ROM end addresses table
        0x00, 0x07, 0x18, 0x80,             # +0x38 sll        v1,a3,0x2
        0x00, 0x6f, 0x10, 0x21,             # +0x3C addu       v0,v1,t7
        0x27, 0x18, WILDCARD, WILDCARD,     # +0x40 addiu      t8,t8,0x1c2c
        0x8c, 0x50, 0xff, 0xfc,             # +0x44 lw         s0,-0x4(v0)    ; apparently we expect an argument of at least 1
        0x00, 0x78, 0x40, 0x21,             # +0x48 addu       t0,v1,t8
        0x3c, 0x0e, 0x80, WILDCARD,         # +0x4C lui        t6,0x8003      <-- RAM load address table
        0x8d, 0x19, 0xff, 0xfc,             # +0x50 lw         t9,-0x4(t0)
        0x25, 0xce, WILDCARD, WILDCARD,     # +0x54 addiu      t6,t6,0x1c40
    ]) \
    .const_op32_hi16("rom_start_address_table_address", 0x2C) \
    .const_op32_lo16("rom_start_address_table_address", 0x30) \
    .const_op32_hi16("rom_end_address_table_address", 0x34) \
    .const_op32_lo16("rom_end_address_table_address", 0x40) \
    .const_op32_hi16("ram_load_address_table_address", 0x4C) \
    .const_op32_lo16("ram_load_address_table_address", 0x54) \
    .build()


def bodyharvest_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    builder = BffiBuilder()
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)

    bootexe = rom.boot_exe()[:earliest_bss-ipc]

    builder.fix(ipc, bootexe)
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.initial_stack_pointer(preamble.initial_stack_pointer())

    if not BODYHARVEST_MAIN_OVERLAY_LOAD_PATTERN.find(bootexe):
        return None

    overlay_loads = find_all_instances(bootexe, BODYHARVEST_MAIN_OVERLAY_LOAD_PATTERN)
    if not overlay_loads:
        return None
    
    level_overlay_loader_offset = BODYHARVEST_LEVEL_OVERLAY_LOADER_PATTERN.find(bootexe)
    if level_overlay_loader_offset is None:
        return None
    
    consts = BODYHARVEST_LEVEL_OVERLAY_LOADER_PATTERN.consts(ipc, bootexe, level_overlay_loader_offset)
    rom_start_address_table_address = consts["rom_start_address_table_address"].get_value()
    rom_end_address_table_address = consts["rom_end_address_table_address"].get_value()
    ram_load_address_table_address = consts["ram_load_address_table_address"].get_value()
    
    addresses = [ rom_start_address_table_address,
                 rom_end_address_table_address,
                 ram_load_address_table_address ]
    addresses.sort()

    if (addresses[2] - addresses[1]) != (addresses[1] - addresses[0]):
        return None
    
    rom_start_address_table_offset = rom_start_address_table_address - ipc
    rom_end_address_table_address = rom_end_address_table_address - ipc
    ram_load_address_table_address = ram_load_address_table_address - ipc

    num_level_overlays = (addresses[2] - addresses[1]) >> 2

    logger.info("found DMA Design Body Harvest segment loaders")

    logger.info("locating and dumping main segments")
    
    offset = 0
    while offset is not None:
        offset = BODYHARVEST_MAIN_OVERLAY_LOAD_PATTERN.find(bootexe, offset)
        if offset is None:
            break

        consts = BODYHARVEST_MAIN_OVERLAY_LOAD_PATTERN.consts(ipc, bootexe, offset)
        rom_start_address = consts["rom_start_address"].get_value()
        rom_end_address = consts["rom_end_address"].get_value()
        ram_load_address = consts["ram_load_address"].get_value()

        offset += BODYHARVEST_MAIN_OVERLAY_LOAD_PATTERN.size()

        logger.info("main segment: ROM 0x%08x-0x%08x -> RAM 0x%08x",
                    rom_start_address,
                    rom_end_address,
                    ram_load_address)

        # check for BSS - one call doesn't have it
        if BODYHARVEST_AFTER_LOAD_OVERLAY_CLEAR_BSS_PATTERN.compare(bootexe, offset) is True:
            consts  = BODYHARVEST_AFTER_LOAD_OVERLAY_CLEAR_BSS_PATTERN.consts(ipc, bootexe, offset)
            bss_start_address = consts["bss_start_address"].get_value()
            bss_end_address   = consts["bss_end_address"].get_value()
            
            logger.info("\t- has BSS 0x%08x-0x%08x", bss_start_address, bss_end_address)

            offset += BODYHARVEST_AFTER_LOAD_OVERLAY_CLEAR_BSS_PATTERN.size()
        else:
            logger.info("\t- no BSS")

        builder.seg(ram_load_address, rom.read_bytes(rom_start_address, rom_end_address-rom_start_address))

    logger.info("dumping %d level-specific code segments", num_level_overlays)

    for i in range(num_level_overlays):
        rom_start_address_offset = rom_start_address_table_offset + (i*4)
        rom_end_address_offset   = rom_end_address_table_address  + (i*4)
        ram_load_address_offset  = ram_load_address_table_address + (i*4)
        
        rom_start_address = struct.unpack(">I",
                                          bootexe[rom_start_address_offset:rom_start_address_offset+4])[0]

        rom_end_address = struct.unpack(">I",
                                        bootexe[rom_end_address_offset:rom_end_address_offset+4])[0]

        ram_load_address = struct.unpack(">I",
                                         bootexe[ram_load_address_offset:ram_load_address_offset+4])[0]

        logger.info("level %d code segment: ROM 0x%08x-0x%08x -> RAM 0x%08x",
                    i + 1,
                    rom_start_address,
                    rom_end_address,
                    ram_load_address)
        
        segment = rom.read_bytes(rom_start_address, rom_end_address-rom_start_address)
        builder.seg(ram_load_address, segment)

    return builder.build()
