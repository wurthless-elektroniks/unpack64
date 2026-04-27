'''
HAL Laboratory, Inc.

All of HAL's games use the same code segment loader, which reads uncompressed segments
from ROM with osPiStartDma(). Offsets then are hardcoded into the games.

Kirby 64 has two important differences:

- This game is copy protected; 80002e48 will copy 256 bytes from the IPL3
  area (ROM 0xB70~0xC70 -> 0x80048900), and the game will check this later.
  This is to catch people running the game with an IPL3/CIC combo it wasn't
  intended for.

- Instead of using hardcoded pointers to the various overlay structs,
  it instead groups them in one table and uses a centralized function to
  load each one.

'''

import logging
import struct

from bffi import BffiBuilder, Bffi
from n64rom import N64Rom
from preamble import preamble_extract_bss_sections_to_bffi, identify_preamble
from signature import SignatureBuilder, WILDCARD

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------
#
# Kirby 64
#
# The function at 80002d8c is one of the overlay loaders.
# It takes a parameter pointing to a stuct containing the following:
#
# - 4 bytes ROM start address
# - 4 bytes ROM end address
# - 4 bytes pointer load address
# - 4 bytes pointer code start
# - 4 bytes pointer code end
# - 4 bytes pointer data start
# - 4 bytes pointer data end
# - 4 bytes pointer bss start
# - 4 bytes pointer bss end
#
# ---------------------------------------------------------------

KIRBY64_OVERLAY_LOADER_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xd8,     # addiu      sp,sp,-0x28
        0xaf, 0xbf, 0x00, 0x24,     # sw         ra,local_4(sp)
        0xaf, 0xb0, 0x00, 0x20,     # sw         s0,local_8(sp)
        0x8c, 0x8e, 0x00, 0x10,     # lw         t6,0x10(a0)
        0x8c, 0x82, 0x00, 0x0c,     # lw         v0,0xc(a0)
        0x00, 0x80, 0x80, 0x25,     # or         s0,a0,zero
        0x01, 0xc2, 0x18, 0x23,     # subu       v1,t6,v0
        0x10, 0x60, 0x00, 0x08,     # beq        v1,zero,LAB_80002dcc
        0x00, 0x40, 0x20, 0x25,     # _or        a0,v0,zero
        0x0c, WILDCARD, WILDCARD, WILDCARD,     # jal        osInvalDCache?
        0x00, 0x60, 0x28, 0x25,     # _or        a1,v1,zero
        0x8e, 0x02, 0x00, 0x0c,     # lw         v0,0xc(s0)
        0x8e, 0x0f, 0x00, 0x10,     # lw         t7,0x10(s0)
        0x00, 0x40, 0x20, 0x25,     # or         a0,v0,zero
        0x0c, WILDCARD, WILDCARD, WILDCARD,     # jal        osInvalICache?
        0x01, 0xe2, 0x28, 0x23,     # _subu      a1,t7,v0
    ]) \
    .build()

# found in first segment loaded by the overlay loader
KIRBY64_MAIN_OVERLAY_TABLE_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xe8,             # +0x00 addiu  sp,sp,-0x18
        0x2c, 0x81, WILDCARD, WILDCARD,     # +0x04 sltiu  at,a0,0x14             # <-- number of overlays
        0xaf, 0xbf, 0x00, 0x14,             # +0x08 sw     ra,local_4(sp)
        0x14, 0x20, 0x00, 0x04,             # +0x0C bne    at,zero,LAB_800a6b40
        0x00, 0x80, 0x28, 0x25,             # +0x10 _or    a1,a0,zero
        0x2c, 0xa1, WILDCARD, WILDCARD,     # +0x14 sltiu  at,a1,0x14
        0x50, 0x20, 0xff, 0xff,             # +0x18 beql   at,zero,LAB_800a6b38
        0x2c, 0xa1, 0x00, 0x14,             # +0x1C _sltiu at,a1,0x14
        0x00, 0x05, 0x70, 0x80,             # +0x20 sll    t6,a1,0x2
        0x3c, 0x04, 0x80, WILDCARD,         # +0x24 lui    a0,0x800c
        0x00, 0x8e, 0x20, 0x21,             # +0x28 addu   a0,a0,t6
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x2C jal    SUB_80002d8c          <-- overlay load fcn
        0x8c, 0x84, WILDCARD, WILDCARD,     # +0x30 _lw    a0,-0x1760(a0)        <-- overlay table
    ]) \
    .const_imm32("num_overlays", 0x04) \
    .const_op32_hi16("segment_table_address", 0x24) \
    .const_op32_lo16("segment_table_address", 0x30) \
    .xref_j_imm26("overlay_loader_address", 0x2C) \
    .build()

def _find_instances_of(pattern, data):
    instances = []

    offset = 0
    while offset is not None:
        offset = pattern.find(data, offset)
        if offset is None:
            return instances
        
        instances.append(offset)
        offset += 4

def _dump_segment(rom: N64Rom,
                  segment: bytes,
                  segment_load_address: int,
                  segment_table_address: int):
    segment_table_offset = segment_table_address - segment_load_address

    rom_start, \
    rom_end, \
    load_address, \
    code_start_address, \
    code_end_address, \
    data_start_address, \
    data_end_address, \
    bss_start_address, \
    bss_end_address = struct.unpack(">IIIIIIIII", segment[segment_table_offset:segment_table_offset+(9*4)])

    logger.info( \
"""dumping segment loaded from %08x:
\trom: 0x%08x~0x%08x
\tloads to: 0x%08x
\tcode: 0x%08x~0x%08x
\tdata: 0x%08x~0x%08x
\tbss: 0x%08x~0x%08x""",
    segment_load_address,
    rom_start,rom_end,
    load_address,
    code_start_address,code_end_address,
    data_start_address,data_end_address,
    bss_start_address,bss_end_address)

    return load_address, rom.read_bytes(rom_start, rom_end-rom_start)


# recursive segment finding can be done for smash 64, but it can't
# for kirby 64, because kirby 64 has a table with all of its segments
def _find_segments(rom: N64Rom,
                   current_segment: bytes,
                   segment_load_base: int,
                   mainseg_load_pattern,
                   builder: BffiBuilder,
                   dumping_fix: bool = False):
    overlay_load_calls = _find_instances_of(mainseg_load_pattern, current_segment)
    if not overlay_load_calls:
        return None
    
    for overlay_load_offset in overlay_load_calls:
        consts = mainseg_load_pattern.consts(segment_load_base, current_segment, overlay_load_offset)
        segment_table_address = consts["segment_table_address"].get_value()

        load_address, segment = _dump_segment(rom, current_segment, segment_load_base, segment_table_address)

        if dumping_fix:
            builder.fix(load_address, segment)
        else:
            builder.seg(load_address, segment)

        _find_segments(rom,
                       segment,
                       load_address,
                       mainseg_load_pattern,
                       builder)

def kirby64_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    builder = BffiBuilder()
    earliest_bss_segment, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    bootexe = rom.boot_exe()[:earliest_bss_segment-ipc]

    builder.fix(ipc, bootexe)
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())

    overlay_loader_offset = KIRBY64_OVERLAY_LOADER_PATTERN.find(bootexe)
    if overlay_loader_offset is None:
        return None
    
    overlay_loader_address = overlay_loader_offset + ipc

    logger.info("found HAL overlay loader at 0x%08x", overlay_loader_address)

    mainseg_load_pattern = SignatureBuilder() \
        .bits(
            bytes([0x3c, 0x04, 0x80, 0x00]) + \
            struct.pack(">I", (overlay_loader_address & 0x03FFFFFF) >> 2 | 0x0C000000) + \
            bytes([0x24, 0x84, 0x00, 0x00])
        ) \
        .andmask(bytes([
            0xFF, 0xFF, 0xFF, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0x00, 0x00,
        ])) \
        .const_op32_hi16("segment_table_address", 0x00) \
        .const_op32_lo16("segment_table_address", 0x08) \
        .build()
    
    # called exactly once in the boot segment
    mainseg_load_offset = mainseg_load_pattern.find(bootexe)
    if mainseg_load_offset is None:
        logger.error("can't find main segment load pattern")
        return None

    consts = mainseg_load_pattern.consts(ipc, bootexe, mainseg_load_offset)
    segment_table_address = consts["segment_table_address"].get_value()
    
    mainsegment_load_address, mainsegment = _dump_segment(rom, bootexe, ipc, segment_table_address)
    builder.fix(mainsegment_load_address, mainsegment)

    overlay_table_loader_offset = KIRBY64_MAIN_OVERLAY_TABLE_PATTERN.find(mainsegment)
    if overlay_table_loader_offset is None:
        logger.error("can't find overlay table in main segment!!")
        return None
    
    xrefs = KIRBY64_MAIN_OVERLAY_TABLE_PATTERN.xrefs(mainsegment_load_address, mainsegment, overlay_table_loader_offset)
    if xrefs["overlay_loader_address"].get_address() != overlay_loader_address:
        logger.error("main segment overlay table loader does NOT call the overlay loader in the boot stub!!")
        return None
    
    consts = KIRBY64_MAIN_OVERLAY_TABLE_PATTERN.consts(mainsegment_load_address, mainsegment, overlay_table_loader_offset)
    segment_table_address = consts["segment_table_address"].get_value()

    # HACK: num_overlays should be an imm16 value
    num_overlays = consts["num_overlays"].get_value() & 0xFFFF
    logger.info("dumping %d overlays from the main overlay table at 0x%08x", num_overlays, segment_table_address)

    for i in range(num_overlays):
        pointer_offset = (segment_table_address - mainsegment_load_address) + (i*4)
        overlay_struct_address = struct.unpack(">I", mainsegment[pointer_offset:pointer_offset+4])[0]
        logger.info("- segment %d: overlay struct at 0x%08x", i, overlay_struct_address)

        segment_load_address, segment = _dump_segment(rom, mainsegment, mainsegment_load_address, overlay_struct_address)

        builder.seg(segment_load_address, segment)

    return builder.build()


def smash64_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    builder = BffiBuilder()
    earliest_bss_segment, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    bootexe = rom.boot_exe()[:earliest_bss_segment-ipc]

    builder.fix(ipc, bootexe)
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())

    overlay_loader_offset = KIRBY64_OVERLAY_LOADER_PATTERN.find(bootexe)
    if overlay_loader_offset is None:
        return None
    
    overlay_loader_address = overlay_loader_offset + ipc

    logger.info("found HAL overlay loader at 0x%08x", overlay_loader_address)

    mainseg_load_pattern = SignatureBuilder() \
        .bits(
            bytes([0x3c, 0x04, 0x80, 0x00]) + \
            struct.pack(">I", (overlay_loader_address & 0x03FFFFFF) >> 2 | 0x0C000000) + \
            bytes([0x24, 0x84, 0x00, 0x00])
        ) \
        .andmask(bytes([
            0xFF, 0xFF, 0xFF, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0x00, 0x00,
        ])) \
        .const_op32_hi16("segment_table_address", 0x00) \
        .const_op32_lo16("segment_table_address", 0x08) \
        .build()
    
    _find_segments(rom, bootexe, ipc, mainseg_load_pattern, builder, dumping_fix=True)

    return builder.build()
