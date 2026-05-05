'''
Dual Heroes
Because even the shittiest N64 games deserve some love.

8000a470 is the main segment loader.

It takes a pointer to a struct (in $a0) formatted as follows
- +0x00 [0] ROM start address
- +0x04 [1] ROM end address
- +0x08 [2] RAM load address
- +0x0C [3] text segment start?
- +0x10 [4] text segment end?
- +0x14 [5] data segment start?
- +0x18 [6] data segment end?
- +0x1C [7] BSS segment start
- +0x20 [8] BSS segment end

This is eerily similar to the one used by Deadly Arts.
However, the routines are different.

There are two main loader points, both in the main thread.

The first selects which of the "main" segments should be loaded.
This one is very easy to find as the main segments are placed in a table
that we can find and read from easily.

The other is more annoying. When a main segment is loaded and running,
it's free to request the main thread to load more code or data; to do so
it drops a pointer at 0x800f1c00 to the struct that needs loading and
the entry point at 0x800f1bc0.
'''

import logging
import struct

from bffi import BffiBuilder, Bffi
from n64rom import N64Rom
from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi
from reloc import munge_mips_hilo_offset
from signature import SignatureBuilder, WILDCARD
from sigutil import find_all_instances

logger = logging.getLogger(__name__)

# ------------------------------------------------

DUAL_HEROES_LOAD_AND_EXECUTE_FROM_INBOX_FCN_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xe8,             # +0x00 addiu      sp,sp,-0x18
        0x3c, 0x04, 0x80, WILDCARD,         # +0x04 lui        a0,0x800f
        0xaf, 0xbf, 0x00, 0x14,             # +0x08 sw         ra,local_4(sp)
        0x8c, 0x84, WILDCARD, WILDCARD,     # +0x0C lw         a0,offset PTR_DAT_800f1c00(a0)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x10 jal        FUN_8000a470
        0x00, 0x00, 0x00, 0x00,             # _nop
        0x3c, 0x19, 0x80, WILDCARD,         # lui        t9,0x800f
        0x8f, 0x39, WILDCARD, WILDCARD,     # lw         t9,offset ->FUN_801413a0(t9)
        0x00, 0x00, 0x00, 0x00,             # nop
        0x03, 0x20, 0xf8, 0x09,             # jalr       t9
        0x00, 0x00, 0x00, 0x00,             # _nop
        0x8f, 0xbf, 0x00, 0x14,             # lw         ra,local_4(sp)
        0x27, 0xbd, 0x00, 0x18,             # addiu      sp,sp,0x18
        0x03, 0xe0, 0x00, 0x08,             # jr         ra
        0x00, 0x00, 0x00, 0x00,             # _nop
    ]) \
    .const_op32_hi16("requested_segstruct_address", 0x04) \
    .const_op32_lo16("requested_segstruct_address", 0x0C) \
    .build()

DUAL_HEROES_MAIN_SEGMENT_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x87, 0xaf, WILDCARD, WILDCARD,     # +0x00 _lh        t7,0x42(sp)
        0x00, 0x02, 0x40, 0x80,             # +0x04 sll        t0,v0,0x2
        0x3c, 0x04, 0x80, WILDCARD,         # +0x08 lui        a0,0x8003
        0x00, 0x88, 0x20, 0x21,             # +0x0C addu       a0,a0,t0
        0x8c, 0x84, WILDCARD, WILDCARD,     # +0x10 lw         a0,-0x4a64(a0)=>LAB_8000f464
        0x24, 0x09, 0x00, 0x01,             # +0x14 li         t1,0x1
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x18 jal        FUN_8000a470
    ]) \
    .const_op32_hi16("main_overlay_table_address", 0x08) \
    .const_op32_lo16("main_overlay_table_address", 0x10) \
    .build()

'''

DUAL_HEROES_SUB_SEGMENT_LOAD_PATTERN_B = SignatureBuilder() \
    .pattern([
        80136d8c 3c 0d 80 14     lui        t5,0x8014
        80136d90 00 0b 60 80     sll        t4,t3,0x2
        80136d94 01 ac 68 21     addu       t5,t5,t4
        80136d98 8d ad b5 1c     lw         t5,-0x4ae4(t5)=>PTR_DAT_8013b590                           = 8013b420
        80136d9c ac 20 12 04     sw         zero,offset DAT_80141204(at)
        80136da0 3c 01 80 0f     lui        at,0x800f
        80136da4 3c 0e 80 14     lui        t6,0x8014
        80136da8 ac 2d 1c 00     sw         t5=>DAT_8013b420,offset PTR_DAT_800f1c00(at)               = 8013b1e0
    ])
'''

def _dump_segment(rom: N64Rom,
                  segment: bytes,
                  segment_load_address: int,
                  struct_address: int) -> tuple[int,bytes,int,int,int]:

    # - +0x00 [0] ROM start address
    # - +0x04 [1] ROM end address
    # - +0x08 [2] RAM load address
    # - +0x0C [3] text segment start?
    # - +0x10 [4] text segment end?
    # - +0x14 [5] data segment start?
    # - +0x18 [6] data segment end?
    # - +0x1C [7] BSS segment start
    # - +0x20 [8] BSS segment end

    offset = struct_address - segment_load_address

    rom_start_address, \
    rom_end_address, \
    ram_load_address, \
    ram_text_segment_start_address, \
    ram_text_segment_end_address, \
    ram_data_segment_start_address, \
    ram_data_segment_end_address, \
    ram_bss_segment_start_address, \
    ram_bss_segment_end_address = struct.unpack(">IIIIIIIII", segment[offset:offset+(4*9)])

#     logger.info( \
# """segment in ROM 0x%08x-0x%08x -> RAM 0x%08x
# - text 0x%08x-0x%08x
# - data 0x%08x-0x%08x
# - bss  0x%08x-0x%08x""",
#     rom_start_address, rom_end_address, ram_load_address,
#     ram_text_segment_start_address, ram_text_segment_end_address,
#     ram_data_segment_start_address, ram_data_segment_end_address,
#     ram_bss_segment_start_address, ram_bss_segment_end_address)
    
    if (ram_text_segment_end_address-ram_text_segment_start_address) == 0:
        # logger.info("- ...not a code segment, dropping")
        return None, None, None, None, None

    return rom_start_address, \
           rom.read_bytes(rom_start_address, rom_end_address-rom_start_address), \
           ram_load_address, \
           ram_bss_segment_start_address, \
           ram_bss_segment_end_address

def _find_subsegments(rom: N64Rom,
                      segment: bytes,
                      segment_load_address: int,
                      requested_segstruct_address: int):
    
    munged_segstruct_hi, munged_segstruct_lo = munge_mips_hilo_offset(requested_segstruct_address)

    load_pattern_a = SignatureBuilder() \
    .bits(
        bytes([ 0x3c, 0x0e, 0x80, 0x00 ]) + # +0x00 lui        t6,0x8014
        bytes([ 0x00, 0x02, 0x68, 0x80 ]) + # +0x04 sll        t5,v0,0x2
        bytes([ 0x01, 0xcd, 0x70, 0x21 ]) + # +0x08 addu       t6,t6,t5
        bytes([ 0x8d, 0xce, 0x00, 0x00 ]) + # +0x0C lw         t6,xxxx(t6)
        struct.pack(">I", 0x3C010000 | (munged_segstruct_hi)) + # lui        at,0x800f
        struct.pack(">I", 0xAC2E0000 | (munged_segstruct_lo))
    ) \
    .andmask([
        0xFF, 0xFF, 0xFF, 0x00, # +0x00
        0xFF, 0xFF, 0xFF, 0xFF, # +0x04
        0xFF, 0xFF, 0xFF, 0xFF, # +0x08
        0xFF, 0xFF, 0x00, 0x00, # +0x0C
        0xFF, 0xFF, 0xFF, 0xFF, # +0x10
        0xFF, 0xFF, 0xFF, 0xFF, # +0x14
    ]) \
    .const_op32_hi16("subseg_table_address", 0x00) \
    .const_op32_lo16("subseg_table_address", 0x0C) \
    .build()

    load_pattern_b = SignatureBuilder() \
    .bits(
        bytes([ 0x3c, 0x0d, 0x80, 0x00 ]) + # +0x00 lui        t5,0x8014
        bytes([ 0x00, 0x0b, 0x60, 0x80 ]) + # +0x04 sll        t4,t3,0x2
        bytes([ 0x01, 0xac, 0x68, 0x21 ]) + # +0x08 addu       t5,t5,t4
        bytes([ 0x8d, 0xad, 0x00, 0x00 ]) + # +0x0C lw         t5,-0x4ae4(t5)
        bytes([ 0xac, 0x20, 0x00, 0x00 ]) + # +0x10 sw         zero,offset DAT_80141204(at)
        struct.pack(">I", 0x3C010000 | (munged_segstruct_hi)) + # +0x14 lui        at,0x800f
        bytes([ 0x3c, 0x0e, 0x80, 0x00 ]) + # +0x18 lui        t6,0x80xx
        struct.pack(">I", 0xAC2D0000 | (munged_segstruct_lo)) # 0x1C sw t5,xxxx($at)
    ) \
    .andmask([
        0xFF, 0xFF, 0xFF, 0x00, # +0x00
        0xFF, 0xFF, 0xFF, 0xFF, # +0x04
        0xFF, 0xFF, 0xFF, 0xFF, # +0x08
        0xFF, 0xFF, 0x00, 0x00, # +0x0C
        0xFF, 0xFF, 0x00, 0x00, # +0x10
        0xFF, 0xFF, 0xFF, 0xFF, # +0x14
        0xFF, 0xFF, 0x00, 0x00, # +0x18
        0xFF, 0xFF, 0xFF, 0xFF, # +0x1C
    ]) \
    .const_op32_hi16("subseg_table_address", 0x00) \
    .const_op32_lo16("subseg_table_address", 0x0C) \
    .build()

    segments_out = []

    for pattern in [ load_pattern_a, load_pattern_b ]:
        offsets = find_all_instances(segment, pattern)

        for offset in offsets:
            consts = pattern.consts(segment_load_address, segment, offset)
            subseg_table_address = consts["subseg_table_address"].get_value()

            logger.info("found subsegment load table at 0x%08x", subseg_table_address)

            segtable_offset = subseg_table_address - segment_load_address
            while True:
                struct_address = struct.unpack(">I", segment[segtable_offset:segtable_offset+4])[0]
                if struct_address & 0xFF000000 != 0x80000000:
                    break

                segtable_offset += 4

                subsegment_rom_address, subsegment, subsegment_load_address, bss_start, bss_end = \
                    _dump_segment(rom, segment, segment_load_address, struct_address)
                
                if None in [subsegment_rom_address, subsegment, subsegment_load_address, bss_start, bss_end]:
                    continue
                
                tup = (subsegment_rom_address, subsegment, subsegment_load_address, bss_start, bss_end)
                if tup in segments_out:
                    continue
                logger.info("subsegment: ROM 0x%08x-0x%08x -> RAM 0x%08x (bss: 0x%08x-0x%08x)",
                            subsegment_rom_address,
                            subsegment_rom_address + len(subsegment),
                            subsegment_load_address, bss_start, bss_end)

                segments_out.append(tup)

    return segments_out

def dualheroes_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    builder = BffiBuilder()
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)

    bootexe = rom.boot_exe()[:earliest_bss-ipc]

    builder.fix(ipc, bootexe)
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.initial_stack_pointer(preamble.initial_stack_pointer())

    load_and_execute_from_inbox_offset = DUAL_HEROES_LOAD_AND_EXECUTE_FROM_INBOX_FCN_PATTERN.find(bootexe)
    if load_and_execute_from_inbox_offset is None:
        return None

    consts = DUAL_HEROES_LOAD_AND_EXECUTE_FROM_INBOX_FCN_PATTERN.consts(ipc, bootexe, load_and_execute_from_inbox_offset)
    requested_segstruct_address = consts["requested_segstruct_address"].get_value()

    logger.info("found Dual Heroes segment swapper")

    main_segment_load_offset = DUAL_HEROES_MAIN_SEGMENT_LOAD_PATTERN.find(bootexe)
    if main_segment_load_offset is None:
        raise RuntimeError("cannot find main segment table!!")

    consts = DUAL_HEROES_MAIN_SEGMENT_LOAD_PATTERN.consts(ipc, bootexe, main_segment_load_offset)
    main_overlay_table_address = consts["main_overlay_table_address"].get_value()

    logger.info("main segment load table at 0x%08x", main_overlay_table_address)

    offset = main_overlay_table_address - ipc
    while True:
        struct_address = struct.unpack(">I", bootexe[offset:offset+4])[0]
        if struct_address & 0xFF000000 != 0x80000000:
            break

        segment_rom_address, segment, segment_load_address, bss_start, bss_end = \
            _dump_segment(rom, bootexe, ipc, struct_address)
        
        builder.seg(segment_load_address, segment)

        logger.info("main segment: ROM 0x%08x-0x%08x -> 0x%08x (bss 0x%08x-0x%08x)",
                    segment_rom_address, segment_rom_address + len(segment),
                    segment_load_address,
                    bss_start,
                    bss_end)
        
        logger.info("find subsegments...")
        subsegments = _find_subsegments(rom, segment, segment_load_address, requested_segstruct_address)
        logger.info("find subsegments... done")

        for subsegment in subsegments:
            segment_rom_address, segment, segment_load_address, bss_start, bss_end = subsegment
            builder.seg(segment_load_address, segment)

        offset += 4

    return builder.build()
