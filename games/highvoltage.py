'''
High Voltage Software

For Allstar Baseball 2001 and NFL QB Club 2001, see iguanatlb.py
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
# Lego Racers
#
# Main thread loads main segment (at 0x033010-0x080b80) before running it.
# There are more segments though:
#
# mainseg 0x800460f0 loads 0x080b80-0x0e88b0 -> 0x800ca7c0
# mainseg 0x80045cf4 loads 0x0e88b0-0x145280 -> 0x800ca7c0
#
# The filesystem follows at 0x145280.
#
# ----------------------------------------------------------

LEGORACERS_MAIN_SEGMENT_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x11, 0x80, WILDCARD,             # +0x00 lui        s1,0x8004        <-- segment start
        0x26, 0x31, WILDCARD, WILDCARD,         # +0x04 addiu      s1,s1,-0x4320
        0x02, 0x20, 0x20, 0x21,                 # +0x08 move       a0,s1
        0x00, 0x00, 0x28, 0x21,                 # +0x0C clear      a1
        0x3c, 0x10, 0x80, WILDCARD,             # +0x10 lui        s0,0x800d        <-- segment end (incl bss)
        0x26, 0x10, WILDCARD, WILDCARD,         # +0x14 addiu      s0,s0,-0x5840
        0x02, 0x11, 0x80, 0x23,                 # +0x18 subu       s0,s0,s1
        0x0c, WILDCARD, WILDCARD, WILDCARD,     # +0x1C jal        memset
        0x02, 0x00, 0x30, 0x21,                 # +0x20 _move      a2,s0
        0x02, 0x20, 0x20, 0x21,                 # +0x24 move       a0,s1
        0x0c, WILDCARD, WILDCARD, WILDCARD,     # +0x28 jal        osInvalDCache?
        0x02, 0x00, 0x28, 0x21,                 # +0x2C _move      a1,s0
        0x02, 0x20, 0x20, 0x21,                 # +0x30 move       a0,s1
        0x0c, WILDCARD, WILDCARD, WILDCARD,     # +0x34 jal        osInvalICache
        0x02, 0x00, 0x28, 0x21,                 # +0x38 _move      a1,s0
        0x3c, 0x04, 0x80, WILDCARD,             # +0x3C lui        a0,0x8002
        0x24, 0x84, WILDCARD, WILDCARD,         # +0x40 addiu      a0,a0,0x7280
        0x00, 0x00, 0x28, 0x21,                 # +0x44 clear      a1
        0x00, 0xa0, 0x30, 0x21,                 # +0x48 move       a2,a1
        0x3c, 0x07, 0xb0, WILDCARD,             # +0x4C lui        a3,0xb003       <-- ROM start address
        0x24, 0xe7, WILDCARD, WILDCARD,         # +0x50 addiu      a3,a3,0x3010
        0x3c, 0x02, 0xb0, WILDCARD,             # +0x54 lui        v0,0xb008       <-- ROM end address
        0x24, 0x42, WILDCARD, WILDCARD,         # +0x58 addiu      v0,v0,0xb80
        0x00, 0x47, 0x10, 0x23,                 # +0x5C subu       v0,v0,a3
        0xaf, 0xb1, 0x00, 0x10,                 # +0x60 sw         s1,local_20(sp)
        0xaf, 0xa2, 0x00, 0x14,                 # +0x64 sw         v0,local_1c(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD,     # +0x68 jal        osPiStartDma
        0xaf, 0xb2, 0x00, 0x18,                 # +0x6C _sw        s2,local_18(sp)
    ]) \
    .const_op32_hi16("segment_start_address", 0x00) \
    .const_op32_lo16("segment_start_address", 0x04) \
    .const_op32_hi16("segment_end_address",   0x10) \
    .const_op32_lo16("segment_end_address",   0x14) \
    .const_op32_hi16("rom_start_address",     0x4C) \
    .const_op32_lo16("rom_start_address",     0x50) \
    .const_op32_hi16("rom_end_address",       0x54) \
    .const_op32_lo16("rom_end_address",       0x58) \
    .build()

# matches 0x80045cf4
# thank u compiler for stupid differences
LEGORACERS_SECOND_OVERLAY_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x04, 0x80, WILDCARD,         # +0x00 lui        a0,0x800d       <-- segment start
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x04 addiu      a0,a0,-0x5840
        0x00, 0x00, 0x28, 0x21,             # +0x08 clear      a1
        0x3c, 0x06, 0x80, WILDCARD,         # +0x0C lui        a2,0x8013       <-- segment end (incl bss)
        0x24, 0xc6, WILDCARD, WILDCARD,     # +0x10 addiu      a2,a2,0x2f70
        0x0c, 0x00, 0x06, 0x97,             # +0x14 jal        memset
        0x00, 0xc4, 0x30, 0x23,             # +0x18 _subu      a2,a2,a0
        0x3c, 0x11, 0x80, WILDCARD,         # +0x1C lui        s1,0x800d
        0x26, 0x31, WILDCARD, WILDCARD,     # +0x20 addiu      s1,s1,-0x5840
        0x02, 0x20, 0x20, 0x21,             # +0x24 move       a0,s1
        0x3c, 0x10, 0x80, WILDCARD,         # +0x28 lui        s0,0x8013
        0x26, 0x10, WILDCARD, WILDCARD,     # +0x2C addiu      s0,s0,-0x5a30
        0x02, 0x11, 0x80, 0x23,             # +0x30 subu       s0,s0,s1
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x34 jal        osInvalDCache?
        0x02, 0x00, 0x28, 0x21,             # +0x38 _move      a1,s0
        0x02, 0x20, 0x20, 0x21,             # +0x3C move       a0,s1
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x40 jal        osInvalICache
        0x02, 0x00, 0x28, 0x21,             # +0x44 _move      a1,s0
        0x3c, 0x04, 0x80, WILDCARD,         # +0x48 lui        a0,0x8002
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x4C addiu      a0,a0,0x7280
        0x00, 0x00, 0x28, 0x21,             # +0x50 clear      a1
        0x00, 0xa0, 0x30, 0x21,             # +0x54 move       a2,a1
        0x3c, 0x07, 0xb0, WILDCARD,         # +0x58 lui        a3,0xb00f      <-- ROM start address
        0x24, 0xe7, WILDCARD, WILDCARD,     # +0x5C addiu      a3,a3,-0x7750
        0x3c, 0x02, 0xb0, WILDCARD,         # +0x60 lui        v0,0xb014      <-- ROM end address
        0x24, 0x42, WILDCARD, WILDCARD,     # +0x64 addiu      v0,v0,0x5280
        0x00, 0x47, 0x10, 0x23,             # +0x68 subu       v0,v0,a3
        0x3c, 0x10, 0x80, WILDCARD,         # +0x70 lui        s0,0x8002
        0x26, 0x10, WILDCARD, WILDCARD,     # +0x74 addiu      s0,s0,0x7248
        0xaf, 0xb1, 0x00, 0x10,             # +0x78 sw         s1,local_28(sp)
        0xaf, 0xa2, 0x00, 0x14,             # +0x7C sw         v0,local_24(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x80 jal        osPiStartDma
        0xaf, 0xb0, 0x00, 0x18,             # +0x84 _sw        s0,local_20(sp)
    ]) \
    .const_op32_hi16("segment_start_address", 0x00) \
    .const_op32_lo16("segment_start_address", 0x04) \
    .const_op32_hi16("segment_end_address",   0x0C) \
    .const_op32_lo16("segment_end_address",   0x10) \
    .const_op32_hi16("rom_start_address",     0x58) \
    .const_op32_lo16("rom_start_address",     0x5C) \
    .const_op32_hi16("rom_end_address",       0x60) \
    .const_op32_lo16("rom_end_address",       0x64) \
    .build()

# matches 0x800460f0
# thank u compiler for stupid differences
LEGORACERS_FIRST_OVERLAY_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x11, 0x80, WILDCARD,         # +0x00 lui        s1,0x800d
        0x26, 0x31, WILDCARD, WILDCARD,     # +0x04 addiu      s1,s1,-0x5840
        0x02, 0x20, 0x20, 0x21,             # +0x08 move       a0,s1
        0x00, 0x00, 0x28, 0x21,             # +0x0C clear      a1
        0x3c, 0x10, 0x80, WILDCARD,         # +0x10 lui        s0,0x8013
        0x26, 0x10, WILDCARD, WILDCARD,     # +0x14 addiu      s0,s0,0x2f70
        0x02, 0x11, 0x80, 0x23,             # +0x18 subu       s0,s0,s1
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x1C jal        memset
        0x02, 0x00, 0x30, 0x21,             # +0x20 _move      a2,s0
        0x02, 0x20, 0x20, 0x21,             # +0x24 move       a0,s1
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x28 jal        osInvalDCache?
        0x02, 0x00, 0x28, 0x21,             # +0x2C _move      a1,s0
        0x02, 0x20, 0x20, 0x21,             # +0x30 move       a0,s1
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x34 jal        osInvalICache
        0x02, 0x00, 0x28, 0x21,             # +0x38 _move      a1,s0
        0x3c, 0x04, 0x80, WILDCARD,         # +0x3C lui        a0,0x8002
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x40 addiu      a0,a0,0x7280
        0x00, 0x00, 0x28, 0x21,             # +0x44 clear      a1
        0x00, 0xa0, 0x30, 0x21,             # +0x48 move       a2,a1
        0x3c, 0x07, 0xb0, WILDCARD,         # +0x4C lui        a3,0xb008
        0x24, 0xe7, WILDCARD, WILDCARD,     # +0x50 addiu      a3,a3,0xb80
        0x3c, 0x02, 0xb0, WILDCARD,         # +0x54 lui        v0,0xb00f
        0x24, 0x42, WILDCARD, WILDCARD,     # +0x58 addiu      v0,v0,-0x7750
        0x00, 0x47, 0x10, 0x23,             # +0x5C subu       v0,v0,a3
        0x3c, 0x10, 0x80, WILDCARD,         # +0x60 lui        s0,0x8002
        0x26, 0x10, WILDCARD, WILDCARD,     # +0x64 addiu      s0,s0,0x7248
        0xaf, 0xb1, 0x00, 0x10,             # +0x68 sw         s1,local_20(sp)
        0xaf, 0xa2, 0x00, 0x14,             # +0x6C sw         v0,local_1c(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x70 jal        osPiStartDma
        0xaf, 0xb0, 0x00, 0x18,             # +0x74 _sw        s0,local_18(sp)
    ]) \
    .const_op32_hi16("segment_start_address", 0x00) \
    .const_op32_lo16("segment_start_address", 0x04) \
    .const_op32_hi16("segment_end_address",   0x10) \
    .const_op32_lo16("segment_end_address",   0x14) \
    .const_op32_hi16("rom_start_address",     0x4C) \
    .const_op32_lo16("rom_start_address",     0x50) \
    .const_op32_hi16("rom_end_address",       0x54) \
    .const_op32_lo16("rom_end_address",       0x58) \
    .build()

def _legoracers_parse_segment(segment_load_address,
                             segment_data,
                             pattern,
                             offset):
    
    consts = pattern.consts(segment_load_address, segment_data, offset)
    segment_start_address = consts["segment_start_address"].get_value()
    segment_end_address   = consts["segment_end_address"].get_value()
    rom_start_address = consts["rom_start_address"].get_value() & 0x03FFFFFF
    rom_end_address   = consts["rom_end_address"].get_value() & 0x03FFFFFF
    segment_bin_size  = rom_end_address - rom_start_address
    bss_start_address = segment_start_address + segment_bin_size

    logger.info("segment: ROM 0x%08x-0x%08x -> RAM 0x%08x-0x%08x (bss 0x%08x-0x%08x)",
                rom_start_address,
                rom_end_address,
                segment_start_address,
                bss_start_address,
                bss_start_address,
                segment_end_address)

    return rom_start_address, rom_end_address, segment_start_address, bss_start_address, segment_end_address

def legoracers_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None

    builder = BffiBuilder()
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    bootexe = rom.boot_exe()[:earliest_bss-ipc]
    builder.fix(ipc, bootexe)
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.initial_stack_pointer(preamble.initial_stack_pointer())

    mainseg_load_offset = LEGORACERS_MAIN_SEGMENT_LOAD_PATTERN.find(bootexe)
    if mainseg_load_offset is None:
        return None
    
    logger.info("found Lego Racers main segment load")
 
    main_segment_rom_start_address, main_segment_rom_end_address, \
        main_segment_start_address, main_segment_bss_start_address, \
            main_segment_end_address = \
                _legoracers_parse_segment(ipc, bootexe, LEGORACERS_MAIN_SEGMENT_LOAD_PATTERN, mainseg_load_offset)
    
    main_segment = rom.read_bytes(main_segment_rom_start_address, main_segment_rom_end_address-main_segment_rom_start_address)
    builder.fix(main_segment_start_address, main_segment)
    builder.bss(main_segment_bss_start_address, main_segment_end_address-main_segment_bss_start_address)

    first_overlay_load_offset  = LEGORACERS_FIRST_OVERLAY_LOAD_PATTERN.find(main_segment)
    second_overlay_load_offset = LEGORACERS_SECOND_OVERLAY_LOAD_PATTERN.find(main_segment)

    if None in [ first_overlay_load_offset, second_overlay_load_offset ]:
        raise RuntimeError("cannot find one or more overlay loads in main segment")
    
    for pattern, offset in [ (LEGORACERS_FIRST_OVERLAY_LOAD_PATTERN, first_overlay_load_offset),
                             (LEGORACERS_SECOND_OVERLAY_LOAD_PATTERN, second_overlay_load_offset) ]:
        
        overlay_rom_start_address, overlay_rom_end_address, \
        overlay_start_address, overlay_bss_start_address, \
            overlay_end_address = \
                _legoracers_parse_segment(main_segment_start_address,
                                          main_segment,
                                          pattern,
                                          offset)
        
        overlay = rom.read_bytes(overlay_rom_start_address, overlay_rom_end_address-overlay_rom_start_address)
        builder.seg(overlay_start_address, overlay)
    
    return builder.build()

# ----------------------------------------------------------
#
# Paperboy
#
# Pretty much the same setup as Lego Racers, but they're passing around a
# global object pointer this time around, which throws off signature matching.
#
# 80007a60 loads the main segment: ROM 0x079ae0-0x0f19c0 -> RAM 0x800b1700.
# Main segment loads a second segment: ROM 0x0f19c0-0x1106a0 -> RAM 0x80129690.
# 
# Filesystem (LJAM) follows at 0x1106A0.
#
# ----------------------------------------------------------

PAPERBOY_MAIN_SEGMENT_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x11, 0x80, WILDCARD,             # +0x00 lui        s1,0x800b      <-- RAM start address
        0x26, 0x31, WILDCARD, WILDCARD,         # +0x04 addiu      s1,s1,0x1700
        0x02, 0x20, 0x20, 0x21,                 # +0x08 move       a0,s1
        0x00, 0x00, 0x28, 0x21,                 # +0x0C clear      a1
        0xaf, 0xb0, 0x00, 0x20,                 # +0x10 sw         s0,local_10(sp)
        0x3c, 0x10, 0x80, WILDCARD,             # +0x14 lui        s0,0x8013      <-- RAM end address, incl. bss
        0x26, 0x10, WILDCARD, WILDCARD,         # +0x18 addiu      s0,s0,-0x6970
        0x02, 0x11, 0x80, 0x23,                 # +0x1C subu       s0,s0,s1
        0xaf, 0xbf, 0x00, 0x2c,                 # +0x20 sw         ra,local_4(sp)   <-- thank u compiler
        0x0c, WILDCARD, WILDCARD, WILDCARD,     # +0x24 jal        memset
        0x02, 0x00, 0x30, 0x21,                 # +0x28 _move      a2,s0
        0x02, 0x20, 0x20, 0x21,                 # +0x2C move       a0,s1
        0x0c, WILDCARD, WILDCARD, WILDCARD,     # +0x30 jal        osInvalDCache
        0x02, 0x00, 0x28, 0x21,                 # +0x34 _move      a1,s0
        0x02, 0x20, 0x20, 0x21,                 # +0x38 move       a0,s1
        0x0c, WILDCARD, WILDCARD, WILDCARD,     # +0x3C jal        osInvalICache
        0x02, 0x00, 0x28, 0x21,                 # +0x40 _move      a1,s0
        0x26, 0x44, 0x00, 0x30,                 # +0x44 addiu      a0,s2,0x30
        0x00, 0x00, 0x28, 0x21,                 # +0x48 clear      a1
        0x00, 0xa0, 0x30, 0x21,                 # +0x4C move       a2,a1
        0x3c, 0x07, 0x00, WILDCARD,             # +0x50 lui        a3,0x8        <-- ROM start address
        0x24, 0xe7, WILDCARD, WILDCARD,         # +0x54 addiu      a3,a3,-0x6520
        0x3c, 0x02, 0x00, WILDCARD,             # +0x58 lui        v0,0xf        <-- ROM end address
        0x24, 0x42, WILDCARD, WILDCARD,         # +0x5C addiu      v0,v0,0x19c0
        0x00, 0x47, 0x10, 0x23,                 # +0x60 subu       v0,v0,a3
        0x26, 0x50, 0x00, 0x14,                 # +0x64 addiu      s0,s2,0x14
        0xaf, 0xb1, 0x00, 0x10,                 # +0x68 sw         s1,local_20(sp)
        0xaf, 0xa2, 0x00, 0x14,                 # +0x6C sw         v0,local_1c(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD,     # +0x70 jal        osPiStartDma
        0xaf, 0xb0, 0x00, 0x18,                 # +0x74 _sw        s0,local_18(sp)
    ]) \
    .const_op32_hi16("segment_start_address", 0x00) \
    .const_op32_lo16("segment_start_address", 0x04) \
    .const_op32_hi16("segment_end_address",   0x14) \
    .const_op32_lo16("segment_end_address",   0x18) \
    .const_op32_hi16("rom_start_address",     0x50) \
    .const_op32_lo16("rom_start_address",     0x54) \
    .const_op32_hi16("rom_end_address",       0x58) \
    .const_op32_lo16("rom_end_address",       0x5C) \
    .build()

# same as above but with different instruction order
PAPERBOY_SUB_SEGMENT_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x11, 0x80, WILDCARD,         # +0x00 lui        s1,0x8013      <-- RAM start address
        0x26, 0x31, WILDCARD, WILDCARD,     # +0x04 addiu      s1,s1,-0x6970
        0x02, 0x20, 0x20, 0x21,             # +0x08 move       a0,s1
        0x00, 0x00, 0x28, 0x21,             # +0x0C clear      a1
        0xaf, 0xb0, 0x00, 0x20,             # +0x10 sw         s0,local_10(sp)
        0x3c, 0x10, 0x80, WILDCARD,         # +0x14 lui        s0,0x8015      <-- RAM end address, incl. bss
        0x26, 0x10, WILDCARD, WILDCARD,     # +0x18 addiu      s0,s0,-0x7c90
        0x02, 0x11, 0x80, 0x23,             # +0x1C subu       s0,s0,s1
        0xaf, 0xbf, 0x00, 0x28,             # +0x20 sw         ra,local_8(sp) <-- thanks again compiler
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x24 jal        memset
        0x02, 0x00, 0x30, 0x21,             # +0x28 _move      a2,s0
        0x02, 0x20, 0x20, 0x21,             # +0x2C move       a0,s1
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x30 jal        osInvalDCache
        0x02, 0x00, 0x28, 0x21,             # +0x34 _move      a1,s0
        0x02, 0x20, 0x20, 0x21,             # +0x38 move       a0,s1
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x3C jal        osInvalICache
        0x02, 0x00, 0x28, 0x21,             # +0x40 _move      a1,s0
        0x00, 0x00, 0x28, 0x21,             # +0x44 clear      a1
        0x00, 0xa0, 0x30, 0x21,             # +0x48 move       a2,a1
        0x3c, 0x03, 0x80, WILDCARD,         # +0x4C lui        v1,0x8007
        0x3c, 0x07, 0x00, WILDCARD,         # +0x50 lui        a3,0xf           <-- ROM start
        0x24, 0xe7, WILDCARD, WILDCARD,     # +0x54 addiu      a3,a3,0x19c0
        0x3c, 0x02, 0x00, WILDCARD,         # +0x58 lui        v0,0x11          <-- ROM end
        0x24, 0x42, WILDCARD, WILDCARD,     # +0x5C addiu      v0,v0,0x6a0
        0x8c, 0x70, WILDCARD, WILDCARD,     # +0x60 lw         s0,-0x54fc(v1)
        0x00, 0x47, 0x10, 0x23,             # +0x64 subu       v0,v0,a3
        0xaf, 0xb1, 0x00, 0x10,             # +0x68 sw         s1,local_20(sp)
        0xaf, 0xa2, 0x00, 0x14,             # +0x6C sw         v0,local_1c(sp)
        0x26, 0x04, 0x00, 0x30,             # +0x70 addiu      a0,s0,0x30
        0x26, 0x10, 0x00, 0x14,             # +0x74 addiu      s0,s0,0x14
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x78 jal        SUB_80055cb0
        0xaf, 0xb0, 0x00, 0x18,             # +0x7C _sw        s0,local_18(sp)
    ]) \
    .const_op32_hi16("segment_start_address", 0x00) \
    .const_op32_lo16("segment_start_address", 0x04) \
    .const_op32_hi16("segment_end_address",   0x14) \
    .const_op32_lo16("segment_end_address",   0x18) \
    .const_op32_hi16("rom_start_address",     0x50) \
    .const_op32_lo16("rom_start_address",     0x54) \
    .const_op32_hi16("rom_end_address",       0x58) \
    .const_op32_lo16("rom_end_address",       0x5C) \
    .build()

def paperboy_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None

    builder = BffiBuilder()
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    bootexe = rom.boot_exe()[:earliest_bss-ipc]
    builder.fix(ipc, bootexe)
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.initial_stack_pointer(preamble.initial_stack_pointer())

    mainseg_load_offset = PAPERBOY_MAIN_SEGMENT_LOAD_PATTERN.find(bootexe)
    if mainseg_load_offset is None:
        return None
    
    logger.info("found Paperboy main segment load")
 
    main_segment_rom_start_address, main_segment_rom_end_address, \
        main_segment_start_address, main_segment_bss_start_address, \
            main_segment_end_address = \
                _legoracers_parse_segment(ipc, bootexe, PAPERBOY_MAIN_SEGMENT_LOAD_PATTERN, mainseg_load_offset)
    
    main_segment = rom.read_bytes(main_segment_rom_start_address, main_segment_rom_end_address-main_segment_rom_start_address)
    builder.fix(main_segment_start_address, main_segment)
    builder.bss(main_segment_bss_start_address, main_segment_end_address-main_segment_bss_start_address)

    sub_segment_load_offset = PAPERBOY_SUB_SEGMENT_LOAD_PATTERN.find(main_segment)
    if sub_segment_load_offset is None:
        raise RuntimeError("can't find subsegment load")
    
    overlay_rom_start_address, overlay_rom_end_address, \
    overlay_start_address, overlay_bss_start_address, \
            overlay_end_address = \
        _legoracers_parse_segment(main_segment_start_address, main_segment, PAPERBOY_SUB_SEGMENT_LOAD_PATTERN, sub_segment_load_offset)
    
    overlay = rom.read_bytes(overlay_rom_start_address, overlay_rom_end_address-overlay_rom_start_address)
    builder.seg(overlay_start_address, overlay)

    return builder.build()
