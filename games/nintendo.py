'''
Unsorted Nintendo games with not much segment loading
'''

import logging
import struct
import zlib

from bffi import Bffi,BffiBuilder
from n64rom import N64Rom
from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi
from signature import SignatureBuilder, WILDCARD, Signature
from sigutil import pick_pattern

logger = logging.getLogger(__name__)

# ------------------------------------------------
#
# Super Mario 64
#
# Well, guess I'm an asshole for not reading the decomp.
# This is not a single-load game, it's actually a two-load game...
#
# Anyway, this game was pretty low priority because it's been thoroughly
# torn apart by the community, but might as well add it for thoroughness...
#
# ------------------------------------------------

# see decomp, src/game/memory.c load_engine_code_segment()
SM64_LOAD_ENGINE_CODE_SEGMENT_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xd8,         # +0x00 addiu      sp,sp,-0x28
        0xaf, 0xbf, 0x00, 0x14,         # +0x04 sw         ra,local_14(sp)
        0x3c, 0x0e, 0x80, WILDCARD,     # +0x08 lui        t6,0x8037        <-- load address
        0x35, 0xce, WILDCARD, WILDCARD, # +0x0C ori        t6,t6,0x8800
        0xaf, 0xae, 0x00, 0x24,         # +0x10 sw         t6,local_4(sp)
        0x3c, 0x0f, WILDCARD, WILDCARD, # +0x14 lui        t7,0x1
        0x35, 0xef, WILDCARD, WILDCARD, # +0x18 ori        t7,t7,0x7000
        0xaf, 0xaf, 0x00, 0x20,         # +0x1C sw         t7,local_8(sp)
        0x3c, 0x18, WILDCARD, WILDCARD, # +0x20 lui        t8,0x11         <-- ROM end address
        0x3c, 0x19, WILDCARD, WILDCARD, # +0x24 lui        t9,0xf          <-- ROM start address
        0x27, 0x39, WILDCARD, WILDCARD, # +0x28 addiu      t9,t9,0x5580
        0x27, 0x18, WILDCARD, WILDCARD, # +0x2C addiu      t8,t8,-0x75f0
        0x03, 0x19, 0x40, 0x23,         # +0x30 subu       t0,t8,t9
    ]) \
    .const_op32_hi16("load_address",    0x08) \
    .const_op32_lo16("load_address",    0x0C) \
    .const_op32_hi16("rom_end_address", 0x20) \
    .const_op32_lo16("rom_end_address", 0x2C) \
    .const_op32_hi16("rom_start_address", 0x24) \
    .const_op32_lo16("rom_start_address", 0x28) \
    .build()

# europe/shindou compile it differently, probably because someone
# realized compiler optimization could be turned on
SM64_EU_LOAD_ENGINE_CODE_SEGMENT_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xe8,             # +0x00 addiu  sp,sp,-0x18
        0xaf, 0xbf, 0x00, 0x14,             # +0x04 sw     ra,local_4(sp)
        0x3c, 0x04, 0x80, WILDCARD,         # +0x08 lui    a0,0x8036
        0x3c, 0x05, WILDCARD, WILDCARD,     # +0x0C lui    a1,0x1
        0x34, 0xa5, WILDCARD, WILDCARD,     # +0x10 ori    a1,a1,0xf900
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x14 jal    FUN_802f12e0
        0x34, 0x84, WILDCARD, WILDCARD,     # +0x18 _ori   a0,a0,0xff00
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x1C jal    FUN_802ef610
        0x00, 0x00, 0x00, 0x00,             # +0x20 _nop
        0x3c, 0x04, 0x80, WILDCARD,         # +0x24 lui    a0,0x8036
        0x3c, 0x05, WILDCARD, WILDCARD,     # +0x28 lui    a1,0xc
        0x3c, 0x06, WILDCARD, WILDCARD,     # +0x2C lui    a2,0xe
        0x24, 0xc6, WILDCARD, WILDCARD,     # +0x30 addiu  a2,a2,-0x1ea0
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x34 addiu  a1,a1,0x7650
        0x0c, WILDCARD,WILDCARD, WILDCARD,  # +0x38 jal    FUN_80269758
        0x34, 0x84, WILDCARD, WILDCARD,     # +0x3C _ori   a0,a0,0xff00
    ]) \
    .const_op32_hi16("load_address", 0x24) \
    .const_op32_lo16("load_address", 0x3C) \
    .const_op32_hi16("rom_start_address", 0x28) \
    .const_op32_lo16("rom_start_address", 0x34) \
    .const_op32_hi16("rom_end_address", 0x2C) \
    .const_op32_lo16("rom_end_address", 0x30) \
    .build()

def sm64_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    builder = BffiBuilder()
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)

    bootexe = rom.boot_exe()[:earliest_bss-ipc]

    builder.fix(ipc, bootexe)
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.initial_stack_pointer(preamble.initial_stack_pointer())

    load_engine_code_pattern, \
    load_engine_code_segment_offset = pick_pattern(bootexe,
                                                   [SM64_LOAD_ENGINE_CODE_SEGMENT_PATTERN, \
                                                    SM64_EU_LOAD_ENGINE_CODE_SEGMENT_PATTERN])
    
    if load_engine_code_segment_offset is None:
        return None

    logger.info("found Super Mario 64 load_engine_code_segment()")

    consts = load_engine_code_pattern.consts(ipc, bootexe, load_engine_code_segment_offset)
    load_address = consts["load_address"].get_value()
    rom_start_address = consts["rom_start_address"].get_value()
    rom_end_address = consts["rom_end_address"].get_value()

    logger.info("engine overlay in ROM 0x%08x-0x%08x -> RAM 0x%08x",
                rom_start_address,
                rom_end_address,
                load_address)
    
    # called only once in game/main.c and never again after that
    builder.fix(load_address, rom.read_bytes(rom_start_address, rom_end_address-rom_start_address))

    return builder.build()

# ------------------------------------------------
#
# Dr. Mario 64
#
# zlib... what a yawner!!
#
# ------------------------------------------------

DRMARIO_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xe0,             # +0x00 addiu      sp,sp,-0x20
        0xaf, 0xb1, 0x00, 0x14,             # +0x04 sw         s1,0x14(sp)
        0x00, 0x80, 0x88, 0x21,             # +0x08 move       s1,a0
        0x3c, 0x04, WILDCARD, WILDCARD,     # +0x0C lui        a0,0x1       <-- 16 byte header address in ROM
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x10 addiu      a0,a0,0x1a60
        0xaf, 0xb0, 0x00, 0x10,             # +0x14 sw         s0,0x10(sp)
        0x3c, 0x10, 0x80, WILDCARD,         # +0x18 lui        s0,0x8003
        0x26, 0x10, WILDCARD, WILDCARD,     # +0x1C addiu      s0,s0,-0x63c0
        0x02, 0x00, 0x28, 0x21,             # +0x20 move       a1,s0
        0x3c, 0x06, 0x00, WILDCARD,         # +0x24 lui        a2,0x1
        0x24, 0xc6, WILDCARD, WILDCARD,     # +0x28 addiu      a2,a2,0x1a70
        0xaf, 0xbf, 0x00, 0x18,             # +0x2C sw         ra,0x18(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x30 jal        copy_from_rom
        0x00, 0xc4, 0x30, 0x23,             # +0x34 _subu      a2,a2,a0
        0x3c, 0x04, 0x00, WILDCARD,         # +0x38 lui        a0,0x1
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x3C addiu      a0,a0,0x1a7
        0x8e, 0x05, 0x00, 0x00,             # +0x40 lw         a1,0x0(s0)
        0x3c, 0x06, 0x00, WILDCARD,         # +0x44 lui        a2,0x5
        0x24, 0xc6, WILDCARD, WILDCARD,     # +0x48 addiu      a2,a2,-0x680
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x4C jal        FUN_80002380 <-- read and zlib decompress main exe
        0x00, 0xc4, 0x30, 0x23,             # +0x50 _subu      a2,a2,a0
    ]) \
    .const_op32_hi16("rom_exe_header_address", 0x0C) \
    .const_op32_lo16("rom_exe_header_address", 0x10) \
    .const_op32_hi16("rom_exe_data_start_address", 0x38) \
    .const_op32_lo16("rom_exe_data_start_address", 0x3C) \
    .const_op32_hi16("rom_exe_data_end_address", 0x44) \
    .const_op32_lo16("rom_exe_data_end_address", 0x48) \
    .build()

def drmario_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    builder = BffiBuilder()
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)

    bootexe = rom.boot_exe()[:earliest_bss-ipc]

    builder.fix(ipc, bootexe)
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.initial_stack_pointer(preamble.initial_stack_pointer())

    load_pattern_offset = DRMARIO_LOAD_PATTERN.find(bootexe)
    if load_pattern_offset is None:
        return None
    
    logger.info("found Dr. Mario zlib loader")

    consts = DRMARIO_LOAD_PATTERN.consts(ipc, bootexe, load_pattern_offset)
    rom_exe_header_address = consts["rom_exe_header_address"].get_value()
    rom_exe_data_start_address = consts["rom_exe_data_start_address"].get_value()
    rom_exe_data_end_address = consts["rom_exe_data_end_address"].get_value()
    
    header = rom.read_bytes(rom_exe_header_address, 0x10)
    load_address, entry_point, bss_start, bss_end = struct.unpack(">IIII", header)

    logger.info("compressed main segment in ROM: 0x%08x-0x%08x -> RAM 0x%08x (bss 0x%08x-0x%08x)",
                rom_exe_data_start_address,
                rom_exe_data_end_address,
                load_address,
                bss_start,
                bss_end)

    logger.info("loading and inflating the payload...")

    payload = rom.read_bytes(rom_exe_data_start_address, rom_exe_data_end_address-rom_exe_data_start_address)
    payload = zlib.decompress(payload, wbits=-15)

    logger.info("inflated OK, uncompressed size %d", len(payload))
    builder.fix(load_address, payload)
    builder.bss(bss_start, bss_end-bss_start)

    # TODO: main segment will zlib decompress other resources...
    # are any of them overlays? probably not if the game is only 4 MB

    return builder.build()
