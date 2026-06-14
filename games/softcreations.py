'''
Software Creations games

Only games that belong in here are:
- Carmageddon 64
- Hexen

The others:
- Wayne Gretzky's 3D Hockey '98: see midway.py
- World Cup 98: see ea.py

'''

import logging
import struct

from compression.lzhexen import lzhexen_decompress
from bffi import Bffi,BffiBuilder
from n64rom import N64Rom
from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi
from signature import SignatureBuilder, WILDCARD, Signature

logger = logging.getLogger(__name__)

# ------------------------------------------------
#
# Hexen
#
# Game loads two segments.
#
# The first is compressed with some LZH variant.
# - textbuffer is 0xF80 bytes
# - LZH_N_CHAR = 381/0x17D
# - LZH_T = 763/0x2FB
# - LZH_R = 763/0x2FB
#
# The second follows the bootexe and is uncompressed.
#
# ------------------------------------------------

HEXEN_SEGMENT_LOADER_PATTERN = SignatureBuilder() \
    .pattern([
        # first segment is LZSS compressed
        0x3c, 0x0e, 0x00, WILDCARD,         # +0x00 lui        t6,0x7b <-- ROM address
        0x25, 0xce, WILDCARD, WILDCARD,     # +0x04 addiu      t6,t6,0x31f0
        0x3c, 0x01, 0x80, WILDCARD,         # +0x08 lui        at,0x8007
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x0C jal        read_16k_from_rom_76f40
        0xac, 0x2e, WILDCARD, WILDCARD,     # +0x10 _sw        t6,offset DAT_80076f40(at)
        0x3c, 0x06, 0x80, WILDCARD,         # +0x14 lui        a2,0x8007 <-- first 4 bytes
        0x3c, 0x05, 0x80, WILDCARD,         # +0x18 lui        a1,0x800d <-- load address
        0x8c, 0xc6, WILDCARD, WILDCARD,     # +0x1C lw         a2,0x6f50(a2) <-- read uncompressed size from the payload
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x20 addiu      a1,a1,-0xb20
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x24 jal        lzss_decompress
        0x00, 0x00, 0x20, 0x25,             # +0x28 _or        a0,zero,zero
        0x3c, 0x04, 0x80, WILDCARD,         # +0x2C lui        a0,0x8014 <-- first segment BSS start
        0x3c, 0x0f, 0x80, WILDCARD,         # +0x30 lui        t7,0x8015 <-- first segment BSS end
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x34 addiu      a0,a0,-0x3850
        0x25, 0xef, WILDCARD, WILDCARD,     # +0x38 addiu      t7,t7,-0x52c0
        0x01, 0xe4, 0x30, 0x23,             # +0x3C subu       a2,t7,a0
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x40 jal        SUB_800dc940 <-- memset()
        0x00, 0x00, 0x28, 0x25,             # +0x44 _or        a1,zero,zero

        # second is in plaintext
        0x3c, 0x04, 0x00, WILDCARD,         # +0x48 lui        a0,0x2 <-- second segment ROM start
        0x3c, 0x18, 0x00, WILDCARD,         # +0x4C lui        t8,0x4 <-- second segment ROM end
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x50 addiu      a0,a0,0xff0
        0x27, 0x18, WILDCARD, WILDCARD,     # +0x54 addiu      t8,t8,-0x7d90
        0x3c, 0x05, 0x80, WILDCARD,         # +0x58 lui        a1,0x803c <-- load address
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x5C addiu      a1,a1,-0x5800
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x60 jal        readcart
        0x03, 0x04, 0x30, 0x23,             # +0x64 _subu      a2,t8,a0
        0x3c, 0x04, 0x80, WILDCARD,         # +0x68 lui        a0,0x803d <-- second segment BSS start
        0x3c, 0x19, 0x80, WILDCARD,         # +0x6C lui        t9,0x803d <-- second segment BSS end
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x70 addiu      a0,a0,0x1a80
        0x27, 0x39, WILDCARD, WILDCARD,     # +0x74 addiu      t9,t9,0x1f70
        0x03, 0x24, 0x30, 0x23,             # +0x78 subu       a2,t9,a0
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x7C jal        SUB_800dc940
        0x00, 0x00, 0x28, 0x25,             # +0x80 _or        a1,zero,zero
    ]) \
    .const_op32_hi16("lzss_segment_rom_address", 0x00) \
    .const_op32_lo16("lzss_segment_rom_address", 0x04) \
    .const_op32_hi16("lzss_segment_load_address", 0x14) \
    .const_op32_lo16("lzss_segment_load_address", 0x1C) \
    .const_op32_hi16("lzss_segment_bss_start_address", 0x2C) \
    .const_op32_lo16("lzss_segment_bss_start_address", 0x34) \
    .const_op32_hi16("lzss_segment_bss_end_address", 0x30) \
    .const_op32_lo16("lzss_segment_bss_end_address", 0x38) \
    .const_op32_hi16("raw_segment_rom_start_address", 0x48) \
    .const_op32_lo16("raw_segment_rom_start_address", 0x50) \
    .const_op32_hi16("raw_segment_rom_end_address", 0x4C) \
    .const_op32_lo16("raw_segment_rom_end_address", 0x54) \
    .const_op32_hi16("raw_segment_load_address", 0x58) \
    .const_op32_lo16("raw_segment_load_address", 0x5C) \
    .const_op32_hi16("raw_segment_bss_start_address", 0x68) \
    .const_op32_lo16("raw_segment_bss_start_address", 0x70) \
    .const_op32_hi16("raw_segment_bss_end_address", 0x6C) \
    .const_op32_lo16("raw_segment_bss_end_address", 0x74) \
    .build()

def hexen_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    builder = BffiBuilder()
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)

    bootexe = rom.boot_exe()[:earliest_bss-ipc]

    builder.fix(ipc, bootexe)
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.initial_stack_pointer(preamble.initial_stack_pointer())

    segment_loader_offset = HEXEN_SEGMENT_LOADER_PATTERN.find(bootexe)
    if segment_loader_offset is None:
        return None
    
    logger.info("found Hexen segment loader")

    consts = HEXEN_SEGMENT_LOADER_PATTERN.consts(ipc, bootexe, segment_loader_offset)
    
    lzss_segment_rom_address = consts["lzss_segment_rom_address"].get_value()
    lzss_segment_load_address = consts["lzss_segment_load_address"].get_value()
    lzss_segment_bss_start_address = consts["lzss_segment_bss_start_address"].get_value()
    lzss_segment_bss_end_address = consts["lzss_segment_bss_end_address"].get_value()
    raw_segment_rom_start_address = consts["raw_segment_rom_start_address"].get_value()
    raw_segment_rom_end_address = consts["raw_segment_rom_end_address"].get_value()
    raw_segment_load_address = consts["raw_segment_load_address"].get_value()
    raw_segment_bss_start_address = consts["raw_segment_bss_start_address"].get_value()
    raw_segment_bss_end_address = consts["raw_segment_bss_end_address"].get_value()

    logger.info("compressed segment: ROM 0x%08x -> RAM 0x%08x (bss 0x%08x-0x%08x)",
                lzss_segment_rom_address,
                lzss_segment_load_address,
                lzss_segment_bss_start_address,
                lzss_segment_bss_end_address
                )
    
    lzh_segment = rom.read_bytes_until_end(lzss_segment_rom_address)
    lzh_segment = lzhexen_decompress(lzh_segment[4:], struct.unpack(">I", lzh_segment[:4])[0])

    builder.seg(lzss_segment_load_address, lzh_segment)

    logger.info("raw segment: ROM 0x%08x-0x%08x -> RAM 0x%08x (bss 0x%08x-0x%08x)",
                raw_segment_rom_start_address,
                raw_segment_rom_end_address,
                raw_segment_load_address,
                raw_segment_bss_start_address,
                raw_segment_bss_end_address)
    
    raw_segment = rom.read_bytes(raw_segment_rom_start_address, raw_segment_rom_end_address-raw_segment_rom_start_address)

    builder.seg(raw_segment_load_address, raw_segment)

    return builder.build()

# ------------------------------------------------
#
# Carmageddon 64
# Very likely is a single-load game
#
# This game compresses most of its resources, including game texts,
# with some LZSS variant that does not use the text buffer.
# The decompression routine is at 80015be8 in the US version.
#
# ------------------------------------------------

