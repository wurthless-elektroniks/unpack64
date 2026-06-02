'''
EA Sports Madden NFL games

Kept separate from ea.py because it's a bit of a departure from what those games do.

These games don't use a BIGF file format, instead the unpacker will drop a table of entries
at the start of the bootexe (in normally zeroed space) before starting the game.
Each entry points to a blob in the ROM, and each blob has the following header format:
- 4 bytes offset from start of blob file to data
- 4 bytes decompressed size
- 4 bytes compressed size (AND with 0xFFFFFF to get actual size; bit 31 will be set if compressed)

'''

import struct
import logging

from compression.madden import madden_v1_decompress

from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi
from n64rom import N64Rom
from bffi import Bffi,BffiBuilder
from signature import SignatureBuilder, WILDCARD, Signature

logger = logging.getLogger(__name__)

# ----------------------------------------------------------
#
# Madden Football 64
#
# Overlay loader is at 0x8003c7e4 in the decompressed bootexe
# and takes two parameters, which look like a0=file_id and
# a1=binary_id.
#
# ----------------------------------------------------------

MADDEN64_UNPACKER_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xe8,             # +0x00 addiu sp,sp,-0x18
        0x3c, 0x03, 0xa4, 0x50,             # +0x04 lui   v1,0xa450
        0x34, 0x63, 0x00, 0x10,             # +0x08 ori   v1,v1,0x10
        0x3c, 0x05, 0xa4, 0x50,             # +0x0C lui   a1,0xa450
        0x34, 0xa5, 0x00, 0x14,             # +0x10 ori   a1,a1,0x14
        0x3c, 0x06, 0xa4, 0x50,             # +0x14 lui   a2,0xa450
        0x34, 0xc6, 0x00, 0x08,             # +0x18 ori   a2,a2,0x8
        0xaf, 0xb0, 0x00, 0x10,             # +0x1C sw    s0,0x10(sp)
        0x3c, 0x10, 0x80, 0x00,             # +0x20 lui   s0,0x8000    <-- load address
        0x36, 0x10, 0x04, 0x00,             # +0x24 ori   s0,s0,0x400
        0x3c, 0x04, 0x80, 0x20,             # +0x28 lui   a0,0x8020    <-- compressed file header
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x2C addiu a0,a0,0x6d0
        0x24, 0x02, 0x08, 0xff,             # +0x30 li    v0,0x8ff
        0xaf, 0xbf, 0x00, 0x14,             # +0x34 sw    ra,0x14(sp)
        0xac, 0x62, 0x00, 0x00,             # +0x38 sw    v0,0x0(v1)
        0x24, 0x02, 0x00, 0x0f,             # +0x3C li    v0,0xf
        0xac, 0xa2, 0x00, 0x00,             # +0x40 sw    v0,0x0(a1)
        0x24, 0x02, 0x00, 0x01,             # +0x44 li    v0,0x1
        0xac, 0xc2, 0x00, 0x00,             # +0x48 sw    v0,0x0(a2)
        0x8c, 0x82, 0x00, 0x00,             # +0x4C lw    v0,0x0(a0)   <-- offset to compressed data
        0x3c, 0x05, 0x80, 0x00,             # +0x50 lui   a1,0x8000    <-- decompress destination
        0x34, 0xa5, 0x04, 0x00,             # +0x54 ori   a1,a1,0x400
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x58 jal   madden_v1_decompress
        0x00, 0x44, 0x20, 0x21,             # +0x5C _addu a0,v0,a0
        0x24, 0x06, 0x00, WILDCARD,         # +0x60 li    a2,0xf       <-- number of entries to copy
        0x3c, 0x05, 0x80, 0x00,             # +0x64 lui   a1,0x8000    <-- address of final boot argument destination
        0x34, 0xa5, WILDCARD, WILDCARD,     # +0x68 ori   a1,a1,0x43c
        0x3c, 0x04, 0x80, WILDCARD,         # +0x6C lui   a0,0x8020    <-- address of final boot argument source
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x70 addiu a0,a0,0x6cc
    ]) \
    .const_op32_hi16("file_header_address", 0x28) \
    .const_op32_lo16("file_header_address", 0x2C) \
    .const_op32_imm16("num_files", 0x60) \
    .const_op32_hi16("file_table_dest_address", 0x64) \
    .const_op32_lo16("file_table_dest_address", 0x68) \
    .const_op32_hi16("file_table_source_address", 0x6C) \
    .const_op32_lo16("file_table_source_address", 0x70) \
    .build()

def madden64_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    if preamble.bss_sections():
        return None
    
    unpacker_stub = rom.boot_exe()

    unpacker_main_offset = preamble.crt_entry_point() - ipc
    if MADDEN64_UNPACKER_PATTERN.compare(unpacker_stub, unpacker_main_offset) is False:
        return None
    
    logger.info("found Madden Football 64 unpacker stub")

    consts = MADDEN64_UNPACKER_PATTERN.consts(ipc, unpacker_stub, unpacker_main_offset)
    file_header_address = consts["file_header_address"].get_value()
    num_files = consts["num_files"].get_value()
    file_table_dest_address = consts["file_table_dest_address"].get_value()
    file_table_source_address = consts["file_table_source_address"].get_value()
    
    file_header_offset = file_header_address - ipc

    bootexe_offset, bootexe_uncompressed_size, bootexe_compressed_size = \
        struct.unpack(">III", unpacker_stub[file_header_offset:file_header_offset+12])
    bootexe_compressed_size &= 0x00FFFFFF

    bootexe_offset += file_header_offset
    bootexe = unpacker_stub[bootexe_offset:bootexe_offset+bootexe_compressed_size]

    logger.info("decompressing bootexe...")
    bootexe = madden_v1_decompress(bootexe)

    if len(bootexe) != bootexe_uncompressed_size:
        logger.error("uncompressed bootexe size mismatch: expected %d, got %d",
                     bootexe_uncompressed_size,
                     len(bootexe))
        return None
    
    bootexe_load_address       = 0x80000400 # should always be the case
    bootexe_preamble_address   = file_table_dest_address + 4

    # move filetable into place
    logger.info("move filetable into place")
    file_table_dest_offset     = file_table_dest_address   - bootexe_load_address
    file_table_source_address  = file_table_source_address - ipc
    for _ in range(num_files + 1):
        bootexe[file_table_dest_offset:file_table_dest_offset+4] = unpacker_stub[file_table_source_address:file_table_source_address+4]
        file_table_dest_offset    -= 4
        file_table_source_address -= 4

    logger.info("checking real preamble in bootexe")
    preamble = identify_preamble(bootexe[bootexe_preamble_address-bootexe_load_address:], bootexe_preamble_address)
    if preamble is None:
        logger.error("can't identify real preamble")

    builder = BffiBuilder()
    preamble_extract_bss_sections_to_bffi(preamble, builder)
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.fix(bootexe_load_address, bootexe)

    # TODO: overlays

    return builder.build()

# ----------------------------------------------------------
#
# Madden '99
#
# ----------------------------------------------------------

# used on Madden 99 and Madden 2000
MADDEN_99_UNPACKER_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xe8,         # addiu      sp,sp,-0x18
        0x3c, 0x03, 0xa4, 0x50,         # lui        v1,0xa450
        0x34, 0x63, 0x00, 0x10,         # ori        v1,v1,0x10
        0x3c, 0x04, 0xa4, 0x50,         # lui        a0,0xa450
        0x34, 0x84, 0x00, 0x14,         # ori        a0,a0,0x14
        0x3c, 0x05, 0xa4, 0x50,         # lui        a1,0xa450
        0x34, 0xa5, 0x00, 0x08,         # ori        a1,a1,0x8
        0xaf, 0xb0, 0x00, 0x10,         # sw         s0,local_8(sp)
        0x3c, 0x10, 0x80, 0x00,         # lui        s0,0x8000
        0x36, 0x10, 0x04, 0x00,         # ori        s0,s0,0x400
        0x3c, 0x06, 0x7f, 0xff,         # lui        a2,0x7fff
        0x34, 0xc6, 0xff, 0xff,         # ori        a2,a2,0xffff
        0x24, 0x02, 0x08, 0xff,         # li         v0,0x8ff
        0xaf, 0xbf, 0x00, 0x14,         # sw         ra,local_4(sp)
        0xac, 0x62, 0x00, 0x00,         # sw         v0,0x0(v1)
        0x24, 0x02, 0x00, 0x0f,         # li         v0,0xf
        0xac, 0x82, 0x00, 0x00,         # sw         v0,0x0(a0)
        0x24, 0x02, 0x00, 0x01,         # li         v0,0x1
        0xac, 0xa2, 0x00, 0x00,         # sw         v0,0x0(a1)
        0x3c, 0x02, 0x80, 0x20,         # lui        v0,0x8020 <-- points to start of bootexe payload
        0x24, 0x47, WILDCARD, WILDCARD, # addiu      a3,v0,0xb38
    ]) \
    .build()
