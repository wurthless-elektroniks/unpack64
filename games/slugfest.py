'''
Ken Griffey Jr.'s Slugfest and MLB feat Ken Griffey Jr.
Chunky MIO0-based nonsense

The overlay table starts with the string "*OVRDIR*", and following that are the actual entries:

- 16 bytes string identifying the filename
- 4 bytes code entry ID in ROM table
- 4 bytes data entry ID in ROM table
- 4 bytes code segment load address
- 4 bytes data segment load address
- 4 bytes BSS start address
- 4 bytes BSS end address
- 4 bytes pointer to something (data/rodata boundary, probably)
- 4 bytes always zero

If code/data entries are the same, then load as one segment.

The ROM table contains 12 byte entries of three words:
- 4 bytes ROM start address
- 4 bytes ROM end address
- 4 bytes uncompressed size; if less than 2, the resource is uncompressed

The boot segment overlay is named "toplevel".

If the file is uncompressed, it is copied directly to RDRAM, no questions asked.

The MIO0 format is a chunky subtype, read in 0x2000 (8k) chunks.

Each chunk has the following 8 byte header, which the game converts to a normal MIO0 header:
 - 2 bytes something (unpacker ignores it. crc16?)
 - 2 bytes uncompressed size of chunk
 - 2 bytes compressed offset, minus 8
 - 2 bytes uncompressed offset, minus 8

When the MIO0 decompressor performs a back-seek operation, it will read into the previously
decompressed chunks, so normal MIO0 decompressors won't support this variant by default. 

Resident Evil 2 uses a completely different unpacker.
'''

import logging
import struct

from bffi import BffiBuilder
from compression.mio0 import mio0_decompress
from n64rom import N64Rom
from preamble import preamble_extract_bss_sections_to_bffi, identify_preamble
from signature import SignatureBuilder, WILDCARD
from sigutil import pick_pattern
from strutil import extract_cstring

logger = logging.getLogger(__name__)

# --------------------------------------------------------

SLUGFEST_BOOTENTRY_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x03, 0x80, WILDCARD,        # +0x00 lui   v1,0x8006
        0x24, 0x63, WILDCARD, WILDCARD,    # +0x04 addiu v1,v1,0x7da8   <-- overlay table address
        0x8c, 0x6e, 0x00, 0x10,            # +0x08 lw    t6,0x10(v1)
        0x27, 0xbd, 0xff, 0xc8,            # +0x0C addiu sp,sp,-0x38
        0xaf, 0xb4, 0x00, 0x24,            # +0x10 sw    s4,0x24(sp)
        0x24, 0x14, 0x00, 0x0c,            # +0x14 li    s4,0xc
        0x01, 0xd4, 0x00, 0x19,            # +0x18 multu t6,s4
        0xaf, 0xb1, 0x00, 0x18,            # +0x1C sw    s1,0x18(sp)
        0x3c, 0x11, 0x80, WILDCARD,        # +0x20 lui   s1,0x8006
        0x26, 0x31, WILDCARD, WILDCARD,    # +0x24 addiu s1,s1,0x6eb8   <-- ROM resource location table address
    ]) \
    .const_op32_hi16("overlay_table_address", 0x00) \
    .const_op32_lo16("overlay_table_address", 0x04) \
    .const_op32_hi16("rom_location_table", 0x20) \
    .const_op32_lo16("rom_location_table", 0x24) \
    .build()

# griffey mlb has different instruction order
GRIFFEY_BOOTENTRY_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x03, 0x80, WILDCARD,        # +0x00 lui   v1,0x8006
        0x24, 0x63, WILDCARD, WILDCARD,    # +0x04 addiu v1,v1,0x7da8   <-- overlay table address
        0x27, 0xbd, 0xff, 0xc8,            # +0x08 addiu sp,sp,-0x38    <-- reordered
        0x8c, 0x6e, 0x00, 0x10,            # +0x0C lw    t6,0x10(v1)    <-- reordered
        0xaf, 0xb4, 0x00, 0x24,            # +0x10 sw    s4,0x24(sp)
        0x24, 0x14, 0x00, 0x0c,            # +0x14 li    s4,0xc
        0x01, 0xd4, 0x00, 0x19,            # +0x18 multu t6,s4
        0xaf, 0xb1, 0x00, 0x18,            # +0x1C sw    s1,0x18(sp)
        0x3c, 0x11, 0x80, WILDCARD,        # +0x20 lui   s1,0x8006
        0x26, 0x31, WILDCARD, WILDCARD,    # +0x24 addiu s1,s1,0x6eb8   <-- ROM resource location table address
    ]) \
    .const_op32_hi16("overlay_table_address", 0x00) \
    .const_op32_lo16("overlay_table_address", 0x04) \
    .const_op32_hi16("rom_location_table", 0x20) \
    .const_op32_lo16("rom_location_table", 0x24) \
    .build()

def _slugfest_unpack_chunky_mio0(chunky_data: bytes, output_size: int):
    output = bytearray([0] * output_size)

    offset = 0
    output_offset = 0
    while offset < len(chunky_data):
        read_count = min(len(chunky_data) - offset, 0x2000)
        chunk = chunky_data[offset:offset + read_count]
        
        # logger.debug("offset %08x", offset)
        offset += read_count

        _, uncomp_size, comp_offset, uncomp_offset = struct.unpack(">HHHH", chunk[:8])
    
        # this is actually what the game does; it's a bit janky, but it works.
        comp_offset += 8
        uncomp_offset += 8

        mio0data = struct.pack(">IIII",
                               0x4D494F30,
                               uncomp_size,
                               comp_offset,
                               uncomp_offset) + chunk[8:]

        # in this variant, backseeking goes into the previous chunks we've decompressed
        uncompressed_chunk, output_offset = mio0_decompress(mio0data,
                                             output_buffer=output,
                                             output_offset=output_offset)

        if uncompressed_chunk is None:
            return None
        
    return output

def _load_overlay_segment(rom: N64Rom, bootexe: bytes, ipc: int, rom_location_table: int, rom_entry_id: int):
    rom_entry_offset = (rom_location_table - ipc) + (rom_entry_id * 12)
    rom_start_address, rom_end_address, uncompressed_size = \
        struct.unpack(">III", bootexe[rom_entry_offset:rom_entry_offset+12])

    logger.info("- rom location 0x%08x~0x%08x", rom_start_address, rom_end_address)
    logger.info("- uncompressed size %d byte(s)", uncompressed_size)

    overlay = rom.read_bytes(rom_start_address, rom_end_address-rom_start_address)

    # uncompress if needed
    if uncompressed_size >= 2:
        overlay = _slugfest_unpack_chunky_mio0(overlay, uncompressed_size)

    if overlay is None:
        return None
    
    return overlay

def slugfest_unpack(rom: N64Rom, ipc: int):
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    builder = BffiBuilder()
    earliest_bss_address, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    bootexe = rom.boot_exe()[:earliest_bss_address-ipc]

    builder.fix(ipc, bootexe)
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())

    crt_entry_offset = preamble.crt_entry_point() - ipc

    bootentry_pattern, _ = pick_pattern(bootexe,
                                     [GRIFFEY_BOOTENTRY_PATTERN, SLUGFEST_BOOTENTRY_PATTERN],
                                     comparing_at_offset=crt_entry_offset)
    if bootentry_pattern is None:
        return None
    
    logger.info("found Griffey/Slugfest unpacker")
    consts = bootentry_pattern.consts(ipc, bootexe, crt_entry_offset)

    overlay_table_address = consts["overlay_table_address"].get_value()
    rom_location_table = consts["rom_location_table"].get_value()

    logger.info("overlay table in RAM at 0x%08x", overlay_table_address)
    logger.info("ROM data table in RAM at 0x%08x", rom_location_table)

    overlay_table_read_offset = overlay_table_address - ipc
    while True:
        overlay_name = extract_cstring(bootexe[overlay_table_read_offset:overlay_table_read_offset+0x10])

        if overlay_name == "":
            break

        logger.info("overlay: %s", overlay_name)

        code_section_rom_entry_id, \
        data_section_rom_entry_id, \
        code_load_address, \
        data_load_address, \
        bss_start_address, \
        bss_end_address = \
            struct.unpack(">IIIIII", bootexe[overlay_table_read_offset+0x10:overlay_table_read_offset+0x28])
        overlay_table_read_offset += 0x30

        logger.info("\tcode (rom entry %2d): 0x%08x-0x%08x", code_section_rom_entry_id, code_load_address, data_load_address)
        logger.info("\tdata (rom entry %2d): 0x%08x-0x%08x", data_section_rom_entry_id, data_load_address, bss_start_address)
        logger.info("\t                bss: 0x%08x-0x%08x", bss_start_address, bss_end_address)

        combined_code_data = bytearray()
        if code_section_rom_entry_id == data_section_rom_entry_id:
            combined_code_data = _load_overlay_segment(rom, bootexe, ipc, rom_location_table, code_section_rom_entry_id)
        else:
            code = _load_overlay_segment(rom, bootexe, ipc, rom_location_table, code_section_rom_entry_id)
            data = _load_overlay_segment(rom, bootexe, ipc, rom_location_table, data_section_rom_entry_id)
            combined_code_data = code + data

        builder.seg(code_load_address, combined_code_data)
    
    return builder.build()
