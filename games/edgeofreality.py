'''
Edge of Reality "ERZ" packer

Used on:
- Monster Truck Madness 64
- Spider-Man
- Tony Hawk's Pro Skater
- Tony Hawk's Pro Skater 2
- Tony Hawk's Pro Skater 3

ERZ is actually standard RNC compression.
The RNC decompression routines look exactly the same as the ones used by Acclaim,
which makes sense because the company was founded by Rob Cohen from Iguana Entertainment.

The unpacker reads two words to start with:
- 4 bytes PI address EOF?
- 4 bytes number of entries

Each entry is four bytes long and is a relative offset.

First, get the unpack address and the base PI address of the table you want to decompress,
then, for i...n entries:
- Read from pi_base+entry_offset[i] to pi_base+entry_offset[i+1]
- If the payload is RNC ("ERZ") compressed, unpack it, otherwise copy directly to the unpack address
- Increment the unpack address by 64kbytes (0x010000)

'''

import logging
import struct

from compression.rnc import rnc_unpack
from bffi import Bffi, BffiBuilder
from n64rom import N64Rom
from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi
from signature import SignatureBuilder, WILDCARD, Signature

logger = logging.getLogger(__name__)

# found on Monster Truck Madness 64
ERZ_MTM64_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x10, 0xb0, WILDCARD,         # +0x00 _lui       s0,0xb001
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x04 jal        FUN_80002d40
        0x24, 0x04, 0x00, 0x01,             # +0x08 _li        a0,0x1
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x0C jal        FUN_80002be0
        0x24, 0x04, 0x56, 0x22,             # +0x10 _li        a0,0x5622
        0x26, 0x10, WILDCARD, WILDCARD,     # +0x14 addiu      s0,s0,0x1f10
        0x3c, 0x02, 0x80, WILDCARD,         # +0x18 lui        v0,0x8001
        0x24, 0x54, WILDCARD, WILDCARD,     # +0x1C addiu      s4,v0,0x4ec0
    ]) \
    .const_op32_hi16("erz_pi_address", 0x00) \
    .const_op32_lo16("erz_pi_address", 0x14) \
    .const_op32_hi16("load_address", 0x18) \
    .const_op32_lo16("load_address", 0x1C) \
    .build()

# found on Spiderman and all the Tony Hawk games
ERZ_GENERIC_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x10, 0xb0, WILDCARD,       # +0x00 lui        s0,0xb001     <-- resource location in ROM
        0x26, 0x10, WILDCARD, WILDCARD,   # +0x04 addiu      s0,s0,0x3b30
        0x3c, 0x02, 0x80, WILDCARD,       # +0x08 lui        v0,0x8001
        0x24, 0x54, WILDCARD, WILDCARD,   # +0x0C addiu      s4,v0,0x6ae0  <-- loads to here
    ]) \
    .const_op32_hi16("erz_pi_address", 0x00) \
    .const_op32_lo16("erz_pi_address", 0x04) \
    .const_op32_hi16("load_address", 0x08) \
    .const_op32_lo16("load_address", 0x0C) \
    .build()

ERZ_ENTRY_POINT_PATTERN = SignatureBuilder() \
    .pattern([
        0x0c, WILDCARD, WILDCARD, WILDCARD, # jal        FUN_800c16cc                                               undefined FUN_800c16cc()
        0x00, 0x00, 0x00, 0x00,             # _nop
        0x8f, 0xbf, 0x00, 0x34,             # lw         ra,local_4(sp)
        0x8f, 0xb6, 0x00, 0x30,             # lw         s6,local_8(sp)
        0x8f, 0xb5, 0x00, 0x2c,             # lw         s5,local_c(sp)
        0x8f, 0xb4, 0x00, 0x28,             # lw         s4,local_10(sp)
        0x8f, 0xb3, 0x00, 0x24,             # lw         s3,local_14(sp)
        0x8f, 0xb2, 0x00, 0x20,             # lw         s2,local_18(sp)
        0x8f, 0xb1, 0x00, 0x1c,             # lw         s1,local_1c(sp)
        0x8f, 0xb0, 0x00, 0x18,             # lw         s0,local_20(sp)
        0x03, 0xe0, 0x00, 0x08,             # jr         ra
        0x27, 0xbd, 0x00, 0x38,             # _addiu     sp,sp,0x38
    ]) \
    .xref_j_imm26("entry_point", 0) \
    .build()

def _unpack_erz_table(rom: N64Rom, table_base_pi_address: int):
    table_base_offset = table_base_pi_address & 0x03FFFFFF
    _, num_entries = struct.unpack(">II", rom.read_bytes(table_base_offset, 8))

    logger.info("ERZ table has %d entries", num_entries)

    output = bytearray()
    for i in range(num_entries):
        rel_start, rel_end = struct.unpack(">II", rom.read_bytes(table_base_offset + 8 + (i*4), 8))

        compressed_payload = rom.read_bytes(table_base_offset + 4 + rel_start, rel_end-rel_start)

        logger.info("chunk %d - %08x~%08x relative (%d bytes) - %08x~%08x phys",
                    i,
                    rel_start,
                    rel_end,
                    rel_end-rel_start,
                    table_base_offset + 4 + rel_start,
                    table_base_offset + 4 + rel_end,
                    )

        payload = None
        if compressed_payload[:3] == b'ERZ':
            compressed_payload = b'RNC' + compressed_payload[3:]
            payload = rnc_unpack(compressed_payload)
        else:
            payload = compressed_payload

        logger.info("\tactual size: %d bytes", len(payload))

        output += payload

    return output

def _pick_pattern(bootroutine: bytes) -> tuple[Signature, int]:
    erz_pattern_offset = ERZ_GENERIC_PATTERN.find(bootroutine)
    if erz_pattern_offset is not None:
        return ERZ_GENERIC_PATTERN, erz_pattern_offset
    
    erz_pattern_offset = ERZ_MTM64_PATTERN.find(bootroutine)
    if erz_pattern_offset is not None:
        return ERZ_MTM64_PATTERN, erz_pattern_offset

    return None, None

def erz_unpack(rom: N64Rom, ipc: int) -> Bffi:
    logger.info("using identify_preamble() to grab standard libultra bss-free preamble")
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None

    # find unpacker within 0x250 bytes of the entry point
    bootroutine = rom.boot_exe()[preamble.crt_entry_point()-ipc:(preamble.crt_entry_point()+0x250)-ipc]

    erz_pattern, erz_pattern_offset = _pick_pattern(bootroutine)
    if erz_pattern_offset is None:
        logger.error("can't find ERZ pattern")
        return None
    
    erz_entrypoint_offset = ERZ_ENTRY_POINT_PATTERN.find(bootroutine, erz_pattern_offset)
    if erz_entrypoint_offset is None:
        logger.error("can't find entrypoint pattern")
        return None

    # TODO: there is a second bss range that the unpacker clears... maybe add it?

    logger.info("found Edge of Reality ERZ unpacker")

    consts = erz_pattern.consts(preamble.crt_entry_point(), bootroutine, offset=erz_pattern_offset)
    erz_pi_address = consts["erz_pi_address"].get_value()
    load_address = consts["load_address"].get_value()

    logger.info("ERZ payload in PI space at 0x%08x", erz_pi_address)
    logger.info("ERZ payload is decompressed to 0x%08x", load_address)

    logger.info("attempting bootexe unpack...")
    bootexe = _unpack_erz_table(rom, erz_pi_address)
    logger.info("bootexe unpacked OK.")

    builder = BffiBuilder()
    
    # TODO: this is a hack, preamble should have initial global pointer set
    builder.initial_global_pointer(0)

    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())

    earliest_bss_address, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)

    builder.fix(ipc, rom.boot_exe()[:earliest_bss_address-ipc])
    builder.fix(load_address, bootexe)

    return builder.build()
