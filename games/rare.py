'''
Rareware games, all using variations on zlib deflate
GEDecompressor used as primary reference here
'''

import struct
import logging
import zlib

from preamble import identify_preamble
from n64rom import N64Rom
from bffi import Bffi,BffiBuilder,BffiSectionType
from signature import SignatureBuilder, WILDCARD

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------
#
# Banjo-Kazooie
# Standard zlib deflate with six-byte header
# 0x11 0x72 followed by big endian 4-byte size of decompressed payload
#
# ---------------------------------------------------------------

BK_BOOTLOADER_DECOMPRESS_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xe0,              # +0x00 addiu      sp,sp,-0x20
        0x3c, 0x0e, 0x80, WILDCARD,          # +0x04 lui        t6,0x8003        <-- t6 = where to read compressed payload into RDRAM
        0x3c, 0x0f, 0x80, WILDCARD,          # +0x08 lui        t7,0x8024        <-- t7 = where to decompress payload to
        0xaf, 0xbf, 0x00, 0x14,              # +0x0C sw         ra,0x14(sp)
        0x25, 0xce, WILDCARD, WILDCARD,      # +0x10 addiu      t6,t6,-0x2b00
        0x25, 0xef, WILDCARD, WILDCARD,      # +0x14 addiu      t7,t7,-0x25e0
        0xaf, 0xa4, 0x00, 0x20,              # +0x18 sw         a0,0x20(sp)
        0xaf, 0xae, 0x00, 0x1c,              # +0x1C sw         t6,0x1c(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD,  # +0x20 jal        FUN_80001d70     <-- osInitialize()
        0xaf, 0xaf, 0x00, 0x18,              # +0x24 _sw        t7,0x18(sp)
        0x3c, 0x02, WILDCARD, WILDCARD,      # +0x28 lui        v0,0xf2          <-- v0 = start address of deflated payload in ROM
        0x3c, 0x18, WILDCARD, WILDCARD,      # +0x2C lui        t8,0xf3          <-- t8 = end address of deflated payload in ROM
        0x24, 0x45, WILDCARD, WILDCARD,      # +0x30 addiu      a1,v0,-0x6db0
        0x27, 0x18, WILDCARD, WILDCARD,      # +0x34 addiu      t8,t8,0x7f90
        0x03, 0x05, 0x38, 0x23,              # +0x38 subu       a3,t8,a1
        0x00, 0x00, 0x20, 0x25,              # +0x3C or         a0,zero,zero
        0x0c, WILDCARD, WILDCARD, WILDCARD,  # +0x40 jal        FUN_80002000     <-- start PI DMA
    ]) \
    .const_op32_hi16("payload_target_address", 0x08) \
    .const_op32_lo16("payload_target_address", 0x14) \
    .const_op32_hi16("payload_rom_start",      0x28) \
    .const_op32_lo16("payload_rom_start",      0x30) \
    .const_op32_hi16("payload_rom_end",        0x2C) \
    .const_op32_lo16("payload_rom_end",        0x34) \
    .build()

def bk_unpack(rom: N64Rom, ipc: int):
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    if BK_BOOTLOADER_DECOMPRESS_PATTERN.compare(rom.boot_exe(), preamble.crt_entry_point() - ipc) is False:
        return None
    
    logger.info("found Banjo-Kazooie unpacker stub")

    consts = BK_BOOTLOADER_DECOMPRESS_PATTERN.consts(ipc, rom.boot_exe(), preamble.crt_entry_point() - ipc)

    payload_target_address = consts["payload_target_address"].get_value()
    payload_rom_start = consts["payload_rom_start"].get_value()
    payload_rom_end   = consts["payload_rom_end"].get_value()

    compressed_payload = rom.read_bytes(payload_rom_start, payload_rom_end-payload_rom_start)

    if compressed_payload[0:2] != bytes([0x11, 0x72]):
        logger.error("payload at 0x%08x in ROM did not start with 11 72 magic", payload_rom_start)
        return None

    logger.info("payload at 0x%08x~0x%08x in ROM, decompressing it", payload_rom_start, payload_rom_end)

    decompressed_size = struct.unpack(">I", compressed_payload[2:6])[0]
    payload = zlib.decompress(compressed_payload[6:], wbits=-15)

    if len(payload) != decompressed_size:
        logger.error("decompressed payload size mismatch: expected %d, got %d", decompressed_size, len(payload))
        return None
    
    logger.info("decompress ok; payload drops to 0x%08x in RDRAM", payload_target_address)

    builder = BffiBuilder()

    earliest_bss_address = 0x80800000
    for bss_start_address,bss_end_address in preamble.bss_sections():
        logger.info("bss section: 0x%08x~0x%08x", bss_start_address, bss_end_address)
        bss_this_size = bss_end_address-bss_start_address
        builder.bss(bss_start_address, bss_this_size)

        if bss_start_address < earliest_bss_address:
            earliest_bss_address = bss_start_address

    builder.fix(ipc, rom.boot_exe()[:earliest_bss_address-ipc], segment_id=0)
    logger.info("fix segment with osInitialize and deflate routines: 0x%08x~0x%08x", ipc, earliest_bss_address)

    # this segment contains another copy of osInitialize()
    # so it *might* be okay to nuke the main bootloader stub and just use this instead
    # and yes i know there's a complete decomp available
    builder.seg(payload_target_address, payload)

    # deflate() stub still has to run because the rare programmers put osInitialize() in it
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.initial_stack_pointer(preamble.initial_stack_pointer())

    return builder.build()
