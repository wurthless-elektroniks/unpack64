'''
Rareware games, all using variations on zlib deflate
GEDecompressor used as primary reference here

The boot stubs typically work by decompressing the first bit of code to
higher memory, then initialize a table of magic locations before running it.
The magic table contains pointers in ROM for additional code stubs and resources
that need to be decompressed.
'''

import struct
import logging
import zlib
import gzip

from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi
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

# this massive piece of crap initializes a table in high RAM that points to
# various zlib-compressed resources, including the main engine code segment.
# for now, i'm only extracting the engine.
BK_MAIN_EXECUTABLE_TABLE_INIT_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x02, 0x80, WILDCARD,         # +0x00 lui   v0,0x8040     <-- table base
        0x24, 0x42, WILDCARD, WILDCARD,     # +0x04 addiu v0,v0,-0x1f0
        0x3c, 0x0e, 0x00, WILDCARD,         # +0x08 lui   t6,0xf3 <-- t6 = engine code start address in ROM
        0x3c, 0x0f, WILDCARD, WILDCARD,         # +0x0C lui   t7,0xfa <-- t7 = some other resource
        0x3c, 0x18, WILDCARD, WILDCARD,         # +0x10 lui   t8,0xfe
        0x3c, 0x19, WILDCARD, WILDCARD,         # +0x14 lui   t9,0xfe
        0x3c, 0x08, WILDCARD, WILDCARD,         # +0x18 lui   t0,0xfa
        0x3c, 0x09, WILDCARD, WILDCARD,         # +0x1C lui   t1,0xfa
        0x3c, 0x0a, WILDCARD, WILDCARD,         # +0x20 lui   t2,0xfa
        0x3c, 0x0b, WILDCARD, WILDCARD,         # +0x24 lui   t3,0xfb
        0x3c, 0x0c, WILDCARD, WILDCARD,         # +0x28 lui   t4,0xfb
        0x3c, 0x0d, WILDCARD, WILDCARD,         # +0x2C lui   t5,0xfb
        0x25, 0xce, WILDCARD, WILDCARD,     # +0x30 addiu t6,t6,0x7f90 
        0x25, 0xef, WILDCARD, WILDCARD      # +0x34 addiu t7,t7,0x3fd0
    ]) \
    .const_op32_hi16("engine_start_address", 0x08) \
    .const_op32_lo16("engine_start_address", 0x30) \
    .const_op32_hi16("engine_end_address",   0x0C) \
    .const_op32_lo16("engine_end_address",   0x34) \
    .build()

# the main code segment clears its own BSS section, then reinitializes
# the OS because the bootloader stub is likely to be cleared from RAM soon.
# then it creates the idle thread, which starts the main thread, and the main
# thread loads in a code segment of its own (not sure where it comes from yet)
BK_MAINSEG_ENTRY_POINT_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xe8,             # +0x00 addiu  sp,sp,-0x18
        0xaf, 0xa4, 0x00, 0x18,             # +0x04 sw     a0,0x18(sp)
        0x3c, 0x04, 0x80, WILDCARD,         # +0x08 lui    a0,0x8028 <-- a0 = BSS start
        0x3c, 0x0e, 0x80, WILDCARD,         # +0x0C lui    t6,0x8028 <-- t6 = BSS end
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x10 addiu  a0,a0,-0x5ed0
        0xaf, 0xbf, 0x00, 0x14,             # +0x14 sw     ra,0x14(sp)
        0x25, 0xce, WILDCARD, WILDCARD,     # +0x18 addiu  t6,t6,0x6f90
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x1C jal    FUN_80263b40    <-- memory clear function
    ]) \
    .const_op32_hi16("bss_start", 0x08) \
    .const_op32_lo16("bss_start", 0x10) \
    .const_op32_hi16("bss_end", 0x0C) \
    .const_op32_lo16("bss_end", 0x18) \
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

    if BK_MAINSEG_ENTRY_POINT_PATTERN.compare(payload) is False:
        logger.error("oops, payload entry point mismatch")
        return None
    
    entrypoint_consts = BK_MAINSEG_ENTRY_POINT_PATTERN.consts(payload_target_address, payload)

    main_bss_start = entrypoint_consts["bss_start"].get_value()
    main_bss_end   = entrypoint_consts["bss_end"].get_value()

    magic_table_init_offset = BK_MAIN_EXECUTABLE_TABLE_INIT_PATTERN.find(rom.boot_exe()[:0x2000])
    if magic_table_init_offset is None:
        logger.error("magic table init function wasn't found. can't extract engine code.")
        return None
    
    logger.info("magic table init function at 0x%08x", magic_table_init_offset + ipc)
    
    magic_table_consts = BK_MAIN_EXECUTABLE_TABLE_INIT_PATTERN.consts(ipc, rom.boot_exe(), magic_table_init_offset)

    engine_start_address = magic_table_consts["engine_start_address"].get_value()
    engine_end_address   = magic_table_consts["engine_end_address"].get_value()
    
    engine_compressed_payload = rom.read_bytes(engine_start_address, engine_end_address-engine_start_address)
    if engine_compressed_payload[0:2] != bytes([0x11, 0x72]):
        logger.error("engine payload at 0x%08x in ROM did not start with 11 72 magic", engine_start_address)
        return None
    logger.info("compressed engine code in ROM at 0x%08x~0x%08x, decompressing it", engine_start_address, engine_end_address)
    engine_decompressed_size = struct.unpack(">I", engine_compressed_payload[2:6])[0]
    engine_payload = zlib.decompress(engine_compressed_payload[6:], wbits=-15)
    if len(engine_payload) != engine_decompressed_size:
        logger.error("decompressed engine size mismatch: expected %d, got %d", engine_decompressed_size, len(engine_payload))
        return None

    logger.info("decompressed engine code OK.")

    builder = BffiBuilder()

    earliest_bss_address, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)

    logger.info("main BSS segment 0x%08x~0x%08x", main_bss_start, main_bss_end)
    builder.bss(main_bss_start, main_bss_end-main_bss_start)

    builder.fix(ipc, rom.boot_exe()[:earliest_bss_address-ipc], segment_id=0)
    logger.info("fix segment with osInitialize and deflate routines: 0x%08x~0x%08x", ipc, earliest_bss_address)

    # this segment contains another copy of osInitialize()
    # so it *might* be okay to nuke the main bootloader stub and just use this instead
    # and yes i know there's a complete decomp available
    builder.seg(payload_target_address, payload)

    # the engine segment should be dropped in RDRAM right after the main exe's bss segment.
    # not sure if this is a fix segment or not, but its size is massive, so it might stay in RDRAM.
    builder.seg(main_bss_end, engine_payload)

    # deflate() stub still has to run because the rare programmers put osInitialize() in it
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.initial_stack_pointer(preamble.initial_stack_pointer())

    return builder.build()

# ---------------------------------------------------------------
#
# Blast Corps
# Standard gzip
#
# ---------------------------------------------------------------

BLASTCORPS_BOOTLOADER_DECOMPRESS_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xc0,             # +0x00 addiu sp,sp,-0x40
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x04 jal   FUN_80220c40  <-- osInitialize() or something like it
        0x00, 0x80, 0xe0, 0x25,             # +0x08 _or   gp,a0,zero
        0x3c, 0x05, WILDCARD, WILDCARD,     # +0x0C lui   a1,0x78       <-- start of main code gzip
        0x3c, 0x07, WILDCARD, WILDCARD,     # +0x10 lui   a3,0x7e       <-- end of main code gzip
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x14 addiu a1,a1,0x7fd0
        0x3c, 0x06, WILDCARD, WILDCARD,     # +0x18 lui   a2,0x8000     <-- where it gets dumped in RDRAM
        0x24, 0xe7, WILDCARD, WILDCARD,     # +0x1C addiu a3,a3,0x3bf0
        0x24, 0x04, 0x00, 0x00,             # +0x20 li    a0,0x0
        0x34, 0xc6, WILDCARD, WILDCARD,     # +0x24 ori   a2,a2,0x400
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x28 jal   FUN_80220e70  <-- start PI DMA
        0x00, 0xe5, 0x38, 0x22,             # +0x2C _sub  a3,a3,a1

        # spin until DMA done
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x30 jal   FUN_80220f50
        0x00, 0x00, 0x00, 0x00,             # +0x34 _nop
        0x30, 0x42, 0x00, 0x01,             # +0x38 andi  v0,v0,0x1
        0x14, 0x40, 0xff, 0xfc,             # +0x3C bne   v0,zero,LAB_80220760
        0x00, 0x00, 0x00, 0x00,             # +0x40 _nop

        0x3c, 0x04, WILDCARD, WILDCARD,     # +0x44 lui   a0,0x8000
        0x3c, 0x05, WILDCARD, WILDCARD,     # +0x48 lui   a1,0x8024     <-- decompress location in RDRAM
        0x3c, 0x06, WILDCARD, WILDCARD,     # +0x4C lui   a2,0x801e
        0x34, 0x84, WILDCARD, WILDCARD,     # +0x50 ori   a0,a0,0x400
        0x34, 0xa5, WILDCARD, WILDCARD,     # +0x54 ori   a1,a1,0x47c0
        0x34, 0xc6, WILDCARD, WILDCARD,     # +0x5C ori   a2,a2,0x7000
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x60 jal   FUN_80220998  <-- gzip decompress
    ]) \
    .const_op32_hi16("payload_rom_start", 0x0C) \
    .const_op32_lo16("payload_rom_start", 0x14) \
    .const_op32_hi16("payload_rom_end",   0x10) \
    .const_op32_lo16("payload_rom_end",   0x1C) \
    .const_op32_hi16("payload_target_address",  0x48) \
    .const_op32_lo16("payload_target_address",  0x54) \
    .build()

def blastcorps_unpack(rom: N64Rom, ipc: int):
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None

    if BLASTCORPS_BOOTLOADER_DECOMPRESS_PATTERN.compare(rom.boot_exe(), preamble.crt_entry_point() - ipc) is False:
        return None

    logger.info("found Blast Corps gzip unpacker stub")

    consts = BLASTCORPS_BOOTLOADER_DECOMPRESS_PATTERN.consts(ipc, rom.boot_exe(), preamble.crt_entry_point() - ipc)

    payload_target_address = consts["payload_target_address"].get_value()
    payload_rom_start = consts["payload_rom_start"].get_value()
    payload_rom_end   = consts["payload_rom_end"].get_value()

    logger.info("main executable code is in gzip in ROM at 0x%08x~0x%08x, loads to 0x0%08x",
                payload_rom_start,
                payload_rom_end,
                payload_target_address)
    
    gzipped_payload = rom.read_bytes(payload_rom_start, payload_rom_end-payload_rom_start)
    payload = gzip.decompress(gzipped_payload)

    logger.info("decompressed payload OK")

    builder = BffiBuilder()

    earliest_bss_address, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)

    builder.fix(ipc, rom.boot_exe()[:earliest_bss_address-ipc], segment_id=0)
    logger.info("fix segment with osInitialize and deflate routines: 0x%08x~0x%08x", ipc, earliest_bss_address)

    builder.fix(payload_target_address, payload, segment_id=1)

    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())

    return builder.build()

# ---------------------------------------------------------------
#
# Donkey Kong 64
# Standard gzip without filenames
#
# The boot stub on this one is a bit larger than usual because the
# game needs to detect RDRAM size. If less than 8 mbytes, it runs
# the "Expansion Pak not present" screen and halts. But if the
# Expansion Pak is present, the game decompresses the main code
# to 0x805xxxxx, initializes the big table o' magic pointers,
# and runs it.
#
# This game is the main reason why we have a "required memory size" field
# in the BFFI format.
#
# ---------------------------------------------------------------

# ---------------------------------------------------------------
#
# Banjo-Tooie
# zlib with a two-byte header that means... uh... something?
#
# ---------------------------------------------------------------
