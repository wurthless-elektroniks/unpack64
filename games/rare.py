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
from mips import make_andmask_load_store, make_andmask_reg_opcode
from n64rom import N64Rom
from bffi import Bffi,BffiBuilder,BffiSectionType
from signature import SignatureBuilder, WILDCARD
from sigutil import pick_pattern, contains_code

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

DK64_U_IDLETHREAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x0e, 0x80, 0x00,         # +0x00 lui        t6,0x8000
        0x8d, 0xce, 0x03, 0x18,         # +0x04 lw         t6,offset DAT_80000318(t6) <-- osMemSize
        0x3c, 0x01, 0x00, 0x80,         # +0x08 lui        at,0x80
        0x3c, 0x0f, 0x80, 0x00,         # +0x0C lui        t7,0x8000
        0x01, 0xc1, 0x08, 0x2b,         # +0x10 sltu       at,t6,at
        0x14, 0x20, 0x00, 0x06,         # +0x14 bne        at,zero,LAB_800006b0       <-- expansionpak not present path
        0x3c, 0x02, WILDCARD, WILDCARD, # +0x18 _lui       v0,0x8001
        0x8d, 0xef, 0x03, 0x00,         # +0x1C lw         t7,offset DAT_80000300(t7) <-- no idea what this is
        0x3c, 0x04, WILDCARD, WILDCARD, # +0x20 lui        a0,0x1                     <-- a0 = small uncompressed code section
        0x24, 0x84, WILDCARD, WILDCARD, # +0x24 addiu      a0,a0,0x1320
        0x15, 0xe0, 0x00, 0x0b,         # +0x28 bne        t7,zero,LAB_800006d8       <-- happy path if this is taken
        0x3c, 0x05, WILDCARD, WILDCARD, # +0x2C _lui       a1,0x1                     <-- a1 = end of code section

        # "expansionpak not present" path
        # we don't care about the resources being setup here, we're skipping over this entirely
        0x3c, 0x08, WILDCARD, WILDCARD,     # +0x30 lui   t0,0x10
        0x3c, 0x09, WILDCARD, WILDCARD,     # +0x34 lui   t1,0x189
        0x24, 0x42, WILDCARD, WILDCARD,     # +0x38 addiu v0,v0,-0x233c
        0x25, 0x29, WILDCARD, WILDCARD,     # +0x3C addiu t1,t1,-0x50e0
        0x25, 0x08, WILDCARD, WILDCARD,     # +0x40 addiu t0,t0,0x1c50
        0xac, 0x48, WILDCARD, WILDCARD,     # +0x44 sw    t0,0x108(v0)=>DAT_8000ddcc
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x48 jal   FUN_80000a30
        0xac, 0x49, WILDCARD, WILDCARD,     # +0x4C _sw   t1,0x10c(v0)=>DAT_8000ddd0
        0x10, 0x00, 0x00, 0x9e,             # +0x50 b     LAB_8000094c
        0x00, 0x00, 0x00, 0x00,             # +0x54 _nop

        # happy path: load/decompress initial code overlays,
        # setup magic table, and start the game
        0x3c, 0x06, 0x80, WILDCARD,          # +0x58 lui        a2,0x805f     <-- where to copy small uncompressed section
        0x34, 0xc6, WILDCARD, WILDCARD,      # +0x5C ori        a2,a2,0xb000
        0x0c, WILDCARD, WILDCARD, WILDCARD,  # +0x60 jal        FUN_80000450
        0x24, 0xa5, WILDCARD, WILDCARD,      # +0x64 _addiu     a1,a1,0x13f0  <-- lo16 end of uncompressed section (finally!)

        # brief intermission to set audio sample rate to 22050 Hz
        0x0c, WILDCARD, WILDCARD, WILDCARD,  # +0x68 jal        FUN_80005070
        0x24, 0x04, 0x56, 0x22,              # +0x6C _li        a0,0x5622

        # okay, back to the task at hand: decompressing the main executable.
        # first clear about 2 MB of RAM where we're about to dump all this crap
        0x3c, 0x01, WILDCARD, WILDCARD,      # +0x70 lui        at,0x8001
        0x3c, 0x04, WILDCARD, WILDCARD,      # +0x74 lui        a0,0x805f      <-- a0 = start of code section
        0x3c, 0x05, WILDCARD, WILDCARD,      # +0x78 lui        a1,0x20        <-- a1 = size of memzero() operation in bytes
        0xac, 0x22, WILDCARD, WILDCARD,      # +0x7C sw         v0,-0x234c(at)
        0x34, 0xa5, WILDCARD, WILDCARD,      # +0x80 ori        a1,a1,0x4d00
        0x0c, WILDCARD, WILDCARD, WILDCARD,  # +0x84 jal        FUN_800051c0   <-- memzero() function
        0x34, 0x84, WILDCARD, WILDCARD,      # +0x88 _ori       a0,a0,0xb300

        # copy gzipped payload to RAM and decompress it
        0x3c, 0x0a, WILDCARD, WILDCARD,      # +0x8C lui        t2,0x805f      <-- t2 is where we drop the uncompressed code
        0x3c, 0x06, WILDCARD, WILDCARD,      # +0x90 lui        a2,0x8002      <-- a2 is where we cache the compressed code
        0x35, 0x4a, WILDCARD, WILDCARD,      # +0x94 ori        t2,t2,0xb300
        0x3c, 0x04, WILDCARD, WILDCARD,      # +0x98 lui        a0,0x1         <-- a0 = gzip payload start address in ROM
        0x3c, 0x05, WILDCARD, WILDCARD,      # +0x9C lui        a1,0xd         <-- a1 = gzip payload end address in ROM
        0xaf, 0xa6, 0x00, 0x34,              # +0xA0 sw         a2,0x34(sp)
        0xaf, 0xaa, 0x00, 0x30,              # +0xA4 sw         t2,0x30(sp)
        0x24, 0xa5, WILDCARD, WILDCARD,      # +0xA8 addiu      a1,a1,-0x4190
        0x0c, WILDCARD, WILDCARD, WILDCARD,  # +0xAC jal        FUN_80000450
        0x24, 0x84, WILDCARD, WILDCARD,      # +0xB0 _addiu     a0,a0,0x13f0
    ]) \
    .const_op32_hi16("small_segment_start", 0x20) \
    .const_op32_lo16("small_segment_start", 0x24) \
    .const_op32_hi16("small_segment_end", 0x2C) \
    .const_op32_lo16("small_segment_end", 0x64) \
    .const_op32_hi16("small_segment_load_address", 0x58) \
    .const_op32_lo16("small_segment_load_address", 0x5C) \
    .const_op32_hi16("code_section_bss_address", 0x74) \
    .const_op32_lo16("code_section_bss_address", 0x88) \
    .const_op32_hi16("code_section_bss_size", 0x78) \
    .const_op32_lo16("code_section_bss_size", 0x80) \
    .const_op32_hi16("code_section_load_address", 0x8C) \
    .const_op32_lo16("code_section_load_address", 0x94) \
    .const_op32_hi16("code_section_gz_rom_start", 0x98) \
    .const_op32_lo16("code_section_gz_rom_start", 0xB0) \
    .const_op32_hi16("code_section_gz_rom_end",   0x9C) \
    .const_op32_lo16("code_section_gz_rom_end",   0xA8) \
    .build()

# compiler optimizations and code differences mean a different pattern is needed
# for the japanese and european versions
DK64_J_IDLETHREAD_PATTERN = SignatureBuilder() \
    .pattern([
        # we pick up just after the memory check
        0x11, 0xc0, 0x00, 0x0c,         # +0x00 beq        t6,zero,LAB_80000788
        0x3c, 0x04, WILDCARD, WILDCARD, # +0x04 _lui       a0,0x1

        # unhappy path: display "expansion pak not found" message and stop
        0x3c, 0x02, WILDCARD, WILDCARD,     # +0x08 lui   v0,0x8001
        0x3c, 0x08, WILDCARD, WILDCARD,     # +0x0C lui   t0,0x10
        0x3c, 0x09, WILDCARD, WILDCARD,     # +0x10 lui   t1,0x189
        0x24, 0x42, WILDCARD, WILDCARD,     # +0x14 addiu v0,v0,-0x20cc
        0x25, 0x29, WILDCARD, WILDCARD,     # +0x18 addiu t1,t1,-0x2500
        0x25, 0x08, WILDCARD, WILDCARD,     # +0x1C addiu t0,t0,0x39c0
        0xac, 0x48, WILDCARD, WILDCARD,     # +0x20 sw    t0,0x108(v0)=>DAT_8000e03c
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x24 jal   FUN_80000ad0
        0xac, 0x49, WILDCARD, WILDCARD,     # +0x28 _sw   t1,0x10c(v0)=>DAT_8000e040
        0x10, 0x00, WILDCARD, WILDCARD,     # +0x2C b     LAB_80000a04
        0x00, 0x00, 0x00, 0x00,             # +0x30 _nop

        # happy path
        # copy the small uncompressed section to memory
        0x3c, 0x05, WILDCARD, WILDCARD,     # +0x34 lui    a1,0x1
        0x3c, 0x06, WILDCARD, WILDCARD,     # +0x38 lui    a2,0x805f
        0x34, 0xc6, WILDCARD, WILDCARD,     # +0x3C ori    a2,a2,0x8800
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x40 addiu  a1,a1,0x16f0
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x44 jal    FUN_800004cc
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x48 _addiu a0,a0,0x1620

        # set sampling rate to 22050 Hz
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x4C jal FUN_800052e0
        0x24, 0x04, 0x56, 0x22,             # +0x50 _li a0,0x5622
        
        # clear memory range where we're dropping the main code segment
        0x3c, 0x01, WILDCARD, WILDCARD,     # +0x54 lui  at,0x8001
        0x3c, 0x04, WILDCARD, WILDCARD,     # +0x58 lui  a0,0x805f
        0x3c, 0x05, WILDCARD, WILDCARD,     # +0x5C lui  a1,0x20
        0xac, 0x22, WILDCARD, WILDCARD,     # +0x60 sw   v0,-0x20dc(at)=>DAT_8000df24
        0x34, 0xa5, WILDCARD, WILDCARD,     # +0x64 ori  a1,a1,0x7500
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x68 jal  FUN_80005430
        0x34, 0x84, WILDCARD, WILDCARD,     # +0x6C _ori a0,a0,0x8b00
        
        # read the compressed payload into RDRAM and unpack it
        0x3c, 0x0a, WILDCARD, WILDCARD,     # +0x70 lui        t2,0x805f
        0x3c, 0x06, WILDCARD, WILDCARD,     # +0x74 lui        a2,0x8002
        0x35, 0x4a, WILDCARD, WILDCARD,     # +0x78 ori        t2,t2,0x8b00
        0x3c, 0x04, WILDCARD, WILDCARD,     # +0x7C lui        a0,0x1
        0x3c, 0x05, WILDCARD, WILDCARD,     # +0x80 lui        a1,0xd
        0xaf, 0xa6, WILDCARD, WILDCARD,     # +0x84 sw         a2,0x3c(sp)
        0xaf, 0xaa, WILDCARD, WILDCARD,     # +0x88 sw         t2,0x38(sp)
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x8C addiu      a1,a1,-0x27c0
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x90 jal        FUN_800004cc
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x94 _addiu     a0,a0,0x16f0
    ]) \
    .const_op32_hi16("small_segment_start", 0x04) \
    .const_op32_lo16("small_segment_start", 0x48) \
    .const_op32_hi16("small_segment_end", 0x34) \
    .const_op32_lo16("small_segment_end", 0x40) \
    .const_op32_hi16("small_segment_load_address", 0x38) \
    .const_op32_lo16("small_segment_load_address", 0x3C) \
    .const_op32_hi16("code_section_bss_address", 0x58) \
    .const_op32_lo16("code_section_bss_address", 0x6C) \
    .const_op32_hi16("code_section_bss_size", 0x5C) \
    .const_op32_lo16("code_section_bss_size", 0x64) \
    .const_op32_hi16("code_section_load_address", 0x70) \
    .const_op32_lo16("code_section_load_address", 0x78) \
    .const_op32_hi16("code_section_gz_rom_start", 0x7C) \
    .const_op32_lo16("code_section_gz_rom_start", 0x94) \
    .const_op32_hi16("code_section_gz_rom_end",   0x80) \
    .const_op32_lo16("code_section_gz_rom_end",   0x8C) \
    .build()

def dk64_unpack(rom: N64Rom, ipc: int) -> Bffi:
    idlethread_pattern, idlethread_pos = \
        pick_pattern(rom.boot_exe()[:0x2000],
                     [DK64_U_IDLETHREAD_PATTERN, DK64_J_IDLETHREAD_PATTERN])

    if idlethread_pos is None:
        logger.error("idlethread not found")
        return None

    logger.info("found Donkey Kong 64 unpacker")

    logger.info("idle thread code is at 0x%08x", ipc + idlethread_pos)
    consts = idlethread_pattern.consts(ipc, rom.boot_exe(), idlethread_pos)

    logger.info("now identifying preamble...")
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    builder = BffiBuilder()

    builder.required_memory_size(8)

    earliest_bss_section, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    builder.fix(ipc, rom.boot_exe()[:earliest_bss_section-ipc], segment_id=0)
    
    small_segment_start         = consts["small_segment_start"].get_value()
    small_segment_end           = consts["small_segment_end"].get_value()
    small_segment_load_address  = consts["small_segment_load_address"].get_value()
    code_section_bss_address = consts["code_section_bss_address"].get_value()
    code_section_bss_size    = consts["code_section_bss_size"].get_value()
    code_section_load_address = consts["code_section_load_address"].get_value()
    code_section_gz_rom_start = consts["code_section_gz_rom_start"].get_value()
    code_section_gz_rom_end = consts["code_section_gz_rom_end"].get_value()

    logger.info("small segment loads from ROM 0x%08x~0x%08x -> RDRAM 0x%08x",
                small_segment_start,
                small_segment_end,
                small_segment_load_address)
    
    builder.fix(small_segment_load_address,
                rom.read_bytes(small_segment_start,small_segment_end-small_segment_start),
                segment_id=1)
    
    logger.info("main code section BSS: 0x%08x~0x%08x", code_section_bss_address, code_section_bss_size+code_section_bss_address)
    builder.bss(code_section_bss_address, code_section_bss_size)

    logger.info("main code gzip payload in ROM at 0x%08x~0x%08x, loads to 0x%08x",
                code_section_gz_rom_start,
                code_section_gz_rom_end,
                code_section_load_address)
    
    gzipped_payload = rom.read_bytes(code_section_gz_rom_start, code_section_gz_rom_end-code_section_gz_rom_start)
    payload = gzip.decompress(gzipped_payload)

    logger.info("decompressed main payload OK")

    builder.fix(code_section_load_address, payload, segment_id=2)

    builder.initial_program_counter(preamble.crt_entry_point())
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    return builder.build()

# ---------------------------------------------------------------
#
# Banjo-Tooie
# zlib with a two-byte header that means... uh... something?
#
# ---------------------------------------------------------------

# ---------------------------------------------------------------
#
# Killer Instinct Gold
# 
# Boot stub loads main overlay, which is zlib with a "11 72" magic word.
#
# As usual in Rare games, overlay loading is a pain to trace:
#
# - 0x80000900 is the deflate routine
# - 0x800121c8 loads the second overlay in the main table (=0x800071f8/fc) to 0x801abb20 and runs it
# - 0x8000fa80 loads the third overlay in the main table (=0x80007200/04) to 0x801ad900 and then
#   eventually some callback loaded from that is run
# - 0x80012a8c reads overlay table starting from 0x80007260 and grabs the load
#   addresses from 0x80044df4, but the addresses in that table are always 0x802D4000
# - 0x80012100 takes two ints and then uses them to read compressed data from the overlay
#   table starting at 0x80007208/0C. This is probably loading scripting data for the characters.
#
# The first three entries in the overlay table contain code
# (probably main, frontend and ingame, in that order.)
# These are followed by what I think are scripting data, as they don't seem to
# contain any MIPS machine code.
# 
# ---------------------------------------------------------------

KIG_MAIN_SEGMENT_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x02, 0x80, WILDCARD,         # +0x00 lui   v0,0x8000 <-- overlay table address
        0x24, 0x42, WILDCARD, WILDCARD,     # +0x04 addiu v0,v0,0x71f0
        0x8c, 0x44, 0x00, 0x00,             # +0x08 lw    a0,0x0(v0)
        0x8c, 0x4f, 0x00, 0x04,             # +0x0C lw    t7,0x4(v0)
        0x3c, 0x05, 0x80, WILDCARD,         # +0x10 lui   a1,0x802d
        0x34, 0xa5, WILDCARD, WILDCARD,     # +0x14 ori   a1,a1,0x4000
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x18 jal   readcart
        0x01, 0xe4, 0x30, 0x23,             # +0x1C _subu a2,t7,a0
        0x3c, 0x04, 0x80, WILDCARD,         # +0x20 lui   a0,0x802d
        0x3c, 0x05, 0x80, WILDCARD,         # +0x24 lui   a1,0x8000 <-- load address
        0x3c, 0x06, 0x80, WILDCARD,         # +0x28 lui   a2,0x803a
        0x34, 0xc6, WILDCARD, WILDCARD,     # +0x2C ori   a2,a2,0x2000
        0x34, 0xa5, WILDCARD, WILDCARD,     # +0x30 ori   a1,a1,0xf960
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x34 jal   deflate
        0x34, 0x84, WILDCARD, WILDCARD,     # +0x38 _ori  a0,a0,0x4000
    ]) \
    .const_op32_hi16("overlay_table_address", 0x00) \
    .const_op32_lo16("overlay_table_address", 0x04) \
    .const_op32_hi16("load_address", 0x24) \
    .const_op32_lo16("load_address", 0x30) \
    .build()

KIG_OVERLAY_2_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x02, 0x80, 0x00,             # +0x00 lui        v0,0x8000 <-- should match base of overlay table
        0x24, 0x42, WILDCARD, WILDCARD,     # +0x04 addiu      v0,v0,0x71f0
        0x8c, 0x44, WILDCARD, WILDCARD,     # +0x08 lw         a0,0x8(v0)=>DAT_800071f8
        0x8c, 0x59, WILDCARD, WILDCARD,     # +0x0C lw         t9,0xc(v0)=>DAT_800071fc
        0x3c, 0x05, 0x80, WILDCARD,         # +0x10 lui        a1,0x802d <-- buffer for deflated data
        0x34, 0xa5, WILDCARD, WILDCARD,     # +0x14 ori        a1,a1,0x6000
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x18 jal        SUB_800007b4
        0x03, 0x24, 0x30, 0x23,             # +0x1C _subu      a2,t9,a0
        0x3c, 0x04, 0x80, WILDCARD,         # +0x20 lui        a0,0x802d
        0x3c, 0x05, 0x80, WILDCARD,         # +0x24 lui        a1,0x801b <-- where to inflate
        0x3c, 0x06, 0x80, WILDCARD,         # +0x28 lui        a2,0x802d
        0x34, 0xc6, WILDCARD, WILDCARD,     # +0x2C ori        a2,a2,0x4000
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x30 addiu      a1,a1,-0x44e0
        0x0c, 0x00, 0x02, 0x40,             # jal        SUB_80000900
        0x34, 0x84, WILDCARD, WILDCARD,     # _ori       a0,a0,0x6000
    ]) \
    .const_op32_hi16("overlay_table_address", 0x00) \
    .const_op32_lo16("overlay_table_address", 0x04) \
    .const_imm32("overlay_rom_start_offset", 0x08) \
    .const_imm32("overlay_rom_end_offset", 0x0C) \
    .const_op32_hi16("load_address", 0x24) \
    .const_op32_lo16("load_address", 0x30) \
    .build()

# similar to overlay 2 load but one less opcode and different reg usage
KIG_OVERLAY_3_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x02, 0x80, 0x00,             # +0x00 lui        v0,0x8000
        0x24, 0x42, WILDCARD, WILDCARD,     # +0x04 addiu      v0,v0,0x71f0
        0x8c, 0x44, WILDCARD, WILDCARD,     # +0x08 lw         a0,0x10(v0)=>DAT_80007200
        0x8c, 0x40, WILDCARD, WILDCARD,     # +0x0C lw         t7,0x14(v0)=>DAT_80007204
        0x3c, 0x10, 0x80, WILDCARD,         # +0x10 lui        s0,0x802d
        0x36, 0x10, WILDCARD, WILDCARD,     # +0x14 ori        s0,s0,0x4000
        0x02, 0x00, 0x28, 0x25,             # +0x18 or         a1,s0,zero
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x1C jal        SUB_800007b4
        0x01, 0xe4, 0x30, 0x23,             # +0x20 _subu      a2,t7,a0
        0x3c, 0x05, 0x80, WILDCARD,         # +0x24 lui        a1,0x801b
        0x3c, 0x06, 0x80, WILDCARD,         # +0x28 lui        a2,0x803a
        0x34, 0xc6, WILDCARD, WILDCARD,     # +0x2C ori        a2,a2,0x2000
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x30 addiu      a1,a1,-0x2700
        0x0c, WILDCARD, WILDCARD, WILDCARD, # jal        SUB_80000900
        0x02, 0x00, 0x20, 0x25,             # _or        a0,s0,zero
    ]) \
    .modify_andmask(0x0C, make_andmask_load_store(mask_dest=True, mask_imm16=True)) \
    .modify_andmask(0x20, make_andmask_reg_opcode(mask_source=True)) \
    .const_op32_hi16("overlay_table_address", 0x00) \
    .const_op32_lo16("overlay_table_address", 0x04) \
    .const_imm32("overlay_rom_start_offset", 0x08) \
    .const_imm32("overlay_rom_end_offset", 0x0C) \
    .const_op32_hi16("load_address", 0x24) \
    .const_op32_lo16("load_address", 0x30) \
    .build()

# this sub overlay loader looks like it's loading code.
# it even clears the instruction cache.
# but it looks to be loading resources and nothing else.
# i'm leaving this in here just in case.
KIG_SUB_OVERLAY_TABLE_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x18, 0x80, 0x00,             # +0x00 lui        t8,0x8000
        0x27, 0x18, WILDCARD, WILDCARD,     # +0x04 addiu      t8,t8,0x7260
        0x00, 0x0e, 0x78, 0xc0,             # +0x08 sll        t7,t6,0x3
        0x01, 0xf8, 0x10, 0x21,             # +0x0C addu       v0,t7,t8
        0x8c, 0x44, 0x00, 0x00,             # +0x10 lw         a0,0x0(v0)
        0x8c, 0x59, 0x00, 0x04,             # +0x14 lw         t9,0x4(v0)
        0x3c, 0x05, 0x80, WILDCARD,         # +0x18 lui        a1,0x8031
        0x34, 0xa5, WILDCARD, WILDCARD,     # +0x1C ori        a1,a1,0x3090
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x20 jal        SUB_80000740
        0x03, 0x24, 0x30, 0x23,             # +0x24 _subu      a2,t9,a0
        0x93, 0xa8, 0x00, WILDCARD,         # +0x28 lbu        t0,local_res0+0x3(sp)
        0x3c, 0x05, 0x80, WILDCARD,         # +0x2C lui        a1,0x8004
        0x3c, 0x04, 0x80, WILDCARD,         # +0x30 lui        a0,0x8031
        0x00, 0x08, 0x48, 0x80,             # +0x34 sll        t1,t0,0x2
        0x00, 0xa9, 0x28, 0x21,             # +0x38 addu       a1,a1,t1
        0x3c, 0x06, 0x80, WILDCARD,         # +0x3C lui        a2,0x8031
        0x34, 0xc6, WILDCARD, WILDCARD,     # +0x40 ori        a2,a2,0x1090
        0x8c, 0xa5, 0x4d, 0xf4,             # +0x44 lw         a1,0x4DF4(a1)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x48 jal        SUB_80000900
        0x34, 0x84, WILDCARD, WILDCARD,     # +0x4C _ori       a0,a0,0x3090
    ]) \
    .const_op32_hi16("sub_overlay_table_address", 0x00) \
    .const_op32_lo16("sub_overlay_table_address", 0x04) \
    .const_op32_hi16("sub_overlay_loadaddr_table_address", 0x2C) \
    .const_op32_lo16("sub_overlay_loadaddr_table_address", 0x44) \
    .build()

def kig_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    builder = BffiBuilder()
    earliest_bss_address, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    bootexe = rom.boot_exe()[:earliest_bss_address-ipc]
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.fix(ipc, bootexe)

    main_segment_load_offset = KIG_MAIN_SEGMENT_LOAD_PATTERN.find(bootexe)
    if main_segment_load_offset is None:
        return None
    
    logger.info("found Killer Instinct Gold main segment load")

    consts = KIG_MAIN_SEGMENT_LOAD_PATTERN.consts(ipc, bootexe, main_segment_load_offset)
    overlay_table_address = consts["overlay_table_address"].get_value()
    load_address = consts["load_address"].get_value()

    overlay_table_offset = overlay_table_address - ipc

    main_overlay_rom_start, main_overlay_rom_end = struct.unpack(">II", bootexe[overlay_table_offset:overlay_table_offset+8])
    main_overlay = rom.read_bytes(main_overlay_rom_start, main_overlay_rom_end)
    if main_overlay[:2] != bytes([0x11,0x72]):
        logger.error("main overlay did not start with 0x11 0x72")
        return None
    
    main_overlay = zlib.decompress(main_overlay[2:], wbits=-15)
    logger.info("main overlay decompressed: ROM 0x%08x-0x%08x -> RAM 0x%08x",
                main_overlay_rom_start,
                main_overlay_rom_end,
                load_address)
    
    with open("private/kig_12_main.bin", "wb") as f:
        f.write(main_overlay)

    overlay_2_load_offset = KIG_OVERLAY_2_LOAD_PATTERN.find(main_overlay)
    if overlay_2_load_offset is None:
        logger.error("can't find overlay 2 load")
        return None
    
    overlay_3_load_offset = KIG_OVERLAY_3_LOAD_PATTERN.find(main_overlay)
    if overlay_3_load_offset is None:
        logger.error("can't find overlay 3 load")
        return None
    
    for pattern, offset in [ (KIG_OVERLAY_2_LOAD_PATTERN, overlay_2_load_offset),
                             (KIG_OVERLAY_3_LOAD_PATTERN, overlay_3_load_offset)]:
        consts = pattern.consts(load_address, main_overlay, offset)
        if consts["overlay_table_address"].get_value() != overlay_table_address:
            logger.warning("false positive hit - ignoring")
            continue
        
        overlay_rom_start_offset = consts["overlay_rom_start_offset"].get_value() & 0xFFFF
        overlay_rom_end_offset = consts["overlay_rom_end_offset"].get_value() & 0xFFFF
        if overlay_rom_end_offset != overlay_rom_start_offset+4:
            logger.warning("wha?? overlay start offset/end offset not in order (%04x, %04x)",
                           overlay_rom_start_offset,
                           overlay_rom_end_offset)
            continue
        
        overlay_load_address = consts["load_address"].get_value()

        overlay_table_entry_offset = overlay_table_offset + overlay_rom_start_offset
        overlay_rom_start, overlay_rom_end = struct.unpack(">II",bootexe[overlay_table_entry_offset:overlay_table_entry_offset+8])

        logger.info("overlay: ROM 0x%08x-0x%08x -> RAM 0x%08x",
                    overlay_rom_start,
                    overlay_rom_end,
                    overlay_load_address)
        
        overlay = rom.read_bytes(overlay_rom_start, overlay_rom_end-overlay_rom_start)
        if overlay[:2] != bytes([0x11, 0x72]):
            logger.error("overlay did not start with 0x11 0x72")
            return None
        
        overlay = zlib.decompress(overlay[2:], wbits=-15)

        if contains_code(overlay) is False:
            # should NOT end up here
            logger.info("overlay doesn't contain code, skipping")
            continue
        builder.seg(overlay_load_address, overlay)
    
    # disabled because none of these contain MIPS machine code
    # and because the pattern check fails on euro version.
    # it's here in case someone needs to re-enable it
    if False:
        sub_overlay_loader_offset = KIG_SUB_OVERLAY_TABLE_LOAD_PATTERN.find(main_overlay)
        if sub_overlay_loader_offset is None:
            logger.error("can't find sub overlay loader")
            return None
        
        consts = KIG_SUB_OVERLAY_TABLE_LOAD_PATTERN.consts(load_address, main_overlay, sub_overlay_loader_offset)
        sub_overlay_table_address = consts["sub_overlay_table_address"].get_value()
        sub_overlay_loadaddr_table_address = consts["sub_overlay_loadaddr_table_address"].get_value()

        # yes, this is split between two segments, so be aware of that
        sub_overlay_table_offset           = sub_overlay_table_address - ipc
        sub_overlay_loadaddr_table_offset  = sub_overlay_loadaddr_table_address - load_address

        while True:
            # read load address first, as the sub overlay table goes right up to the
            # end of the boot segment and we don't want to read out of bounds
            ram_address = struct.unpack(">I", main_overlay[sub_overlay_loadaddr_table_offset:sub_overlay_loadaddr_table_offset+4])[0]
            if (ram_address >> 24) != 0x80:
                break
            sub_overlay_loadaddr_table_offset += 4

            rom_start, rom_end = struct.unpack(">II", bootexe[sub_overlay_table_offset:sub_overlay_table_offset+0x08])
            sub_overlay_table_offset += 8

            logger.info("sub overlay: ROM 0x%08x-0x%08x -> RAM 0x%08x",
                        rom_start,
                        rom_end,
                        ram_address)
            
            sub_overlay = rom.read_bytes(rom_start, rom_end-rom_start)
            if sub_overlay[:2] != bytes([0x11, 0x72]):
                logger.error("sub overlay did not start with 0x11 0x72")
                return None
            
            sub_overlay = zlib.decompress(sub_overlay[2:], wbits=-15)

            if contains_code(sub_overlay) is False:
                logger.info("sub overlay doesn't contain code, skipping")
                continue

            builder.seg(ram_address, sub_overlay)
    
    return builder.build()
