'''
Stormfront Studios games, all published by EA, but not using any of EA's usual tools

Games that go here:
- Hot Wheels Turbo Racing
- NASCAR 99
- NASCAR 2000

'''

import logging
import struct

from bffi import Bffi,BffiBuilder,BffiSectionType
from n64rom import N64Rom
from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi
from signature import SignatureBuilder, WILDCARD
from sigutil import pick_pattern

logger = logging.getLogger(__name__)

# ----------------------------------------------------------
#
# NASCAR 99
#
# Uncompressed overlays, nothing special.
#
# Overlay 1 (menus): 0x4f8f0-0x71680
# Overlay 2 (ingame): 0x71680-0x105100
#
# NASCAR 2000 uses the same overlay scheme but there are code differences
# which throw off our pattern matching.
#
# ----------------------------------------------------------

# FPU crap mixed in here, thanks compiler
NASCAR99_MENUS_OVERLAY_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x04, 0x80, WILDCARD,             # +0x00 lui        a0,0x8010       <-- BSS start
        0x24, 0x84, WILDCARD, WILDCARD,         # +0x04 addiu      a0,a0,-0x16d0
        0x3c, 0x01, 0x3f, 0x80,                 # +0x08 lui        at,0x3f80
        0x44, 0x81, 0x00, 0x00,                 # +0x0C mtc1       at,f0
        0x3c, 0x05, 0x80, WILDCARD,             # +0x10 lui        a1,0x8010       <-- BSS end
        0x24, 0xa5, WILDCARD, WILDCARD,         # +0x14 addiu      a1,a1,-0xe50
        0x3c, 0x01, 0x80, WILDCARD,             # +0x18 lui        at,0x8004
        0xac, 0x20, WILDCARD, WILDCARD,         # +0x1C sw         zero,0x2e30(at)
        0x3c, 0x01, 0x80, WILDCARD,             # +0x20 lui        at,0x8004
        0xac, 0x20, WILDCARD, WILDCARD,         # +0x24 sw         zero,0x2e34(at)
        0x3c, 0x01, 0x80, WILDCARD,             # +0x28 lui        at,0x800d
        0xac, 0x20, WILDCARD, WILDCARD,         # +0x2C sw         zero,-0x5bc0(at)
        0x3c, 0x01, 0x80, WILDCARD,             # +0x30 lui        at,0x800d
        0xac, 0x20, WILDCARD, WILDCARD,         # +0x34 sw         zero,-0x5bbc(at)
        0x3c, 0x01, 0x80, WILDCARD,             # +0x38 lui        at,0x8004
        0xe4, 0x20, WILDCARD, WILDCARD,         # +0x3C swc1       f0,0x2d14(at)
        0x0c, WILDCARD, WILDCARD, WILDCARD,     # +0x40 jal        bzero
        0x00, 0xa4, 0x28, 0x23,                 # +0x44 _subu      a1,a1,a0
        0x3c, 0x04, 0x80, WILDCARD,             # +0x48 lui        a0,0x800e
        0x24, 0x84, WILDCARD, WILDCARD,         # +0x4C addiu      a0,a0,-0x3460
        0x3c, 0x05, 0x80, WILDCARD,             # +0x50 lui        a1,0x800f
        0x24, 0xa5, WILDCARD, WILDCARD,         # +0x54 addiu      a1,a1,-0x3760
        0x0c, WILDCARD, WILDCARD, WILDCARD,     # +0x58 jal        osInvalICache
        0x00, 0xa4, 0x28, 0x23,                 # +0x5C _subu      a1,a1,a0
        0x3c, 0x04, 0x80, WILDCARD,             # +0x60 lui        a0,0x800f
        0x24, 0x84, WILDCARD, WILDCARD,         # +0x64 addiu      a0,a0,-0x3760
        0x3c, 0x05, 0x80, WILDCARD,             # +0x68 lui        a1,0x8010
        0x24, 0xa5, WILDCARD, WILDCARD,         # +0x6C addiu      a1,a1,-0x16d0
        0x0c, WILDCARD, WILDCARD, WILDCARD,     # +0x70 jal        osInvalDCache
        0x00, 0xa4, 0x28, 0x23,                 # +0x74 _subu      a1,a1,a0
        0x3c, 0x04, 0x80, WILDCARD,             # +0x78 lui        a0,0x8009
        0x24, 0x84, WILDCARD, WILDCARD,         # +0x7C addiu      a0,a0,0x5218
        0x00, 0x00, 0x28, 0x21,                 # +0x80 clear      a1
        0x00, 0x00, 0x30, 0x21,                 # +0x84 clear      a2
        0x3c, 0x07, 0x00, WILDCARD,             # +0x88 lui        a3,0x5              <-- ROM start address
        0x24, 0xe7, WILDCARD, WILDCARD,         # +0x8C addiu      a3,a3,-0x710
        0x3c, 0x02, 0x80, WILDCARD,             # +0x90 lui        v0,0x800e           <-- RAM load address
        0x24, 0x42, WILDCARD, WILDCARD,         # +0x94 addiu      v0,v0,-0x3460
        0xaf, 0xa2, 0x00, 0x10,                 # +0x98 sw         v0,local_68(sp)
        0x3c, 0x02, 0x00, WILDCARD,             # +0x9C lui        v0,0x7              <-- ROM end address
        0x24, 0x42, WILDCARD, WILDCARD,         # +0xA0 addiu      v0,v0,0x1680
        0x00, 0x47, 0x10, 0x23,                 # +0xA4 subu       v0,v0,a3
        0x3c, 0x10, 0x80, WILDCARD,             # +0xA8 lui        s0,0x800d
        0x26, 0x10, WILDCARD, WILDCARD,         # +0xAC addiu      s0,s0,-0x5be8
        0xaf, 0xa2, 0x00, 0x14,                 # +0xB0 sw         v0,local_64(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD,     # +0xB4 jal        osPiStartDma
        0xaf, 0xb0, 0x00, 0x18,                 # +0xB8 _sw        s0,local_60(sp)
    ]) \
    .const_op32_hi16("bss_start", 0x00) \
    .const_op32_lo16("bss_start", 0x04) \
    .const_op32_hi16("bss_end",   0x10) \
    .const_op32_lo16("bss_end",   0x14) \
    .const_op32_hi16("rom_start", 0x88) \
    .const_op32_lo16("rom_start", 0x8C) \
    .const_op32_hi16("ram_address", 0x90) \
    .const_op32_lo16("ram_address", 0x94) \
    .const_op32_hi16("rom_end", 0x9C) \
    .const_op32_lo16("rom_end", 0xA0) \
    .build()

NASCAR99_INGAME_OVERLAY_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x04, 0x80, WILDCARD,         # +0x00 lui        a0,0x8017        <-- BSS start
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x04 addiu      a0,a0,0x620
        0x3c, 0x05, 0x80, WILDCARD,         # +0x08 lui        a1,0x8018        <-- BSS end
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x0C addiu      a1,a1,-0x5cd0
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x10 jal        bzero
        0x00, 0xa4, 0x28, 0x23,             # +0x14 _subu      a1,a1,a0
        0x3c, 0x04, 0x80, WILDCARD,         # +0x18 lui        a0,0x800e
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x1C addiu      a0,a0,-0x3460
        0x3c, 0x05, 0x80, WILDCARD,         # +0x20 lui        a1,0x8015
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x24 addiu      a1,a1,-0x17f0
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x28 jal        osInvalICache
        0x00, 0xa4, 0x28, 0x23,             # +0x2C _subu      a1,a1,a0
        0x3c, 0x04, 0x80, WILDCARD,         # +0x30 lui        a0,0x8015
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x34 addiu      a0,a0,-0x17f0
        0x3c, 0x05, 0x80, WILDCARD,         # +0x38 lui        a1,0x8017
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x3C addiu      a1,a1,0x620
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x40 jal        osInvalICache
        0x00, 0xa4, 0x28, 0x23,             # +0x44 _subu      a1,a1,a0
        0x3c, 0x11, 0x80, WILDCARD,         # +0x48 lui        s1,0x8009
        0x26, 0x31, WILDCARD, WILDCARD,     # +0x4C addiu      s1,s1,0x5218
        0x02, 0x20, 0x20, 0x21,             # +0x50 move       a0,s1
        0x00, 0x00, 0x28, 0x21,             # +0x54 clear      a1
        0x00, 0x00, 0x30, 0x21,             # +0x58 clear      a2
        0x3c, 0x07, 0x00, WILDCARD,         # +0x5C lui        a3,0x7           <-- ROM start
        0x24, 0xe7, WILDCARD, WILDCARD,     # +0x60 addiu      a3,a3,0x1680
        0x3c, 0x02, 0x80, WILDCARD,         # +0x64 lui        v0,0x800e        <-- RAM load address
        0x24, 0x42, WILDCARD, WILDCARD,     # +0x68 addiu      v0,v0,-0x3460
        0xaf, 0xa2, 0x00, 0x10,             # +0x6C sw         v0,local_20(sp)
        0x3c, 0x02, 0x00, WILDCARD,         # +0x70 lui        v0,0x10          <-- ROM end
        0x24, 0x42, WILDCARD, WILDCARD,     # +0x74 addiu      v0,v0,0x5100
        0x00, 0x47, 0x10, 0x23,             # +0x78 subu       v0,v0,a3
        0x3c, 0x10, 0x80, WILDCARD,         # +0x7C lui        s0,0x800d
        0x26, 0x10, WILDCARD, WILDCARD,     # +0x80 addiu      s0,s0,-0x5be8
        0xaf, 0xa2, 0x00, 0x14,             # +0x84 sw         v0,local_1c(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x88 jal        osPiStartDma
        0xaf, 0xb0, 0x00, 0x18,             # +0x8C _sw        s0,local_18(sp)
    ]) \
    .const_op32_hi16("bss_start", 0x00) \
    .const_op32_lo16("bss_start", 0x04) \
    .const_op32_hi16("bss_end",   0x08) \
    .const_op32_lo16("bss_end",   0x0C) \
    .const_op32_hi16("rom_start", 0x5C) \
    .const_op32_lo16("rom_start", 0x60) \
    .const_op32_hi16("ram_address", 0x64) \
    .const_op32_lo16("ram_address", 0x68) \
    .const_op32_hi16("rom_end", 0x70) \
    .const_op32_lo16("rom_end", 0x74) \
    .build()

# FPU stuff thankfully moved before the overlay init/load
NASCAR2000_MENUS_OVERLAY_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x04, 0x80, WILDCARD,         # +0x00 lui        a0,0x8010 <-- BSS start
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x04 addiu      a0,a0,-0x3850
        0x3c, 0x05, 0x80, WILDCARD,         # +0x08 lui        a1,0x8010 <-- BSS end
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x0C addiu      a1,a1,-0x2780
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x10 jal        bzero
        0x00, 0xa4, 0x28, 0x23,             # +0x14 _subu      a1,a1,a0
        0x3c, 0x04, 0x80, WILDCARD,         # +0x18 lui        a0,0x800e
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x1C addiu      a0,a0,-0x6ec0
        0x3c, 0x05, 0x80, WILDCARD,         # +0x20 lui        a1,0x800f
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x24 addiu      a1,a1,-0x6420
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x28 jal        osInvalICache
        0x00, 0xa4, 0x28, 0x23,             # +0x2C _subu      a1,a1,a0
        0x3c, 0x04, 0x80, WILDCARD,         # +0x30 lui        a0,0x800f
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x34 addiu      a0,a0,-0x6420
        0x3c, 0x05, 0x80, WILDCARD,         # +0x38 lui        a1,0x8010
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x3C addiu      a1,a1,-0x3850
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x40 jal        osInvalDCache
        0x00, 0xa4, 0x28, 0x23,             # +0x44 _subu      a1,a1,a0
        0x3c, 0x04, 0x80, WILDCARD,         # +0x48 lui        a0,0x8009
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x4C addiu      a0,a0,0x5598
        0x00, 0x00, 0x28, 0x21,             # +0x50 clear      a1
        0x00, 0x00, 0x30, 0x21,             # +0x54 clear      a2
        0x3c, 0x07, 0x00, WILDCARD,         # +0x58 lui        a3,0x5 <-- ROM start
        0x24, 0xe7, WILDCARD, WILDCARD,     # +0x5C addiu      a3,a3,0xba0
        0x3c, 0x02, 0x80, WILDCARD,         # +0x60 lui        v0,0x800e <-- RAM load address
        0x24, 0x42, WILDCARD, WILDCARD,     # +0x64 addiu      v0,v0,-0x6ec0
        0xaf, 0xa2, 0x00, 0x10,             # +0x68 sw         v0,local_60(sp)
        0x3c, 0x02, 0x00, WILDCARD,         # +0x6C lui        v0,0x7 <-- ROM end
        0x24, 0x42, WILDCARD, WILDCARD,     # +0x70 addiu      v0,v0,0x4210
        0x00, 0x47, 0x10, 0x23,             # +0x74 subu       v0,v0,a3
        0x3c, 0x10, 0x80, WILDCARD,         # +0x78 lui        s0,0x800c
        0x26, 0x10, WILDCARD, WILDCARD,     # +0x7C addiu      s0,s0,0x7748
        0xaf, 0xa2, 0x00, 0x14,             # +0x80 sw         v0,local_5c(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x84 jal        osPiStartDma
        0xaf, 0xb0, 0x00, 0x18,             # +0x88 _sw        s0,local_58(sp)
    ])  \
    .const_op32_hi16("bss_start", 0x00) \
    .const_op32_lo16("bss_start", 0x04) \
    .const_op32_hi16("bss_end",   0x08) \
    .const_op32_lo16("bss_end",   0x0C) \
    .const_op32_hi16("rom_start", 0x58) \
    .const_op32_lo16("rom_start", 0x5C) \
    .const_op32_hi16("ram_address", 0x60) \
    .const_op32_lo16("ram_address", 0x64) \
    .const_op32_hi16("rom_end", 0x6C) \
    .const_op32_lo16("rom_end", 0x70) \
    .build()

# goes through a readcart routine this time
NASCAR2000_INGAME_OVERLAY_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x04, 0x80, WILDCARD,         # +0x00 lui        a0,0x8017       <-- BSS start
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x04 addiu      a0,a0,-0x2c0
        0x3c, 0x05, 0x80, WILDCARD,         # +0x08 lui        a1,0x8018       <-- BSS end
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x0C addiu      a1,a1,-0x5850
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x10 jal        bzero
        0x00, 0xa4, 0x28, 0x23,             # +0x14 _subu      a1,a1,a0
        0x3c, 0x04, 0x80, WILDCARD,         # +0x18 lui        a0,0x800e
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x1C addiu      a0,a0,-0x6ec0
        0x3c, 0x05, 0x80, WILDCARD,         # +0x20 lui        a1,0x8015
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x24 addiu      a1,a1,-0x28a0
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x28 jal        osInvalICache
        0x00, 0xa4, 0x28, 0x23,             # +0x2C _subu      a1,a1,a0
        0x3c, 0x04, 0x80, WILDCARD,         # +0x30 lui        a0,0x8015
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x34 addiu      a0,a0,-0x28a0
        0x3c, 0x05, 0x80, WILDCARD,         # +0x38 lui        a1,0x8017
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x3C addiu      a1,a1,-0x2c0
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x40 jal        osInvalDCache
        0x00, 0xa4, 0x28, 0x23,             # +0x44 _subu      a1,a1,a0
        0x3c, 0x04, 0x00, WILDCARD,         # +0x48 lui        a0,0x7          <-- ROM start
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x4C addiu      a0,a0,0x4210
        0x3c, 0x05, 0x80, WILDCARD,         # +0x50 lui        a1,0x800e       <-- RAM load address
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x54 addiu      a1,a1,-0x6ec0
        0x3c, 0x06, 0x00, WILDCARD,         # +0x58 lui        a2,0x11         <-- ROM end
        0x24, 0xc6, WILDCARD, WILDCARD,     # +0x5C addiu      a2,a2,-0x51f0
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x60 jal        readcart
        0x00, 0xc4, 0x30, 0x23              # +0x64 _subu      a2,a2,a0
    ])  \
    .const_op32_hi16("bss_start", 0x00) \
    .const_op32_lo16("bss_start", 0x04) \
    .const_op32_hi16("bss_end",   0x08) \
    .const_op32_lo16("bss_end",   0x0C) \
    .const_op32_hi16("rom_start", 0x48) \
    .const_op32_lo16("rom_start", 0x4C) \
    .const_op32_hi16("ram_address", 0x50) \
    .const_op32_lo16("ram_address", 0x54) \
    .const_op32_hi16("rom_end", 0x58) \
    .const_op32_lo16("rom_end", 0x5C) \
    .build()

def nascar99_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None

    builder = BffiBuilder()
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    bootexe = rom.boot_exe()[:earliest_bss-ipc]
    builder.fix(ipc, bootexe)
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.initial_stack_pointer(preamble.initial_stack_pointer())

    menus_overlay_load_offset  = None
    ingame_overlay_load_offset = None
    for menus_overlay_pattern, ingame_overlay_pattern in [
        (NASCAR99_MENUS_OVERLAY_LOAD_PATTERN, NASCAR99_INGAME_OVERLAY_LOAD_PATTERN),
        (NASCAR2000_MENUS_OVERLAY_LOAD_PATTERN, NASCAR2000_INGAME_OVERLAY_LOAD_PATTERN),
        ]:
        menus_overlay_load_offset  = menus_overlay_pattern.find(bootexe)
        ingame_overlay_load_offset = ingame_overlay_pattern.find(bootexe)

        if None not in [ menus_overlay_load_offset, ingame_overlay_load_offset ]:
            break
    
    if None in [ menus_overlay_load_offset, ingame_overlay_load_offset ]:
        return None

    logger.info("found NASCAR overlay loaders")

    for pattern, offset in [
        (menus_overlay_pattern, menus_overlay_load_offset),
        (ingame_overlay_pattern, ingame_overlay_load_offset)
        ]:
        consts = pattern.consts(ipc, bootexe, offset)

        bss_start = consts["bss_start"].get_value()
        bss_end = consts["bss_end"].get_value()
        rom_start = consts["rom_start"].get_value()
        rom_end = consts["rom_end"].get_value()
        ram_address = consts["ram_address"].get_value()

        logger.info("segment: ROM 0x%08x-0x%08x -> RAM 0x%08x (bss 0x%08x-0x%08x)",
                    rom_start,
                    rom_end,
                    ram_address,
                    bss_start,
                    bss_end)
        
        seg = rom.read_bytes(rom_start, rom_end-rom_start)
        builder.seg(ram_address, seg)

    return builder.build()

# ----------------------------------------------------------
#
# Hot Wheels Turbo Racing
#
# Either there's a bug in compression/hotwheels.py, or this is a single load game.
# Based on the fact that the resource table's .OVL files don't contain MIPS bytecode
# I'm calling this a single load game for now.
#
# This game has a simple filesystem table at 0x800f05f0.
# It's structured as follows:
#
# - +0x00: pointer to filename string
# - +0x04: little endian compression type
#          0 - no compression (default)
#          1 - one-shot
#          2 - chunky (handler at 0x8006eeec)
#          decompression routine at 0x8007f050
# - +0x08: compressed file size 
# - +0x0C: decompressed file size
# - +0x10: size of first chunk in chunky mode, 0 if not chunky
# - +0x14: ROM start address
# - +0x18: ROM end address
#
# When reading in chunky mode, the chunk will start with an 8 byte header,
# and then the compressed data will follow. The first 4 bytes are the size of the
# next chunk, or 0 if this is the last chunk.
#
# ----------------------------------------------------------
