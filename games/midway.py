'''
Various Midway games

TODO for all: we only grab the main segment, other overlays still need to be dumped
'''

import logging
import struct
import zlib

from compression.lzssmidway import lzssmidway_decompress

from bffi import Bffi, BffiBuilder
from n64rom import N64Rom
from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi
from signature import SignatureBuilder, WILDCARD
from sigutil import pick_pattern

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------
#
# San Francisco Rush
#
# Main segment compressed using variant of LZSS
#
# ----------------------------------------------------------------

SFRUSH_MAIN_SEGMENT_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x04, WILDCARD, WILDCARD,     # +0x00 lui    a0,0x7a         <-- compressed payload in ROM
        0x3c, 0x05, 0x80, WILDCARD,         # +0x04 lui    a1,0x8006       <-- RAM load address
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x08 addiu  a1,a1,-0x44f0
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x0C jal    decompress_resource_from_rom
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x10 _addiu a0,a0,0x7930
        0x3c, 0x0e, WILDCARD, WILDCARD,     # +0x14 lui    t6,0x800e       <-- BSS start
        0x3c, 0x0f, WILDCARD, WILDCARD,     # +0x18 lui    t7,0x8017       <-- BSS end
        0x25, 0xef, WILDCARD, WILDCARD,     # +0x1C addiu  t7,t7,-0x5650
        0x25, 0xce, WILDCARD, WILDCARD,     # +0x20 addiu  t6,t6,-0x7fa0
        0x01, 0xc0, 0x20, 0x25,             # +0x24 or     a0,t6,zero
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x28 jal    bzero
        0x01, 0xee, 0x28, 0x23,             # +0x30 _subu  a1,t7,t6
    ]) \
    .const_op32_hi16("payload_rom_address", 0x00) \
    .const_op32_lo16("payload_rom_address", 0x10) \
    .const_op32_hi16("payload_ram_load_address", 0x04) \
    .const_op32_lo16("payload_ram_load_address", 0x08) \
    .const_op32_hi16("bss_start_address", 0x14) \
    .const_op32_lo16("bss_start_address", 0x20) \
    .const_op32_hi16("bss_end_address", 0x18) \
    .const_op32_lo16("bss_end_address", 0x1C) \
    .build()

def sfrush_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None

    builder = BffiBuilder()
    earliest_bss_section, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    bootexe = rom.boot_exe()[:earliest_bss_section-ipc]

    main_segment_load_offset = SFRUSH_MAIN_SEGMENT_LOAD_PATTERN.find(bootexe)
    if main_segment_load_offset is None:
        return None

    logger.info("found San Francisco Rush loader")

    consts = SFRUSH_MAIN_SEGMENT_LOAD_PATTERN.consts(ipc, bootexe, main_segment_load_offset)

    payload_rom_address      = consts["payload_rom_address"].get_value()
    payload_ram_load_address = consts["payload_ram_load_address"].get_value()
    bss_start_address        = consts["bss_start_address"].get_value()
    bss_end_address          = consts["bss_end_address"].get_value()

    logger.info("LZSS payload in ROM at 0x%08x, loads to 0x%08x", payload_rom_address, payload_ram_load_address)
    logger.info("BSS at 0x%08x-0x%08x", bss_start_address, bss_end_address)

    payload = rom.read_bytes_until_end(payload_rom_address)

    payload = lzssmidway_decompress(payload)
    
    if len(payload) != (bss_start_address-payload_ram_load_address):
        logger.error("huh? payload didn't decompress up until start of BSS")
        return None
    
    logger.info("unpacked payload OK.")

    builder.fix(ipc, bootexe)
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.bss(bss_start_address, bss_end_address-bss_start_address)
    builder.fix(payload_ram_load_address, payload)

    # sfrush: i went looking for code overlays in the main table,
    # and i found nothing... maybe you'll have better luck

    # table = payload[0x800C7C38-payload_ram_load_address:]
    # offset = 0
    # counter = 0
    # while True:
    #     rom_pointer = struct.unpack(">I", table[offset:offset+4])[0]
    #     if rom_pointer == 0xFFFF0000:
    #         break
    #     offset += 4
    #     compressed = rom.read_bytes_until_end(rom_pointer)
    #     decompressed = lzssmidway_decompress(compressed)
    #     pattern = SignatureBuilder() \
    #     .pattern([
    #         0x03, 0xE0, 0x00, 0x08,
    #         0x27, 0xBD
    #     ]) \
    #     .build()
    #     with open(f"private/sfrush/sfrush_{counter:04x}.bin", "wb") as f:
    #         f.write(decompressed)
    #     counter += 1

    return builder.build()

# ----------------------------------------------------------------
#
# Rush 2 and San Francisco Rush 2049
#
# Main segment is zlibbed
#
# ----------------------------------------------------------------

RUSH2_MAIN_SEGMENT_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x04, WILDCARD, WILDCARD,     # +0x00 lui   a0,0xb0        <-- rom read location
        0x3c, 0x05, WILDCARD, WILDCARD,     # +0x04 lui   a1,0x8005      <-- ram load location
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x08 addiu a1,a1,0x39e0
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x0C addiu a0,a0,-0x2f40
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x10 jal   FUN_800059d4
        0x00, 0x00, 0x30, 0x25,             # +0x14 _or   a2,zero,zero
        0x3c, 0x0e, WILDCARD, WILDCARD,     # +0x18 lui   t6,0x800d      <-- BSS start
        0x3c, 0x0f, WILDCARD, WILDCARD,     # +0x1C lui   t7,0x8012      <-- BSS end
        0x25, 0xef, WILDCARD, WILDCARD,     # +0x20 addiu t7,t7,0x5c90
        0x25, 0xce, WILDCARD, WILDCARD,     # +0x24 addiu t6,t6,0x110
        0x01, 0xc0, WILDCARD, WILDCARD,     # +0x28 or    a0,t6,zero
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x2C jal   FUN_800064f0
        0x01, 0xee, 0x28, 0x23,             # +0x30 _subu a1,t7,t6
    ]) \
    .const_op32_hi16("payload_rom_address", 0x00) \
    .const_op32_lo16("payload_rom_address", 0x0C) \
    .const_op32_hi16("payload_ram_load_address", 0x04) \
    .const_op32_lo16("payload_ram_load_address", 0x08) \
    .const_op32_hi16("bss_start_address", 0x18) \
    .const_op32_lo16("bss_start_address", 0x24) \
    .const_op32_hi16("bss_end_address", 0x1C) \
    .const_op32_lo16("bss_end_address", 0x20) \
    .build()

# rush 2049: same unpacker, different register usage
RUSH2049_MAIN_SEGMENT_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x04, WILDCARD, WILDCARD,     # +0x00 lui   a0,0xb0        <-- rom read location
        0x3c, 0x05, WILDCARD, WILDCARD,     # +0x04 lui   a1,0x8005      <-- ram load location
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x08 addiu a1,a1,0x39e0
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x0C addiu a0,a0,-0x2f40
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x10 jal   FUN_800059d4
        0x00, 0x00, 0x30, 0x25,             # +0x14 _or   a2,zero,zero
        0x3c, 0x09, 0x80, WILDCARD,         # +0x18 lui   t1,0x8012
        0x3c, 0x0a, 0x80, WILDCARD,         # +0x1C lui   t2,0x8018
        0x25, 0x4a, WILDCARD, WILDCARD,     # +0x20 addiu t2,t2,-0x59c0
        0x25, 0x29, WILDCARD, WILDCARD,     # +0x24 addiu t1,t1,0x49f0
        0x01, 0x20, 0x20, 0x25,             # +0x28 or    a0,t1,zero
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x2C jal   FUN_80008590
        0x01, 0x49, 0x28, 0x23,             # +0x30 _subu a1,t2,t1
    ]) \
    .const_op32_hi16("payload_rom_address", 0x00) \
    .const_op32_lo16("payload_rom_address", 0x0C) \
    .const_op32_hi16("payload_ram_load_address", 0x04) \
    .const_op32_lo16("payload_ram_load_address", 0x08) \
    .const_op32_hi16("bss_start_address", 0x18) \
    .const_op32_lo16("bss_start_address", 0x24) \
    .const_op32_hi16("bss_end_address", 0x1C) \
    .const_op32_lo16("bss_end_address", 0x20) \
    .build()

def rush2_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None

    builder = BffiBuilder()
    earliest_bss_section, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    bootexe = rom.boot_exe()[:earliest_bss_section-ipc]

    pattern, main_segment_load_offset = pick_pattern(bootexe,
                                                     [ RUSH2_MAIN_SEGMENT_LOAD_PATTERN,
                                                       RUSH2049_MAIN_SEGMENT_LOAD_PATTERN
                                                     ])
    if pattern is None:
        return None

    logger.info("found Rush 2 loader")

    consts = pattern.consts(ipc, bootexe, main_segment_load_offset)

    payload_rom_address      = consts["payload_rom_address"].get_value()
    payload_ram_load_address = consts["payload_ram_load_address"].get_value()
    bss_start_address        = consts["bss_start_address"].get_value()
    bss_end_address          = consts["bss_end_address"].get_value()

    logger.info("deflated payload in ROM at 0x%08x, loads to 0x%08x", payload_rom_address, payload_ram_load_address)
    logger.info("BSS at 0x%08x-0x%08x", bss_start_address, bss_end_address)

    payload = rom.read_bytes_until_end(payload_rom_address)

    payload = zlib.decompress(payload, wbits=-15)

    if len(payload) != (bss_start_address-payload_ram_load_address):
        logger.error("huh? payload didn't decompress up until start of BSS")
        return None
    
    logger.info("unpacked payload OK.")

    builder.fix(ipc, bootexe)
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.bss(bss_start_address, bss_end_address-bss_start_address)
    builder.fix(payload_ram_load_address, payload)

    return builder.build()

# ----------------------------------------------------------------
#
# California Speed
#
# Main segment is uncompressed and is read in by osPiStartDma().
#
# ----------------------------------------------------------------

CALISPEED_MAIN_SEGMENT_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x00, 0x00, 0x28, 0x21,             # +0x00 clear a1
        0x00, 0x00, 0x30, 0x21,             # +0x04 clear a2
        0x3c, 0x07, WILDCARD, WILDCARD,     # +0x08 lui   a3,0x2         <-- ROM start address
        0x24, 0xe7, WILDCARD, WILDCARD,     # +0x0C addiu a3,a3,-0x32a0
        0x3c, 0x02, 0x80, WILDCARD,         # +0x10 lui   v0,0x8005      <-- RAM destination
        0x24, 0x42, WILDCARD, WILDCARD,     # +0x14 addiu v0,v0,0x3710
        0xaf, 0xa2, 0x00, 0x10,             # +0x18 sw    v0,0x10(sp)
        0x3c, 0x02, WILDCARD, WILDCARD,     # +0x1C lui   v0,0xa         <-- ROM end address
        0x24, 0x42, WILDCARD, WILDCARD,     # +0x20 addiu v0,v0,0x6c70
        0x00, 0x47, 0x10, 0x23,             # +0x24 subu  v0,v0,a3
        0x3c, 0x10, 0x80, WILDCARD,         # +0x28 lui   s0,0x8002      <-- handle that we don't care about
        0x26, 0x10, WILDCARD, WILDCARD,     # +0x2C addiu s0,s0,0xf8
        0xaf, 0xa2, 0x00, 0x14,             # +0x30 sw    v0,0x14(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x34 jal   osPiStartDma
        0xaf, 0xb0, 0x00, 0x18,             # +0x38 _sw   s0,0x18(sp)
        0x3c, 0x04, 0x80, WILDCARD,         # +0x3C lui   a0,0x800e      <-- BSS start
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x40 addiu a0,a0,-0x29e0
        0x3c, 0x05, 0x80, WILDCARD,         # +0x44 lui   a1,0x8017      <-- BSS end
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x48 addiu a1,a1,-0x1e40
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x4C jal   bzero
        0x00, 0xa4, 0x28, 0x23,             # +0x50 _subu a1,a1,a0
    ]) \
    .const_op32_hi16("rom_start_address", 0x08) \
    .const_op32_lo16("rom_start_address", 0x0C) \
    .const_op32_hi16("ram_load_address",  0x10) \
    .const_op32_lo16("ram_load_address",  0x14) \
    .const_op32_hi16("rom_end_address",   0x1C) \
    .const_op32_lo16("rom_end_address",   0x20) \
    .const_op32_hi16("bss_start_address", 0x3C) \
    .const_op32_lo16("bss_start_address", 0x40) \
    .const_op32_hi16("bss_end_address", 0x44) \
    .const_op32_lo16("bss_end_address", 0x48) \
    .build()

# nfl blitz needs its own pattern because someone left in a call to a
# debug print message
NFLBLITZ_MAIN_SEGMENT_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xd0,         # +0x00 addiu      sp,sp,-0x30
        0x3c, 0x02, WILDCARD, WILDCARD, # +0x04 lui        v0,0x7  <-- ROM end address
        0x24, 0x42, WILDCARD, WILDCARD, # +0x08 addiu      v0,v0,-0x7770
        0xaf, 0xb2, 0x00, 0x28,         # +0x0C sw         s2,local_8(sp)
        0x3c, 0x12, WILDCARD, WILDCARD, # +0x10 lui        s2,0x3  <-- ROM start address
        0x26, 0x52, WILDCARD, WILDCARD, # +0x14 addiu      s2,s2,-0xe0
        0xaf, 0xb0, 0x00, 0x20,         # +0x18 sw         s0,local_10(sp)
        0x00, 0x52, 0x80, 0x23,         # +0x1C subu       s0,v0,s2
        0x3c, 0x02, 0x80, WILDCARD,     # +0x20 lui        v0,0x802b      <-- RAM end address
        0x24, 0x42, WILDCARD, WILDCARD, # +0x24 addiu      v0,v0,-0x8b0
        0xaf, 0xb1, 0x00, 0x24,         # +0x28 sw         s1,local_c(sp)
        0x3c, 0x11, 0x80, WILDCARD,     # +0x2C lui        s1,0x8027        <-- RAM load address
        0x26, 0x31, WILDCARD, WILDCARD, # +0x30 addiu      s1,s1,0x0
    ]) \
    .tail_pattern([
        0x00, 0x00, 0x28, 0x21,             # +0x94 clear      a1
        0x00, 0x00, 0x30, 0x21,             # +0x98 clear      a2
        0x02, 0x40, 0x38, 0x21,             # +0x9C move       a3,s2
        0xaf, 0xb0, 0x00, 0x14,             # +0xA0 sw         s0,local_1c(sp)
        0x3c, 0x10, 0x80, WILDCARD,         # +0xA4 lui        s0,0x8005    <-- handle to something
        0x26, 0x10, WILDCARD, WILDCARD,     # +0xA8 addiu      s0,s0,0x2650
        0xaf, 0xb1, 0x00, 0x10,             # +0xAC sw         s1,local_20(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0xB0 jal        osPiStartDma
        0xaf, 0xb0, 0x00, 0x18,             # +0xB4 _sw        s0,local_18(sp)
        0x3c, 0x04, 0x80, WILDCARD,         # +0xB8 lui        a0,0x802b <-- bss start
        0x24, 0x84, WILDCARD, WILDCARD,     # +0xBC addiu      a0,a0,-0x7690
        0x3c, 0x05, 0x80, WILDCARD,         # +0xC0 lui        a1,0x802b <-- bss end
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0xC4 addiu      a1,a1,-0x8b0
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0xC8 jal        bzero
        0x00, 0xa4, 0x28, 0x23,             # +0xCC _subu      a1,a1,a0
    ]) \
    .size(0xD0) \
    .const_op32_hi16("rom_end_address",   0x04) \
    .const_op32_lo16("rom_end_address",   0x08) \
    .const_op32_hi16("rom_start_address", 0x10) \
    .const_op32_lo16("rom_start_address", 0x14) \
    .const_op32_hi16("ram_load_address",  0x2C) \
    .const_op32_lo16("ram_load_address",  0x30) \
    .const_op32_hi16("bss_start_address", 0xB8) \
    .const_op32_lo16("bss_start_address", 0xBC) \
    .const_op32_hi16("bss_end_address", 0xC0) \
    .const_op32_lo16("bss_end_address", 0xC4) \
    .build()

# NFL Blitz 2001 reorders opcodes again; when it clears caches the pointers to
# the segment load addresses will be stashed in $s0 and $s1.
# the weird bit is that they're referencing PI addresses directly instead
# of just an offset in the ROM
NFLBLITZ_2001_MAIN_SEGMENT_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xd0,             # +0x00 addiu  sp,sp,-0x30
        0x3c, 0x04, 0x80, WILDCARD,         # +0x04 lui    a0,0x8008
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x08 addiu  a0,a0,0x4d30      <-- just setting up stuff for cache clears
        0x3c, 0x05, 0x80, WILDCARD,         # +0x0C lui    a1,0x800c
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x10 addiu  a1,a1,0x13d0
        0x00, 0xa4, 0x28, 0x23,             # +0x14 subu   a1,a1,a0
        0xaf, 0xb1, 0x00, 0x24,             # +0x18 sw     s1,local_c(sp)
        0x3c, 0x11, 0xb0, WILDCARD,         # +0x1C lui    s1,0xb00b                   <-- ROM main segment end address
        0x26, 0x31, WILDCARD, WILDCARD,     # +0x20 addiu  s1,s1,0x4660
        0xaf, 0xb0, 0x00, 0x20,             # +0x24 sw     s0,local_10(sp)
        0x3c, 0x10, 0xb0, WILDCARD,         # +0x28 lui    s0,0xb005                   <-- ROM main segment start address
        0xaf, 0xbf, WILDCARD, WILDCARD,     # +0x2C sw     ra,local_8(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x30 jal    FUN_80022af0
        0x26, 0x10, WILDCARD, WILDCARD,     # +0x34 _addiu s0,s0,-0x5880
        0x3c, 0x04, 0x80, WILDCARD,         # +0x38 lui    a0,0x800c                   <-- more cache clears
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x3C addiu  a0,a0,0x13d0
        0x3c, 0x05, 0x80, WILDCARD,         # +0x40 lui    a1,0x800f
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x44 addiu  a1,a1,-0x4870
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x48 jal    FUN_80022a40
        0x00, 0xa4, 0x28, 0x23,             # +0x4C _subu  a1,a1,a0
        0x3c, 0x04, 0x80, WILDCARD,         # +0x50 lui    a0,0x8005
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x54 addiu  a0,a0,-0x3e30              <-- PI handle thing
        0x00, 0x00, 0x28, 0x21,             # +0x58 clear  a1
        0x00, 0x00, 0x30, 0x21,             # +0x5C clear  a2
        0x02, 0x00, 0x38, 0x21,             # +0x60 move   a3,s0                      <-- ROM address pulled back into args registers
        0x3c, 0x02, 0x80, WILDCARD,         # +0x64 lui    v0,0x8008                  <-- actual RAM load address
        0x24, 0x42, WILDCARD, WILDCARD,     # +0x68 addiu  v0,v0,0x18b0
        0x02, 0x30, 0x88, 0x23,             # +0x6C subu   s1,s1,s0                   <-- finally we calced our segment loadsize
        0x3c, 0x10, 0x80, WILDCARD,         # +0x70 lui    s0,0x8005
        0x26, 0x10, WILDCARD, WILDCARD,     # +0x74 addiu  s0,s0,0x77b0
        0xaf, 0xa2, 0x00, 0x10,             # +0x78 sw     v0,local_20(sp)
        0xaf, 0xb1, 0x00, 0x14,             # +0x7C sw     s1,local_1c(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x80 jal    osPiStartDma
        0xaf, 0xb0, 0x00, 0x18,             # +0x84 _sw    s0,local_18(sp)
        0x3c, 0x04, 0x80, WILDCARD,         # +0x88 lui    a0,0x800f                 <-- BSS start address
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x8C addiu  a0,a0,-0x4870
        0x3c, 0x05, 0x80, WILDCARD,         # +0x90 lui    a1,0x8012                 <-- BSS end address
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x94 addiu  a1,a1,0x78a0
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x98 jal    bzero
        0x00, 0xa4, 0x28, 0x23,             # +0x9C _subu  a1,a1,a0
    ]) \
    .const_op32_hi16("rom_end_address",   0x1C) \
    .const_op32_lo16("rom_end_address",   0x20) \
    .const_op32_hi16("rom_start_address", 0x28) \
    .const_op32_lo16("rom_start_address", 0x34) \
    .const_op32_hi16("ram_load_address",  0x64) \
    .const_op32_lo16("ram_load_address",  0x68) \
    .const_op32_hi16("bss_start_address", 0x88) \
    .const_op32_lo16("bss_start_address", 0x8C) \
    .const_op32_hi16("bss_end_address",   0x90) \
    .const_op32_lo16("bss_end_address",   0x94) \
    .build()

def calispeed_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None

    builder = BffiBuilder()
    earliest_bss_section, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    bootexe = rom.boot_exe()[:earliest_bss_section-ipc]

    builder.fix(ipc, bootexe)
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())

    pattern, main_segment_load_offset = pick_pattern(bootexe,
                                               [CALISPEED_MAIN_SEGMENT_LOAD_PATTERN,
                                                NFLBLITZ_MAIN_SEGMENT_LOAD_PATTERN,
                                                NFLBLITZ_2001_MAIN_SEGMENT_LOAD_PATTERN])
    if main_segment_load_offset is None:
        return None

    logger.info("found Midway osPiStartDma() stub")

    consts = pattern.consts(ipc, bootexe, main_segment_load_offset)
    rom_start_address      = consts["rom_start_address"].get_value() & 0x03FFFFFF
    rom_end_address        = consts["rom_end_address"].get_value() & 0x03FFFFFF
    ram_load_address       = consts["ram_load_address"].get_value()
    bss_start_address      = consts["bss_start_address"].get_value()
    bss_end_address        = consts["bss_end_address"].get_value()

    logger.info("main segment is in ROM at 0x%08x-0x%08x, loads to 0x%08x",
                rom_start_address,
                rom_end_address,
                ram_load_address)
    logger.info("BSS is at 0x%08x-0x%08x", bss_start_address,bss_end_address)
    builder.bss(bss_start_address, bss_end_address-bss_start_address)
    builder.fix(ram_load_address, rom.read_bytes(rom_start_address, rom_end_address-rom_start_address))

    return builder.build()
