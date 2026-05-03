'''
Konami games

"Nisitenma-Ichigo" (Nishitenma Type 1) resource table and compression system
developed by Konami Osaka, which was based in Nishitenma in Kita-ku, Osaka City
at the time.

The resource table scheme is used on:

- Castlevania
- Castlevania - Legacy of Darkness
- Goemon's Great Adventure (main segments compressed)
- Hybrid Heaven
- Mystical Ninja Starring Goemon

'''

import logging
import struct

from bffi import Bffi, BffiBuilder
from n64rom import N64Rom
from preamble import preamble_extract_bss_sections_to_bffi, identify_preamble
from signature import SignatureBuilder, WILDCARD, Signature
from sigutil import find_all_instances, pick_pattern

logger = logging.getLogger(__name__)


# -------------------------------------------------
#
# "Nisitenma-Ichigo" generic handlings
#
# -------------------------------------------------

NISITENMA_MAGIC_PATTERN = SignatureBuilder() \
    .bits( b'Nisitenma-Ichigo' ) \
    .andmask( [0xFF] * 16 ) \
    .build()

def _nisitenma_find_table_offset(segment: bytes) -> int | None:
    return NISITENMA_MAGIC_PATTERN.find(segment)

# -------------------------------------------------
#
# Deadly Arts
#
# Overlay loader abstracts osPiStartDma and such to a high level call.
# This struct is passed to it:
#
# - +0x00 [0] ROM start address
# - +0x04 [1] ROM end address
# - +0x08 [2] RAM load address
# - +0x0C [3]
# - +0x10 [4]
# - +0x14 [5]
# - +0x18 [6]
# - +0x1C [7] BSS start
# - +0x20 [8] BSS end
#
# If ROM start and end addresses are the same, the function will
# not start the DMA, but call osRecvMesg() anyway.
#
# -------------------------------------------------

DEADLYARTS_OVERLAY_LOAD_FCN_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xd0,             # addiu      sp,sp,-0x30
        0xaf, 0xb0, 0x00, 0x28,             # sw         s0,local_8(sp)
        0x00, 0x80, 0x80, 0x25,             # or         s0,a0,zero
        0xaf, 0xbf, 0x00, 0x2c,             # sw         ra,local_4(sp)
        0x8e, 0x0f, 0x00, 0x00,             # lw         t7,0x0(s0)
        0x8e, 0x0e, 0x00, 0x04,             # lw         t6,0x4(s0)
        0x8c, 0x84, 0x00, 0x08,             # lw         a0,0x8(a0)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # jal        FUN_8001cf90
        0x01, 0xcf, 0x28, 0x23,             # _subu      a1,t6,t7
        0x8e, 0x18, 0x00, 0x04,             # lw         t8,0x4(s0)
        0x8e, 0x19, 0x00, 0x00,             # lw         t9,0x0(s0)
        0x8e, 0x04, 0x00, 0x08,             # lw         a0,0x8(s0)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # jal        FUN_8001cb80
        0x03, 0x19, 0x28, 0x23,             #  _subu      a1,t8,t9
        0x8e, 0x07, 0x00, 0x00,             # lw         a3,0x0(s0)
        0x8e, 0x08, 0x00, 0x04,             # lw         t0,0x4(s0)
    ]) \
    .build()

def _extract_segment_struct(segment_load_address: int,
                            segment: bytes,
                            segment_struct_address: int):

    offset = segment_struct_address-segment_load_address

    # logger.debug("_extract_segment_struct: %08x-%08x=%0x",
    #              segment_struct_address,
    #              segment_load_address,
    #              offset)

    packed = segment[offset:offset+0x24]

    rom_start_address, \
    rom_end_address, \
    ram_load_address, \
    _, \
    _, \
    _, \
    _, \
    bss_start_address, \
    bss_end_address = struct.unpack(">IIIIIIIII", packed)

    return rom_start_address, \
           rom_end_address, \
           ram_load_address, \
           bss_start_address, \
           bss_end_address

def _deadlyarts_extract_overlays(rom: N64Rom,
                      builder: BffiBuilder,
                      overlay_load_call_pattern: Signature,
                      segment: bytes,
                      segment_load_address: int,
                      extracted_rom_addresses: list):


    overlay_load_instances = find_all_instances(segment, overlay_load_call_pattern)
    if not overlay_load_instances:
        return
    
    for offset in overlay_load_instances:
        consts = overlay_load_call_pattern.consts(segment_load_address, segment, offset)
        struct_address = consts["struct_address"].get_value()

        if (segment_load_address <= struct_address <= segment_load_address+len(segment)) is False:
            # FIXME: actually grab the data from the other segment
            logger.info("our segment struct is in another castle: 0x%08x", struct_address)
            continue

        
        rom_start_address, \
        rom_end_address, \
        ram_load_address, \
        bss_start_address, \
        bss_end_address = _extract_segment_struct(segment_load_address,
                                                  segment,
                                                  struct_address)
        
        if (rom_start_address,rom_end_address) in extracted_rom_addresses:
            logger.info("segment already loaded from ROM: 0x%08x-0x%08x",
                        rom_start_address,
                        rom_end_address)
            continue

        extracted_rom_addresses.append((rom_start_address,rom_end_address))
        
        logger.info("segment at 0x%08x loads ROM 0x%08x-0x%08x -> RAM 0x%08x, bss 0x%08x-0x%08x",
                    segment_load_address,
                    rom_start_address,
                    rom_end_address,
                    ram_load_address,
                    bss_start_address,
                    bss_end_address)
        
        loaded_segment = rom.read_bytes(rom_start_address, rom_end_address-rom_start_address)

        # TODO: attach bss to segment

        builder.seg(ram_load_address, loaded_segment)

        _deadlyarts_extract_overlays(rom,
                          builder,
                          overlay_load_call_pattern,
                          loaded_segment,
                          ram_load_address,
                          extracted_rom_addresses)

def deadlyarts_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    builder = BffiBuilder()
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)

    bootexe = rom.boot_exe()[:earliest_bss-ipc]

    builder.fix(ipc, bootexe)
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.initial_stack_pointer(preamble.initial_stack_pointer())

    overlay_load_fcn_offset = DEADLYARTS_OVERLAY_LOAD_FCN_PATTERN.find(bootexe)
    if overlay_load_fcn_offset is None:
        return None
    
    overlay_load_fcn_address = ipc+overlay_load_fcn_offset

    logger.info("found Konami Deadly Arts overlay loader at 0x%08x", overlay_load_fcn_address)

    overlay_load_call_pattern = SignatureBuilder() \
    .bits(
        # lui a0,XXXX
        bytes([0x3c, 0x04, 0x00, 0x00]) + \
        
        # jal to the function
        struct.pack(">I",
                    0x0C000000 | ((overlay_load_fcn_address & 0x3FFFFFFF) >> 2)
                    ) + \
        
        # addiu a0,XXXX in the delayslot
        bytes([0x24, 0x84, 0x00, 0x00])
    ) \
    .andmask(bytes([
        0xFF, 0xFF, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0x00, 0x00
    ])) \
    .const_op32_hi16("struct_address", 0x00) \
    .const_op32_lo16("struct_address", 0x08) \
    .build()

    overlay_load_instances = find_all_instances(bootexe, overlay_load_call_pattern)
    if not overlay_load_instances:
        logger.error("cannot find any calls to the overlay loader!!")
        return None
    
    _deadlyarts_extract_overlays(rom,
                      builder,
                      overlay_load_call_pattern,
                      bootexe,
                      ipc,
                      [])

    return builder.build()

# -------------------------------------------------
#
# Castlevania
#
# Pretty unnotable osPiStartDma() abstraction.
# This game does use the Nisitenma-Ichigo table, but there's no sign of it
# decompressing code from it (yet).
#
# -------------------------------------------------

# Castlevania only uses this to load uncompressed overlays
CASTLEVANIA_LOAD_OVERLAY_FCN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xe0,             # +0x00 addiu      sp,sp,-0x20
        0xaf, 0xa6, 0x00, 0x28,             # +0x04 sw         a2,local_res8(sp)
        0x8c, 0x00, 0x00, 0x28,             # +0x08 lw         tX,local_res8(sp)
        0x00, 0x80, 0x38, 0x25,             # +0x0C or         a3,a0,zero
        0x00, 0xa0, 0x30, 0x25,             # +0x10 or         a2,a1,zero
        0xaf, 0xbf, 0x00, 0x1c,             # +0x14 sw         ra,local_4(sp)
        0xaf, 0xa5, 0x00, 0x24,             # +0x18 sw         a1,local_res4(sp)
        0x3c, 0x04, 0x80, WILDCARD,         # +0x1C lui        a0,0x800d
        0x8c, 0x84, WILDCARD, WILDCARD,     # +0x20 lw         a0,offset DAT_800d5e78(a0)
        0x00, 0x00, 0x28, 0x25,             # +0x24 or         a1,zero,zero
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x28 jal        readcart
        0xac, 0x00, 0x00, 0x10,             # +0x2C _sw        tX,local_10(sp)
        0x8f, 0xbf, 0x00, 0x1c,             # +0x30 lw         ra,local_4(sp)
        0x27, 0xbd, 0x00, 0x20,             # +0x34 addiu      sp,sp,0x20
        0x03, 0xe0, 0x00, 0x08,             # +0x38 jr         ra
        0x00, 0x00, 0x00, 0x00,             # +0x3C _nop
    ]) \
    .modify_andmask(0x08, bytearray([0b11111100, 0b00000000])) \
    .modify_andmask(0x2C, bytearray([0b11111100, 0b00000000])) \
    .build()

# NBA In The Zone's function inlines osPiStartDma()/osRecvMesg(),
# but has the same method signature.
NBAITZ_LOAD_OVERLAY_FCN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xb8,             # +0x00 addiu      sp,sp,-0x48
        0xaf, 0xa4, 0x00, 0x48,             # +0x04 sw         a0,local_res0(sp)
        0xaf, 0xbf, 0x00, 0x24,             # +0x08 sw         ra,local_24(sp)
        0xaf, 0xa5, 0x00, 0x4c,             # +0x0C sw         a1,local_res4(sp)
        0x00, 0xa0, 0x20, 0x25,             # +0x10 or         a0,a1,zero
        0xaf, 0xa6, 0x00, 0x50,             # +0x14 sw         a2,local_res8(sp)
        0xaf, 0xa0, 0x00, 0x2c,             # +0x18 sw         zero,local_1c(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x1C jal        FUN_800cae70
        0x00, 0xc0, 0x28, 0x25,             # +0x20 _or        a1,a2,zero
        0x8f, 0xa4, 0x00, 0x4c,             # +0x24 lw         a0,local_res4(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x28 jal        FUN_800caf20
        0x8f, 0xa5, 0x00, 0x50,             # +0x2C _lw        a1,local_res8(sp)
        0x8c, 0x00, 0x00, 0x4c,             # +0x30 lw         tX,local_res4(sp)
        # rest of function has numerous differences which
        # cause this pattern not to match on several games
    ]) \
    .modify_andmask(0x30, bytearray([0b11111100, 0b00000000])) \
    .build()

def _castlevania_extract_overlays(rom: N64Rom,
                      builder: BffiBuilder,
                      overlay_load_call_pattern: Signature,
                      segment: bytes,
                      segment_load_address: int,
                      extracted_rom_addresses: list):


    overlay_load_instances = find_all_instances(segment, overlay_load_call_pattern)
    if not overlay_load_instances:
        return
    
    for offset in overlay_load_instances:
        consts = overlay_load_call_pattern.consts(segment_load_address, segment, offset)
        rom_start_address = consts["rom_start_address"].get_value()
        rom_end_address = consts["rom_end_address"].get_value()
        ram_load_address = consts["ram_load_address"].get_value()
        
        if (rom_start_address,rom_end_address) in extracted_rom_addresses:
            logger.info("segment already loaded from ROM: 0x%08x-0x%08x",
                        rom_start_address,
                        rom_end_address)
            continue

        extracted_rom_addresses.append((rom_start_address,rom_end_address))
        
        logger.info("segment at 0x%08x loads ROM 0x%08x-0x%08x -> RAM 0x%08x",
                    segment_load_address,
                    rom_start_address,
                    rom_end_address,
                    ram_load_address)
        
        loaded_segment = rom.read_bytes(rom_start_address, rom_end_address-rom_start_address)

        builder.seg(ram_load_address, loaded_segment)

        _castlevania_extract_overlays(rom,
                          builder,
                          overlay_load_call_pattern,
                          loaded_segment,
                          ram_load_address,
                          extracted_rom_addresses)

def castlevania_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    builder = BffiBuilder()
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)

    bootexe = rom.boot_exe()[:earliest_bss-ipc]

    builder.fix(ipc, bootexe)
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.initial_stack_pointer(preamble.initial_stack_pointer())

    nisitenma_table_offset = _nisitenma_find_table_offset(bootexe)
    if nisitenma_table_offset is None:
        return None

    logger.info("found Konami Nisitenma-Ichigo resource table in RAM at 0x%08x",
                ipc + nisitenma_table_offset)

    _, overlay_load_fcn_offset = \
        pick_pattern(bootexe,
                     [ CASTLEVANIA_LOAD_OVERLAY_FCN,
                       NBAITZ_LOAD_OVERLAY_FCN ]
                       )

    if overlay_load_fcn_offset is None:
        logger.error("can't find main cartridge read routine")
        raise RuntimeError("raising exception to stop try-all-unpackers unpack!")
    
    overlay_load_fcn_address = ipc+overlay_load_fcn_offset

    logger.info("found Konami Castlevania-style overlay loader at 0x%08x", overlay_load_fcn_address)

    overlay_load_call_pattern = SignatureBuilder() \
    .pattern([
        0x3c, 0x04, WILDCARD, WILDCARD,     # +0x00 lui        a0,0xb
        0x3c, WILDCARD, WILDCARD, WILDCARD, # +0x04 lui        tX,0x11
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x08 addiu      a0,a0,-0x7be0
        0x24, WILDCARD, WILDCARD, WILDCARD, # +0x0C addiu      tX,tX,-0x3c0
        0x3c, 0x05, 0x80, WILDCARD,         # +0x10 lui        a1,0x8012
        0x24, 0xA5, WILDCARD, WILDCARD,     # +0x14 addiu      a1,a1,0x5230
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x18 jal        load_overlay
        0x00, 0x04, 0x30, 0x23,             # +0x1C _subu      a2,tX,a0
    ]) \
    .modify_andmask(0x04, bytes([0b11111100])) \
    .modify_andmask(0x0C, bytes([0b11111100])) \
    .modify_andmask(0x1C, bytes([0b11111100, 0b00001111])) \
    .const_op32_hi16("rom_start_address", 0x00) \
    .const_op32_lo16("rom_start_address", 0x08) \
    .const_op32_hi16("rom_end_address", 0x04) \
    .const_op32_lo16("rom_end_address", 0x0C) \
    .const_op32_hi16("ram_load_address", 0x10) \
    .const_op32_lo16("ram_load_address", 0x14) \
    .build()

    # TODO: Goemon's Great Adventure and Hybrid Heaven almost certainly
    # have compressed overlays, so for those games, not finding these
    # will not necessarily be an error condition
    overlay_load_instances = find_all_instances(bootexe, overlay_load_call_pattern)
    if not overlay_load_instances:
        logger.error("cannot find any calls to the overlay loader!!")
        return None
    
    _castlevania_extract_overlays(rom,
                                  builder,
                                  overlay_load_call_pattern,
                                  bootexe,
                                  ipc,
                                  [])
    
    return builder.build()
