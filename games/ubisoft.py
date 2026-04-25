'''
Ubisoft games on the Rayman 2 (OpenSpace) engine, which are decidedly not single-load games.

Rayman 2 (US) has a function at 0x800026D8 which we'll call ReadCart.
It clears caches, kicks off a DMA transfer through osPiStartDma(), then optionally
blocks until the transfer completes (using osRecvMesg()).

It takes the parameters:
    void ReadCart(a0 = rom_start_address,
                  a1 = rom_end_address,
                  a2 = rdram_address,
                  a3 = dma_is_async)

Donald Duck was built off the same codebase so it can be fed through this unpacker.

Tonic Trouble appears to be a single load game, so it is not covered here.

TODO: Monaco Grand Prix - does it belong here?
'''

import struct
import logging

from bffi import Bffi,BffiBuilder,BffiSectionType
from n64rom import N64Rom
from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi
from signature import SignatureBuilder, WILDCARD

logger = logging.getLogger(__name__)

#
# Rayman 2 (US)
#
# Code overlays are as follows:
# - seg0: 0x1DCC0~0xC5BF0 --> 80025C50: seems like the main engine code
#   bonus french swearing debugmessage "C'est quoi ce bordel !?!??!"" ("what the fuck is this?")
# - seg1: 0xC5BF0~0xD0A20 --> 800F64A0: Controller Pak menuing, loaded from 0x80000B20
#

# 0x800008c8 through 8000096c
RAY2_MAIN_OVERLAY_READ_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x06, 0x80, WILDCARD,     # +0x00 lui        a2,0x8002
        0x24, 0xc6, WILDCARD, WILDCARD, # +0x04 addiu      a2=>SUB_80025c50,a2,0x5c50
        0x3c, 0x02, WILDCARD, WILDCARD, # +0x08 lui        v0,0x0
        0x24, 0x42, WILDCARD, WILDCARD, # +0x0C addiu      v0,v0,0x0
        0x3c, 0x01, 0x80, WILDCARD,     # +0x10 lui        at,0x8002
        0xac, 0x26, WILDCARD, WILDCARD, # +0x14 sw         a2=>SUB_80025c50,offset LAB_80021ed0(at)
        0x10, 0x40, 0x00, 0x1c,         # +0x18 beq        v0,zero,LAB_80000954
        0x00, 0x00, 0x00, 0x00,         # +0x1C _nop
    ]) \
    .tail_pattern([
        0x3c, 0x04, WILDCARD, WILDCARD,     # +0x8C lui        a0,0x2
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x90 addiu      a0,a0,-0x2340
        0x3c, 0x05, WILDCARD, WILDCARD,     # +0x94 lui        a1,0xc
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x98 addiu      a1,a1,0x5bf0
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x9C jal        ReadCart
        0x00, 0x00, 0x38, 0x21,             # +0xA0 _clear     a3    
    ]) \
    .size(0xA4) \
    .const_op32_hi16("main_overlay_load_address", 0x00) \
    .const_op32_lo16("main_overlay_load_address", 0x04) \
    .const_op32_hi16("should_be_zero",            0x08) \
    .const_op32_lo16("should_be_zero",            0x0C) \
    .const_op32_hi16("main_overlay_rom_start",    0x8C) \
    .const_op32_lo16("main_overlay_rom_start",    0x90) \
    .const_op32_hi16("main_overlay_rom_end",      0x94) \
    .const_op32_lo16("main_overlay_rom_end",      0x98) \
    .xref_j_imm26("readcart_fcn_address",         0x9C) \
    .build()

# Rayman 2 uses this to load its Controller Pak screens
RAY2_GENERIC_OVERLAY_READ_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x04, WILDCARD, WILDCARD,     # +0x00 lui    a0,0xc
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x04 addiu  a0,a0,0x5bf0
        0x3c, 0x05, WILDCARD, WILDCARD,     # +0x08 lui    a1,0xd
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x0C addiu  a1,a1,0xa20
        0x3c, 0x06, 0x80, WILDCARD,         # +0x10 lui    a2,0x800f
        0x24, 0xc6, WILDCARD, WILDCARD,     # +0x14 addiu  a2,a2,0x64a0
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x18 jal    ReadCart
        0x00, 0x00, 0x38, 0x21,             # +0x1C _clear a3
    ]) \
    .const_op32_hi16("overlay_rom_start",    0x00) \
    .const_op32_lo16("overlay_rom_start",    0x04) \
    .const_op32_hi16("overlay_rom_end",      0x08) \
    .const_op32_lo16("overlay_rom_end",      0x0C) \
    .const_op32_hi16("overlay_load_address", 0x10) \
    .const_op32_lo16("overlay_load_address", 0x14) \
    .xref_j_imm26("readcart_fcn_address", 0x18) \
    .build()

def _find_overlays(segment: bytes,
                   segment_load_address: int,
                   readcart_fcn_address: int,
                   rom: N64Rom,
                   builder: BffiBuilder):
    offset = 0

    while True:
        offset = RAY2_GENERIC_OVERLAY_READ_PATTERN.find(segment, offset)
        if offset is None:
            break
        
        consts = RAY2_GENERIC_OVERLAY_READ_PATTERN.consts(segment_load_address, segment, offset)
        xrefs  = RAY2_GENERIC_OVERLAY_READ_PATTERN.xrefs(segment_load_address, segment,  offset)

        offset += 4

        if xrefs["readcart_fcn_address"].get_address() != readcart_fcn_address:
            continue

        overlay_load_address = consts["overlay_load_address"].get_value()
        overlay_rom_start = consts["overlay_rom_start"].get_value()
        overlay_rom_end = consts["overlay_rom_end"].get_value()

        logger.info("segment at 0x%08x loads code segment from ROM 0x%08x~0x%08x -> RDRAM 0x%08x",
                    segment_load_address,
                    overlay_rom_start,
                    overlay_rom_end,
                    overlay_load_address
                    )
        
        next_segment = rom.read_bytes(overlay_rom_start, overlay_rom_end-overlay_rom_start)
        
        # TODO: debatable as to whether or not the controller pak manager is
        # a seg or a fix...
        builder.seg(overlay_load_address, next_segment)

        _find_overlays(next_segment,
                       overlay_load_address,
                       readcart_fcn_address,
                       rom,
                       builder)

    possible_overlay_swap_pattern = SignatureBuilder() \
        .pattern( struct.pack(">I", 0x0C000000 | ((readcart_fcn_address & 0x03FFFFFF) >> 2)) ) \
        .build()
    
    offset = 0
    while True:
        offset = possible_overlay_swap_pattern.find(segment, offset)
        if offset is None:
            break
        
        logger.info("segment %08x: possible ReadCart() call at 0x%08x",
                    segment_load_address,
                    segment_load_address + offset)
        
        offset += 4


def ray2_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None

    builder = BffiBuilder()
    builder.rom_hash(rom.sha256())
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    os_segment = rom.boot_exe()[:earliest_bss-ipc]

    main_overlay_load_address_pattern = RAY2_MAIN_OVERLAY_READ_PATTERN.find(os_segment)
    if main_overlay_load_address_pattern is None:
        return None
    
    consts = RAY2_MAIN_OVERLAY_READ_PATTERN.consts(ipc, os_segment, main_overlay_load_address_pattern)
    if consts["should_be_zero"].get_value() != 0:
        logger.error("ray2 swapper present, but should_be_zero was not zero")
        return None
    
    xrefs = RAY2_MAIN_OVERLAY_READ_PATTERN.xrefs(ipc, os_segment, main_overlay_load_address_pattern)
    readcart_fcn_address = xrefs["readcart_fcn_address"].get_address()

    main_overlay_load_address = consts["main_overlay_load_address"].get_value()
    main_overlay_rom_start = consts["main_overlay_rom_start"].get_value()
    main_overlay_rom_end = consts["main_overlay_rom_end"].get_value()
    main_overlay_size = main_overlay_rom_end - main_overlay_rom_start

    logger.info("found Ubisoft Rayman 2-style code overlay swapper")
    logger.info("ReadCart() routine is at 0x%08x", readcart_fcn_address)

    builder.fix(ipc, os_segment)

    logger.info("main overlay loads to 0x%08x~0x%08x (in ROM at 0x%08x~0x%08x)",
                main_overlay_load_address,
                main_overlay_load_address + main_overlay_size,
                main_overlay_rom_start,
                main_overlay_rom_end)

    main_overlay = rom.read_bytes(main_overlay_rom_start, main_overlay_size)
    builder.fix(main_overlay_load_address, main_overlay)

    _find_overlays(os_segment, ipc, readcart_fcn_address, rom, builder)
    _find_overlays(main_overlay, main_overlay_load_address, readcart_fcn_address, rom, builder)

    builder.initial_program_counter(preamble.crt_entry_point())
    builder.initial_stack_pointer(preamble.initial_stack_pointer())

    return builder.build()
