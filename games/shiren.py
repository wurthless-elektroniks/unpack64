'''
Shiren the Wanderer 2 from Chunsoft

Small boot stub loads most of the game via a readcart routine at 80025dcc.
Parameters for that routine are: $a0=ROM address, $a1=RAM address, $a2=sizeof.
'''

import logging

from bffi import Bffi, BffiBuilder
from n64rom import N64Rom
from preamble import preamble_extract_bss_sections_to_bffi, identify_preamble
from signature import SignatureBuilder, WILDCARD
from sigutil import find_all_instances

logger = logging.getLogger(__name__)

# ------------------------------------------

# this function's at least interesting because of the use of 64-bit opcodes,
# but it's just your average "clear caches, osPiStartDma, wait for DMA complete"
# readcart routine

SHIREN_READCART_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xa0,             # addiu      sp,sp,-0x60
        0xaf, 0xb4, 0x00, 0x58,             # sw         s4,local_8(sp)
        0x00, 0x80, 0xa0, 0x2d,             # daddu      s4,a0,zero
        0xaf, 0xb0, 0x00, 0x48,             # sw         s0,local_18(sp)
        0x00, 0xa0, 0x80, 0x2d,             # daddu      s0,a1,zero
        0xaf, 0xb1, 0x00, 0x4c,             # sw         s1,local_14(sp)
        0x00, 0xc0, 0x88, 0x2d,             # daddu      s1,a2,zero
        0xaf, 0xbf, 0x00, 0x5c,             # sw         ra,local_4(sp)
        0xaf, 0xb3, 0x00, 0x54,             # sw         s3,local_c(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # jal        FUN_80026680
        0xaf, 0xb2, 0x00, 0x50,             # _sw        s2,local_10(sp)
    ]) \
    .build()

# this will match most calls in the boot and main segments
SHIREN_READCART_CALL_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x04, 0x00, WILDCARD,         # +0x00 lui        a0,0x1
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x04 addiu      a0,a0,0x4400
        0x3c, 0x05, 0x80, WILDCARD,         # +0x08 lui        a1,0x8004
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x0C addiu      a1,a1,0x13c0
        0x3c, 0x06, 0x00, WILDCARD,         # +0x10 lui        a2,0x13
        0x24, 0xc6, WILDCARD, WILDCARD,     # +0x14 addiu      a2,a2,0x39f0
        0x08, WILDCARD, WILDCARD, WILDCARD, # +0x18 jal        readcart (one instance is a jump to some code that does that)
    ]) \
    .modify_andmask(0x18, bytes([0xFB])) \
    .const_op32_hi16("rom_start_address", 0x00) \
    .const_op32_lo16("rom_start_address", 0x04) \
    .const_op32_hi16("ram_load_address", 0x08) \
    .const_op32_lo16("ram_load_address", 0x0C) \
    .const_op32_hi16("rom_end_address", 0x10) \
    .const_op32_lo16("rom_end_address", 0x14) \
    .xref_j_imm26("readcart_address", 0x18) \
    .build()

def _shiren_find_segments(rom: N64Rom,
                          segment: bytes,
                          segment_load_address: int,
                          readcart_address: int) -> list:
    
    results = []
    for instance_offset in find_all_instances(segment, SHIREN_READCART_CALL_PATTERN):
        xrefs = SHIREN_READCART_CALL_PATTERN.xrefs(segment_load_address, segment, instance_offset)

        if xrefs["readcart_address"].get_address() != readcart_address and \
            segment[instance_offset+0x18] != 0x08:
            continue

        consts = SHIREN_READCART_CALL_PATTERN.consts(segment_load_address, segment, instance_offset)
        rom_start_address = consts["rom_start_address"].get_value()
        rom_end_address = consts["rom_end_address"].get_value()
        ram_load_address = consts["ram_load_address"].get_value()
        
        seg = rom.read_bytes(rom_start_address, rom_end_address-rom_start_address)
        results.append( (rom_start_address,rom_end_address,ram_load_address) )

        results += _shiren_find_segments(rom, seg, ram_load_address, readcart_address)
    
    return results

def shiren_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    builder = BffiBuilder()
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)

    bootexe = rom.boot_exe()[:earliest_bss-ipc]

    builder.fix(ipc, bootexe)
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.initial_stack_pointer(preamble.initial_stack_pointer())

    readcart_offset = SHIREN_READCART_PATTERN.find(bootexe)
    if readcart_offset is None:
        return None
    
    readcart_address = ipc + readcart_offset
    logger.info("found Shiren readcart routine at 0x%08x", readcart_address)

    segments = _shiren_find_segments(rom, bootexe, ipc, readcart_address)

    if not segments:
        logger.error("could not capture any segments")
        return None
    
    added = []
    for segtuple in segments:
        if segtuple in added:
            continue
        added.append(segtuple)

        rom_start_address = segtuple[0]
        rom_end_address = segtuple[1]
        ram_load_address = segtuple[2]

        logger.info("captured segment: ROM 0x%08x-0x%08x -> RAM 0x%08x",
                    rom_start_address,
                    rom_end_address,
                    ram_load_address)

        seg = rom.read_bytes(rom_start_address, rom_end_address-rom_start_address)

        builder.seg(ram_load_address, seg)

    # TODO: main segment BSS clear range (0x801609b0-0x801e4ea0)

    return builder.build()
