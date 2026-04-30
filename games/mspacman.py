'''
Ms. Pac Man - Maze Madness

Custom packer, custom compression
'''

import logging
import struct

from bffi import BffiBuilder
from compression.mspacman import mspacman_decompress_op_by_op
from n64rom import N64Rom
from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi
from signature import SignatureBuilder, WILDCARD

logger = logging.getLogger(__name__)

MSPACMAN_UNPACK_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xe8,         # +0x000 addiu      sp,sp,-0x18
        0x3c, 0x02, 0x80, WILDCARD,     # +0x004 lui        v0,0x8020                        <-- base address of payload
        0x24, 0x48, WILDCARD, WILDCARD, # +0x008 addiu      t0,v0,0x6b0
        0x25, 0x08, 0x00, 0x04,         # +0x00C addiu      input_pointer,input_pointer,0x4  <-- first 4 bytes are sizeof
        0x3c, 0x07, 0x80, WILDCARD,     # +0x010 lui        a3,0x8000
        0x34, 0xe7, WILDCARD, WILDCARD, # +0x014 ori        a3,a3,0x400 <-- load address
    ]) \
    .tail_pattern([
        0x3c, 0x04, WILDCARD, WILDCARD, # +0x148 lui        a0,0xb008
        0x3c, 0x01, 0x80, WILDCARD,     # +0x14C lui        at,0x8000
        0x34, 0x21, WILDCARD, WILDCARD, # +0x150 ori        at,at,0x400
        0x00, 0x20, 0xf8, 0x09,         # +0x154 jalr       at
        0x24, 0x84, WILDCARD, WILDCARD, # +0x158 _addiu     a0,a0,-0x4400
        0x8f, 0xbf, 0x00, 0x10,         # +0x15C lw         ra,local_8(sp)
        0x03, 0xe0, 0x00, 0x08,         # +0x160 jr         ra
        0x27, 0xbd, 0x00, 0x18,         # +0x164 _addiu     sp,sp,0x18
    ]) \
    .size(0x168) \
    .const_op32_hi16("payload_base_address", 0x004) \
    .const_op32_lo16("payload_base_address", 0x008) \
    .const_op32_hi16("load_address",         0x010) \
    .const_op32_lo16("load_address",         0x014) \
    .const_op32_hi16("a0_argument",          0x148) \
    .const_op32_lo16("a0_argument",          0x158) \
    .const_op32_hi16("entry_point",          0x14C) \
    .const_op32_lo16("entry_point",          0x150) \
    .build()

def mspacman_unpack(rom: N64Rom, ipc: int):
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    unpacker_offset = MSPACMAN_UNPACK_PATTERN.find(rom.boot_exe()[:0x400], preamble.crt_entry_point() - ipc)
    if unpacker_offset is None:
        print("piss")
        return None

    logger.info("found Ms Pacman unpacker")

    consts = MSPACMAN_UNPACK_PATTERN.consts(ipc, rom.boot_exe(), unpacker_offset)

    payload_base_address = consts["payload_base_address"].get_value()
    load_address = consts["load_address"].get_value()
    a0_argument = consts["a0_argument"].get_value()
    entry_point = consts["entry_point"].get_value()
    
    payload = rom.boot_exe()[payload_base_address - ipc:]
    
    # uncompressed payload size
    payload_size = struct.unpack(">I", payload[:4])[0]

    logger.info("payload at 0x%08x, size is %d", payload_base_address, payload_size)

    payload = mspacman_decompress_op_by_op( payload[4:4+payload_size], payload_size )

    logger.info("unpacked the boot executable, treating it as if it was supposed to load where it did")
    
    # the entry point for ms pacman is just a generic nustd preamble that clears BSS,
    # so expect that to be there
    preamble = identify_preamble(payload[entry_point-load_address:], entry_point)
    if preamble is None:
        logger.error("couldn't find a standard preamble in the uncompressed bootexe!!")
        return None

    logger.info("real preamble was identified as: %s", preamble.type())

    builder = BffiBuilder()
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)

    builder.fix(load_address, payload[:earliest_bss-load_address])
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.initial_stack_pointer(preamble.initial_stack_pointer())

    # TODO: the unpacker stub passed a0 to the entry point, which it needs!!
    
    # HACK: just because the payload gives us gp=0 doesn't mean we can
    # cheat like this. add initial gp setting to preamble later
    builder.initial_global_pointer(0)

    return builder.build()
