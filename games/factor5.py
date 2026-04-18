'''
Factor 5 / Lucasarts games

Battle for Naboo and Indiana Jones both use the TLB.
'''

import logging
import struct

from preamble import identify_preamble
from tlb import tlb_try_detect_preamble
from n64rom import N64Rom
from bffi import Bffi,BffiBuilder,BffiSectionType, BffiTlb, BffiTlbEntry
from signature import SignatureBuilder, WILDCARD

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------
#
# Star Wars - Rogue Squadron
#
# Boot executable is larger than the 1 MB limit, so the remaining code
# is manually loaded later in the boot.
#
# ----------------------------------------------------------------------

# this has room for two bss slots, but they just end up zeroing the same
# range twice...
ROGUE_US_ENTRYPOINT_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xe0,             # +0x00 addiu sp,sp,-0x20
        0x3c, 0x04, 0x80, WILDCARD,         # +0x04 lui   a0,0x8011      <-- bss 1 start
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x08 addiu a0,a0,-0x2e00
        0x3c, 0x05, WILDCARD, WILDCARD,     # +0x0C lui   a1,0x2         <-- bss 1 size
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x10 addiu a1,a1,0x38c2
        0xaf, 0xbf, 0x00, 0x1c,             # +0x14 sw    ra,local_4(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x18 jal   FUN_8000040c
        0xaf, 0xb0, 0x00, 0x18,             # +0x1C _sw   s0,local_8(sp)
        0x3c, 0x04, 0x80, WILDCARD,         # +0x20 lui   a0,0x8011      <-- bss 2 start
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x24 addiu a0,a0,-0x2e00
        0x3c, 0x05, WILDCARD, WILDCARD,     # +0x28 lui   a1,0x4         <-- bss 2 size
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x2C addiu a1,a1,0x7490
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x30 jal   FUN_8000040c
        0x00, 0x00, 0x00, 0x00,             # +0x34 _nop
    ]) \
    .const_op32_hi16("bss1_start", 0x04) \
    .const_op32_lo16("bss1_start", 0x08) \
    .const_op32_hi16("bss1_size", 0x0C) \
    .const_op32_lo16("bss1_size", 0x10) \
    .const_op32_hi16("bss2_start", 0x20) \
    .const_op32_lo16("bss2_start", 0x24) \
    .const_op32_hi16("bss2_size", 0x28) \
    .const_op32_lo16("bss2_size", 0x2C) \
    .build()

# japanese version reorders opcodes slightly
ROGUE_JP_ENTRYPOINT_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xe0,             # +0x00 addiu sp,sp,-0x20
        0x3c, 0x04, 0x80, WILDCARD,         # +0x04 lui   a0,0x8011      <-- bss 1 start
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x08 addiu a0,a0,-0x2e00
        0x3c, 0x05, WILDCARD, WILDCARD,     # +0x0C lui   a1,0x2         <-- bss 1 size
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x10 addiu a1,a1,0x38c2
        0xaf, 0xbf, 0x00, 0x1c,             # +0x14 sw    ra,local_4(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x18 jal   FUN_8000040c
        0xaf, 0xb0, 0x00, 0x18,             # +0x1C _sw   s0,local_8(sp)
        0x3c, 0x04, 0x80, WILDCARD,         # +0x20 lui   a0,0x8011      <-- bss 2 start
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x24 addiu a0,a0,-0x2e00
        0x3c, 0x05, WILDCARD, WILDCARD,     # +0x28 lui   a1,0x4         <-- bss 2 size
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x2C jal   FUN_8000040c
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x30 addiu a1,a1,0x7490
    ]) \
    .const_op32_hi16("bss1_start", 0x04) \
    .const_op32_lo16("bss1_start", 0x08) \
    .const_op32_hi16("bss1_size", 0x0C) \
    .const_op32_lo16("bss1_size", 0x10) \
    .const_op32_hi16("bss2_start", 0x20) \
    .const_op32_lo16("bss2_start", 0x24) \
    .const_op32_hi16("bss2_size", 0x28) \
    .const_op32_lo16("bss2_size", 0x30) \
    .build()

def rogue_unpack_common(rom: N64Rom, ipc: int, preamble, consts) -> Bffi:
    bss1_start = consts["bss1_start"].get_value()
    bss1_size  = consts["bss1_size"].get_value()
    bss2_start = consts["bss2_start"].get_value()
    bss2_size  = consts["bss2_size"].get_value()

    # FIXME: there might be a bug with the japanese version as it drops
    # its BSS segment in where the bootexe still exists... verify this later
    earliest_bss = min(bss1_start, bss2_start)
    full_bootexe = rom.read_bytes(0x1000, earliest_bss - ipc)

    builder = BffiBuilder()
    builder.bss(bss1_start, bss1_size)
    builder.bss(bss2_start, bss2_size)
    builder.fix(ipc, full_bootexe)
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())

    return builder.build()

def rogue_us_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    if ROGUE_US_ENTRYPOINT_PATTERN.compare(rom.boot_exe(), preamble.crt_entry_point() - ipc) is False:
        return None
    
    logger.info("found Rogue Squadron (US) entry point")

    consts = ROGUE_US_ENTRYPOINT_PATTERN.consts(ipc, rom.boot_exe(), preamble.crt_entry_point() - ipc)
    return rogue_unpack_common(rom, ipc, preamble, consts)

def rogue_jp_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    if ROGUE_JP_ENTRYPOINT_PATTERN.compare(rom.boot_exe(), preamble.crt_entry_point() - ipc) is False:
        return None
    
    logger.info("found Rogue Squadron (Japan) entry point")

    consts = ROGUE_JP_ENTRYPOINT_PATTERN.consts(ipc, rom.boot_exe(), preamble.crt_entry_point() - ipc)
    return rogue_unpack_common(rom, ipc, preamble, consts)