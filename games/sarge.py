'''
Army Men - Sarge's Heroes and Sarge's Heroes 2 from 3DO

All preambles load a useless pointer in $a0 that points to the string
"Copyright 1999 The 3DO Company.  All rights reserved."
prior to actually setting up the initial sections.

The "initialize to 0x55" space is used for the stack and is set to that value
probably so that 3DO could tell how the stack grew in debugging memory dumps.

There was also room for a third .bss range that was never used.

Sarge's Heroes (US):
1. Set range 0x800b57f0 ~ 0x800b97f0 to 0x55
2. Set range 0x800b97f0 ~ 0x8016e670 to 0x00 (typical BSS loop)
3. Slot for third BSS range is unused (game uses 0x800b97f0~0x800b97f0)
4. Copy osMemSize (0x80000318) -> 0x8007cadc (seems to be ignored)
5. Call CRT startup at 0x80050810
'''

import struct
import logging

from n64rom import N64Rom
from bffi import Bffi,BffiBuilder,BffiSectionType
from signature import SignatureBuilder, WILDCARD


logger = logging.getLogger(__name__)

SARGE_PREAMBLE = SignatureBuilder() \
    .pattern([
        0x3C, 0x05, 0x80, 0x0C,
        0x24, 0xA5, WILDCARD, WILDCARD,
        0x00, 0xA0, 0xE8, 0x21,
        0x00, 0xA0, 0xF0, 0x21,
        0x24, 0x1C, 0xFF, 0xFF,
        0x3C, 0x04, 0x80, WILDCARD,     # +$10 - load address that doesn't matter
        0x24, 0x84, WILDCARD, WILDCARD, # +$14   (points to a copyright string)
        0x3C, 0x04, 0x80, WILDCARD,     # +$18 - start of 0x55 section
        0x24, 0x84, WILDCARD, WILDCARD,
        0x3C, 0x05, 0x80, WILDCARD,     # +$20 - end of 0x55 section
        0x24, 0xA5, WILDCARD, WILDCARD,
        0x3C, 0x06, 0x55, 0x55,
        0x34, 0xC6, 0x55, 0x55,
        0x0C, 0x00, 0x01, 0x28, # +$30
        0x00, 0x00, 0x00, 0x00,
        0x3C, 0x04, 0x80, WILDCARD,     # +$38 - start of bss section
        0x24, 0x84, WILDCARD, WILDCARD,
        0x3C, 0x05, 0x80, WILDCARD,     # +$40 - end of bss section
        0x24, 0xA5, WILDCARD, WILDCARD,
        0x0C, 0x00, 0x01, 0x28,
    ]) \
    .size(0xA0) \
    .xref_op32_hi16("initial_sp", 0x00) \
    .xref_op32_lo16("initial_sp", 0x04) \
    .xref_op32_hi16("i55_start_address", 0x1C) \
    .xref_op32_lo16("i55_start_address", 0x20) \
    .xref_op32_hi16("i55_end_address", 0x24) \
    .xref_op32_lo16("i55_end_address", 0x28) \
    .xref_op32_hi16("bss_start_address", 0x3C) \
    .xref_op32_lo16("bss_start_address", 0x40) \
    .xref_op32_hi16("bss_end_address", 0x44) \
    .xref_op32_lo16("bss_end_address", 0x48) \
    .xref_j_imm26("crt_entry", 0x90) \
    .xref_op32_hi16("osMemSize_shadow_base", 0x74) \
    .xref_op32_lo16("osMemSize_shadow_base", 0x78) \
    .build()

def sarge_unpack(rom: N64Rom, ipc: int) -> Bffi:
    bootexe = rom.boot_exe()

    if SARGE_PREAMBLE.compare(bootexe) is False:
        return None
    
    logger.info("using Sarge's Heroes unpacker")

    xrefs  = SARGE_PREAMBLE.xrefs(ipc, bootexe, 0)

    initial_sp              = xrefs["initial_sp"].get_address()
    i55_start_address       = xrefs["i55_start_address"].get_address()
    i55_end_address         = xrefs["i55_end_address"].get_address()
    bss_start_address       = xrefs["bss_start_address"].get_address()
    bss_end_address         = xrefs["bss_end_address"].get_address()
    crt_entry               = xrefs["crt_entry"].get_address()
    osMemSize_shadow_base   = xrefs["osMemSize_shadow_base"].get_address()
    osMemSize_shadow_offset = struct.unpack(">H",bootexe[0x8E:0x90])[0]

    osMemSize_shadow_address = osMemSize_shadow_base + osMemSize_shadow_offset

    logger.info(\
"""fast facts:
- entry point: 0x%08x
- initial sp: 0x%08x
- bss 0x55 section range: 0x%08x-0x%08x
- bss 0x00 section range: 0x%08x-0x%08x
- osMemSize shadowed at: (0x%08x + 0x%04x) --> 0x%08x
""",
    crt_entry,
    initial_sp,
    i55_start_address, i55_end_address,
    bss_start_address, bss_end_address,
    osMemSize_shadow_base, osMemSize_shadow_offset, osMemSize_shadow_address
    )

    builder = BffiBuilder()
    builder.rom_hash(rom.sha256())
    builder.fix(ipc, bootexe[:i55_start_address-ipc])
    builder.bss(i55_start_address, i55_end_address-i55_start_address, init_word=0x55555555)
    builder.bss(bss_start_address, bss_end_address-bss_start_address)
    builder.initial_stack_pointer(initial_sp)
    builder.initial_program_counter(crt_entry)
    builder.copy(0x80000318, osMemSize_shadow_address, 4)
    return builder.build()
