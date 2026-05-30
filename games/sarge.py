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
from sigutil import pick_pattern


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

SARGE_MISSIONS_OVERLAY_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0x98,             # +0x00 addiu      sp,sp,-0x68
        0xaf, 0xb2, 0x00, 0x58,             # +0x04 sw         s2,local_10(sp)
        0x3c, 0x12, 0x80, WILDCARD,         # +0x08 lui        s2,0x8020         <-- RAM start address
        0x26, 0x52, WILDCARD, WILDCARD,     # +0x0C addiu      s2,s2,-0x6790
        0x02, 0x40, 0x20, 0x21,             # +0x10 move       a0,s2
        0xaf, 0xb1, 0x00, 0x54,             # +0x14 sw         s1,local_14(sp)
        0x3c, 0x11, 0x80, WILDCARD,         # +0x18 lui        s1,0x8020 <-- RAM end address
        0x26, 0x31, WILDCARD, WILDCARD,     # +0x1C addiu      s1,s1,-0x3990
        0x02, 0x32, 0x88, 0x23,             # +0x20 subu       s1,s1,s2
        0x02, 0x20, 0x28, 0x21,             # +0x24 move       a1,s1
        0x3c, 0x02, 0x80, WILDCARD,         # +0x28 lui        v0,0x8015
        0xaf, 0xb3, 0x00, 0x5c,             # +0x2C sw         s3,local_c(sp)
        0x3c, 0x13, 0xb0, WILDCARD,         # +0x30 lui        s3,0xb013 <-- ROM address
        0x26, 0x73, WILDCARD, WILDCARD,     # +0x34 addiu      s3,s3,0x55f0
        0xaf, 0xbf, 0x00, 0x64,             # +0x38 sw         ra,local_4(sp)
        0xaf, 0xb4, 0x00, 0x60,             # +0x3C sw         s4,local_8(sp)
        0xaf, 0xb0, 0x00, 0x50,             # +0x40 sw         s0,local_18(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x44 jal        osInvalDCache
        0xac, 0x40, WILDCARD, WILDCARD,     # +0x48 _sw        zero,-0x1e8c(v0)
        0x27, 0xa4, 0x00, 0x20,             # +0x4C addiu      a0,sp,0x20
    ]) \
    .const_op32_hi16("ram_start_address", 0x08) \
    .const_op32_lo16("ram_start_address", 0x0C) \
    .const_op32_hi16("ram_end_address", 0x18) \
    .const_op32_lo16("ram_end_address", 0x1C) \
    .const_op32_hi16("rom_address", 0x30) \
    .const_op32_lo16("rom_address", 0x34) \
    .build()

# different registers and i'm too lazy to AND mask them all
SARGE_2_MISSIONS_OVERLAY_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0x98,             # +0x00 addiu      sp,sp,-0x68
        0xaf, 0xb1, 0x00, 0x54,             # +0x04 sw         s1,local_14(sp)
        0x3c, 0x11, 0x80, WILDCARD,         # +0x08 lui        s1,0x8021
        0x26, 0x31, WILDCARD, WILDCARD,     # +0x0C addiu      s1,s1,0x4560
        0x02, 0x20, 0x20, 0x21,             # +0x10 move       a0,s1
        0xaf, 0xb0, 0x00, 0x50,             # +0x14 sw         s0,local_18(sp)
        0x3c, 0x10, 0x80, WILDCARD,         # +0x18 lui        s0,0x8021
        0x26, 0x10, WILDCARD, WILDCARD,     # +0x1C addiu      s0,s0,0x7140
        0x02, 0x11, 0x80, 0x23,             # +0x20 subu       s0,s0,s1
        0x02, 0x00, 0x28, 0x21,             # +0x24 move       a1,s0
        0x3c, 0x02, 0x80, WILDCARD,         # +0x28 lui        v0,0x8016
        0xaf, 0xb2, 0x00, 0x58,             # +0x2C sw         s2,local_10(sp)
        0x3c, 0x12, 0xb0, WILDCARD,         # +0x30 lui        s2,0xb015
        0x26, 0x52, WILDCARD, WILDCARD,     # +0x34 addiu      s2,s2,-0xd90
        0xaf, 0xbf, 0x00, 0x64,             # +0x38 sw         ra,local_4(sp)
        0xaf, 0xb4, 0x00, 0x60,             # +0x3C sw         s4,local_8(sp)
        0xaf, 0xb3, 0x00, 0x5c,             # +0x40 sw         s3,local_c(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x44 jal        osInvalDCache
        0xac, 0x40, WILDCARD, WILDCARD,     # +0x48 _sw        zero,-0x39fc(v0)
        0x27, 0xa4, 0x00, 0x20,             # +0x4C addiu      a0,sp,0x20

    ]) \
    .const_op32_hi16("ram_start_address", 0x08) \
    .const_op32_lo16("ram_start_address", 0x0C) \
    .const_op32_hi16("ram_end_address", 0x18) \
    .const_op32_lo16("ram_end_address", 0x1C) \
    .const_op32_hi16("rom_address", 0x30) \
    .const_op32_lo16("rom_address", 0x34) \
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


    bootexe = bootexe[:i55_start_address-ipc]

    missions_overlay_pattern, missions_overlay_load_offset = pick_pattern(bootexe, 
                                                                          [ SARGE_MISSIONS_OVERLAY_LOAD_PATTERN, 
                                                                            SARGE_2_MISSIONS_OVERLAY_LOAD_PATTERN ])
    if missions_overlay_load_offset is None:
        logger.error("can't find missions overlay load")
        return None
    
    consts = missions_overlay_pattern.consts(ipc, bootexe, missions_overlay_load_offset)
    missions_overlay_ram_start_address = consts["ram_start_address"].get_value()
    missions_overlay_ram_end_address = consts["ram_end_address"].get_value()
    missions_overlay_size = missions_overlay_ram_end_address - missions_overlay_ram_start_address
    missions_overlay_rom_address = consts["rom_address"].get_value() & 0x03FFFFFF
    missions_overlay = rom.read_bytes(missions_overlay_rom_address, missions_overlay_size)


    logger.info(\
"""fast facts:
- entry point: 0x%08x
- initial sp: 0x%08x
- bss 0x55 section range: 0x%08x-0x%08x
- bss 0x00 section range: 0x%08x-0x%08x
- osMemSize shadowed at: (0x%08x + 0x%04x) --> 0x%08x
- missions overlay: ROM 0x%08x-0x%08x -> RAM 0x%08x
""",
    crt_entry,
    initial_sp,
    i55_start_address, i55_end_address,
    bss_start_address, bss_end_address,
    osMemSize_shadow_base, osMemSize_shadow_offset, osMemSize_shadow_address,
    missions_overlay_rom_address, missions_overlay_rom_address+missions_overlay_size, missions_overlay_ram_start_address
    )

    builder = BffiBuilder()
    builder.rom_hash(rom.sha256())
    builder.fix(ipc, bootexe[:i55_start_address-ipc])
    builder.seg(missions_overlay_ram_start_address, missions_overlay)
    builder.bss(i55_start_address, i55_end_address-i55_start_address, init_word=0x55555555)
    builder.bss(bss_start_address, bss_end_address-bss_start_address)
    builder.initial_stack_pointer(initial_sp)
    builder.initial_program_counter(crt_entry)
    builder.copy(0x80000318, osMemSize_shadow_address, 4)
    return builder.build()
