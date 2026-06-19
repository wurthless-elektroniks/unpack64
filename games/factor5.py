'''
Factor 5 / Lucasarts games

Battle for Naboo and Indiana Jones both use the TLB in a very elegant way to
effectively treat the ROM as RAM and execute code from it.
'''

import logging
import struct

from preamble import identify_preamble
from tlbconst import TLB_PAGEMASK_1MBYTES
from tlbident import tlb_try_detect_preamble
from tlbutil import tlbutil_pack_entrylo
from mips import disassemble_jump_imm26_target
from n64rom import N64Rom
from bffi import Bffi,BffiBuilder,BffiSectionType, BffiTlb, BffiTlbEntry
from signature import SignatureBuilder, WILDCARD
from sigutil import pick_pattern

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

def rogue_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    pattern, _ = pick_pattern(rom.boot_exe(),
                              [ROGUE_JP_ENTRYPOINT_PATTERN, ROGUE_US_ENTRYPOINT_PATTERN],
                              comparing_at_offset=preamble.crt_entry_point() - ipc)

    if pattern is None:
        return None
    
    logger.info("found Rogue Squadron entry point")

    consts = pattern.consts(ipc, rom.boot_exe(), preamble.crt_entry_point() - ipc)
    
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

# ----------------------------------------------------------------------
#
# Indiana Jones and the Infernal Machine
#
# This is Factor 5 being Factor 5, so it requires a bit of explanation...
#
# After preamble maps TLB, we jump to a function that jumps to the entry point.
# Entry point clears BSS, then does the usual osInitialize()/osCreateThread()/osStartThread() combo.
#
# Unsurprisingly, the boot executable loads more overlays, but because this is a Factor 5
# game, the overlay loader code is completely custom, and it's complex, but a very elegant
# solution. Since the game uses the TLB, all it needs to do to load a segment is to call
# the unmapped space where it should be loaded, and the TLB miss exception handler
# will load it for us.
#
# If we access unmapped space, the exception handler at 0x800009CC will fire, which tries to map
# a page. The exception handler will return, but since we've landed back in space that still
# isn't really mapped, the next exception handler at 0x80000AE0 runs, and this will load the code
# required in 4k chunks, then map those chunks in the 0x41xxxxxx range.
#
# This setup effectively treats the ROM as RAM. Executing from ROM directly would be too slow,
# so this TLB setup will swap in ROM data as needed.
#
# There is also a mode where the game will load the program code in one shot rather than
# swapping it out on the fly, but it appears to be disabled for Indiana Jones,
# even when the Expansion Pak is present (at least in MAME).
# When that mode is active it will map in 6x64k pages to the 0x41xxxxxx range and load
# the code there. So, instead of simulating the "ROM as RAM", we can grab the
# code from there and save it out to the BFFI.
#
# ----------------------------------------------------------------------

INDY_BSS_CLEAR_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xe0,             # addiu      sp,sp,-0x20
        0x3c, 0x04, WILDCARD, WILDCARD,     # lui        a0,0x4005
        0x24, 0x84, WILDCARD, WILDCARD,     # addiu      a0,a0,-0x2fd0
        0x3c, 0x05, WILDCARD, WILDCARD,     # lui        a1,0x3
        0x24, 0xa5, WILDCARD, WILDCARD,     # addiu      a1,a1,0x4d20
        0xaf, 0xbf, 0x00, 0x1c,             # sw         ra,0x1c(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # jal        FUN_80000f50
        0xaf, 0xb0, 0x00, 0x18,             # _sw        s0,0x18(sp)
    ]) \
    .const_op32_hi16("bss_base", 0x04) \
    .const_op32_lo16("bss_base", 0x08) \
    .const_op32_hi16("bss_size", 0x0C) \
    .const_op32_lo16("bss_size", 0x10) \
    .build()

INDY_CODE_OVERLAY_ONESHOT_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x05, 0xB0, WILDCARD,          # lui        a1,0xb005
        0x24, 0xa5, WILDCARD, WILDCARD,      # addiu      a1,a1,-0x23d0
        0x3c, 0x03, 0x00, WILDCARD,          # lui        v1,0xc
        0x0c, WILDCARD, WILDCARD, WILDCARD,  # jal        FUN_400407a0
        0x24, 0x67, WILDCARD, WILDCARD,      # _addiu     a3,v1,-0x19e0
    ]) \
    .const_op32_hi16("overlay_rom_address", 0x00) \
    .const_op32_lo16("overlay_rom_address", 0x04) \
    .const_op32_hi16("overlay_size", 0x08) \
    .const_op32_lo16("overlay_size", 0x10) \
    .build()

def indy_unpack(rom: N64Rom, ipc: int) -> Bffi:
    # expect TLB or else this isn't indiana jones
    tlb, preamble = tlb_try_detect_preamble(rom, ipc)
    if None in [ tlb, preamble ]:
        return None

    entry_point_phys = tlb.virtual_to_physical(preamble.crt_entry_point())
    ipc_phys = tlb.virtual_to_physical(ipc)

    first_op = rom.boot_exe()[entry_point_phys-ipc_phys:(entry_point_phys-ipc_phys)+4]
    jump_target = disassemble_jump_imm26_target(ipc_phys, first_op)
    if jump_target is None:
        return None

    if INDY_BSS_CLEAR_PATTERN.compare(rom.boot_exe(), jump_target - ipc_phys) is False:
        return None

    logger.info("found Factor 5 bss clear in TLB mapped space")

    # HACK: segment base set arbitrarily. consts() doesn't really use it, but still...
    consts = INDY_BSS_CLEAR_PATTERN.consts(0, rom.boot_exe(), jump_target - ipc_phys)

    bss_base = consts["bss_base"].get_value()
    bss_size = consts["bss_size"].get_value()
    bss_base_phys = tlb.virtual_to_physical(bss_base)

    logger.info("BSS at 0x%08x-0x%08x", bss_base, bss_base+bss_size)

    bootexe = rom.boot_exe()[:bss_base_phys - ipc_phys]

    builder = BffiBuilder()
    builder.bss(bss_base, bss_size)
    builder.fix(ipc, bootexe)
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(jump_target)

    indy_oneshot_load_address = INDY_CODE_OVERLAY_ONESHOT_LOAD_PATTERN.find(bootexe)
    if indy_oneshot_load_address is None:
        logger.error("cannot find code overlay location/size")
        return None
    
    consts = INDY_CODE_OVERLAY_ONESHOT_LOAD_PATTERN.consts(0, bootexe, indy_oneshot_load_address)
    overlay_rom_address = consts["overlay_rom_address"].get_value() & 0x03FFFFFF
    overlay_size = consts["overlay_size"].get_value()

    logger.info("main overlay in ROM at 0x%08x-0x%08x (%d byte(s))",
                overlay_rom_address,
                overlay_rom_address+overlay_size,
                overlay_size)

    # HACK: this is true for indy, not sure about naboo yet.
    # DOUBLE HACK: this is not how the game actually uses the TLB as explained above
    logger.info("BFFI will map 1 mb page at 0x80300000 -> 0x41000000 (the real game code doesn't do this, FYI)")

    entry_01 = BffiTlbEntry()
    entry_01.pagemask(TLB_PAGEMASK_1MBYTES)
    entry_01.entryhi(0x41000000)
    entry_01.entrylo0( tlbutil_pack_entrylo(0x00300000, 0x1F) )
    entry_01.entrylo1( 1 )
    tlb.entry(0x01, entry_01)

    phys = tlb.virtual_to_physical(0x41000000)
    if phys != 0x300000:
        raise RuntimeError(f"fake TLB entry didn't map correctly, got {phys:08x}")

    builder.fix(0x41000000, rom.read_bytes(overlay_rom_address, overlay_size))
    builder.initial_tlb(tlb)
    return builder.build()
