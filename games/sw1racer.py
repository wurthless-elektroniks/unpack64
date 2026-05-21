'''
Star Wars Episode 1 - Racer from Lucasarts

Very strange boot stub. The preamble has no BSS, but the bootexe is not packed,
and there is some odd code that looks like it should be moving the boot segment into place,
but it ends up moving code where it already is, then does a gigantic BSS clear
to wipe all of memory higher than the bootexe.

It doesn't look like this is a multi-load game. If it turns out that there are
overlays, they will be added later...
'''

import logging

from bffi import BffiBuilder, Bffi
from n64rom import N64Rom
from preamble import identify_preamble
from signature import SignatureBuilder, WILDCARD

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------------

SW1RACER_ENTRY_POINT_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x05, 0x00, 0x00,         # +0x00 lui        a1,0x0 <-- bootexe ROM start
        0x24, 0xa5, WILDCARD, WILDCARD, # +0x04 addiu      a1,a1,0x1120 
        0x3c, 0x0f, 0x00, WILDCARD,     # +0x08 lui        t7,0xb <-- bootexe ROM end
        0x25, 0xef, WILDCARD, WILDCARD, # +0x0C addiu      t7,t7,-0xb50
        0x24, 0xa3, 0xf4, 0x00,         # +0x10 addiu      v1,a1,-0xc00 <-- -0xC00 (estimating load address in RAM)
        0x3c, 0x01, 0x80, 0x00,         # +0x14 lui        at,0x8000
        0x01, 0xe5, 0x30, 0x23,         # +0x18 subu       a2,t7,a1
        0x00, 0x61, 0xc0, 0x25,         # +0x1C or         t8,v1,at
        0x27, 0xbd, 0xff, 0xe8,         # +0x20 addiu      sp,sp,-0x18
        0xaf, 0xbf, 0x00, 0x14,         # +0x24 sw         ra,0x14(sp)
        0x3c, 0x0e, 0xa4, 0x40,         # +0x28 lui        t6,0xa440
        0x3c, 0x02, 0x80, 0x00,         # +0x2C lui        v0,0x8000 <-- bootexe is loaded here (defeats point of ROM range stuff)
        0xad, 0xc0, 0x00, 0x24,         # +0x30 sw         zero,offset DAT_a4400024(t6)
        0x00, 0xc0, 0x38, 0x25,         # +0x34 or         a3,a2,zero
        0x03, 0x00, 0x18, 0x25,         # +0x38 or         v1,t8,zero
        0x24, 0x42, WILDCARD, WILDCARD, # +0x3C addiu      v0,v0,0x520
        0x00, 0x00, 0x20, 0x25,         # +0x40 or         a0,zero,zero
    ]) \
    .const_op32_hi16("bootexe_rom_start", 0x00) \
    .const_op32_lo16("bootexe_rom_start", 0x04) \
    .const_op32_hi16("bootexe_rom_end", 0x08) \
    .const_op32_lo16("bootexe_rom_end", 0x0C) \
    .const_op32_hi16("bootexe_load_address", 0x2C) \
    .const_op32_lo16("bootexe_load_address", 0x3C) \
    .build()


def sw1racer_unpack(rom: N64Rom, ipc: int) -> Bffi:
    if ipc != 0x80000400:
        return None
    
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    if preamble.bss_sections():
        # because preamble does not have BSS
        return None
    
    bootexe = rom.boot_exe()
    bootstub_offset = preamble.crt_entry_point() - ipc
    if SW1RACER_ENTRY_POINT_PATTERN.compare(bootexe, bootstub_offset) is False:
        return None
    
    logger.info("found Star Wars Ep 1 Racer boot stub")

    consts = SW1RACER_ENTRY_POINT_PATTERN.consts(ipc, bootexe, offset=bootstub_offset)

    bootexe_rom_start = consts["bootexe_rom_start"].get_value()
    bootexe_rom_end = consts["bootexe_rom_end"].get_value()
    bootexe_load_address = consts["bootexe_load_address"].get_value()

    bootstub_length = bootexe_rom_start-0x1000
    program_length = bootexe_rom_end-bootexe_rom_start

    if (bootexe_load_address - ipc) != bootstub_length:
        logger.error("bootstub length mismatch. program should be loaded at 0x%08x, got 0x%08x",
                     ipc+bootstub_length,
                     bootexe_load_address)
        return None

    # search for first jal in the boot stub, that's our entry point
    bootstub = bootexe[:bootstub_length]

    p = SignatureBuilder() \
        .pattern([0x0C, WILDCARD, WILDCARD, WILDCARD, WILDCARD]) \
        .xref_j_imm26("entry_point", 0) \
        .build()
    
    ep_offset = p.find(bootstub)
    if ep_offset is None:
        logger.error("where's the jal to the entry point?")
        return None
    
    entry_point = p.xrefs(ipc, bootstub, ep_offset)["entry_point"].get_address()

    logger.info("bootstub 0x%08x-0x%08x, program 0x%08x-0x%08x (entry point 0x%08x), BSS follows end of program",
                ipc,
                ipc+bootstub_length,
                ipc+bootstub_length,
                ipc+bootstub_length+program_length,
                entry_point)

    full_exe = bootexe[:bootstub_length+program_length]

    builder = BffiBuilder()
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(entry_point)
    builder.fix(ipc, full_exe)
    builder.bss(ipc+bootstub_length+program_length, 0x80400000-(ipc+bootstub_length+program_length))
    return builder.build()
