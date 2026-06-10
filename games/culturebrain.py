'''
Culture Brain
'''


import logging
import struct


from bffi import BffiBuilder, Bffi
from n64rom import N64Rom
from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi
from signature import SignatureBuilder, WILDCARD

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------
#
# Hamster Monogatari 64
#
# Game swaps between two uncompressed overlays.
#
# Overlay struct is 10 words:
# - 4 bytes load address
# - 4 bytes code start address
# - 4 bytes code end address
# - 4 bytes data start address
# - 4 bytes data end address
# - 4 bytes bss start address (0 if no bss)
# - 4 bytes bss end address
# - 4 bytes ROM start address
# - 4 bytes ROM end address
# - 4 bytes entry point/init address
#
# ----------------------------------------------------------------------

# at 0x80029840
HAMSTER64_OVERLAY_SWAPPER_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xd0,         # +0x00 addiu      sp,sp,-0x30
        0xaf, 0xbf, 0x00, 0x2c,         # +0x04 sw         ra,local_4(sp)
        0xaf, 0xb2, 0x00, 0x28,         # +0x08 sw         s2,local_8(sp)
        0xaf, 0xb1, 0x00, 0x24,         # +0x0C sw         s1,local_c(sp)
        0xaf, 0xb0, 0x00, 0x20,         # +0x10 sw         s0,local_10(sp)
        0x00, 0x80, 0x88, 0x21,         # +0x14 move       s1,a0
        0x00, 0x11, 0x10, 0x80,         # +0x18 sll        v0,s1,0x2
        0x00, 0x51, 0x10, 0x21,         # +0x1C addu       v0,v0,s1
        0x00, 0x02, 0x80, 0xc0,         # +0x20 sll        s0,v0,0x3
        0x3c, 0x02, 0x80, WILDCARD,     # +0x24 lui        v0,0x8006 <-- overlay table start
        0x00, 0x50, 0x10, 0x21,         # +0x28 addu       v0,v0,s0
        0x8c, 0x42, WILDCARD, WILDCARD, # +0x2C lw         v0,-0x40c0(v0)
        0x10, 0x40, 0x00, 0x43,         # +0x30 beq        v0,zero,LAB_80029980
        0x00, 0xa0, 0x90, 0x21,         # +0x34 _move      s2,a1
    ]) \
    .const_op32_hi16("overlay_table_address", 0x24) \
    .const_op32_lo16("overlay_table_address", 0x2C) \
    .build()

def hamster64_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None

    builder = BffiBuilder()
    earliest_bss_address, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    bootexe = rom.boot_exe()[:earliest_bss_address-ipc]
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.fix(ipc, bootexe)

    overlay_swapper_offset = HAMSTER64_OVERLAY_SWAPPER_PATTERN.find(bootexe)
    if overlay_swapper_offset is None:
        return None
    
    logger.info("found Hamster Monogatari 64 overlay swapper")

    consts = HAMSTER64_OVERLAY_SWAPPER_PATTERN.consts(ipc, bootexe, overlay_swapper_offset)

    overlay_table_address = consts["overlay_table_address"].get_value()
    logger.info("overlay table is at 0x%08x", overlay_table_address)
    overlay_table_offset = overlay_table_address - ipc

    for i in range(99999):
        offs = overlay_table_offset + (i * 10 * 4)

        load_address, \
        code_start, code_end, \
        data_start, data_end, \
        bss_start, bss_end, \
        rom_start, rom_end, \
        entry_point = struct.unpack(">IIIIIIIIII", bootexe[offs:offs+(10*4)])

        if load_address == 0:
            # game can have gaps in the overlay table
            continue

        if (code_start >> 24) != 0x80 or (code_end >> 24) != 0x80 or (entry_point >> 24) != 0x80:
            break
        
        logger.info("overlay %d: ROM 0x%08x-0x%08x -> RAM 0x%08x",
                    i,
                    rom_start,
                    rom_end,
                    load_address)
        
        if bss_start != 0:
            logger.info("overlay %d: BSS 0x%08x-0x%08x",
                        i,
                        bss_start,
                        bss_end)

        segment = rom.read_bytes(rom_start, rom_end-rom_start)
        builder.seg(load_address, segment)
    
    return builder.build()
