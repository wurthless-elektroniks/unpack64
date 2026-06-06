'''
Hudson Soft
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
# Mario Party (also Mario Party 2 and 3)
#
# Simple uncompressed overlay swapper.
#
# Overlay table in US version at 0x800c1c74 structured as:
# - 4 bytes ROM start address
# - 4 bytes ROM end address
# - 4 bytes RAM load address
# - 4 bytes code section start?
# - 4 bytes code section end?
# - 4 bytes data section start?
# - 4 bytes data section end?
# - 4 bytes BSS section start
# - 4 bytes BSS section end
#
# ----------------------------------------------------------------------

# the read_overlay function called by this routine will call osInvalICache.
# not sure if that function's called somewhere else...
MARIOPARTY_OVERLAY_LOADER_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xe0,             # +0x00 addiu      sp,sp,-0x20
        0xaf, 0xbf, 0x00, 0x18,             # +0x04 sw         ra,local_8(sp)
        0xaf, 0xb1, 0x00, 0x14,             # +0x08 sw         s1,local_c(sp)
        0xaf, 0xb0, 0x00, 0x10,             # +0x0C sw         s0,local_10(sp)
        0x00, 0x04, 0x10, 0xc0,             # +0x10 sll        v0,a0,0x3
        0x00, 0x44, 0x10, 0x21,             # +0x14 addu       v0,v0,a0
        0x00, 0x02, 0x10, 0x80,             # +0x18 sll        v0,v0,0x2
        0x3c, 0x06, 0x80, WILDCARD,         # +0x1C lui        a2,0x800c
        0x00, 0xc2, 0x30, 0x21,             # +0x20 addu       a2,a2,v0
        0x8c, 0xc6, WILDCARD, WILDCARD,     # +0x24 lw         a2,offset DAT_800c1c74(a2)
        0x3c, 0x03, 0x80, WILDCARD,         # lui        v1,0x800c
        0x00, 0x62, 0x18, 0x21,             # addu       v1,v1,v0
        0x8c, 0x63, WILDCARD, WILDCARD,     # lw         v1,offset DAT_800c1c78(v1)
        0x3c, 0x10, 0x80, WILDCARD,         # lui        s0,0x800c
        0x02, 0x02, 0x80, 0x21,             # addu       s0,s0,v0
        0x8e, 0x10, WILDCARD, WILDCARD,     # lw         s0,offset PTR_DAT_800c1c90(s0)
        0x3c, 0x11, 0x80, WILDCARD,         # lui        s1,0x800c
        0x02, 0x22, 0x88, 0x21,             # addu       s1,s1,v0
        0x8e, 0x31, WILDCARD, WILDCARD,     # lw         s1,offset DAT_800c1c94(s1)
        0x00, 0xc0, 0x20, 0x21,             # move       a0,a2
        0x3c, 0x05, 0x80, WILDCARD,         # lui        a1,0x800c
        0x00, 0xa2, 0x28, 0x21,             # addu       a1,a1,v0
        0x8c, 0xa5, WILDCARD, WILDCARD,     # lw         a1,offset PTR_SUB_800c1c7c(a1)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # jal        read_overlay
        0x00, 0x66, 0x30, 0x23,             # _subu      a2,v1,a2
    ]) \
    .const_op32_hi16("overlay_table_address", 0x1c) \
    .const_op32_lo16("overlay_table_address", 0x24) \
    .build()

def marioparty_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    builder = BffiBuilder()
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    bootexe = rom.boot_exe()[:earliest_bss-ipc]

    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.fix(ipc, bootexe)

    overlay_loader_offset = MARIOPARTY_OVERLAY_LOADER_PATTERN.find(bootexe)
    if overlay_loader_offset is None:
        return None
    
    logger.info("found Mario Party overlay loader")

    consts = MARIOPARTY_OVERLAY_LOADER_PATTERN.consts(ipc, bootexe, overlay_loader_offset)
    overlay_table_address = consts["overlay_table_address"].get_value()
    overlay_table_offset = overlay_table_address - ipc

    i = 0
    while True:
        offs = overlay_table_offset + (i * 0x24)

        rom_start_address, rom_end_address, ram_load_address, \
        _, _, _, _, \
        bss_start_address, bss_end_address = struct.unpack(">IIIIIIIII", bootexe[offs:offs+0x24])

        if (ram_load_address >> 24) != 0x80:
            break

        logger.info("overlay %d: ROM 0x%08x-0x%08x -> RAM 0x%08x, bss 0x%08x-0x%08x",
                    i,
                    rom_start_address,
                    rom_end_address,
                    ram_load_address,
                    bss_start_address,
                    bss_end_address
                    )

        builder.seg(ram_load_address, rom.read_bytes(rom_start_address, rom_end_address-rom_start_address))

        i += 1
    
    return builder.build()
