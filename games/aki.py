'''
Aki Corporation's output of pro wrestling games
'''

import logging
import struct

from bffi import BffiBuilder, Bffi
from n64rom import N64Rom
from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi
from signature import SignatureBuilder, WILDCARD

logger = logging.getLogger(__name__)

# ------------------------------------------------
#
# WWF No Mercy
#
# 8000073c swaps overlays. The main thread is at 80026918 and will
# swap overlays in a loop depending on the game state.
#
# Though this game has an overlay table it passes the data directly to
# the overlay swapper. The table starts at 80052e40 and is in this format:
#
# - +0x00 [0] 4 bytes ROM start address
# - +0x04 [1] 4 bytes ROM end address
# - +0x08 [2] 4 bytes RAM load address
# - +0x0C [3] 4 bytes code start address
# - +0x10 [4] 4 bytes code end address
# - +0x14 [5] 4 bytes data start address
# - +0x18 [6] 4 bytes data end address
# - +0x1C [7] 4 bytes bss start address
# - +0x20 [8] 4 bytes bss end address
#
# Immediately following the last overlay (at 0x001bd1b0) is compressed data.
# This game is known to use compressed text and textures, probably not code though.
#
# ------------------------------------------------

WWFNOMERCY_MAINLOOP_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x14, 0x80, WILDCARD,     # lui        s4,0x8005 <-- start of overlay table, plus 0x10
        0x26, 0x94, WILDCARD, WILDCARD, # addiu      s4,s4,0x2e50
        0x3c, 0x13, 0x80, WILDCARD,     # lui        s3,0x8005
        0x26, 0x73, WILDCARD, WILDCARD, # addiu      s3,s3,0x2e74
        0x3c, 0x12, 0x80, WILDCARD,     # lui        s2,0x8005
        0x26, 0x52, WILDCARD, WILDCARD, # addiu      s2,s2,0x2e98
        0x3c, 0x11, 0x80, WILDCARD,     # lui        s1,0x8005
        0x26, 0x31, WILDCARD, WILDCARD, # addiu      s1,s1,0x2ee0
        0x3c, 0x10, 0x80, WILDCARD,     # lui        s0,0x8005
        0x26, 0x10, WILDCARD, WILDCARD, # addiu      s0,s0,0x2ebc
        0x3c, 0x01, 0x80, WILDCARD,     # lui        at,0x800a
        0xac, 0x20, WILDCARD, WILDCARD, # sw         zero,offset DAT_800a25e0(at)
        0x3c, 0x01, 0x80, WILDCARD,     # lui        at,0x800a
        0xa0, 0x20, WILDCARD, WILDCARD, # sb         zero,-0x6af8(at)=>DAT_80099508
        0x8e, 0x84, 0xff, 0xf0,         # lw         a0,-0x10(s4)
    ]) \
    .const_op32_hi16("overlay_table_address", 0x00) \
    .const_op32_lo16("overlay_table_address", 0x04) \
    .build()

def wwfnomercy_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    builder = BffiBuilder()
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    bootexe = rom.boot_exe()[:earliest_bss-ipc]

    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.fix(ipc, bootexe)

    mainloop_offset = WWFNOMERCY_MAINLOOP_PATTERN.find(bootexe)
    if mainloop_offset is None:
        return None
    
    logger.info("found WWF No Mercy mainloop")

    consts = WWFNOMERCY_MAINLOOP_PATTERN.consts(ipc, bootexe, mainloop_offset)

    # remember, this offset is +0x10, so subtract that before reading the table!
    overlay_table_address = consts["overlay_table_address"].get_value() - 0x10

    overlay_table_offset = overlay_table_address - ipc

    for i in range(999):
        overlay_entry_offset = overlay_table_offset + (i * 0x24)

        # don't care about code/data ranges when dumping. maybe we will in the future though
        rom_start, rom_end, load_address, _, _, _, _, bss_start, bss_end = \
            struct.unpack(">IIIIIIIII", bootexe[overlay_entry_offset:overlay_entry_offset+0x24])
        
        if (load_address >> 24) != 0x80:
            break

        logger.info("overlay: ROM 0x%08x-0x%08x -> RAM 0x%08x (bss 0x%08x-0x%08x)",
                    rom_start,
                    rom_end,
                    load_address,
                    bss_start,
                    bss_end)

        seg = rom.read_bytes(rom_start, rom_end - rom_start)
        builder.seg(load_address, seg)
    
    return builder.build()
