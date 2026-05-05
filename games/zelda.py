'''
Zelda - Ocarina of Time / Majora's Mask
And also Dobutsu no Mori / Animal Forest because it uses the same framework

This framework relies heavily on Yaz0 compression, and everyone's favorite,
dynamically loaded segments. Maybe the EAD guys should've hollered down the
hall to the English gentlemen to use their USO framework so I didn't have to
write this.

The Zelda community has reverse engineered these games almost completely so
there's not much point adding this to unpack64, but I have to be as thorough
as possible...

Decomp links for reference:
- https://github.com/zeldaret/oot
- https://github.com/zeldaret/mm
- https://github.com/zeldaret/af
'''

import logging
import struct

from compression.yaz0 import yaz0_decompress

from bffi import Bffi,BffiBuilder
from n64rom import N64Rom
from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi
from signature import SignatureBuilder, WILDCARD, Signature
from sigutil import pick_pattern

logger = logging.getLogger(__name__)

# ------------------------------------------------
#
# Dobutsu no Mori (Animal Forest)
#
# Main executable is Yaz0 compressed.
#
# ------------------------------------------------

DOBUTSU_DMAMGR_INIT_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xe0,             # +0x00 addiu      sp,sp,-0x20
        0xaf, 0xbf, 0x00, 0x1c,             # +0x04 sw         ra,local_4(sp)
        0x3c, 0x04, 0x00, WILDCARD,         # +0x08 lui        a0,0x2 <-- ROM table start
        0x3c, 0x0e, 0x00, WILDCARD,         # +0x0C lui        t6,0x2 <-- ROM table end
        0x25, 0xce, WILDCARD, WILDCARD,     # +0x10 addiu      t6,t6,0x7130
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x14 addiu      a0,a0,-0x62c0
        0x3c, 0x05, 0x80, WILDCARD,         # lui        a1,0x8004
        0x24, 0xa5, WILDCARD, WILDCARD,     # addiu      a1=>DAT_80044690,a1,0x4690
        0x0c, WILDCARD, WILDCARD, WILDCARD, # jal        DmaMgr_DmaRomToRam
        0x01, 0xc4, 0x30, 0x23,             # _subu      a2,t6,a0
    ]) \
    .const_op32_hi16("rom_dma_table_start", 0x08) \
    .const_op32_lo16("rom_dma_table_start", 0x14) \
    .const_op32_hi16("rom_dma_table_end", 0x0C) \
    .const_op32_lo16("rom_dma_table_end", 0x10) \
    .build()

# see decomp, boot/idle.c, Main_ThreadEntry()
DOBUTSU_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x02, 0x00, WILDCARD,         # +0x00 lui        v0,0x67       <-- ROM start address
        0x3c, 0x0e, 0x00, WILDCARD,         # +0x04 lui        t6,0x74       <-- ROM end address
        0x24, 0x45, WILDCARD, WILDCARD,     # +0x08 addiu      a1,v0,0x5720
        0x25, 0xce, WILDCARD, WILDCARD,     # +0x0C addiu      t6,t6,-0xb30
        0x3c, 0x04, 0x80, WILDCARD,         # +0x10 lui        a0,0x8005     <-- load address
        0x3c, 0x07, 0x80, WILDCARD,         # +0x14 lui        a3,0x8004
        0x24, 0x0f, 0x00, 0x35,             # +0x18 li         t7,0x35
        0xaf, 0xaf, 0x00, 0x10,             # +0x1C sw         t7,0x10(sp)
        0x24, 0xe7, WILDCARD, WILDCARD,     # +0x20 addiu      a3,a3,-0x2e70
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x24 addiu      a0,a0,0x1a80
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x28 jal        DmaMgr_RequestSyncDebug
        0x01, 0xc5, 0x30, 0x23,             # +0x2C _subu      a2,t6,a1
        0x3c, 0x04, 0x80, WILDCARD,         # +0x30 lui        a0,0x8012     <-- BSS start
        0x3c, 0x18, 0x80, WILDCARD,         # +0x34 lui        t8,0x8015     <-- BSS end
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x38 addiu      a0,a0,-0x47d0
        0x27, 0x18, WILDCARD, WILDCARD,     # +0x3C addiu      t8,t8,0x24c0
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x40 jal        bzero
        0x03, 0x04, 0x28, 0x23,             # +0x44 _subu      a1,t8,a0
    ]) \
    .const_op32_hi16("yaz0_rom_start_address", 0x00) \
    .const_op32_lo16("yaz0_rom_start_address", 0x08) \
    .const_op32_hi16("yaz0_rom_end_address", 0x04) \
    .const_op32_lo16("yaz0_rom_end_address", 0x0C) \
    .const_op32_hi16("mainseg_load_address", 0x10) \
    .const_op32_lo16("mainseg_load_address", 0x24) \
    .const_op32_hi16("bss_start", 0x30) \
    .const_op32_lo16("bss_start", 0x38) \
    .const_op32_hi16("bss_end", 0x34) \
    .const_op32_lo16("bss_end", 0x3C) \
    .build()

def dobutsu_unpack(rom: N64Rom, ipc: int):
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    builder = BffiBuilder()
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)

    bootexe = rom.boot_exe()[:earliest_bss-ipc]

    builder.fix(ipc, bootexe)
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.initial_stack_pointer(preamble.initial_stack_pointer())

    dma_init_pattern_offset = DOBUTSU_DMAMGR_INIT_PATTERN.find(bootexe)
    load_pattern_offset = DOBUTSU_LOAD_PATTERN.find(bootexe)
    if None in [ dma_init_pattern_offset, load_pattern_offset ]:
        return None

    logger.info("found Dobutsu no Mori mainthread at 0x%08x", ipc+load_pattern_offset)
    logger.info("DMA manager init at 0x%08x", ipc+dma_init_pattern_offset)

    consts = DOBUTSU_DMAMGR_INIT_PATTERN.consts(ipc, bootexe, dma_init_pattern_offset)
    rom_dma_table_start = consts["rom_dma_table_start"].get_value()
    rom_dma_table_end = consts["rom_dma_table_end"].get_value()
    
    logger.info("DMA table in ROM at 0x%08x-0x%08x",
                rom_dma_table_start,
                rom_dma_table_end)
    
    dmatable = rom.read_bytes(rom_dma_table_start, rom_dma_table_end-rom_dma_table_start)

    consts = DOBUTSU_LOAD_PATTERN.consts(ipc, bootexe, load_pattern_offset)
    yaz0_rom_start_address = consts["yaz0_rom_start_address"].get_value()
    yaz0_rom_end_address = consts["yaz0_rom_end_address"].get_value()
    mainseg_load_address = consts["mainseg_load_address"].get_value()
    bss_start = consts["bss_start"].get_value()
    bss_end = consts["bss_end"].get_value()

    logger.info("main segment Yaz0: ROM 0x%08x-0x%08x -> decompress to RAM 0x%08x (bss 0x%08x-0x%08x)",
                yaz0_rom_start_address,
                yaz0_rom_end_address,
                mainseg_load_address,
                bss_start,
                bss_end)

    logger.info("decompressing the payload...")
    payload = rom.read_bytes(yaz0_rom_start_address, yaz0_rom_end_address-yaz0_rom_start_address)
    payload = yaz0_decompress(payload)

    builder.bss(bss_start, bss_end-bss_start)
    builder.fix(mainseg_load_address, payload)

    # TODO: capture all other overlays and code.
    # when debugging, a1 points to addresses in ROM that don't even exist,
    # or they point to non-Yaz0 payloads, where the code overlays should be.
    # someone has decompiled this game so i'm leaving this one as low priority.

    logger.info("more overlays are at large... but i'm tired boss")

    return builder.build()
