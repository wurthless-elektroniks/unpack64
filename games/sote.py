'''
Star Wars: Shadows of the Empire

Compression method is a variant on LZH
'''

import logging
import struct

from compression.lzh import lzhsote_decompress
from preamble import identify_preamble
from n64rom import N64Rom
from bffi import Bffi,BffiBuilder
from signature import SignatureBuilder, WILDCARD

logger = logging.getLogger()

# -------------------------------------------------

SOTE_UNPACKER_ENTRY_POINT_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xd0,                 # +0x00 addiu sp,sp,-0x30
        0xaf, 0xbf, 0x00, 0x14,                 # +0x04 sw    ra,local_1c(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD,     # +0x08 jal   FUN_80000450   <-- pokes some hw registers
        0x00, 0x00, 0x00, 0x00,                 # +0x0C _nop
        0x3c, 0x09, 0x80, WILDCARD,             # +0x10 lui   t1,0x8000      <-- points to resource table thingy
        0x25, 0x29, WILDCARD, WILDCARD,         # +0x14 addiu t1,t1,0x1330
        0x8d, 0x24, 0x00, 0x08,                 # +0x18 lw    a0,0x8(t1)=>DAT_80001338
        0x8d, 0x2f, 0x00, 0x0c,                 # +0x1C lw    t7,0xc(t1)=>DAT_8000133c
        0x3c, 0x01, 0x80, 0x00,                 # +0x20 lui   at,0x8000
        0x24, 0x87, 0xf4, 0x00,                 # +0x24 addiu a3,a0,-0xc00
        0x00, 0xe1, 0x70, 0x25,                 # +0x28 or    t6,a3,at
        0x01, 0xe4, 0x40, 0x23,                 # +0x2C subu  t0,t7,a0
        0x01, 0xc0, 0x38, 0x25,                 # +0x30 or    a3,t6,zero
        0x01, 0xc0, 0x10, 0x25,                 # +0x34 or    v0,t6,zero
        0x3c, 0x03, 0x80, 0x30,                 # +0x38 lui   v1,0x8030
        0x00, 0x00, 0x30, 0x25,                 # +0x3C or    a2,zero,zero
        0x05, 0x01, 0x00, 0x03,                 # +0x40 bgez  t0,LAB_800011d4
        0x00, 0x08, 0x28, 0x83,                 # +0x44 _sra  a1,t0,0x2
    ]) \
    .const_op32_hi16("resource_table_address", 0x10) \
    .const_op32_lo16("resource_table_address", 0x14) \
    .build()

SOTE_UNPACKER_AUTO_UNPACK_PATTERN = SignatureBuilder() \
    .pattern([
        0x95, 0x2d, 0x00, 0x06,             # +0x00 lhu        t5,0x6(t1)=>DAT_80001336
        0x3c, 0x04, 0x80, 0x30,             # +0x04 lui        a0,0x8030
        0x3c, 0x02, 0x80, 0x30,             # +0x08 lui        v0,0x8030
        0x11, 0xa0, 0x00, 0x11,             # +0x0C beq        t5,zero,LAB_8000128c
        0x3c, 0x03, 0x80, 0x00,             # +0x10 _lui       v1,0x8000
        0x3c, 0x05, 0x80, WILDCARD,         # +0x14 lui        a1,0x8000
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x18 addiu      a1=>DAT_80001ec0,a1,0x1ec0
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x1C jal        lzhsote_decompress
        0xaf, 0xa6, 0x00, 0x18,             # +0x20 _sw        a2,local_18(sp)
    ]) \
    .const_op32_hi16("payload_load_address", 0x14) \
    .const_op32_lo16("payload_load_address", 0x18) \
    .build()

SOTE_UNPACKER_CALL_ENTRY_POINT_PATTERN = SignatureBuilder() \
    .pattern([
        0x0c, WILDCARD, WILDCARD, WILDCARD, # jal        SUB_800174b0
        0x00, 0x00, 0x00, 0x00,             # _nop
        0x8f, 0xbf, 0x00, 0x14,             # lw         ra,local_1c(sp)
        0x27, 0xbd, 0x00, 0x30,             # addiu      sp,sp,0x30
        0x03, 0xe0, 0x00, 0x08,             # jr         ra
        0x00, 0x00, 0x00, 0x00,             # _nop
    ]) \
    .xref_j_imm26("payload_entry_point", 0x00) \
    .build()

def sote_unpack(rom: N64Rom, ipc: int):
    # preamble has no BSS, so just grab the unpacker entry point
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    if preamble.bss_sections():
        return None

    unpacker_start_offset = preamble.crt_entry_point() - ipc

    bootexe = rom.boot_exe()
    if SOTE_UNPACKER_ENTRY_POINT_PATTERN.compare(bootexe, unpacker_start_offset) is False:
        return None

    consts = SOTE_UNPACKER_ENTRY_POINT_PATTERN.consts(ipc, bootexe, unpacker_start_offset)
    resource_table_address = consts["resource_table_address"].get_value()
    resource_table_address = resource_table_address - ipc

    magic, _, is_compressed, bootexe_rom_start, bootexe_rom_end = struct.unpack(">IHHII", bootexe[resource_table_address:resource_table_address+0x10])

    # 'Ogre' is our magic word for some reason
    if magic != 0x4F677265:
        return None

    auto_unpack_offset = SOTE_UNPACKER_AUTO_UNPACK_PATTERN.find(bootexe[:0x2000], unpacker_start_offset)
    if auto_unpack_offset is None:
        return None
    
    consts = SOTE_UNPACKER_AUTO_UNPACK_PATTERN.consts(ipc, bootexe, auto_unpack_offset)
    payload_load_address = consts["payload_load_address"].get_value()

    # trim unpacker segment; it has to stay loaded because it contains the LZH unpacker routine
    # and the resources table
    bootexe = bootexe[:payload_load_address-ipc]

    call_entry_point_offset = SOTE_UNPACKER_CALL_ENTRY_POINT_PATTERN.find(bootexe, auto_unpack_offset)
    if call_entry_point_offset is None:
        return None
    xrefs = SOTE_UNPACKER_CALL_ENTRY_POINT_PATTERN.xrefs(ipc, bootexe, call_entry_point_offset)
    payload_entry_point = xrefs["payload_entry_point"].get_address()

    logger.info("found Shadows of the Empire unpacker")
    logger.info("payload in ROM at 0x%08x-0x0%08x", bootexe_rom_start, bootexe_rom_end)

    # should always be compressed, but we'll handle this if-then-else anyway
    payload = rom.read_bytes(bootexe_rom_start, bootexe_rom_end-bootexe_rom_start)
    if is_compressed != 0:
        uncompressed_size = struct.unpack(">I", payload[:4])[0]
    
        logger.info("decompressing payload...")
        payload = lzhsote_decompress(payload[4:], uncompressed_size)
    
    logger.info("payload loads to 0x%08x-0x%08x, entry point at 0x%08x",
                payload_load_address,
                payload_load_address+len(payload),
                payload_entry_point)

    # loader drops 1 MB of BSS right after the payload
    bss_start = payload_load_address+len(payload)

    builder = BffiBuilder()
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(payload_entry_point)
    builder.fix(ipc, bootexe)
    builder.fix(payload_load_address, payload)
    builder.bss(bss_start, 0x100000)

    return builder.build()
