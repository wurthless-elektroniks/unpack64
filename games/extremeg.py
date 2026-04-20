'''
Extreme-G from Acclaim / Probe Software

bootexe is LZSS compressed.

From https://hack64.net/wiki/doku.php?id=extreme_g:rom_map, the header is

- u32 number of files in archive (should be 1 for the bootexe)
- u32 padding bytes, typically 0
- n file reference structures, as follows
    - u32 offset of LZSS-compressed data
    - u32 magic number "LZSS"
    - u32 destination size
    - u32 source size

For Extreme-G, this stub is loaded to 0x8004b8a0 (in rom at 0x14A0).
'''


import logging
import struct

from compression.lzss import lzss_decompress
from preamble import identify_preamble
from n64rom import N64Rom
from bffi import Bffi,BffiBuilder,BffiSectionType
from signature import SignatureBuilder, WILDCARD
from mips import disassemble_jump_imm26_target

logger = logging.getLogger(__name__)

EXTREMEG_UNPACKER_PATTERN = SignatureBuilder() \
    .pattern([
    # LZSS decompression is done entirely on the stack
    0x27, 0xbd, 0xef, 0xd0,     # +0x00 addiu      sp,sp,-0x1030
    0xaf, 0xbf, 0x10, 0x28,     # +0x04 sw         ra,local_8(sp)
    
    # loading registers for PIF communications
    0x3c, 0x03, 0xa4, 0x80,     # +0x08 lui        v1,0xa480
    0x34, 0x63, 0x00, 0x18,     # +0x0C ori        v1,v1,0x18
    0x3c, 0x05, 0xbf, 0xc0,     # +0x10 lui        a1,0xbfc0
    0x34, 0xa5, 0x07, 0xfc,     # +0x14 ori        a1,a1,0x7fc
    
    # wait for PIF to not be busy, then read status
    0x8c, 0x62, 0x00, 0x00,     # +0x18 lw         v0,0x0(v1)=>DAT_a4800018
    0x30, 0x42, 0x00, 0x03,     # +0x1C andi       v0,v0,0x3
    0x14, 0x40, 0xff, 0xfd,     # +0x20 bne        v0,zero,LAB_8004b4b0
    0x00, 0x00, 0x00, 0x00,     # +0x24 _nop
    0x8c, 0xa4, 0x00, 0x00,     # +0x28 lw         a0,0x0(a1)=>DAT_bfc007fc

    # wait again for PIF to not be busy, then write command 0x08
    # so that the PIF will not lock the system up while we decompress the payload
    0x8c, 0x62, 0x00, 0x00,     # +0x2C lw         v0,0x0(v1)=>DAT_a4800018
    0x30, 0x42, 0x00, 0x03,     # +0x30 andi       v0,v0,0x3
    0x14, 0x40, 0xff, 0xfd,     # +0x34 bne        v0,zero,LAB_8004b4c4
    0x34, 0x82, 0x00, 0x08,     # +0x38 _ori       v0,a0,0x8
    0xac, 0xa2, 0x00, 0x00,     # +0x3C 0sw         v0,0x0(a1)=>DAT_bfc007fc

    # now what we actually want: the boot executable.
    # we have it in RAM already, so it gets copied to higher RAM
    # and decompressed to where we read it from in the first place.
    # rest of this function can be thrown in the trash.
    0x00, 0x00, 0x28, 0x21,         # +0x40 clear      a1
    0x3c, 0x04, 0x80, WILDCARD,     # +0x44 lui        a0,0x8025
    0x24, 0x84, WILDCARD, WILDCARD, # +0x48 addiu      a0,a0,-0x4760
    0x3c, 0x03, 0x80, WILDCARD,     # +0x4C lui        v1,0x8005      <-- payload lives here
    0x24, 0x63, WILDCARD, WILDCARD, # +0x50 addiu      v1,v1,-0x4760
    ]) \
    .const_op32_hi16("payload_address", 0x4C) \
    .const_op32_lo16("payload_address", 0x50) \
    .build()


def extremeg_unpack_common(rom: N64Rom, ipc: int, payload_address: int) -> Bffi:
    logger.info("payload will load to 0x%08x", payload_address)

    payload_offset = payload_address - ipc
    magic, uncompressed, compressed = struct.unpack(">III", rom.boot_exe()[payload_offset + 0x0C:payload_offset + 0x0C + 0x0C])
    if magic != 0x4C5A5353:
        logger.error("invalid LZSS magic word")
        return None
    logger.info("uncompressed size %d, compressed size %d", uncompressed, compressed)

    lzss_data = rom.boot_exe()[payload_offset + 0x0C + 0x0C:payload_offset + 0x0C + 0x0C + compressed]
    uncompressed_data = lzss_decompress(lzss_data)

    if len(uncompressed_data) != uncompressed:
        logger.error("uncompressed size mismatch. expected %d, got %d", uncompressed, len(uncompressed_data))
        return None
    
    real_preamble = identify_preamble(uncompressed_data, payload_address)
    if real_preamble is None:
        logger.error("real preamble was not recognized")
        return None
    
    builder = BffiBuilder()
    builder.initial_program_counter(real_preamble.crt_entry_point())
    builder.initial_stack_pointer(real_preamble.initial_stack_pointer())
    for bss_start, bss_end in real_preamble.bss_sections():
        builder.bss(bss_start, bss_end-bss_start)

    builder.fix(payload_address, uncompressed_data)

    return builder.build()

def extremeg_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    if EXTREMEG_UNPACKER_PATTERN.compare(rom.boot_exe(), preamble.crt_entry_point() - ipc) is False:
        return None
    
    logger.info("found Extreme-G LZSS unpacker")

    consts = EXTREMEG_UNPACKER_PATTERN.consts(ipc, rom.boot_exe(), preamble.crt_entry_point() - ipc)
    payload_address = consts["payload_address"].get_value()
    return extremeg_unpack_common(rom, ipc, payload_address)

# XG2 is the same unpacker, but the return address and s0 are pushed to the stack
# even though this function will not be returning (it jumps right to the bootexe)
XG2_UNPACKER_PATTERN = SignatureBuilder() \
    .pattern([
    # LZSS decompression is done entirely on the stack
    0x27, 0xbd, 0xef, 0xd0,     # +0x00 addiu      sp,sp,-0x1030

    # loading registers for PIF communications
    0x3c, 0x03, 0xa4, 0x80,     # +0x04 lui        v1,0xa480
    0x34, 0x63, 0x00, 0x18,     # +0x08 ori        v1,v1,0x18
    0x3c, 0x05, 0xbf, 0xc0,     # +0x0C lui        a1,0xbfc0
    0x34, 0xa5, 0x07, 0xfc,     # +0x10 ori        a1,a1,0x7fc

    # useless stack pushes (this function never returns)
    0xaf, 0xbf, 0x10, 0x2c,     # +0x14 sw         ra,local_4(sp)
    0xaf, 0xb0, 0x10, 0x28,     # +0x18 sw         s0,local_8(sp)

    # wait for PIF to not be busy, then read status
    0x8c, 0x62, 0x00, 0x00,     # +0x1C lw         v0,0x0(v1)=>DAT_a4800018
    0x30, 0x42, 0x00, 0x03,     # +0x20 andi       v0,v0,0x3
    0x14, 0x40, 0xff, 0xfd,     # +0x24 bne        v0,zero,LAB_8004b4b0
    0x00, 0x00, 0x00, 0x00,     # +0x28 _nop
    0x8c, 0xa4, 0x00, 0x00,     # +0x2C lw         a0,0x0(a1)=>DAT_bfc007fc

    # wait again for PIF to not be busy, then write command 0x08
    # so that the PIF will not lock the system up while we decompress the payload
    0x8c, 0x62, 0x00, 0x00,     # +0x30 lw         v0,0x0(v1)=>DAT_a4800018
    0x30, 0x42, 0x00, 0x03,     # +0x34 andi       v0,v0,0x3
    0x14, 0x40, 0xff, 0xfd,     # +0x38 bne        v0,zero,LAB_8004b4c4
    0x34, 0x82, 0x00, 0x08,     # +0x3C _ori       v0,a0,0x8
    0xac, 0xa2, 0x00, 0x00,     # +0x40 sw         v0,0x0(a1)=>DAT_bfc007fc

    # small difference here too: a2 starts getting loaded with the size of the
    # payload, but we'll just grab it from the payload itself.
    0x00, 0x00, 0x28, 0x21,         # +0x44 clear      a1
    0x3c, 0x06, 0x00, WILDCARD,     # +0x48 lui        a2,0x3
    0x3c, 0x02, 0x80, WILDCARD,     # +0x4C lui        v0,0x8025
    0x24, 0x44, WILDCARD, WILDCARD, # +0x50 addiu      a0,v0,-0x45E0
    0x3c, 0x02, 0x80, WILDCARD,     # +0x54 lui        v0,0x8005      <-- payload lives here
    0x24, 0x43, WILDCARD, WILDCARD, # +0x58 addiu      v1,v0,-0x45E0
    ]) \
    .const_op32_hi16("payload_address", 0x54) \
    .const_op32_lo16("payload_address", 0x58) \
    .build()

def xg2_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    if XG2_UNPACKER_PATTERN.compare(rom.boot_exe(), preamble.crt_entry_point() - ipc) is False:
        return None
    
    logger.info("found XG2 LZSS unpacker")

    consts = XG2_UNPACKER_PATTERN.consts(ipc, rom.boot_exe(), preamble.crt_entry_point() - ipc)
    payload_address = consts["payload_address"].get_value()
    return extremeg_unpack_common(rom, ipc, payload_address)
