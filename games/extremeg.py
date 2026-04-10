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

def extremeg_unpack(rom: N64Rom, ipc: int) -> Bffi:
    # standard preamble with a small bss section which the unpacker probably needs
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    # TODO: remove all this hardcoding...

    magic, uncompressed, compressed = struct.unpack(">III",rom.read_bytes(0x14AC, 12))
    if magic != 0x4C5A5353:
        logger.error("invalid LZSS magic word")
        return None
    
    logger.info("uncompressed size %d, compressed size %d", uncompressed, compressed)

    lzss_data = rom.read_bytes(0x14AC + 12, compressed)
    uncompressed_data = lzss_decompress(lzss_data)

    if len(uncompressed_data) != uncompressed:
        logger.error("uncompressed size mismatch. expected %d, got %d", uncompressed, len(uncompressed_data))
        return None
    
    builder = BffiBuilder()
    builder.rom_hash(rom.sha256())

    for start_addr,end_addr in preamble.bss_sections():
        logger.info("bss: %08x - %08x", start_addr, end_addr)
        builder.bss(start_addr,end_addr-start_addr)
    
    builder.fix(ipc, rom.boot_exe()[:0x8004b8a0-ipc])
    builder.fix(0x8004b8a0, uncompressed_data)
    builder.initial_program_counter(0x8004B8A0)
    builder.initial_stack_pointer(0x803FFFF0)

    return builder.build()
