'''
Star Wars: Shadows of the Empire

Compression method is a variant on LZH
See also:
- https://github.com/msmiley/lzh/blob/master/src/lzh.c
- https://www.romhacking.net/forum/index.php?topic=40627.0
'''

import logging
import struct
from gzip import decompress

from compression.lzss import lzss_decompress
from preamble import identify_preamble
from n64rom import N64Rom
from bffi import Bffi,BffiBuilder,BffiSectionType
from signature import SignatureBuilder, WILDCARD
from mips import disassemble_jump_imm26_target

def sote_unpack(rom: N64Rom, ipc: int):
    # LZH-compressed payload is in ROM at 0x2AC0, with the decompressed size
    # written as a big-endian integer        
    lzh_payload = bytearray(rom.read_bytes(0x2AC0, 0x83590-0x2AC0))

