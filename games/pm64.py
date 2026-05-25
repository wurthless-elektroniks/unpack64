'''
Premier Manager 64
Eurotrash kickorb game with another awful loader scheme

This game will load 3 MB instead of the usual 1 MB into RDRAM at startup,
and although the actual useful code/data segment goes from 0x80000400-0x801aac40,
the game still expects the rest of the data to have been loaded there.
This driver will only dump the code segment.

This game uses a filesystem that starts at 0x1AB840. The format is:
- 4 bytes file size, including the header
- 4 bytes zero
- 12 bytes filename
- 4 bytes zero
- 4 bytes zero
- ... data follows ...

Some resources are RNC compressed.

Scattered between the various linked .o files are snippets of source code
that can't really be used for any purpose (I think).
'''


import logging

from bffi import Bffi,BffiBuilder
from n64rom import N64Rom
from preamble import identify_preamble
from signature import SignatureBuilder, WILDCARD

logger = logging.getLogger(__name__)

PM64_ENTRY_POINT_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xd8,             # +0x00 addiu sp,sp,-0x28
        0xaf, 0xbf, 0x00, 0x24,             # +0x04 sw    ra,local_4(sp)
        0xaf, 0xbe, 0x00, 0x20,             # +0x08 sw    s8,local_8(sp)
        0x03, 0xa0, 0xf0, 0x21,             # +0x0C move  s8,sp
        0x3c, 0x02, 0x80, 0x00,             # +0x10 lui   v0,0x8000
        0xaf, 0xc2, 0x00, 0x18,             # +0x14 sw    v0,local_10(s8)
        0x00, 0x00, 0x20, 0x21,             # +0x18 clear a0
        0x3c, 0x05, 0xb0, 0x10,             # +0x1C lui   a1,0xb010
        0x34, 0xa5, 0x0c, 0x00,             # +0x20 ori   a1,a1,0xc00
        0x3c, 0x06, 0x80, 0x10,             # +0x24 lui   a2,0x8010
        0x3c, 0x07, 0x00, 0x20,             # +0x28 lui   a3,0x20
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x2C jal osPiRawStartDma or something like it
        0x00, 0x00, 0x00, 0x00,             # +0x30 nop
    ]) \
    .tail_pattern([
        0x3c, 0x03, 0x80, 0x00,              # +0x7C lui   v1,0x8000
        0x8c, 0x63, 0x03, 0x18,              # +0x80 lw    v1,0x0318(v1)
        0x00, 0x43, 0x10, 0x25,              # +0x84 or    v0,v0,v1
        0xaf, 0xc2, 0x00, 0x18,              # +0x88 sw    v0,local_10(s8)
        0x8f, 0xc2, 0x00, 0x18,              # +0x8C lw    v0,local_10(s8)
        0x3c, 0x03, 0x80, WILDCARD,          # +0x90 lui   v1,0x801b
        0x24, 0x63, WILDCARD, WILDCARD,      # +0x94 addiu v1,v1,-0x53c0
        0x00, 0x43, 0x10, 0x23,              # +0x98 subu  v0,v0,v1
        0x3c, 0x04, 0x80, WILDCARD,          # +0x9C lui   a0,0x801b
        0x24, 0x84, WILDCARD, WILDCARD,      # +0xA0 addiu a0,a0,-0x53c0
        0x00, 0x40, 0x28, 0x21,              # +0xA4 move  a1,v0
        0x0c, WILDCARD, WILDCARD, WILDCARD,  # +0xA8 jal   FUN_80002d54
        0x00, 0x00, 0x00, 0x00,              # +0xAC _nop
    ]) \
    .size(0xB0) \
    .const_op32_hi16("code_end_address", 0x90) \
    .const_op32_lo16("code_end_address", 0x94) \
    .build()

def pm64_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None

    if preamble.bss_sections():
        # game does not use BSS
        return None

    # hardcoding always a great idea, ain't it.
    # if there's a similar loader found somewhere else this has to change.
    if ipc != 0x80000400:
        return None

    bootexe = rom.boot_exe()

    if PM64_ENTRY_POINT_PATTERN.compare(bootexe, preamble.crt_entry_point() - ipc) is False:
        return None

    logger.info("found Premier Manager 64 loading an extra 2 MB of code")

    consts = PM64_ENTRY_POINT_PATTERN.consts(ipc, bootexe, preamble.crt_entry_point() - ipc)

    code_end_address = consts["code_end_address"].get_value()
    code_length = code_end_address - ipc
    logger.info("actual code segment runs 0x%08x-0x%08x (%d bytes)", ipc, code_end_address, code_length)

    bootexe = rom.read_bytes(0x1000, code_length)

    # game has no BSS segments, it relies on zeroes loaded from the ROM
    builder = BffiBuilder()
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.fix(ipc, bootexe)

    return builder.build()

