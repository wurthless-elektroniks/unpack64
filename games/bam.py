'''
Bust-A-Move '99

This game uses a .bss-less preamble but is otherwise unpacked, which throws off
the automatic unpacker.

.bss initialization happens in the CRT startup right after osInitialize().
'''

import logging

from n64rom import N64Rom
from bffi import Bffi,BffiBuilder
from signature import SignatureBuilder, WILDCARD
from preamble import identify_preamble

logger = logging.getLogger(__name__)

BAM99_CRT_STARTUP_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xe0,             # +0x00 addiu      sp,sp,-0x20
        0xaf, 0xbf, 0x00, 0x1c,             # +0x04 sw         ra,local_4(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x08 jal        FUN_80097c80    <-- osInitialize()
        0xaf, 0xb0, 0x00, 0x18,             # +0x0C _sw        s0,local_8(sp)
        0x3c, 0x04, 0x80, WILDCARD,         # +0x10 lui        a0,0x800c       <-- bss start
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x14 addiu      a0,a0,-0x3020   <-- bss start
        0x00, 0x00, 0x28, 0x21,             # +0x18 clear      a1
        0x3c, 0x06, 0x80, WILDCARD,         # +0x1C lui        a2,0x8013       <-- bss end
        0x24, 0xc6, WILDCARD, WILDCARD,     # +0x20 addiu      a2,a2,0x68d0    <-- bss end
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x24 jal        FUN_8008ccb4    <-- memset()
        0x00, 0xc4, 0x30, 0x23,             # +0x28 _subu      a2,a2,a0
    ]) \
    .const_op32_hi16("bss_start", 0x10) \
    .const_op32_lo16("bss_start", 0x14) \
    .const_op32_hi16("bss_end",   0x1C) \
    .const_op32_lo16("bss_end",   0x20) \
    .build()

def bam99_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None

    if BAM99_CRT_STARTUP_PATTERN.compare(rom.boot_exe(), preamble.crt_entry_point() - ipc) is False:
        return None

    logger.info("found Bust-A-Move '99 .bss-less entry point with .bss init in CRT startup")

    consts = BAM99_CRT_STARTUP_PATTERN.consts(ipc, rom.boot_exe(), preamble.crt_entry_point() - ipc)
    bss_start = consts["bss_start"].get_value()
    bss_end = consts["bss_end"].get_value()

    builder = BffiBuilder()
    builder.bss(bss_start, bss_end-bss_start)
    builder.fix(ipc, rom.boot_exe()[:bss_start-ipc])
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    return builder.build()
