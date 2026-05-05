'''
Excitebike 64

This one is sorta clever. It initializes a miniature version of the OS and displays
the "N64 Sports" logo while it's decompressing the real game executable.
Then the real boot executable is moved to 0x80000400 and executed.

The bootloader contains a very simple relocation function at 80001698.
It only seems to use it for the function that moves the main executable into
place and runs it.

This game has a lot of copy protection functions that check the IPL3 space,
but I'm not sure what the sideffects are or if it's just leftover debugging code...
'''

import logging
import struct

from compression.brs import brs_decompress

from bffi import BffiBuilder, Bffi
from n64rom import N64Rom
from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi
from signature import SignatureBuilder, WILDCARD

logger = logging.getLogger(__name__)

# ----------------------------------------------------------

EXCITEBIKE_LOAD_BRS_TO_MEMORY_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x06, 0xb0, WILDCARD,          # lui        a2,0xb001
        0x24, 0xc6, WILDCARD, WILDCARD,      # addiu      a2,a2,0x2230
        0x3c, 0x02, 0x80, WILDCARD,          # lui        v0,0x8001
        0x24, 0x10, 0x00, 0x03,              # li         s0,0x3
        0x8c, 0x44, WILDCARD, WILDCARD,      # lw         a0,offset DAT_80017c34(v0)
        0x03, 0xc0, 0x38, 0x21,              # move       a3,s8
        0x0c, WILDCARD, WILDCARD, WILDCARD,  # jal        FUN_80000a30
    ]) \
    .const_op32_hi16("rom_address", 0x00) \
    .const_op32_lo16("rom_address", 0x04) \
    .build()

def excitebike_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, None)
    bootexe = rom.boot_exe()[:earliest_bss-ipc]

    # TODO: this game has two boot exes, the one that decompresses the game while showing
    # the n64 sports logo, and the actual main game code. for now, i'm only saving the
    # main game code.

    load_brs_to_memory_offset = EXCITEBIKE_LOAD_BRS_TO_MEMORY_PATTERN.find(bootexe)
    if load_brs_to_memory_offset is None:
        return None
    
    consts = EXCITEBIKE_LOAD_BRS_TO_MEMORY_PATTERN.consts(ipc, bootexe, load_brs_to_memory_offset)
    rom_address = consts["rom_address"].get_value() & 0x03FFFFFF
    if rom.read_bytes(rom_address, 8) != b'BRSOHYES':
        return None
    
    logger.info("found Excitebike 64 BRS main executable loader")
    logger.info("compressed executable is in ROM at 0x%08x", rom_address)

    unpacked = brs_decompress(rom.read_bytes_until_end(rom_address))

    # HACK: main exe load point is guessed, this hardcoding should be removed!
    preamble = identify_preamble(unpacked, ipc)
    if preamble is None:
        logger.error("unable to identify preamble of unpacked game code!")
        return None
    

    builder = BffiBuilder()
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    mainexe = unpacked[:earliest_bss-ipc]

    if len(mainexe) != len(unpacked):
        raise RuntimeError(f"code segment length mismatch: expected {len(unpacked)} got {len(mainexe)}")
    
    builder.fix(ipc, mainexe)
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.initial_stack_pointer(preamble.initial_stack_pointer())

    # TODO: more code segments? the NES emulator is something that can't be loaded
    # at all times...

    return builder.build()
