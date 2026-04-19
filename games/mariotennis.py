'''
Mario Tennis (custom packed)

Mario Tennis (US):
- BSS clears 0x80000400-0x80100000
- Boot executable is compressed in RAM at 0x80300350-0x803106AF
- Decompresses to 0x80031000~0x8005BE10
- Entry point is at 0x80031000

Once the main thread starts execution, the upper 3 MB are cleared,
so the unpacker will be wiped from memory at that point.

The bootexe is only 176 kbytes so it obviously needs to load more code segments
to start the game.
'''

import logging

from preamble import identify_preamble
from n64rom import N64Rom
from bffi import Bffi,BffiBuilder
from signature import SignatureBuilder, WILDCARD
from compression.mariotennis import mariotennis_decompress

logger = logging.getLogger(__name__)

MARIOTENNIS_UNPACKER_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x04, 0x80, 0x30,             # +0x00 lui   a0,0x8030      <-- compressed payload address
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x04 addiu a0,a0,0x350
        0x40, 0x12, 0x48, 0x00,             # +0x08 mfc0  s2,Count
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x0C jal   FUN_80300080
        0x00, 0x00, 0x00, 0x00,             # +0x10 _nop
        0x3c, 0x04, WILDCARD, WILDCARD,     # +0x14 lui   a0,0x1        <-- some argument to be passed to the payload
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x18 addiu a0,a0,0x16c0
        0x40, 0x06, 0x48, 0x00,             # +0x1C mfc0  a2,Count
        0x08, WILDCARD, WILDCARD, WILDCARD, # +0x20 j     LAB_80031000  <-- payload decompresses here
        0x02, 0x40, 0x28, 0x21,             # +0x24 _move a1,s2
    ]) \
    .const_op32_hi16("payload_address", 0x00) \
    .const_op32_lo16("payload_address", 0x04) \
    .xref_j_imm26("entry_point", 0x20) \
    .build()

def mariotennis_unpack(rom: N64Rom, ipc: int) -> Bffi:
    logger.info("using identify_preamble() to grab standard libultra bss-free preamble")
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None

    if MARIOTENNIS_UNPACKER_PATTERN.compare(rom.boot_exe(), preamble.crt_entry_point()-ipc) is False:
        return None
    
    logger.info("found Mario Tennis unpacker")

    consts = MARIOTENNIS_UNPACKER_PATTERN.consts(ipc, rom.boot_exe(), preamble.crt_entry_point()-ipc)
    xrefs  = MARIOTENNIS_UNPACKER_PATTERN.xrefs(ipc, rom.boot_exe(), preamble.crt_entry_point()-ipc)

    payload_address = consts["payload_address"].get_value()
    entry_point = xrefs["entry_point"].get_address()

    logger.info("unpacker decompresses payload at 0x%08x to 0x%08x", payload_address, entry_point)

    payload = mariotennis_decompress(rom.boot_exe()[payload_address-ipc:])
    
    builder = BffiBuilder()

    # unpacker clears this range; when the game starts execution it will clear
    # the upper 3 MB of RAM
    builder.bss(0x80000400, 0x100000-0x400)
    
    builder.fix(ipc, rom.boot_exe()[payload_address-ipc])
    builder.fix(entry_point, payload)
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())

    return builder.build()
