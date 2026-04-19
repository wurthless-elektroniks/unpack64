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
to start the game. A big table of resources is passed in a0 to the bootexe,
and they're decompressed using the same algorithm (I think).

The bootexe will load the following segments, in order:
- Resource 0x4E is a one-time init stub that loads to 0x80100000 and will be overwritten
  when the game starts.

- Resource 0x13 is the sound engine.

- Resource 0 is the main entry segment and it swaps between various code overlays
  as the game is running.
'''

import struct
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
        0x3c, 0x04, WILDCARD, WILDCARD,     # +0x14 lui   a0,0x1        <-- pointer to big table o' stuff in ROM
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x18 addiu a0,a0,0x16c0
        0x40, 0x06, 0x48, 0x00,             # +0x1C mfc0  a2,Count
        0x08, WILDCARD, WILDCARD, WILDCARD, # +0x20 j     LAB_80031000  <-- payload decompresses here
        0x02, 0x40, 0x28, 0x21,             # +0x24 _move a1,s2
    ]) \
    .const_op32_hi16("payload_address", 0x00) \
    .const_op32_lo16("payload_address", 0x04) \
    .const_op32_hi16("bigtable_rom_address", 0x14) \
    .const_op32_lo16("bigtable_rom_address", 0x18) \
    .xref_j_imm26("entry_point", 0x20) \
    .build()

# function in bootexe that loads resources places.
# if the resource is compressed, it's automatically decompressed
MARIOTENNIS_RESOURCELOADTO_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xe0,             # addiu      sp,sp,-0x20
        0xaf, 0xb0, 0x00, 0x10,             # sw         s0,local_10(sp)
        0x00, 0x80, 0x80, 0x21,             # move       s0,a0
        0xaf, 0xb1, 0x00, 0x14,             # sw         s1,local_c(sp)
        0xaf, 0xbf, 0x00, 0x18,             # sw         ra,local_8(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # jal        ResourceTableGetStartAddress
        0x00, 0xa0, 0x88, 0x21,             # _move      s1,a1
        0x02, 0x00, 0x20, 0x21,             # move       a0,s0
        0x0c, WILDCARD, WILDCARD, WILDCARD, # jal        ResourceTableGetSize
        0x00, 0x40, 0x80, 0x21,             # _move      s0,v0
        0x02, 0x00, 0x20, 0x21,             # move       a0,s0
        0x02, 0x20, 0x28, 0x21,             # move       a1,s1
        0x0c, WILDCARD, WILDCARD, WILDCARD, # jal        ResourceLoadToWithSize                                     undefined ResourceLoadToWithSize()
        0x00, 0x40, 0x30, 0x21,             # _move      a2,v0
        0x8f, 0xbf, 0x00, 0x18,             # lw         ra,local_8(sp)
        0x8f, 0xb1, 0x00, 0x14,             # lw         s1,local_c(sp)
        0x8f, 0xb0, 0x00, 0x10,             # lw         s0,local_10(sp)
        0x03, 0xe0, 0x00, 0x08,             # jr         ra
        0x27, 0xbd, 0x00, 0x20,             # _addiu     sp,sp,0x20
    ]) \
    .build()

MARIOTENNIS_LOAD_RESOURCE_0_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x10, 0x80, WILDCARD,         # +0x00 lui        s0,0x800d        <-- load address
        0x26, 0x10, WILDCARD, WILDCARD,     # +0x04 addiu      s0,s0,-0x8000
        0x3c, 0x04, 0x00, 0x00,             # +0x08 lui        a0,0x0
        0x24, 0x84, 0x00, 0x00,             # +0x0C addiu      a0,a0,0x0        <-- resource id #0: main entry point stub
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x10 jal        ResourceLoadTo
        0x02, 0x00, 0x28, 0x21              # +0x14 _move      a1,s0
    ]) \
    .const_op32_hi16("mainentry_load_address", 0x00) \
    .const_op32_lo16("mainentry_load_address", 0x04) \
    .xref_j_imm26("resourceloadto", 0x10) \
    .build()


MARIOTENNIS_LOAD_RESOURCE_013_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x10, 0x80, WILDCARD,         # +0x00 lui        s0,0x800d        <-- load address
        0x26, 0x10, WILDCARD, WILDCARD,     # +0x04 addiu      s0,s0,-0x8000
        0x3c, 0x04, 0x00, 0x00,             # +0x08 lui        a0,0x0
        0x24, 0x84, 0x00, 0x13,             # +0x0C addiu      a0,a0,0x0        <-- resource id #0x13: main engine?
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x10 jal        ResourceLoadTo
        0x02, 0x00, 0x28, 0x21              # +0x14 _move      a1,s0
    ]) \
    .const_op32_hi16("engine_load_address", 0x00) \
    .const_op32_lo16("engine_load_address", 0x04) \
    .xref_j_imm26("resourceloadto", 0x10) \
    .build()

def _unpack_resource(rom: N64Rom, bigtable_rom_address: int, resource_id: int):
    resource_start_pos, resource_end_pos = struct.unpack(">II", rom.read_bytes(bigtable_rom_address + (resource_id*8), 8))
    logger.info("try extract resource %d: in ROM at 0x%08x~0x%08x", resource_id, resource_start_pos, resource_end_pos)
    return mariotennis_decompress(rom.read_bytes(resource_start_pos, resource_end_pos-resource_start_pos))

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
    bigtable_rom_address = consts["bigtable_rom_address"].get_value()
    entry_point = xrefs["entry_point"].get_address()

    logger.info("unpacker decompresses payload at 0x%08x to 0x%08x", payload_address, entry_point)

    payload = mariotennis_decompress(rom.boot_exe()[payload_address-ipc:])
    
    resourceloadto_pos = MARIOTENNIS_RESOURCELOADTO_PATTERN.find(payload)
    if resourceloadto_pos is None:
        logger.error("cannot find ResourceLoadTo() in unpacked bootexe!")
        return None

    logger.info("ResourceLoadTo() is at 0x%08x", entry_point+resourceloadto_pos)

    loadresource0_pos = MARIOTENNIS_LOAD_RESOURCE_0_PATTERN.find(payload)
    if loadresource0_pos is None:
        logger.error("can't find code that loads resource 0")
        return None

    loadresource0_consts = MARIOTENNIS_LOAD_RESOURCE_0_PATTERN.consts(entry_point, payload, loadresource0_pos)
    loadresource0_xrefs  = MARIOTENNIS_LOAD_RESOURCE_0_PATTERN.xrefs(entry_point, payload, loadresource0_pos)
    if loadresource0_xrefs["resourceloadto"].get_address() != (entry_point + resourceloadto_pos):
        logger.error("resourceloadto mismatch. 0x%08x != 0x%08x",
                     loadresource0_xrefs["resourceloadto"].get_address(),
                     entry_point + resourceloadto_pos)
        return None
    
    loadresource013_pos = MARIOTENNIS_LOAD_RESOURCE_013_PATTERN.find(payload)
    if loadresource013_pos is None:
        logger.error("can't find code that loads resource 0x13")
        return None
    
    loadresource013_consts = MARIOTENNIS_LOAD_RESOURCE_013_PATTERN.consts(entry_point, payload, loadresource013_pos)
    loadresource013_xrefs  = MARIOTENNIS_LOAD_RESOURCE_013_PATTERN.xrefs(entry_point, payload, loadresource013_pos)
    if loadresource013_xrefs["resourceloadto"].get_address() != (entry_point + resourceloadto_pos):
        logger.error("resourceloadto mismatch. 0x%08x != 0x%08x",
                     loadresource0_xrefs["resourceloadto"].get_address(),
                     entry_point + resourceloadto_pos)
        return None

    mainentry_load_address = loadresource0_consts["mainentry_load_address"].get_value()
    engine_load_address = loadresource013_consts["engine_load_address"].get_value()
    logger.info("mainentry stub loads to 0x%08x", mainentry_load_address)
    logger.info("sound driver loads to 0x%08x", engine_load_address)

    builder = BffiBuilder()

    # unpacker clears this range; when the game starts execution it will clear
    # the upper 3 MB of RAM
    builder.bss(0x80000400, 0x100000-0x400)
    
    builder.fix(ipc, rom.boot_exe()[:payload_address-ipc])
    builder.fix(entry_point, payload)
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())

    main_segment = _unpack_resource(rom, bigtable_rom_address, 0)
    builder.fix(mainentry_load_address, main_segment)

    engine_segment = _unpack_resource(rom, bigtable_rom_address, 0x13)
    builder.fix(engine_load_address, engine_segment)


    return builder.build()
