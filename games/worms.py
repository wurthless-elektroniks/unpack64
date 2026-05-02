'''
Worms Armageddon

Incredibly messy code that turns out to just have a normal osPiStartDma() call
here and there.
'''

import logging

from bffi import Bffi, BffiBuilder
from n64rom import N64Rom
from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi
from signature import SignatureBuilder, WILDCARD

logger = logging.getLogger(__name__)

# -------------------------------------------------------

WORMS_FIRST_OVERLAY_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x03, 0x80, WILDCARD,          # +0x00 lui        v1,0x8005        <-- load address
        0x24, 0x76, WILDCARD, WILDCARD,      # +0x04 addiu      s6,v1,-0x7020
        0x02, 0x00, 0x90, 0x21,              # +0x08 move       s2,s0
        0x27, 0xb7, 0x00, 0x30,              # +0x0C addiu      s7,sp,0x30
        0xae, 0x42, 0x15, 0x1c,              # +0x10 sw         v0,0x151c(s2)

        # start of a big ass loop
        0x3c, 0x05, WILDCARD, WILDCARD,      # +0x14 lui    a1,0x4          clearing caches
        0x24, 0xa5, WILDCARD, WILDCARD,      # +0x18 addiu  a1,a1,0x6370
        0x0c, WILDCARD, WILDCARD, WILDCARD,  # +0x1C jal    FUN_8002acc0
        0x02, 0xc0, 0x20, 0x21,              # +0x20 _move  a0,s6
        0x3c, 0x05, WILDCARD, WILDCARD,      # +0x24 lui    a1,0x4          sizeof is set up multiple times
        0x24, 0xa5, WILDCARD, WILDCARD,      # +0x28 addiu  a1,a1,0x6370
        0x0c, WILDCARD, WILDCARD, WILDCARD,  # +0x2C jal    FUN_8002ac10
        0x02, 0xc0, 0x20, 0x21,              # +0x30 _move  a0,s6
        0x3c, 0x04, 0xb0, WILDCARD,          # +0x34 lui    a0,0xb004       <-- ROM address
        0x24, 0x84, WILDCARD, WILDCARD,      # +0x38 addiu  a0,a0,-0x72c0
        0x02, 0xc0, 0x28, 0x21,              # +0x3C move   a1,s6
        0x3c, 0x06, WILDCARD, WILDCARD,      # +0x40 lui    a2,0x4          <-- sizeof
        0x24, 0xc6, WILDCARD, WILDCARD,      # +0x44 addiu  a2,a2,0x6370
        0x0c, 0x00, 0xbf, 0xac,              # +0x48 jal    readcart
        0x3c, 0x10, WILDCARD, WILDCARD,      # +0x4C _lui   s0,0xb008       <-- seemingly useless
    ]) \
    .const_op32_hi16("ram_load_address", 0x00) \
    .const_op32_lo16("ram_load_address", 0x04) \
    .const_op32_hi16("rom_address", 0x34) \
    .const_op32_lo16("rom_address", 0x38) \
    .const_op32_hi16("payload_size", 0x40) \
    .const_op32_lo16("payload_size", 0x44) \
    .build()

WORMS_SUBSEQUENT_OVERLAY_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x04, WILDCARD, WILDCARD,      # +0x00 lui   a0,0xb008
        0x24, 0x84, WILDCARD, WILDCARD,      # +0x04 addiu a0,a0,-0xf50
        0x3c, 0x06, WILDCARD, WILDCARD,      # +0x08 lui   a2,0x7
        0x24, 0xc6, WILDCARD, WILDCARD,      # +0x0C addiu a2,a2,-0x6ef0
        0x0c, WILDCARD, WILDCARD, WILDCARD,  # +0x10 jal   readcart
        0x02, 0xc0, 0x28, 0x21,              # +0x14 _move a1,s6
    ]) \
    .const_op32_hi16("rom_address", 0x00) \
    .const_op32_lo16("rom_address", 0x04) \
    .const_op32_hi16("payload_size", 0x08) \
    .const_op32_lo16("payload_size", 0x0C) \
    .build()


def worms_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None

    builder = BffiBuilder()
    earliest_bss_section, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    bootexe = rom.boot_exe()[:earliest_bss_section-ipc]

    builder.fix(ipc, bootexe)
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())

    # this is NOT a fix segment, the load address is stored in s6 and
    # will be reused throughout this gigantic mainloop
    worms_first_overlay_load_offset = WORMS_FIRST_OVERLAY_LOAD_PATTERN.find(bootexe)
    if worms_first_overlay_load_offset is None:
        return None
    
    logger.info("found Worms Armageddon mainloop")

    consts = WORMS_FIRST_OVERLAY_LOAD_PATTERN.consts(ipc, bootexe, worms_first_overlay_load_offset)
    ram_load_address = consts["ram_load_address"].get_value()
    rom_address = consts["rom_address"].get_value() & 0x03FFFFFF
    payload_size = consts["payload_size"].get_value()

    logger.info("first overlay: ROM 0x%08x-0x%08x -> RAM 0x%08x",
                rom_address,
                payload_size + rom_address,
                ram_load_address)
    
    segment = rom.read_bytes(rom_address, payload_size)
    builder.seg(ram_load_address, segment)

    offset = worms_first_overlay_load_offset + 4
    while True:
        offset = WORMS_SUBSEQUENT_OVERLAY_LOAD_PATTERN.find(bootexe, offset)
        if offset is None:
            break
        consts = WORMS_SUBSEQUENT_OVERLAY_LOAD_PATTERN.consts(ipc, bootexe, offset)
        offset += 4
        rom_address = consts["rom_address"].get_value() & 0x03FFFFFF
        payload_size = consts["payload_size"].get_value()

        logger.info("subsequent overlay: ROM 0x%08x-0x%08x",
                    rom_address,
                    rom_address+payload_size)
        
        segment = rom.read_bytes(rom_address, payload_size)
        builder.seg(ram_load_address, segment)
    
    return builder.build()

# ---------------------------------------------------

# euro version affected by major compiler differences,
# a sign they had stuffed way too much code into the mainloop function
WORMS_EU_FIRST_OVERLAY_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x03, 0x80, WILDCARD,         # +0x00 lui   v1,0x8005       <-- RAM load address
        0x24, 0x74, WILDCARD, WILDCARD,     # +0x04 addiu s4,v1,-0x7330
        0x3c, 0x03, WILDCARD, WILDCARD,     # +0x08 lui   v1,0x7          <-- size of second overlay!!
        0x24, 0x7e, WILDCARD, WILDCARD,     # +0x0C addiu s8,v1,-0x7310
        0x27, 0xb6, 0x00, 0x30,             # +0x10 addiu s6,sp,0x30
        0x02, 0x00, 0x90, 0x21,             # +0x14 move  s2,s0
        0xae, 0x42, 0x15, 0x18,             # +0x18 sw    v0,0x1518(s2)
        0x3c, 0x05, 0x00, WILDCARD,         # +0x1C lui   a1,0x4
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x20 addiu a1,a1,0x5ed0
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x24 jal   FUN_8002a980
        0x02, 0x80, 0x20, 0x21,             # +0x28 _move a0,s4
        0x3c, 0x05, WILDCARD, WILDCARD,     # +0x2C lui   a1,0x4
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x30 addiu a1,a1,0x5ed0
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x34 jal   FUN_8002a8d0
        0x02, 0x80, 0x20, 0x21,             # +0x38 _move a0,s4
        0x3c, 0x04, 0xb0, WILDCARD,         # +0x3C lui   a0,0xb004      <-- first overlay ROM address
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x40 addiu a0,a0,-0x75d0
        0x02, 0x80, 0x28, 0x21,             # +0x44 move  a1,s4
        0x3c, 0x06, WILDCARD, WILDCARD,     # +0x48 lui   a2,0x4         <-- first overlay size
        0x24, 0xc6, WILDCARD, WILDCARD,     # +0x4C addiu a2,a2,0x5ed0
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x50 jal   readcard
        0x3c, 0x10, WILDCARD, WILDCARD,     # +0x54 _lui  s0,0xb008
    ]) \
    .const_op32_hi16("ram_load_address", 0x00) \
    .const_op32_lo16("ram_load_address", 0x04) \
    .const_op32_hi16("second_overlay_size", 0x08) \
    .const_op32_lo16("second_overlay_size", 0x0C) \
    .const_op32_hi16("rom_address", 0x3C) \
    .const_op32_lo16("rom_address", 0x40) \
    .const_op32_hi16("payload_size", 0x48) \
    .const_op32_lo16("payload_size", 0x4C) \
    .build()

WORMS_EU_SUBSEQUENT_OVERLAY_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x04, 0xb0, WILDCARD,         # lui        a0,0xb008
        0x24, 0x84, WILDCARD, WILDCARD,     # addiu      a0,a0,-0x1700
        0x02, 0x80, 0x28, 0x21,             # move       a1,s4
        0x0c, WILDCARD, WILDCARD, WILDCARD, # jal        readcart
        0x03, 0xc0, 0x30, 0x21,             # _move      a2,s8
    ]) \
    .const_op32_hi16("rom_address", 0x00) \
    .const_op32_lo16("rom_address", 0x04) \
    .build()

def worms_eu_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None

    builder = BffiBuilder()
    earliest_bss_section, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    bootexe = rom.boot_exe()[:earliest_bss_section-ipc]

    builder.fix(ipc, bootexe)
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())

    # this is NOT a fix segment, the load address is stored in s6 and
    # will be reused throughout this gigantic mainloop
    worms_first_overlay_load_offset = WORMS_EU_FIRST_OVERLAY_LOAD_PATTERN.find(bootexe)
    if worms_first_overlay_load_offset is None:
        return None
    
    logger.info("found Worms Armageddon (Europe) mainloop")

    consts = WORMS_EU_FIRST_OVERLAY_LOAD_PATTERN.consts(ipc, bootexe, worms_first_overlay_load_offset)
    ram_load_address = consts["ram_load_address"].get_value()
    rom_address = consts["rom_address"].get_value() & 0x03FFFFFF
    payload_size = consts["payload_size"].get_value()
    second_overlay_size = consts["second_overlay_size"].get_value()

    logger.info("first overlay: ROM 0x%08x-0x%08x -> RAM 0x%08x",
                rom_address,
                payload_size + rom_address,
                ram_load_address)
    
    segment = rom.read_bytes(rom_address, payload_size)
    builder.seg(ram_load_address, segment)

    offset = worms_first_overlay_load_offset + 4

    offset = WORMS_EU_SUBSEQUENT_OVERLAY_LOAD_PATTERN.find(bootexe, offset)
    if offset is None:
        logger.info("failed to find second overlay load address")
        return None
        
    consts = WORMS_EU_SUBSEQUENT_OVERLAY_LOAD_PATTERN.consts(ipc, bootexe, offset)
    rom_address = consts["rom_address"].get_value() & 0x03FFFFFF
    payload_size = second_overlay_size

    logger.info("subsequent overlay: ROM 0x%08x-0x%08x",
                rom_address,
                rom_address+payload_size)
    
    segment = rom.read_bytes(rom_address, payload_size)
    builder.seg(ram_load_address, segment)

    return builder.build()
