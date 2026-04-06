'''
Acclaim Entertainment ECW/WWF variant of the RNC unpacker

These are very easy to identify. They start with an immediate jump past a header,
and from that header we can grab all the parameters.

The header is at ipc+0x10 and is structured as follows:

    ```
    +0x10 - payload start address in ROM (should start 0xB0)
    +0x14 - payload end address in ROM (should start 0xB0)
    +0x18 - address in RDRAM to ultimately dump the decompressed payload at
    +0x1C - CRT entry point
    +0x20 - whether the payload is compressed or not
            1 = RNC type 1, 0 = no compression
    +0x24 - seemingly unused but will be set to something of some meaning
    +0x28 - bss section start address
    +0x2c - bss section end address
    +0x30 - value unclear
    +0x34 - value unclear
    +0x38 - 0
    +0x3C - 0
    ```

'''

import logging

from n64rom import N64Rom
from bffi import Bffi,BffiBuilder,BffiSectionType
from signature import SignatureBuilder, WILDCARD
from compression.rnc import rnc_unpack

logger = logging.getLogger(__name__)

# signature to detect the ECW unpacker header
SIG_ECW_PACKER_HEADER = SignatureBuilder() \
    .pattern([
        0x08, WILDCARD, WILDCARD, WILDCARD,      # +$00 immediate jump past header
        0x00, 0x00, 0x00, 0x00,                  # +$04 nop
        0x00, 0x00, 0x00, 0x00,                  # +$08 padding
        0x00, 0x00, 0x00, 0x00,                  # +$0C padding
        0xB0, WILDCARD, WILDCARD, WILDCARD,      # +$10 payload start address in ROM
        0xB0, WILDCARD, WILDCARD, WILDCARD,      # +$14 payload end address in ROM
        0x80, WILDCARD, WILDCARD, WILDCARD,      # +$18 load address for decompressed data
        0x80, WILDCARD, WILDCARD, WILDCARD,      # +$1C CRT entry point
        0x00, 0x00, 0x00, WILDCARD,              # +$20 whether compression is on (1) or off (0)
        WILDCARD, WILDCARD, WILDCARD, WILDCARD,  # +$24 something
        0x80, WILDCARD, WILDCARD, WILDCARD,      # +$28 bss start address
        0x80, WILDCARD, WILDCARD, WILDCARD,      # +$2C bss end address
    ]) \
    .const_imm32("payload_start_address", 0x10) \
    .const_imm32("payload_end_address", 0x14) \
    .const_imm32("exe_load_address", 0x18) \
    .const_imm32("exe_entry_point", 0x1C) \
    .const_imm32("compression_mode", 0x20) \
    .const_imm32("bss_start_address", 0x28) \
    .const_imm32("bss_end_address", 0x2C) \
    .build()

def ecwwf_unpack(rom: N64Rom, ipc: int) -> Bffi:
    bootexe = rom.boot_exe()

    if SIG_ECW_PACKER_HEADER.compare(bootexe) is False:
        return None
    consts = SIG_ECW_PACKER_HEADER.consts(ipc, bootexe, 0)

    logger.info("using Acclaim ECW/WWF packer")

    exe_load_address = consts["exe_load_address"].get_value()
    exe_entry_point = consts["exe_entry_point"].get_value()
    bss_start_address = consts["bss_start_address"].get_value()
    bss_end_address = consts["bss_end_address"].get_value()

    payload_start_address = consts["payload_start_address"].get_value() & 0x0FFFFFFF
    payload_end_address = consts["payload_end_address"].get_value() & 0x0FFFFFFF
    compression_mode = consts["compression_mode"].get_value()

    logger.info(
"""header gave us the following:
- bootexe loads to 0x%08x
- bss at 0x%08x~0x%08x
- entry point at 0x%08x
""", exe_load_address, bss_start_address, bss_end_address, exe_entry_point
    )

    payload = rom.read_bytes(payload_start_address, payload_end_address-payload_start_address)
    if compression_mode != 0:
        logger.info("Unpacking RNC payload in ROM at 0x%08x...",payload_start_address)
        payload = rnc_unpack(payload)
        if payload is None:
            logger.error("Error unpacking RNC-packed bootexe")
            return None
        logger.info("RNC decompress succeeded. uncompressed payload is %d bytes (0x%08x)", len(payload), len(payload))

    bffibuilder = BffiBuilder()
    bffibuilder.rom_hash(rom.sha256())
    bffibuilder.fix(exe_load_address, payload)
    bffibuilder.bss(bss_start_address, bss_end_address-bss_start_address)
    bffibuilder.initial_program_counter(exe_entry_point)

    # TODO: this is a hack, it's taken directly from the ECW bootblock,
    # actual code uses $at register to setup the stack pointer
    bffibuilder.initial_stack_pointer(0x803FFFE0)

    return bffibuilder.build()
