'''
Resident Evil 2

Standard zlib, to the point where they left the zlib error strings in the code,
and used the default headers.

The main overlay table starts with 16 bytes 'OVERLAYTABLENUMC'
then several entries:
- 4 bytes ROM address of zlib payload
- 4 bytes zlib payload length
- 4 bytes RAM start address
- 4 bytes RAM end address
'''

import logging
import struct
import zlib

from bffi import BffiBuilder, Bffi
from n64rom import N64Rom
from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi
from signature import SignatureBuilder, WILDCARD
from sigutil import find_all_instances

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------------

RE2_OVERLAY_GET_ADDRESS_PATTERN = SignatureBuilder() \
    .pattern([
        0x00, 0x04, 0x21, 0x00,          # sll        a0,a0,0x4
        0x3c, 0x02, 0x80, WILDCARD,      # lui        v0,0x8001
        0x24, 0x42, WILDCARD, WILDCARD,  # addiu      v0,v0,0x2150
        0x03, 0xe0, 0x00, 0x08,          # jr         ra
        0x00, 0x82, 0x10, 0x21,          # _addu      v0,a0,v0
    ]) \
    .const_op32_hi16("overlay_table_address", 0x04) \
    .const_op32_lo16("overlay_table_address", 0x08) \
    .build()

def re2_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    builder = BffiBuilder()
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)

    bootexe = rom.boot_exe()[:earliest_bss-ipc]

    builder.fix(ipc, bootexe)
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.initial_stack_pointer(preamble.initial_stack_pointer())

    overlay_table_offset = None

    for candidate in find_all_instances(bootexe, RE2_OVERLAY_GET_ADDRESS_PATTERN):
        consts = RE2_OVERLAY_GET_ADDRESS_PATTERN.consts(ipc, bootexe, candidate)
        overlay_table_address = consts["overlay_table_address"].get_value()

        if (ipc <= overlay_table_address <= (len(bootexe)+ipc)) is False:
            continue

        candidate_offset = overlay_table_address - ipc

        if bootexe[candidate_offset:candidate_offset+0x10] == b'OVERLAYTABLENUMC':
            overlay_table_offset = candidate_offset
            break
    
    if overlay_table_offset is None:
        return None
    
    logger.info("found Resident Evil 2 zlib overlay table")

    while True:
        overlay_table_offset += 0x10
        rom_address, zlibbed_size, ram_start_address, ram_end_address = \
            struct.unpack(">IIII", bootexe[overlay_table_offset:overlay_table_offset+0x10])

        if (ram_start_address & 0xFF000000) != 0x80000000:
            break

        rom_address &= 0x03FFFFFF

        # some entries are completely empty, who knows why
        if zlibbed_size == 0 and (ram_end_address-ram_start_address) == 0:
            continue

        logger.info("zlib segment in ROM 0x%08x-0x%08x -> RAM 0x%08x-0x%08x",
                    rom_address,
                    rom_address+zlibbed_size,
                    ram_start_address,
                    ram_end_address)
        
        payload = rom.read_bytes(rom_address, zlibbed_size)
        
        # FIXME: the overlay table will contain uncompressed entries that will
        # cause exceptions. maybe these are resources, but i'm not parsing those
        # tables just yet.
        try:
            payload = zlib.decompress(payload)
        except Exception:
            logger.error("decompression error on entry: ROM 0x%08x-0x%08x -> RAM 0x%08x-0x%08x",
                    rom_address,
                    rom_address+zlibbed_size,
                    ram_start_address,
                    ram_end_address)
            break

        builder.seg(ram_start_address, payload)
    
    return builder.build()
