'''
Zelda 64 framework VROM utility code

Moved out of zelda.py because that file is getting way too big
'''

import logging
import struct

from compression.yaz0 import yaz0_decompress
from n64rom import N64Rom, ROMENDIANNESS_BIG
from preamble import preamble_extract_bss_sections_to_bffi, Preamble

logger = logging.getLogger(__name__)

SPAM = False

# ------------------------------------------------

def _zeldavrom_dmatable_signature_matches(first_16: bytes):
    return first_16 == bytes([0x00,0x00,0x00,0x00,
                              0x00,0x00,0x10,0x60,
                              0x00,0x00,0x00,0x00,
                              0x00,0x00,0x00,0x00,
                            ])

def zeldavrom_dmatable_present(rom: N64Rom, ipc: int, preamble: Preamble):

    # DMA table immediately follows boot segment in ROM
    # this is true for zelda oot, dobutsu
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, None)
    dmatable_rom_offset = (earliest_bss - ipc) + 0x1000

    first_16 = rom.read_bytes(dmatable_rom_offset, 0x10)
    return _zeldavrom_dmatable_signature_matches(first_16)

def _zelda_parse_dma_table(rom: N64Rom, dmadata_table_offset: int):
    
    table_entries = []
    vrom_sizeof = 0

    while True:
        vrom_start, \
        vrom_end, \
        prom_start, \
        prom_end = struct.unpack(">IIII", rom.read_bytes(dmadata_table_offset, 0x10))

        dmadata_table_offset += 0x10

        # if all zero, treat as EOF (animal forest does this)
        if vrom_start == vrom_end == prom_start == prom_end == 0:
            break
        
        if vrom_sizeof > vrom_end:
            raise RuntimeError("vrom entries appear to be out of order... report bug")

        table_entries.append( (vrom_start, vrom_end, prom_start, prom_end) )
    
    return table_entries

# the zelda framework has a "virtual ROM" setup where data can be addressed
# within compressed blobs or at arbitrary ROM addresses.
# typically the dmatable is located right after the bootexe.
def zeldavrom_inflate_virtual_rom(rom: N64Rom, dmadata_table_offset: int) -> N64Rom:
    # tuple: address -> data
    vrom_chunks: list[tuple[int,bytes]] = []

    vrom_sizeof = 0

    # first entry is the ROM header, IPL3 stub, and preamble.
    first_16 = rom.read_bytes(dmadata_table_offset, 0x10)
    if _zeldavrom_dmatable_signature_matches(first_16) is False:
        raise RuntimeError("zelda dma table didn't match expected format")

    table_entries = _zelda_parse_dma_table(rom, dmadata_table_offset)
    vrom_sizeof = table_entries[-1][1]
    logger.info("vrom size is %d (0x%08x) byte(s)",
                vrom_sizeof,
                vrom_sizeof)

    for vrom_start, vrom_end, prom_start, prom_end in table_entries:
        # if prom_end == 0, file's uncompressed, else it's Yaz0 compressed
        if prom_start == prom_end == 0xFFFFFFFF:
            # majora's mask: prom_start/prom_end being -1 means file is unwired.
            # fill that region with zeroes instead
            if SPAM:
                logger.info("VROM 0x%08x-0x%08x: file entry is unwired", vrom_start, vrom_end)

            sizeof = vrom_end - vrom_start
            vrom_chunks.append( (vrom_start, bytes([0] * sizeof)) )

        if prom_end == 0:
            sizeof = vrom_end - vrom_start
            data = rom.read_bytes(prom_start, sizeof)

            if SPAM:
                logger.info("VROM 0x%08x-0x%08x = uncompressed 0x%08x-0x%08x",
                            vrom_start,
                            vrom_end,
                            prom_start,
                            prom_start + sizeof)
            
            vrom_chunks.append( (vrom_start, data) )

        else:
            sizeof = prom_end - prom_start
            data = rom.read_bytes(prom_start, sizeof)
            
            # should be Yaz0 (iQue games use zlib, but I am not supporting them)
            data = yaz0_decompress(data)

            if data is None:
                raise RuntimeError("compressed chunk in vrom was NOT Yaz0")

            if SPAM:
                logger.info("VROM 0x%08x-0x%08x = Yaz0 at 0x%08x-0x%08x",
                            vrom_start,
                            vrom_end,
                            prom_start,
                            prom_end)

            vrom_chunks.append( (vrom_start, data) )

    # now build the VROM
    vrom_data = bytearray([0] * vrom_sizeof)
    for vrom_address, data in vrom_chunks:
        vrom_data[vrom_address:vrom_address+len(data)] = data

    # what we should do here is patch the table now that all resources are
    # uncompressed, but that won't do much because the games might hardcode
    # addresses to random resources including the main game code.
    # so let's just return the virtual ROM

    return N64Rom(vrom_data, ROMENDIANNESS_BIG)

