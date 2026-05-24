'''
Daikatana

Central overlay load routine that we pass a struct to.

0x801ab6e4 is the overlay load routine. It accepts a struct as follows:
- +0x00 RAM start address
- +0x04 RAM end address
- +0x08 ROM start address
- +0x0C ROM end address
- +0x10 code start address
- +0x14 code end address
- +0x18 data start address
- +0x1C data end address

The overlays are helpfully headered in the ROM itself:
- 4 bytes "MWo2"
- 4 bytes file ID
- 4 bytes load address
- 4 bytes load size
- 16 bytes zero
- cstring containing resource name (up to 32 bytes)
- file data

Overlays should follow the bootexe.
'''

import logging
import struct

from bffi import Bffi, BffiBuilder
from n64rom import N64Rom
from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi
from strutil import extract_cstring

logger = logging.getLogger(__name__)

# this is kind of a lame way of doing things, but this header seems to be ignored
# when loading the overlays. if we need to look for the overlay load code then
# this will be changed...
def daikatana_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    builder = BffiBuilder()
    earliest_bss_address, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    bootexe = rom.boot_exe()[:earliest_bss_address-ipc]
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.fix(ipc, bootexe)

    # 'MWo2' header should follow boot segment
    mwo_read_pointer = 0x1000 + len(bootexe)

    detecting_first_mwo2 = True

    while True:
        header = rom.read_bytes(mwo_read_pointer, 0x40)
        if header[:4] != b'MWo2':
            if detecting_first_mwo2:
                return None
            break

        if detecting_first_mwo2:
            logger.info("found Daikatana MWo2 overlay after bootexe")
            detecting_first_mwo2 = False

        _, overlay_id, load_address, load_size = struct.unpack(">IIII", header[:0x10])
        overlay_name = extract_cstring(header[0x20:])

        logger.info("overlay %d (%s): ROM 0x%08x-0x%08x -> RAM 0x%08x",
                    overlay_id,
                    overlay_name,
                    mwo_read_pointer,
                    mwo_read_pointer + load_size,
                    load_address)
        
        overlay = rom.read_bytes(mwo_read_pointer, load_size)
        builder.seg(load_address, overlay)

        mwo_read_pointer += load_size
    
    return builder.build()
