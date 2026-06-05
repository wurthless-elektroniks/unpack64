'''
Player 1 Inc. games
None seem to load code after boot time, so this file is here only for documentation.

Games that use an anonymous filesystem:
- Blues Brothers 2000 (single-load, no code in resource table)
- Hercules: The Legendary Journeys (single-load, no code in resource table)

Both of the anonymous filesystems are of the same structure and use standard zlib
to compress resources, see bb2k_unpack() for how to dump the filesystems.

Games that use a named filesystem:
- Milo's Astro Lanes
- Robotron 64

For the named file systems, both use different structures. I'm not documenting
these because I doubt those games load more code at runtime, but I'll come back
to them if need be...
'''

import logging
import struct
import zlib

from bffi import BffiBuilder
from n64rom import N64Rom
from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi
from signature import SignatureBuilder, WILDCARD
from sigutil import contains_code

logger = logging.getLogger(__name__)

def bb2k_unpack(rom: N64Rom, ipc: int):
    # this is test code ONLY.
    # do NOT use it for trying to generate bffis.
    resource_blob = rom.read_bytes_until_end(0x0bcbc0) # <-- fileblob

    num_resources = struct.unpack("<I", resource_blob[0:4])[0]

    logger.info("found %d resources", num_resources)

    offset = 8
    for _ in range(num_resources):
        # can't actually rely in resourcelength field because zlib decompress can fail
        resource_offset, resource_length = struct.unpack("<II", resource_blob[offset:offset+8])
        offset += 8

        resource = resource_blob[resource_offset:]
        firsttwo = resource[0:2]

        if firsttwo in [ bytes([0x78, 0x01]), bytes([0x78, 0x5E]), bytes([0x78, 0x9C]), bytes([0x78, 0xDA]) ]:
            try:
                resource = zlib.decompress(resource)
            except:
                logger.error("decompression FAILED for resource at 0x%08x", resource_offset)
                continue

        if contains_code(resource):
            logger.info("!! resource at 0x%08x contains code!!", resource_offset)
        
            with open(f"private/bb2k_{resource_offset:06x}.bin", "wb") as f:
                f.write(resource)
        
