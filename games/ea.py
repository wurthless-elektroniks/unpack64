'''
Electronic Arts games using various bootloaders and compression methods
'''

import logging

from n64rom import N64Rom
from bffi import Bffi,BffiBuilder,BffiSectionType
from signature import SignatureBuilder, WILDCARD
from compression.rnc import rnc_unpack

logger = logging.getLogger(__name__)


# ----------------------------------------------------------
#
# NHL 99
#
# Each segment has this 16 byte header:
#
# - 4 bytes "OVLN"
# - 4 bytes size of (compressed) payload
# - 4 bytes load address
# - 4 bytes entry point
#
# after which the payload follows. If the first two bytes are 0x10FB
# (which they always should be) then the payload is compressed and
# the next three bytes are the uncompressed size of the payload.
#
# ----------------------------------------------------------


# ----------------------------------------------------------
#
# World Cup 98
#
# Immediately following the bootexe (ROM 0x016940) is a table of the following values:
# - 4 bytes ROM address
# - 4 bytes RAM address (0 if this is the BIGF table entry)
# - 4 bytes uncompressed size
# - 4 bytes always zero
#
# Each points to a compressed overlay, except for the last entry,
# which points to a "BIGF" filesystem with all the game resources.
#
# Each payload starts with a 24 bit big endian uncompressed size.
# The decompression routine is entirely different from NHL 99.
#
# ----------------------------------------------------------


# ----------------------------------------------------------
#
# Knockout Kings 2000
#
# Same table structure as World Cup 98 (this time in ROM at 0x031c08)
# - 4 bytes ROM address
# - 4 bytes RAM address (0 if this is the resource blob)
# - 4 bytes uncompressed size
# - 4 bytes always zero
#
# The first entry is the main code overlay.
# The next three are identical data segments (not sure what they mean).
# The final one is the resource blob, which (likely) contains more overlays.
#
# This time the payload starts with a 32 bit big endian uncompressed size.
# Otherwise, the algorithm looks the same as World Cup 98.
#
# FIFA 99: same format but multiple overlays, and last entry is a BIGF
#
# ----------------------------------------------------------
