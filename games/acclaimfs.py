'''
Common Acclaim filesystem handling
'''

import logging
import struct

from n64rom import N64Rom
from compression.rnc import rnc_unpack

logger = logging.getLogger(__name__)

def acclaimfs_read(rom: N64Rom,
                   fstable_address: int,
                   fsdata_address: int,
                   align_nearest_word: bool = False,
                   skip_decompress: bool = False):
    '''
    Read (and decompress if necessary) from an Acclaim filesystem.

    - align_nearest_word: If true, forces the filesystem read pointer
    to align to the nearest 32 bit address. Some games will not need
    this (Chef's Luv Shack doesn't) but others will (NBA Jam 2000 will).
    '''

    entries = {}

    fstable_offset = fstable_address
    fsdata_offset = fsdata_address
    while True:
        sizeof = struct.unpack(">I", rom.read_bytes(fstable_offset, 4))[0]
        if sizeof == 0xFFFFFFFF:
            return entries
        
        fstable_offset += 4

        fn = bytearray([])
        while True:
            char = rom.read_bytes(fstable_offset, 1)[0]
            fstable_offset += 1
            if char == 0:
                break
            fn.append(char)
        
        if align_nearest_word and (fstable_offset & 3) != 0:
            fstable_offset = (fstable_offset + 4) & 0xFFFFFFFC

        fn = fn.decode('ascii')
        filedata = rom.read_bytes(fsdata_offset, sizeof)
        fsdata_offset += sizeof
        if skip_decompress is False and filedata[:3] == b'RNC':
            filedata = rnc_unpack(filedata, skipping_input_checksum=True)

        if filedata is None:
            logger.error("ERROR extracting %s!!", fn)
            continue


        entries[fn] = filedata

def acclaim_anonyfs_read(rom: N64Rom,
                   fstable_address: int,
                   fsdata_address: int,
                   align_nearest_word: bool = False,
                   skip_decompress: bool = False):

    entries = []

    fstable_offset = fstable_address
    fsdata_offset = fsdata_address

    while True:
        start_offset, end_offset = struct.unpack(">II", rom.read_bytes(fstable_offset, 8))
        if end_offset == 0:
            return entries
        fstable_offset += 4
        
        if align_nearest_word and (fstable_offset & 3) != 0:
            fstable_offset = (fstable_offset + 4) & 0xFFFFFFFC

        sizeof = end_offset-start_offset

        filedata = rom.read_bytes(fsdata_offset, sizeof)
        fsdata_offset += sizeof
        if skip_decompress is False and filedata[:3] == b'RNC':
            filedata = rnc_unpack(filedata, skipping_input_checksum=True)

        if filedata is None:
            logger.error("ERROR extracting entry %04x", len(entries))

        entries.append(filedata)
