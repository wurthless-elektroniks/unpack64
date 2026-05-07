'''
Electronic Arts games using various bootloaders and compression methods
'''

import logging
import struct

from compression.refpack import refpack_decompress

from bffi import Bffi,BffiBuilder,BffiSectionType
from n64rom import N64Rom
from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi
from signature import SignatureBuilder, WILDCARD


logger = logging.getLogger(__name__)


# ----------------------------------------------------------
#
# NHL 99
# Refpack-compressed code segments, BIGF resource blob
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

NHL99_ENTRY_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xb0,             # +0x00 addiu      sp,sp,-0x50
        0xaf, 0xb2, 0x00, 0x38,             # +0x04 sw         s2,local_18(sp)
        0x00, 0x00, 0x90, 0x21,             # +0x08 clear      s2
        0xaf, 0xb5, 0x00, 0x44,             # +0x0C sw         s5,local_c(sp)
        0x00, 0x00, 0xa8, 0x21,             # +0x10 clear      s5
        0xaf, 0xb0, 0x00, 0x30,             # +0x14 sw         s0,local_20(sp)
        0x3c, 0x10, WILDCARD, WILDCARD,     # +0x18 lui        s0,0x0            <-- ROM address
        0x26, 0x10, WILDCARD, WILDCARD,     # +0x1C addiu      s0,s0,0x5dd0
        0x02, 0x00, 0x20, 0x21,             # move       a0,s0
        0x27, 0xa5, 0x00, 0x10,             # addiu      a1,sp,0x10
        0x24, 0x06, 0x00, 0x20,             # li         a2,0x20
        0xaf, 0xbf, 0x00, 0x4c,             # sw         ra,local_4(sp)
        0xaf, 0xb6, 0x00, 0x48,             # sw         s6,local_8(sp)
        0xaf, 0xb4, 0x00, 0x40,             # sw         s4,local_10(sp)
        0xaf, 0xb3, 0x00, 0x3c,             # sw         s3,local_14(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # jal        read_cart
    ]) \
    .const_op32_hi16("main_ovln_rom_address", 0x18) \
    .const_op32_lo16("main_ovln_rom_address", 0x1C) \
    .build()

def _ovln_read(rom: N64Rom, rom_address: int) -> tuple[int,int,bytes,int]:
    if rom.read_bytes(rom_address, 4) != b'OVLN':
        return None, None, None, None

    payload_size, \
    load_address, \
    entry_point = struct.unpack(">III", rom.read_bytes(rom_address+4, 12))

    payload = rom.read_bytes(rom_address + 0x10, payload_size - 0x10)

    if payload[:2] == bytes([0x10, 0xFB]):
        payload = refpack_decompress(payload)

    return load_address, entry_point, payload, 0x10+(payload_size - 0x10)

def nhl99_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None

    builder = BffiBuilder()
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    bootexe = rom.boot_exe()[:earliest_bss-ipc]

    # for NHL 99, the unpacker stub does not touch the OS at all,
    # but portions of the OS, including the RSP ucode, are loaded with it,
    # so the bootexe has to be loaded as a fix segment
    builder.fix(ipc, bootexe)
    builder.initial_stack_pointer(preamble.initial_stack_pointer())

    if NHL99_ENTRY_PATTERN.compare(bootexe, preamble.crt_entry_point() - ipc) is False:
        return None
    
    logger.info("found NHL 99 Refpack unpacker stub")

    consts = NHL99_ENTRY_PATTERN.consts(ipc, bootexe, preamble.crt_entry_point() - ipc)
    main_ovln_rom_address = consts["main_ovln_rom_address"].get_value()

    logger.info("main segment OVLN in ROM at 0x%08x", main_ovln_rom_address)

    load_address, entry_point, main_ovln, main_ovln_size = \
        _ovln_read(rom, main_ovln_rom_address)

    if None in [ load_address, entry_point, main_ovln, main_ovln_size ]:
        logger.error("failed to read main OVLN!")

    logger.info("main OVLN: ROM 0x%08x-0x%08x -> RAM 0x%08x, entry point at 0x%08x",
                main_ovln_rom_address,
                main_ovln_rom_address+main_ovln_size,
                load_address,
                entry_point)

    # OVLN overlays have no dedicated BSS section, the BSS is instead zeropadding
    # in the uncompressed data.
    builder.fix(load_address, main_ovln)
    builder.initial_program_counter(entry_point)

    # remaining overlays should immediately follow the main segment,
    # and we should eventually hit the BIGF resource blob and stop
    
    offset = main_ovln_rom_address+main_ovln_size
    
    logger.info("scanning for code overlays starting from 0x%08x...", offset)
    while True:
        if (offset & 0x0F) != 0:
            offset = (offset + 0x10) & 0xFFFFFFF0
        
        load_address, entry_point, ovln, ovln_size = \
            _ovln_read(rom, offset)
        
        if None in [ load_address, entry_point, main_ovln, main_ovln_size ]:
            break

        logger.info("found overlay: ROM 0x%08x-0x%08x -> RAM 0x%08x, entry point at 0x%08x",
                    offset,
                    offset+ovln_size,
                    load_address,
                    entry_point)
        
        builder.seg(load_address, ovln)

        offset += ovln_size

    
    return builder.build()

# ----------------------------------------------------------
#
# NBA Live 98 / 2000
#
# OVLN file but with no compression.
# The other major difference between this and NHL 99 is no unpacker running
# at boot time; it goes through the normal libultra OS init process, then loads
# the main segment before starting the main thread.
#
# NBA Live 98's main code segment is the only OVLN there is.
# NBA Live 2000 loads in more overlays from Refpack-compressed OVLNs.
#
# ----------------------------------------------------------

NBALIVE2K_LOAD_MAIN_SEGMENT_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xb0,              # +0x00 addiu      sp,sp,-0x50
        0xaf, 0xb4, 0x00, 0x40,              # +0x04 sw         s4,local_10(sp)
        0x00, 0x00, 0xa0, 0x21,              # +0x08 clear      s4
        0xaf, 0xb1, 0x00, 0x34,              # +0x0C sw         s1,local_1c(sp)
        0x00, 0x00, 0x88, 0x21,              # +0x10 clear      s1
        0x3c, 0x04, 0x80, WILDCARD,          # +0x14 lui        a0,0x8001
        0x24, 0x84, WILDCARD, WILDCARD,      # +0x18 addiu      a0,a0,-0x3528
        0x3c, 0x05, 0x80, WILDCARD,          # +0x1C lui        a1,0x8001
        0x24, 0xa5, WILDCARD, WILDCARD,      # +0x20 addiu      a1,a1,-0x3510
        0x24, 0x06, 0x00, 0x01,              # +0x24 li         a2,0x1
        0xaf, 0xbf, 0x00, 0x4c,              # +0x28 sw         ra,local_4(sp)
        0xaf, 0xb6, 0x00, 0x48,              # +0x2C sw         s6,local_8(sp)
        0xaf, 0xb5, 0x00, 0x44,              # +0x30 sw         s5,local_c(sp)
        0xaf, 0xb3, 0x00, 0x3c,              # +0x34 sw         s3,local_14(sp)
        0xaf, 0xb2, 0x00, 0x38,              # +0x38 sw         s2,local_18(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD,  # +0x3C jal        FUN_80001920
        0xaf, 0xb0, 0x00, 0x30,              # +0x40 _sw        s0,local_20(sp)
        0x3c, 0x10, 0x00, WILDCARD,          # +0x44 lui        s0,0x1
        0x26, 0x10, WILDCARD, WILDCARD,      # +0x48 addiu      s0,s0,-0x2940  <-- OVLN ROM address
    ]) \
    .const_op32_hi16("main_ovln_rom_address", 0x44) \
    .const_op32_lo16("main_ovln_rom_address", 0x48) \
    .build()

def nbalive2k_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None

    builder = BffiBuilder()
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    bootexe = rom.boot_exe()[:earliest_bss-ipc]
    builder.fix(ipc, bootexe)
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.initial_stack_pointer(preamble.initial_stack_pointer())

    main_segment_load_offset = NBALIVE2K_LOAD_MAIN_SEGMENT_PATTERN.find(bootexe)
    if main_segment_load_offset is None:
        return None
    
    logger.info("found NBA Live 2000 main segment loader")

    consts = NBALIVE2K_LOAD_MAIN_SEGMENT_PATTERN.consts(ipc, bootexe, main_segment_load_offset)
    main_ovln_rom_address = consts["main_ovln_rom_address"].get_value()

    load_address, entry_point, main_ovln, main_ovln_size = \
        _ovln_read(rom, main_ovln_rom_address)

    if None in [ load_address, entry_point, main_ovln, main_ovln_size ]:
        logger.error("failed to read main OVLN!")

    logger.info("main OVLN: ROM 0x%08x-0x%08x -> RAM 0x%08x, entry point at 0x%08x",
                main_ovln_rom_address,
                main_ovln_rom_address+main_ovln_size,
                load_address,
                entry_point)
    
    offset = main_ovln_rom_address+main_ovln_size
    
    logger.info("scanning for code overlays starting from 0x%08x...", offset)
    while True:
        if (offset & 0x0F) != 0:
            offset = (offset + 0x10) & 0xFFFFFFF0
        
        load_address, entry_point, ovln, ovln_size = \
            _ovln_read(rom, offset)
        
        if None in [ load_address, entry_point, main_ovln, main_ovln_size ]:
            break

        logger.info("found overlay: ROM 0x%08x-0x%08x -> RAM 0x%08x, entry point at 0x%08x",
                    offset,
                    offset+ovln_size,
                    load_address,
                    entry_point)
        
        builder.seg(load_address, ovln)

        offset += ovln_size
    
    return builder.build()



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


# ----------------------------------------------------------
#
# WCW Backstage Assault
# WCW Mayhem
#
# Loads main overlays from the BIGF blob.
# Files are Refpack-compressed.
#
# The main segment does not use BSS, it instead relies on IPL3 loading in
# a bunch of zeroes to do BSS clearing.
#
# ----------------------------------------------------------
