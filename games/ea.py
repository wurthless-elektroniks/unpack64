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
from strutil import extract_cstring

logger = logging.getLogger(__name__)

# Main reference: https://chipgw.com/2014/12/19/the-big-file-format/
def bigf_read_filesystem(input_buffer: bytes):
    if input_buffer[:4] != b'BIGF':
        logger.error("not a BIGF file: %s", input_buffer[:4])
        return None
    
    _, filesize, num_entries, header_end_offset = struct.unpack(">IIII", input_buffer[:16])

    read_offset = 0x10
 
    input_buffer = input_buffer[:filesize]

    contents = {}
    for _ in range(num_entries):
        filedat_offset, filedat_size = struct.unpack(">II", input_buffer[read_offset:read_offset+0x08])
        filename = extract_cstring(input_buffer[read_offset+8:])
        read_offset += (8 + (len(filename) + 1))

        data = input_buffer[filedat_offset:filedat_offset+filedat_size]
        magic = struct.unpack(">H", data[0:2])[0]
        logger.warning("bigf file: %s @ 0x%08x (%d bytes)", filename, filedat_offset, filedat_size)
        
        if (magic & 0x3EFF) == 0x10FB:
            logger.warning("file %s refpacked, decompressing it", filename)
            data = refpack_decompress(data)

        contents[filename] = data
    
    return contents

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
# These games load overlays the same:
# - loaded.ovr is the common segment that stays loaded at all times.
# - fe.ovr (frontend/menus) and game.ovr are swapped out to the same address
#   range as necessary.
#
# ----------------------------------------------------------

# excuse this very long string of crap, it's how the game loads
WCW_MAIN_OVERLAY_INIT_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xd0,         # +0x00 addiu      sp,sp,-0x30
        0x24, 0x02, 0x02, 0x00,         # +0x04 li         v0,0x200
        0x3c, 0x01, 0x80, WILDCARD,     # +0x08 lui        at,0x8004
        0xac, 0x22, WILDCARD, WILDCARD, # +0x0C sw         v0,-0x46fc(at)
        0x24, 0x02, 0x00, 0xf0,         # +0x10 li         v0,0xf0
        0x3c, 0x01, 0x80, WILDCARD,     # +0x14 lui        at,0x8004
        0xac, 0x22, WILDCARD, WILDCARD, # +0x18 sw         v0,-0x46f8(at)
        0x24, 0x02, 0x01, 0x00,         # +0x1C li         v0,0x100
        0x3c, 0x01, 0x80, WILDCARD,     # +0x20 lui        at,0x8004
        0xac, 0x22, WILDCARD, WILDCARD, # +0x24 sw         v0,-0x467c(at)
        0x24, 0x02, 0x00, 0x78,         # +0x28 li         v0,0x78
        0x3c, 0x01, 0x80, WILDCARD,     # +0x2C lui        at,0x8004
        0xac, 0x22, WILDCARD, WILDCARD, # +0x30 sw         v0,-0x4678(at)
        0x24, 0x02, 0x00, 0x10,         # +0x34 li         v0,0x10
        0x3c, 0x01, 0x80, WILDCARD,     # +0x38 lui        at,0x8004
        0xac, 0x22, WILDCARD, WILDCARD, # +0x3C sw         v0,-0x4688(at)
        0x3c, 0x02, 0xb0, WILDCARD,     # +0x40 lui        v0,0xb019 <-- BIGF ROM address
        0x24, 0x42, WILDCARD, WILDCARD, # +0x44 addiu      v0,v0,-0x3e40
    ]) \
    .tail_pattern([
        # skipping ahead +0xB0
        0x3c, 0x04, 0x80, WILDCARD,         # +0xB0 lui        a0,0x8004
        0x24, 0x84, WILDCARD, WILDCARD,     # +0xB4 addiu      a0,a0,-0x15b8 <-- should point to "loaded.ovr" string
        0x24, 0x05, 0x00, 0x10,             # +0xB8 li         a1,0x10
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0xBC jal        malloc_from_file?
        0x27, 0xa6, 0x00, 0x18,             # +0xC0 _addiu     a2,sp,0x18
        0x3c, 0x11, 0x80, WILDCARD,         # +0xC4 lui        s1,0x8005 <-- loaded.ovr load address
        0x26, 0x31, WILDCARD, WILDCARD,     # +0xC8 addiu      s1,s1,-0xf40
        0x02, 0x20, 0x20, 0x21,             # +0xCC move       a0,s1
        0x8f, 0xa6, 0x00, 0x18,             # +0xD0 lw         a2=>local_18,0x18(sp)
        0x00, 0x40, 0x80, 0x21,             # +0xD4 move       s0,v0
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0xD8 jal        memcpy?
        0x02, 0x00, 0x28, 0x21,             # +0xDC _move      a1,s0
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0xE0 jal        free? 
        0x02, 0x00, 0x20, 0x21,             # +0xE4 _move      a0,s0
        0x8f, 0xa5, 0x00, 0x18,             # +0xE8 lw         a1,local_18(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0xEC jal        FUN_80011500
        0x02, 0x20, 0x20, 0x21,             # +0xF0 _move      a0,s1
        0x8f, 0xa5, 0x00, 0x18,             # +0xF4 lw         a1,local_18(sp)
        0x3c, 0x04, 0x80, WILDCARD,         # +0xF8 lui        a0,0x8010
        0x24, 0x84, WILDCARD, WILDCARD,     # +0xFC addiu      a0,a0,0x4c80
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x100 jal        FUN_80011440
        0x00, 0x00, 0x00, 0x00,             # +0x104 _nop
        0x3c, 0x04, 0x80, WILDCARD,         # +0x108 lui        a0,0x8004
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x10C addiu      a0,a0,-0x15c0 <-- should point to "fe.ovr" string
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x110 jal        load_generic_overlay?
        0x00, 0x00, 0x00, 0x00,             # +0x114 _nop
    ]) \
    .size(0x118) \
    .const_op32_hi16("bigf_rom_address", 0x40) \
    .const_op32_lo16("bigf_rom_address", 0x44) \
    .const_op32_hi16("loadedovr_string_address", 0xB0) \
    .const_op32_lo16("loadedovr_string_address", 0xB4) \
    .const_op32_hi16("loadedovr_load_address", 0xC4) \
    .const_op32_lo16("loadedovr_load_address", 0xC8) \
    .const_op32_hi16("feovr_string_address", 0x108) \
    .const_op32_lo16("feovr_string_address", 0x10C) \
    .xref_j_imm26("load_generic_overlay", 0x110) \
    .build()

WCW_LOAD_GENERIC_OVERLAY_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xd8,             # +0x00 addiu      sp,sp,-0x28
        0xaf, 0xb2, 0x00, 0x20,             # +0x04 sw         s2,local_8(sp)
        0x00, 0x80, 0x90, 0x21,             # +0x08 move       s2,a0
        0xaf, 0xbf, 0x00, 0x24,             # +0x0C sw         ra,local_4(sp)
        0xaf, 0xb1, 0x00, 0x1c,             # +0x10 sw         s1,local_c(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x14 jal        FUN_8000925c
        0xaf, 0xb0, 0x00, 0x18,             # +0x18 _sw        s0,local_10(sp)
        0x02, 0x40, 0x20, 0x21,             # +0x1C move       a0,s2
        0x24, 0x05, 0x00, 0x10,             # +0x20 li         a1,0x10
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x24 jal        FUN_80000868
        0x27, 0xa6, 0x00, 0x10,             # +0x28 _addiu     a2,sp,0x10
        0x3c, 0x11, 0x80, WILDCARD,         # +0x2C lui        s1,0x800c <-- load address
        0x26, 0x31, WILDCARD, WILDCARD,     # +0x30 addiu      s1,s1,-0x6040
        0x02, 0x20, 0x20, 0x21,             # +0x34 move       a0,s1
    ]) \
    .const_op32_hi16("generic_overlay_load_address", 0x2C) \
    .const_op32_lo16("generic_overlay_load_address", 0x30) \
    .build()

def wcw_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None

    # should not have any BSS sections setup yet
    if preamble.bss_sections():
        return None
    
    bootexe = rom.boot_exe()

    main_overlay_init_offset = WCW_MAIN_OVERLAY_INIT_PATTERN.find(bootexe)
    if main_overlay_init_offset is None:
        return None
    
    logger.info("found WCW Mayhem/WCW Backstage Assault main overlay init")
    consts = WCW_MAIN_OVERLAY_INIT_PATTERN.consts(ipc, bootexe, main_overlay_init_offset)
    xrefs = WCW_MAIN_OVERLAY_INIT_PATTERN.xrefs(ipc, bootexe, main_overlay_init_offset)

    bigf_rom_address = consts["bigf_rom_address"].get_value() & 0x03FFFFFF
    loadedovr_string_address = consts["loadedovr_string_address"].get_value()
    loadedovr_load_address = consts["loadedovr_load_address"].get_value()
    feovr_string_address = consts["feovr_string_address"].get_value()
    load_generic_overlay = xrefs["load_generic_overlay"].get_address()

    if extract_cstring(bootexe[loadedovr_string_address-ipc:]) != "loaded.ovr":
        logger.error("game should load its main overlay from loaded.ovr, but it didn't")
        return None
    
    if extract_cstring(bootexe[feovr_string_address-ipc:]) != "fe.ovr":
        logger.error("game should load its frontend from fe.ovr, but it didn't")
        return None

    if WCW_LOAD_GENERIC_OVERLAY_PATTERN.compare(bootexe, load_generic_overlay-ipc) is False:
        logger.error("call to generic overlay loader didn't point to the function we expected. check 0x%08x",
                     load_generic_overlay)
        return None
    consts = WCW_LOAD_GENERIC_OVERLAY_PATTERN.consts(ipc, bootexe, load_generic_overlay-ipc)
    generic_overlay_load_address = consts["generic_overlay_load_address"].get_value()

    logger.info("loading and unpacking BIGF filesystem...")

    bigf = bigf_read_filesystem(rom.read_bytes_until_end(bigf_rom_address))

    # should have loaded.ovr, fe.ovr and game.ovr
    for must_exist_fname in [ "loaded.ovr", "fe.ovr", "game.ovr" ]:
        if must_exist_fname not in bigf:
            logger.error("%s not found or loaded from bigf", must_exist_fname)
            return None
    
    # since the game relies on a bunch of zeroes to clear BSS,
    # search backwards from end until we find a block that isn't zeroed
    bss_backseek_offset = len(bootexe)
    while True:
        bss_backseek_offset -= 0x10
        if bss_backseek_offset < 0:
            raise RuntimeError("huh? everything was zero")
        if bootexe[bss_backseek_offset:bss_backseek_offset+0x10] != bytes([0]*0x10):
            bss_backseek_offset += 0x10
            break
    
    logger.info("will create BSS from 0x%08x to 0x%08x",
                bss_backseek_offset+ipc,
                ipc+0x100000)
    
    bootexe = bootexe[:bss_backseek_offset]

    builder = BffiBuilder()
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.bss(bss_backseek_offset+ipc, (ipc+0x100000) - (bss_backseek_offset+ipc))
    builder.fix(ipc, bootexe)

    builder.seg(loadedovr_load_address, bigf["loaded.ovr"])
    for s in [ "fe.ovr", "game.ovr" ]:
        builder.seg(generic_overlay_load_address, bigf[s])
    
    return builder.build()

