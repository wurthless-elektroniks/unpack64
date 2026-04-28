'''
Paradigm Entertainment presents the most spaghetti code loader of all time

Beetle Adventure Racing
------------------------

The loader uses files in ROM to boot things. It's a little complex,
and it didn't help that Ghidra choked on this again and completely missed
the ROM read address.

Each file starts with:
- 4 bytes "FORM"
- 4 bytes length of data to follow, including the filetype
- 4 bytes filetype
- file data follows

File structures are:

- MODU indicates this is a code overlay. This system uses relocatable overlays
  (big surprise).
    - COMM, four bytes length, nn bytes data (.rodata/.data sections?)
      The parser always reads 0x24 bytes data, the last 4 are zero padding

    - CODE, four bytes length, nn bytes data

    - MDBG, four bytes section length (typically 0x20),
      then the filename of the object file.
      The parser ignores this.
    
    - RELA, four bytes length, nn bytes data

    - PAD\x20, followed by four bytes section length (typically 4),
    then four zero bytes.

    F1 World Grand Prix compresses its sections:

    - GZIP, four bytes section type (expect CODE, RELA), 4 bytes uncompressed length,
      MIO0, standard MIO0 header and file format

'''

import logging
import struct

from bffi import Bffi,BffiBuilder,BffiSectionType, BffiTlb, BffiTlbEntry
from n64rom import N64Rom
from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi
from signature import SignatureBuilder, WILDCARD

logger = logging.getLogger(__name__)

# -----------------------------------------------

# relocs are:
# - 0   = hi16
# - 1   = lo16
# - 2   =
# - 3/4 = 
# - 5/6 = 
#

def _read_relocs(rela_contents: bytes):
    offset = 0
    while offset < len(rela_contents):
        something, packed_data = struct.unpack(">II", rela_contents[offset:offset+8])

        reloc_offset  = (packed_data & 0x003FFFFF) << 2
        reloc_type    = (packed_data & 0x03C00000) >> 22
        thing         = (packed_data & 0x0C000000) >> 26
        hi4           = (packed_data & 0xF0000000) >> 28

def _read_module(module_contents: bytes):
    offset = 0
    while offset < len(module_contents):
        headertype, datasize = struct.unpack(">II", module_contents[offset:offset+8])
        offset += 8
        data = module_contents[offset:offset + datasize]
        offset += datasize

        if headertype == 0x50414420: # PAD\x20
            # skip padding sections
            continue
        elif headertype == 0x434F4445: # CODE
            logger.info("\tcode: %d bytes", datasize)
        elif headertype == 0x434F4D4D: # COMM
            logger.info("\tdata: %d bytes", datasize)
        elif headertype == 0x4D444247: # MDBG
            logger.info("\tobject name: %s", data.decode('ascii'))
        elif headertype == 0x52454C41: # RELA
            logger.info("\trela: %d bytes", datasize)
        elif headertype == 0:
            break
        else:
            logger.error("illegal header in module: %08x", headertype)

def _walk_filesystem(rom: N64Rom, filesystem_start_address: int):
    offset = filesystem_start_address

    filetypes = []
    i = 0
    while True:
        headertype, datasize, filetype = struct.unpack(">III", rom.read_bytes(offset, 12))

        if headertype != 0x464F524D:
            break
        
        logger.info("file %03x - %s", i, struct.pack(">I", filetype).decode('ascii'))

        i += 1

        # if filetype not in filetypes:
        #     filetypes.append(filetype)
        #     logger.info("- %s", struct.pack(">I", filetype).decode('ascii'))

        contents = rom.read_bytes(offset + 12, datasize - 4)
        offset += 8 + datasize

        if filetype == 0x4D4F4455:
            logger.info("try load module!")
            _read_module(contents)


def beetle_unpack(rom: N64Rom, ipc: int):
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, None)
    bootexe = rom.boot_exe()[:earliest_bss-ipc]

    # two filesystems
    # - 0x237D0 UVFS
    # - 0x25fd0 main entries

    _walk_filesystem(rom, 0x25fd0)


# -----------------------------------------------
#
# Pilotwings 64 / Aero Fighters Assault
#
# Clears additional BSS section and copies the main code segment to RAM.
# The filesystem is only used for resources (I hope).
#
# TODO: doublecheck these guys for additional code segments.
# pilotwings in particular looks a bit small (only 530k)
#
# -----------------------------------------------

# Pilotwings loads the overlay before clearing BSS
PILOTWINGS_MAIN_OVERLAY_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xe8,             # +0x00 addiu      sp,sp,-0x18
        0xaf, 0xa4, 0x00, 0x18,             # +0x04 sw         a0,0x18(sp)
        0x3c, 0x05, WILDCARD, WILDCARD,     # +0x08 lui        a1,0x5
        0x3c, 0x0e, WILDCARD, WILDCARD,     # +0x0C lui        t6,0xe
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x10 addiu      a1,a1,0x1e30
        0xaf, 0xbf, 0x00, 0x14,             # +0x14 sw         ra,0x14(sp)
        0x25, 0xce, WILDCARD, WILDCARD,     # +0x18 addiu      t6,t6,-0x18e0
        0x3c, 0x04, 0x80, WILDCARD,         # +0x1C lui        a0,0x802d
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x20 addiu      a0,a0,-0x5700
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x24 jal        FUN_8022a760
        0x01, 0xc5, 0x30, 0x23,             # +0x28 _subu      a2,t6,a1
        0x3c, 0x04, 0x80, WILDCARD,         # +0x2C lui        a0,0x8035
        0x3c, 0x0f, 0x80, WILDCARD,         # +0x30 lui        t7,0x8038
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x34 addiu      a0,a0,0x71f0
        0x25, 0xef, WILDCARD, WILDCARD,     # +0x38 addiu      t7,t7,0x5e0
        0x01, 0xe4, 0x30, 0x23,             # +0x3C subu       a2,t7,a0
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x40 jal        FUN_8022aa80
        0x00, 0x00, 0x28, 0x25,             # +0x44 _or        a1,zero,zero
    ]) \
    .const_op32_hi16("rom_start_address", 0x08) \
    .const_op32_lo16("rom_start_address", 0x10) \
    .const_op32_hi16("rom_end_address", 0x0C) \
    .const_op32_lo16("rom_end_address", 0x18) \
    .const_op32_hi16("load_address", 0x1C) \
    .const_op32_lo16("load_address", 0x20) \
    .const_op32_hi16("bss_start", 0x2C) \
    .const_op32_lo16("bss_start", 0x34) \
    .const_op32_hi16("bss_end",   0x30) \
    .const_op32_lo16("bss_end",   0x38) \
    .build()

# Aerofighters clears BSS then loads the overlay
AEROFIGHTERS_MAIN_OVERLAY_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xe8,             # +0x00 addiu  sp,sp,-0x18
        0xaf, 0xa4, 0x00, 0x18,             # +0x04 sw     a0,0x18(sp)
        0x3c, 0x04, 0x80, WILDCARD,         # +0x08 lui    a0,0x8032 <-- bss start
        0x3c, 0x0e, 0x80, WILDCARD,         # +0x0C lui    t6,0x8035 <-- bss end
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x10 addiu  a0,a0,0x33c0
        0xaf, 0xbf, 0x00, 0x14,             # +0x14 sw     ra,0x14(sp)
        0x25, 0xce, WILDCARD, WILDCARD,     # +0x18 addiu  t6,t6,-0x6ad0
        0x01, 0xc4, 0x30, 0x23,             # +0x1C subu   a2,t6,a0
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x20 jal    memset
        0x00, 0x00, 0x28, 0x25,             # +0x24 _or    a1,zero,zero
        0x3c, 0x05, WILDCARD, WILDCARD,     # +0x28 lui    a1,0x5          <-- ROM start address
        0x3c, 0x0f, WILDCARD, WILDCARD,     # +0x2C lui    t7,0x12         <-- ROM end address
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x30 addiu  a1,a1,0x7d20
        0x25, 0xef, WILDCARD, WILDCARD,     # +0x34 addiu  t7,t7,-0x7970
        0x3c, 0x04, 0x80, WILDCARD,         # +0x38 lui    a0,0x8028       <-- RAM load address
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x3C addiu  a0=>,a0,0x7430
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x40 jal    read_rom
        0x01, 0xe5, 0x30, 0x23              # +0x44 _subu  a2,t7,a1
    ]) \
    .const_op32_hi16("bss_start", 0x08) \
    .const_op32_lo16("bss_start", 0x10) \
    .const_op32_hi16("bss_end",   0x0C) \
    .const_op32_lo16("bss_end",   0x18) \
    .const_op32_hi16("rom_start_address", 0x28) \
    .const_op32_lo16("rom_start_address", 0x30) \
    .const_op32_hi16("rom_end_address", 0x2C) \
    .const_op32_lo16("rom_end_address", 0x34) \
    .const_op32_hi16("load_address", 0x38) \
    .const_op32_lo16("load_address", 0x3C) \
    .build()


def _pick_pattern(bootexe: bytes):
    pattern_offset = AEROFIGHTERS_MAIN_OVERLAY_LOAD_PATTERN.find(bootexe)
    if pattern_offset is not None:
        return AEROFIGHTERS_MAIN_OVERLAY_LOAD_PATTERN, pattern_offset
    
    pattern_offset = PILOTWINGS_MAIN_OVERLAY_LOAD_PATTERN.find(bootexe)
    if pattern_offset is not None:
        return PILOTWINGS_MAIN_OVERLAY_LOAD_PATTERN, pattern_offset

    return None, None

def aerofighters_unpack(rom: N64Rom, ipc: int):
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None

    builder = BffiBuilder()

    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())

    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    bootexe = rom.boot_exe()[:earliest_bss-ipc]

    pattern, main_overlay_load_offset = _pick_pattern(bootexe)
    if pattern is None:
        return None
    
    logger.info("found Paradigm Entertainment Pilotwings/Aero Fighters-style main segment bootstrap")
    consts = pattern.consts(ipc, bootexe, main_overlay_load_offset)

    bss_start           = consts["bss_start"].get_value()
    bss_end             = consts["bss_end"].get_value()
    rom_start_address   = consts["rom_start_address"].get_value()
    rom_end_address     = consts["rom_end_address"].get_value()
    load_address        = consts["load_address"].get_value()

    logger.info("main segment bss 0x%08x-0x%08x", bss_start, bss_end)
    logger.info("main segment in ROM at 0x%08x-0x%08x, loads to 0x%08x", rom_start_address, rom_end_address, load_address)
    
    main_segment = rom.read_bytes(rom_start_address, rom_end_address-rom_start_address)

    builder.bss(bss_start, bss_end-bss_start)
    builder.fix(load_address, main_segment)

    return builder.build()
