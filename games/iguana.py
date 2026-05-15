'''
Standard Iguana Entertainment / Acclaim Entertainment RNC unpacker

Later versions are identifiable by the string "Acclaim Entertainment, Inc." in the bootexe.
'''

import logging
import struct

from .acclaimfs import acclaimfs_read, acclaim_anonyfs_read

from compression.rnc import rnc_unpack, rnc_get_filesize_from_header
from preamble import identify_preamble
from n64rom import N64Rom
from bffi import Bffi, BffiBuilder
from signature import SignatureBuilder, WILDCARD
from strutil import extract_cstring
from mips import disassemble_jump_imm26_target
from sigutil import pick_pattern

logger = logging.getLogger(__name__)

def _auto_decompress(payload: bytes):
    if payload[:3] == b'RNC':
        logger.info("Unpacking RNC payload...")
        payload = rnc_unpack(payload, skipping_input_checksum=True)
        if payload is None:
            logger.error("Error unpacking RNC-packed bootexe")
            return None
        logger.info("RNC decompress succeeded. uncompressed payload is %d bytes (0x%08x)", len(payload), len(payload))
    return payload

# ------------------------------------------------------------------------------------------
#
# Turok: Dinosaur Hunter
#
# Code in bootexe sets up the initial stackpointer then jumps to the RNC unpacker.
# In the leaked Turok source this lands in boot.c at BootEntry(), which does the following:
# - Read first 12 bytes of bootexe into RDRAM using BootTransfer().
#   a0 = ROM address, a1 = destination RAM address, a2 = sizeof.
# - If first 3 bytes are "RNC", copy payload to RDRAM to the mempool space and
#   decompress it to the code segment start address. Otherwise, copy directly
#   to the code segment start address. (Likely a debugging leftover.)
# - Clear caches, clear BSS, then jump to the CRT entry point (boot()).
#
# The sourcecode states that "the O/S should now be alive!" after the
# bootexe is unpacked. This is a bit misleading; what's actually happened is that,
# now that the program is in memory, the libultra OS functions are present and can
# be called. boot.c relies on this behavior to call the libultra cache clear functions.
#
# The unpacker stub needs to stay in RDRAM afterwards as there's a good chance other
# code might be using it.
#
# ------------------------------------------------------------------------------------------

# all we need here is the bootexe location in ROM.
# the RNC payload already has the uncompressed payload size in its header.
TUROK_BOOTENTRY_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xc0, # +0x00 addiu sp,sp,-0x40
        0xaf, 0xb0, 0x00, 0x18, # +0x04 sw s0,local_28(sp)
        0x3c, 0x10, WILDCARD, WILDCARD, # +0x08 lui s0,0x8000      <-- high bits of bootexe load address
        0x3c, 0x04, WILDCARD, WILDCARD, # +0x0C lui a0,0x78        <-- high bits of RNC payload address in ROM (minus PI base)
        0x26, 0x10, WILDCARD, WILDCARD, # +0x10 addiu s0,s0,0x1300 <-- low bits of bootexe load address
        0xaf, 0xbf, 0x00, 0x1c, # +0x14 sw ra,local_24(sp)
        0x24, 0x84, WILDCARD, WILDCARD, # +0x18 addiu a0,a0,0x3690 <-- low bits of RNC payload address
    ]) \
    .size(0x160) \
    .tail_pattern([
        0x3c, 0x04, WILDCARD, WILDCARD,     # +0x128 lui   a0,0x8010
        0x3c, 0x09, WILDCARD, WILDCARD,     # +0x12C lui   t1,0x8014
        0x24, 0x82, WILDCARD, WILDCARD,     # +0x130 addiu v0,a0,-0x6fe0  - v0 = start of .bss
        0x25, 0x29, WILDCARD, WILDCARD,     # +0x134 addiu t1,t1,-0x5ed0  - t1 = end of .bss
        
        # BSS clear loop, nothing special
        0x01, 0x22, 0x18, 0x23,     # +0x138 subu       v1,t1,v0
        0x00, 0x03, 0x58, 0x82,     # +0x13C srl        t3,v1,0x2
        0x11, 0x60, 0x00, 0x06,     # +0x140 beq        t3,zero,LAB_80000620
        0x25, 0x66, 0xff, 0xff,     # +0x144 _addiu     a2,t3,-0x1
        0x00, 0xc0, 0x18, 0x25,     # +0x148 or         v1,a2,zero
        0xac, 0x40, 0x00, 0x00,     # +0x14C sw         zero,0x0(v0)
        0x24, 0x42, 0x00, 0x04,     # +0x150 addiu      v0,v0,0x4
        0x14, 0xc0, 0xff, 0xfc,     # +0x154 bne        a2,zero,LAB_8000060c
        0x24, 0xc6, 0xff, 0xff,     # +0x158 _addiu     a2,a2,-0x1
        
        # call the entrypoint (should be 0x80001300)
        0x0c, WILDCARD, WILDCARD, WILDCARD,    # +0x15C  jal        FUN_80001300
    ]) \
    .const_op32_hi16("bootexe_load_address", 0x08) \
    .const_op32_lo16("bootexe_load_address", 0x10) \
    .const_op32_hi16("payload_rom_address", 0x0C) \
    .const_op32_lo16("payload_rom_address", 0x18) \
    .const_op32_hi16("bss_start_address", 0x128) \
    .const_op32_lo16("bss_start_address", 0x130) \
    .const_op32_hi16("bss_end_address", 0x12C) \
    .const_op32_lo16("bss_end_address", 0x134) \
    .xref_j_imm26("entrypoint", 0x15C) \
    .build()

def turok_unpack(rom: N64Rom, ipc: int) -> Bffi:
    # game uses generic libultra preamble with no .bss sections
    logger.info("using identify_preamble() to grab standard libultra bss-free preamble")
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None

    bootentry_offset = preamble.crt_entry_point() - ipc

    if TUROK_BOOTENTRY_PATTERN.compare(rom.boot_exe(), bootentry_offset) is False:
        return None
    
    logger.info("found Turok-style RNC unpacker")

    consts = TUROK_BOOTENTRY_PATTERN.consts(ipc, rom.boot_exe(), bootentry_offset)
    xrefs  = TUROK_BOOTENTRY_PATTERN.xrefs(ipc, rom.boot_exe(), bootentry_offset)

    bootexe_load_address = consts["bootexe_load_address"].get_value()
    payload_rom_address = consts["payload_rom_address"].get_value()
    bss_start_address = consts["bss_start_address"].get_value()
    bss_end_address = consts["bss_end_address"].get_value()
    entrypoint = xrefs["entrypoint"].get_address()

    logger.info("bootexe payload is in ROM at 0x%08x", payload_rom_address)
    logger.info("bootexe loads to 0x%08x", bootexe_load_address)
    logger.info("bss segment at 0x%08x~0x%08x", bss_start_address, bss_end_address)
    logger.info("exe entry point at 0x%08x", entrypoint)

    if rom.read_bytes(payload_rom_address, 4) != b'RNC\x01':
        logger.error("payload does not use RNC type 1 compression")
        return None

    payload_compressed_size = struct.unpack(">I", rom.read_bytes(payload_rom_address + 8, 4))[0]
    
    logger.info("payload compressed size is %d byte(s)", payload_compressed_size)
    payload = rom.read_bytes(payload_rom_address, 18 + payload_compressed_size)

    logger.info("Unpacking RNC payload...")
    payload = rnc_unpack(payload)
    if payload is None:
        logger.error("Error unpacking RNC-packed bootexe")
        return None
    logger.info("RNC decompress succeeded. uncompressed payload is %d bytes (0x%08x)", len(payload), len(payload))

    bffi = BffiBuilder()
    bffi.rom_hash(rom.sha256())
    bffi.fix(ipc, rom.boot_exe()[:bootexe_load_address-ipc])
    bffi.fix(bootexe_load_address, payload)
    bffi.bss(bss_start_address, bss_end_address-bss_start_address)
    bffi.initial_stack_pointer(preamble.initial_stack_pointer())
    bffi.initial_program_counter(entrypoint)

    return bffi.build()


# ------------------------------------------------------------------------------------------
#
# All-Star Baseball '99
#
# Has a file table at the start of ROM. Boot executable is called CODE.BIN;
# offset in ROM is hardcoded into the unpack stub.
# "Acclaim Entertainment, Inc." string follows preamble.
#
# Like the later games using the Acclaim filesystem, the bootloader drops some
# arguments into reserved memory space:
# - 0x80000380: filesystem start address
# - 0x80000384: filesystem end address
#
# Then other overlays will be loaded from the filesystem.
#
# ------------------------------------------------------------------------------------------

ALLSTAR99_BOOTENTRY_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xd8,         # +0x00 addiu  sp,sp,-0x28
        0x3c, 0x02, 0x80, 0x00,         # +0x04 lui    v0,0x8000
        0x34, 0x42, 0x03, 0x80,         # +0x08 ori    v0,v0,0x380   <-- ???
        0x3c, 0x04, WILDCARD, WILDCARD, # +0x0C lui    a0,0x0
        0x24, 0x84, WILDCARD, WILDCARD, # +0x10 addiu  a0,a0,0x32e0  <-- start of file table; pointing to bootexe size
        0x27, 0xa5, 0x00, 0x10,         # +0x14 addiu  a1,sp,0x10
        0xaf, 0xb0, 0x00, 0x18,         # +0x18 sw     s0,local_10(sp)
        0x3c, 0x10, WILDCARD, WILDCARD, # +0x1C lui    s0,0x0
        0x26, 0x10, WILDCARD, WILDCARD, # +0x20 addiu  s0,s0,0x5688  <-- bootexe payload ROM address
    ]) \
    .tail_pattern([
        0x3c, 0x01, 0x80, WILDCARD,     # +0xC4 lui at,0x8000
        0x34, 0x21, WILDCARD, WILDCARD, # +0xC8 ori at,at,0x400
        0x00, 0x20, 0xf8, 0x09,         # +0xCC jalr at=>SUB_80000400
        0x00, 0x00, 0x00, 0x00,         # +0xD0 _nop
    ]) \
    .size(0xD4) \
    .const_op32_hi16("bootexe_argbase", 0x04) \
    .const_op32_lo16("bootexe_argbase", 0x08) \
    .const_op32_hi16("fstable_address", 0x0C) \
    .const_op32_lo16("fstable_address", 0x10) \
    .const_op32_hi16("fsdata_address", 0x1C) \
    .const_op32_lo16("fsdata_address", 0x20) \
    .const_op32_hi16("entry_point", 0xC4) \
    .const_op32_lo16("entry_point", 0xC8) \
    .build()

# same boot procedure/structure as Allstar 99, but clears TLB entries 0x00-0x1E.
# this game doesn't really use the TLB though.
NBAJAM99_BOOT_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xd8,             # +0x00 addiu  sp,sp,-0x28
        0xaf, 0xb0, 0x00, 0x18,             # +0x04 sw     s0,local_10(sp)
        0x3c, 0x10, WILDCARD, WILDCARD,     # +0x08 lui    s0,0x0
        0x26, 0x10, WILDCARD, WILDCARD,     # +0x0C addiu  s0,s0,0x3390    <-- fstable ROM address
        0xaf, 0xb1, 0x00, 0x1c,             # +0x10 sw     s1,local_c(sp)
        0x3c, 0x11, WILDCARD, WILDCARD,     # +0x14 lui    s1,0x0
        0x26, 0x31, WILDCARD, WILDCARD,     # +0x18 addiu  s1,s1,0x6c08    <-- fsdata ROM address
        0xaf, 0xbf, 0x00, 0x20,             # +0x1C sw     ra,local_8(sp)
        0x3c, 0x01, 0x80, 0x00,             # +0x20 lui    at,0x8000
        0xac, 0x30, 0x03, 0x5c,             # +0x24 sw     s0,offset DAT_8000035c(at)
        0x3c, 0x01, 0x80, 0x00,             # +0x28 lui    at,0x8000
        0xac, 0x31, 0x03, 0x60,             # +0x2C sw     s1,offset DAT_80000360(at)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x30 jal    tlb_init
        0x00, 0x00, 0x00, 0x00,             # +0x34 _nop
        0x02, 0x00, 0x20, 0x21,             # +0x38 move   a0,s0
        0x27, 0xa5, 0x00, 0x10,             # +0x3C addiu  a1,sp,0x10
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x40 jal    read_cart
        0x24, 0x06, 0x00, 0x04,             # +0x44 _li    a2,0x4
    ]) \
    .tail_pattern([
        0x3c, 0x01, 0x80, WILDCARD,     # +0xC4 lui at,0x8000
        0x34, 0x21, WILDCARD, WILDCARD, # +0xC8 ori at,at,0x400
        0x00, 0x20, 0xf8, 0x09,         # +0xCC jalr at=>SUB_80000400
        0x00, 0x00, 0x00, 0x00,         # +0xD0 _nop
    ]) \
    .size(0xD4) \
    .const_op32_hi16("fstable_address", 0x08) \
    .const_op32_lo16("fstable_address", 0x0C) \
    .const_op32_hi16("fsdata_address", 0x14) \
    .const_op32_lo16("fsdata_address", 0x18) \
    .const_op32_hi16("bootexe_argbase", 0x20) \
    .const_op32_lo16("bootexe_argbase", 0x24) \
    .const_op32_hi16("entry_point", 0xC4) \
    .const_op32_lo16("entry_point", 0xC8) \
    .build()


ALLSTAR99_REAL_ENTRY_POINT_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xe0,             # +0x00 addiu  sp,sp,-0x20
        0xaf, 0xbf, 0x00, 0x1c,             # +0x04 sw     ra,local_4(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x08 jal    FUN_80017c18    <-- another BSS section clear-er
        0xaf, 0xb0, 0x00, 0x18,             # +0x0C _sw    s0,local_8(sp)
        0x3c, 0x03, 0x80, WILDCARD,         # +0x10 lui    v1,0x8006       <-- BSS start
        0x24, 0x63, WILDCARD, WILDCARD,     # +0x14 addiu  v1,v1,0x7770
        0x3c, 0x04, 0x80, WILDCARD,         # +0x18 lui    a0,0x800b       <-- BSS end
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x1C addiu  a0,a0,-0x2b28
    ]) \
    .const_op32_hi16("bss_start", 0x10) \
    .const_op32_lo16("bss_start", 0x14) \
    .const_op32_hi16("bss_end", 0x18) \
    .const_op32_lo16("bss_end", 0x1C) \
    .build()

# TODO: same as NBA Jam 2000 - might be others to hunt down
ALLSTAR99_OVERLAY_TABLE_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x00, 0x12, 0x80, 0x80,             # +0x00 sll        s0,s2,0x2
        0x02, 0x12, 0x80, 0x21,             # +0x04 addu       s0,s0,s2
        0x00, 0x10, 0x80, 0x80,             # +0x08 sll        s0,s0,0x2
        0x3c, 0x01, 0x80, WILDCARD,         # +0x0C lui        at,0x8006
        0x00, 0x30, 0x08, 0x21,             # +0x10 addu       at,at,s0
        0x8c, 0x25, WILDCARD, WILDCARD,     # +0x14 lw         a1,offset PTR_s_ingame.bin_800642f4(at)
        0x27, 0xa4, 0x00, 0x10,             # +0x18 addiu      a0,sp,0x10
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x1C jal        strcat                                                     undefined strcat()
    ]) \
    .const_op32_hi16("overlay_table_address", 0x0C) \
    .const_op32_lo16("overlay_table_address", 0x14) \
    .build()


def allstar99_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None

    bootentry_offset = preamble.crt_entry_point() - ipc
    logger.info("check for BootEntry() at 0x%08x", preamble.crt_entry_point())

    pattern, _ = pick_pattern(rom.boot_exe(),
                              [ NBAJAM99_BOOT_PATTERN, ALLSTAR99_BOOTENTRY_PATTERN ],
                              comparing_at_offset=bootentry_offset)

    if pattern is None:
        return None

    logger.info("found Acclaim All-Star Baseball '99/NBA Jam '99-style RNC unpacker")

    consts = pattern.consts(ipc, rom.boot_exe(), bootentry_offset)
    fstable_address = consts["fstable_address"].get_value()
    fsdata_address = consts["fsdata_address"].get_value()
    entry_point = consts["entry_point"].get_value()
    bootexe_argbase = consts["bootexe_argbase"].get_value()

    logger.info("Dumping filesystem...")
    filesystem = acclaimfs_read(rom,
                                fstable_address,
                                fsdata_address,
                                align_nearest_word=True,
                                skip_decompress=True)

    if "CODE.BIN" not in filesystem:
        logger.error("filesystem does not contain CODE.BIN, needed to boot game")
        return None

    logger.info("Loading main code segment from CODE.BIN")
    payload = _auto_decompress(filesystem["CODE.BIN"])

    if payload[0] != 0x0C:
        logger.error("expected payload to start with a jal, but it didn't")
        return None
    
    real_crt_startup_location = disassemble_jump_imm26_target(entry_point, payload[0:4])
    if real_crt_startup_location is None:
        logger.error("can't grab real CRT startup location")
        return None
    
    logger.info("real CRT startup is at 0x%08x",real_crt_startup_location)

    real_entry_point_offset = real_crt_startup_location - entry_point
    if ALLSTAR99_REAL_ENTRY_POINT_PATTERN.compare(payload, real_entry_point_offset) is False:
        logger.error("expected entry point code didn't match signature")
        return None

    real_entry_point_consts = ALLSTAR99_REAL_ENTRY_POINT_PATTERN.consts(entry_point, payload, real_entry_point_offset)

    bss_start = real_entry_point_consts["bss_start"].get_value()
    bss_end   = real_entry_point_consts["bss_end"].get_value()

    builder = BffiBuilder()
    builder.bss(bss_start, bss_end-bss_start)

    logger.info("dropping bootexe arguments at 0x%08x", bootexe_argbase)
    builder.fix(bootexe_argbase,
                struct.pack(">II", fstable_address, fsdata_address),
                segment_id=0)
    
    builder.fix(entry_point, payload, segment_id=1)
    builder.initial_program_counter(real_crt_startup_location)
    builder.initial_stack_pointer(preamble.initial_stack_pointer())

    overlay_table_pattern_offset = ALLSTAR99_OVERLAY_TABLE_LOAD_PATTERN.find(payload)
    if overlay_table_pattern_offset is None:
        logger.error("can't find overlay table")
        return None
    
    consts = ALLSTAR99_OVERLAY_TABLE_LOAD_PATTERN.consts(0x80000400, payload, overlay_table_pattern_offset)
    overlay_table_address = consts["overlay_table_address"].get_value()
    overlay_table_offset = overlay_table_address - entry_point
    logger.info("overlay table is at 0x%08x", overlay_table_address)

    while True:
        if payload[overlay_table_offset] != 0x80:
            break

        overlay_filename_address, \
        overlay_load_address, \
        _, \
        overlay_bss_address, \
        overlay_bss_size = struct.unpack(">IIIII", payload[overlay_table_offset:overlay_table_offset+(5*4)])
        
        if (entry_point <= overlay_filename_address <= entry_point+len(payload)) is False:
            break

        overlay_filename_offset = overlay_filename_address - entry_point
        overlay_filename = extract_cstring(payload[overlay_filename_offset:])

        logger.info("overlay: %s -> RAM 0x%08x, bss 0x%08x-0x%08x",
                    overlay_filename,
                    overlay_load_address,
                    overlay_bss_address,
                    overlay_bss_address+overlay_bss_size)
        
        for filename, data in filesystem.items():
            if filename.endswith(overlay_filename):
                logger.info("...reading from: %s", filename)

                data = _auto_decompress(data)

                builder.seg(overlay_load_address, data)

                break

        overlay_table_offset += (5*4)

    return builder.build()


# ------------------------------------------------------------------------------------------
#
# NFL Quarterback Club '98
#
# Similar design to Allstar Baseball '98, but it uses an anonymous filesystem.
#
# Like Allstar Baseball, it drops two words into reserved memory space for the bootexe to use:
# - 0x80000380: filesystem start address
# - 0x80000384: filesystem end address
#
# ------------------------------------------------------------------------------------------

NFLQBC98_BOOTENTRY_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xc0,            # +0x00 addiu  sp,sp,-0x40
        0x3c, 0x03, 0x80, 0x00,            # +0x04 lui    v1,0x8000
        0x34, 0x63, 0x03, 0x80,            # +0x08 ori    v1,v1,0x380
        0x3c, 0x05, 0x80, 0x00,            # +0x0C lui    a1,0x8000       <-- BSS/load range start
        0x34, 0xa5, 0x04, 0x00,            # +0x10 ori    a1,a1,0x400
        0x3c, 0x02, 0x00, WILDCARD,        # +0x14 lui    v0,0x30         <-- BSS size in bytes
        0x24, 0x42, WILDCARD, WILDCARD,    # +0x18 addiu  v0,v0,-0x3c0
        0xaf, 0xb0, 0x00, 0x30,            # +0x1C sw     s0,local_10(sp)
        0x00, 0x02, 0x80, 0x82,            # +0x20 srl    s0,v0,0x2
        0x02, 0x00, 0x20, 0x21,            # +0x24 move   a0,s0
        0x3c, 0x02, WILDCARD, WILDCARD,    # +0x28 lui    v0,0x0
        0x24, 0x42, WILDCARD, WILDCARD,    # +0x2C addiu  v0,v0,0x1768    <-- fstable start
        0xaf, 0xbf, 0x00, 0x38,            # +0x30 sw     ra,local_8(sp)
        0xaf, 0xb1, 0x00, 0x34,            # +0x34 sw     s1,local_c(sp)
        0x3c, 0x01, 0x80, WILDCARD,        # +0x38 lui    at,0x8030
        0xac, 0x23, WILDCARD, WILDCARD,    # +0x3C sw     v1,offset DAT_80300768(at)
        0xac, 0x62, 0x00, 0x00,            # +0x40 sw     v0,0x0(v1)=>DAT_80000380
        0x3c, 0x02, WILDCARD, WILDCARD,    # +0x44 lui    v0,0x0
        0x24, 0x42, WILDCARD, WILDCARD,    # +0x48 addiu  v0,v0,0x1978   <-- fstable end/fsdata start
    ]) \
    .const_op32_hi16("bss_size", 0x14) \
    .const_op32_lo16("bss_size", 0x18) \
    .const_op32_hi16("fstable_address", 0x28) \
    .const_op32_lo16("fstable_address", 0x2C) \
    .const_op32_hi16("fsdata_address", 0x44) \
    .const_op32_lo16("fsdata_address", 0x48) \
    .build()

# unpacked payload starts with a generic bss clear loop that clears
# bss space the unpacker already cleared
NFLQBC98_REAL_ENTRY_POINT_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x08, 0x80, WILDCARD,         # +0x00 lui        t0,0x8004
        0x25, 0x08, WILDCARD, WILDCARD,     # +0x04 addiu      t0,t0,0x4bd0
        0x3c, 0x09, 0x80, WILDCARD,         # +0x08 lui        t1,0x8006
        0x25, 0x29, WILDCARD, WILDCARD,     # +0x0C addiu      t1,t1,-0xd90
        0x11, 0x09, 0x00, 0x05,             # +0x10 beq        t0,t1,LAB_80000428
        0x00, 0x00, 0x00, 0x00,             # +0x14 _nop
        0x25, 0x08, 0x00, 0x04,             # +0x18 addiu      t0,t0,0x4
        0x01, 0x09, 0x08, 0x2b,             # +0x1C sltu       at,t0,t1
        0x14, 0x20, 0xff, 0xfd,             # +0x20 bne        at,zero,LAB_80000418
        0xad, 0x00, 0xff, 0xfc,             # +0x24 _sw        zero,-0x4(t0)=>DAT_80044bd0
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x28 jal        FUN_80008040
        0x00, 0x00, 0x00, 0x00,             # +0x2C _nop
    ]) \
    .xref_j_imm26("entry_point", 0x28) \
    .build()

NFLQBC98_OVERLAY_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x00, 0x10, 0x10, 0x80,             # +0x00 sll   v0,s0,0x2
        0x3c, 0x01, 0x80, WILDCARD,         # +0x04 lui   at,0x8004
        0x00, 0x22, 0x08, 0x21,             # +0x08 addu  at,at,v0
        0x8c, 0x23, WILDCARD, WILDCARD,     # +0x0C lw    v1,-0x368(at) <-- load address table (pointers to actual addresses)
        0x00, 0x10, 0x10, 0x40,             # +0x10 sll   v0,s0,0x1
        0x3c, 0x01, 0x80, WILDCARD,         # +0x14 lui   at,0x8004
        0x00, 0x22, 0x08, 0x21,             # +0x18 addu  at,at,v0
        0x94, 0x24, WILDCARD, WILDCARD,     # +0x1C lhu   a0,-0x350(at) <-- overlay resource ID table (halfwords)
        0x8c, 0x62, 0x00, 0x00,             # +0x20 lw    v0,0x0(v1)
        0x27, 0xa5, 0x00, 0x10,             # +0x24 addiu a1,sp,0x10
        0x00, 0x00, 0x30, 0x21,             # +0x28 clear a2
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x2C jal   FUN_8000db14
        0xaf, 0xa2, 0x00, 0x10,             # +0x30 _sw   v0,local_10(sp)
    ]) \
    .const_op32_hi16("loadaddress_pointer_table_address", 0x04) \
    .const_op32_lo16("loadaddress_pointer_table_address", 0x0C) \
    .const_op32_hi16("resourceid_table_address", 0x14) \
    .const_op32_lo16("resourceid_table_address", 0x1C) \
    .build()

# european version has assertions compiled in, so that makes the overlay pattern
# way different...
NFLQBC98_EURO_OVERLAY_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x01, 0x80, WILDCARD,         # +0x00 lui        at,0x8004
        0x00, 0x22, 0x08, 0x21,             # +0x04 addu       at,at,v0
        0x8c, 0x22, WILDCARD, WILDCARD,     # +0x08 lw         v0,offset DAT_80041678(at)
        0x8c, 0x42, 0x00, 0x00,             # +0x0C lw         v0,0x0(v0)
        0x16, 0x00, 0x00, 0x05,             # +0x10 bne        s0,zero,LAB_8001a934
        0xaf, 0xa2, 0x00, 0x10,             # +0x14 _sw        v0,local_18(sp)
        0x3c, 0x04, 0x80, WILDCARD,         # +0x18 lui        a0,0x8004
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x1C addiu      a0,a0,0x5630
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x20 jal        FUN_80006988
        0x24, 0x05, WILDCARD, WILDCARD,     # +0x24 _li        a1,0xbc
        
        0x00, 0x11, 0x10, 0x40,             # +0x28 sll        v0,s1,0x1
        0x3c, 0x01, 0x80, WILDCARD,         # +0x2C lui        at,0x8004
        0x00, 0x22, 0x08, 0x21,             # +0x30 addu       at,at,v0
        0x94, 0x24, WILDCARD, WILDCARD,     # +0x34 lhu        a0,offset DAT_80041690(at)
    ]) \
    .const_op32_hi16("loadaddress_pointer_table_address", 0x00) \
    .const_op32_lo16("loadaddress_pointer_table_address", 0x08) \
    .const_op32_hi16("resourceid_table_address", 0x2C) \
    .const_op32_lo16("resourceid_table_address", 0x34) \
    .build()

    
def nflqbc98_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None

    bootentry_offset = preamble.crt_entry_point() - ipc
    logger.info("check for BootEntry() at 0x%08x", preamble.crt_entry_point())
    if NFLQBC98_BOOTENTRY_PATTERN.compare(rom.boot_exe(), bootentry_offset) is False:
        return None

    logger.info("found Acclaim NFL Quarterback Club '98-style RNC unpacker")

    consts = NFLQBC98_BOOTENTRY_PATTERN.consts(ipc, rom.boot_exe(), bootentry_offset)
    fstable_address = consts["fstable_address"].get_value()
    fsdata_address = consts["fsdata_address"].get_value()
    bss_size = consts["bss_size"].get_value()

    # HACK: and a shitty one, too!
    payload_load_address = 0x80000400

    logger.info("Dumping filesystem...")
    filesystem = acclaim_anonyfs_read(rom,
                                fstable_address,
                                fsdata_address,
                                align_nearest_word=True,
                                skip_decompress=True)

    # first entry in the filesystem is the bootexe, so unpack it.
    payload = _auto_decompress(filesystem[0])

    # we know the real size of the BSS section now, so let's start building the BFFI.
    builder = BffiBuilder()
    bss_start = payload_load_address + len(payload)
    bss_end = (payload_load_address + bss_size)

    builder.fix(payload_load_address, payload)
    builder.fix(0x80000380,
                struct.pack(">II", fstable_address, fsdata_address))

    builder.bss(bss_start, bss_end-bss_start)
    builder.initial_stack_pointer(preamble.initial_stack_pointer())

    # the payload will start with a BSS clear loop
    # (clearing a subset of BSS space we already cleared)
    if NFLQBC98_REAL_ENTRY_POINT_PATTERN.compare(payload) is False:
        logger.error("unexpected code at entry point")
        return None
    
    xrefs = NFLQBC98_REAL_ENTRY_POINT_PATTERN.xrefs(payload_load_address, payload)
    entry_point = xrefs["entry_point"].get_address()
    builder.initial_program_counter(entry_point)

    overlay_load_pattern, overlay_load_offset = pick_pattern(payload,
                                                             [NFLQBC98_EURO_OVERLAY_LOAD_PATTERN,
                                                              NFLQBC98_OVERLAY_LOAD_PATTERN])

    if overlay_load_offset is None:
        logger.error("cannot find overlay loader")
        return None

    consts = overlay_load_pattern.consts(payload_load_address, payload, overlay_load_offset)
    loadaddress_pointer_table_address = consts["loadaddress_pointer_table_address"].get_value()
    resourceid_table_address = consts["resourceid_table_address"].get_value()
    
    loadaddress_pointer_table_offset = loadaddress_pointer_table_address - payload_load_address
    resourceid_table_offset = resourceid_table_address - payload_load_address

    logger.info("Extracting and decompressing overlays...")
    
    while True:
        resource_id         = struct.unpack(">H", payload[resourceid_table_offset:resourceid_table_offset+2])[0]
        loadaddress_pointer = struct.unpack(">I", payload[loadaddress_pointer_table_offset:loadaddress_pointer_table_offset+4])[0]
        if loadaddress_pointer & 0xFF000000 != 0x80000000 or \
            resource_id > len(filesystem):
            break

        resourceid_table_offset += 2
        loadaddress_pointer_table_offset += 4

        loadaddress_pointer_offset = loadaddress_pointer - payload_load_address
        load_address = struct.unpack(">I", payload[loadaddress_pointer_offset:loadaddress_pointer_offset+4])[0]
        logger.info("found overlay: resource %d -> RAM 0x%08x", resource_id, load_address)

        overlay = _auto_decompress(filesystem[resource_id])

        builder.seg(load_address, overlay)
    
    return builder.build()
