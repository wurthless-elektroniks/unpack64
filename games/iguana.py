'''
Standard Iguana Entertainment / Acclaim Entertainment RNC unpacker

Later versions are identifiable by the string "Acclaim Entertainment, Inc." in the bootexe.

Examples:
- Turok: Dinosaur Hunter

Examples that also use the TLB:
- All-Star Baseball 2000 (uses same TLB init block as Re-Volt)

'''

import logging
import struct

from compression.rnc import rnc_unpack
from preamble import identify_preamble
from n64rom import N64Rom
from bffi import Bffi,BffiBuilder,BffiSectionType
from signature import SignatureBuilder, WILDCARD
from mips import disassemble_jump_imm26_target

logger = logging.getLogger(__name__)

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
    .const_op32_hi16("payload_size_offset", 0x0C) \
    .const_op32_lo16("payload_size_offset", 0x10) \
    .const_op32_hi16("payload_offset", 0x1C) \
    .const_op32_lo16("payload_offset", 0x20) \
    .const_op32_hi16("entry_point", 0xC4) \
    .const_op32_lo16("entry_point", 0xC8) \
    .build()

ALLSTAR99_REAL_ENTRY_POINT_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xe0,             # +0x00 addiu  sp,sp,-0x20
        0xaf, 0xbf, 0x00, 0x1c,             # +0x04 sw     ra,local_4(sp)
        0x0c, 0x00, WILDCARD, WILDCARD,     # +0x08 jal    FUN_80017c18    <-- another BSS section clear-er
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


def allstar99_unpack(rom: N64Rom, ipc: int) -> Bffi:
    logger.info("using identify_preamble() to grab standard libultra bss-free preamble")
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None

    bootentry_offset = preamble.crt_entry_point() - ipc
    logger.info("check for BootEntry() at 0x%08x", preamble.crt_entry_point())
    if ALLSTAR99_BOOTENTRY_PATTERN.compare(rom.boot_exe(), bootentry_offset) is False:
        return None

    logger.info("found Acclaim All-Star Baseball '99-style RNC unpacker")

    consts = ALLSTAR99_BOOTENTRY_PATTERN.consts(ipc, rom.boot_exe(), bootentry_offset)

    payload_size_offset = consts["payload_size_offset"].get_value()
    payload_offset = consts["payload_offset"].get_value()
    entry_point = consts["entry_point"].get_value()

    payload_size = struct.unpack(">I",rom.read_bytes(payload_size_offset,4))[0]

    logger.info("Compressed boot executable in ROM at 0x%08x (size %d/0x%08x bytes)",
                payload_offset,
                payload_size,
                payload_size)
    
    payload = rom.read_bytes(payload_offset, payload_size)

    # FIXME: CRC16 fails for Allstar Baseball 99 (Europe)
    logger.info("Unpacking RNC payload...")
    payload = rnc_unpack(payload)
    if payload is None:
        logger.error("Error unpacking RNC-packed bootexe")
        return None
    logger.info("RNC decompress succeeded. uncompressed payload is %d bytes (0x%08x)", len(payload), len(payload))

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

    logger.warning("this unpacker isn't quite complete yet, but i'll produce something for you anyway...")

    builder = BffiBuilder()
    builder.bss(bss_start, bss_end-bss_start)
    builder.fix(entry_point, payload, segment_id=1)
    builder.initial_program_counter(real_crt_startup_location)
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    return builder.build()
