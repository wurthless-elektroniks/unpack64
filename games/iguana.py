'''
Standard Iguana Entertainment / Acclaim Entertainment RNC unpacker

Later versions are identifiable by the string "Acclaim Entertainment, Inc." in the bootexe.

Examples:
- Turok: Dinosaur Hunter

Examples that also use the TLB:
- All-Star Baseball 2000 (uses same TLB init block as Re-Volt)
- NBA Jam 2000 (integrates TLB init into the RNC unpacker stub)

'''

import logging
import struct

from compression.rnc import rnc_unpack, crc16
from preamble import identify_preamble
from tlb import tlb_try_detect_preamble
from n64rom import N64Rom
from bffi import Bffi,BffiBuilder,BffiSectionType, BffiTlb, BffiTlbEntry
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

# ------------------------------------------------------------------------------------------
#
# NBA Jam 2000
#
# Boot stub starts by writing some magic values somewhere.
# Then it initializes TLB by unmapping entries 0x00~0x1E, then maps page 0x1F.
# The main payload is decompressed to low RAM and is executed.
#
# ------------------------------------------------------------------------------------------

NBAJAM2K_BOOT_PATTERN = SignatureBuilder() \
    .pattern([
        # copy some values (probably ROM pointers) to where the main code segment
        # can read them
        0x27, 0xbd, 0xff, 0xd8,         # +0x00 addiu      sp,sp,-0x28
        0x3c, 0x02, WILDCARD, WILDCARD, # +0x04 lui        v0,0x0
        0x24, 0x42, WILDCARD, WILDCARD, # +0x08 addiu      v0,v0,0x79e8
        0x3c, 0x01, 0x80, 0x00,         # +0x0C lui        at,0x8000
        0xac, 0x22, 0x03, 0x5c,         # +0x10 sw         v0,offset DAT_8000035c(at)
        0x3c, 0x02, WILDCARD, WILDCARD, # +0x14 lui        v0,0x1
        0x24, 0x42, WILDCARD, WILDCARD, # +0x18 addiu      v0,v0,-0x66f8
        0xaf, 0xb0, 0x00, 0x18,         # +0x1C sw         s0,local_10(sp)
        0x3c, 0x10, WILDCARD, WILDCARD, # +0x20 lui        s0,0xe9
        0x26, 0x10, WILDCARD, WILDCARD, # +0x24 addiu      s0,s0,-0x42a0
        0x3c, 0x01, 0x80, 0x00,         # +0x28 lui        at,0x8000
        0xac, 0x22, 0x03, 0x60,         # +0x2C sw         v0,offset DAT_80000360(at)
        0x3c, 0x02, WILDCARD, WILDCARD, # +0x30 lui        v0,0xf6
        0x24, 0x42, WILDCARD, WILDCARD, # +0x34 addiu      v0,v0,0x1a38
        0xaf, 0xbf, 0x00, 0x20,         # +0x38 sw         ra,local_8(sp)
        0xaf, 0xb1, 0x00, 0x1c,         # +0x3C sw         s1,local_c(sp)
        0x3c, 0x01, 0x80, 0x00,         # +0x40 lui        at,0x8000
        0xac, 0x30, 0x03, 0x64,         # +0x44 sw         s0,offset DAT_80000364(at)
        0x3c, 0x01, 0x80, 0x00,         # +0x48 lui        at,0x8000
        0xac, 0x22, 0x03, 0x68,         # +0x4C sw         v0,offset DAT_80000368(at)

        # init TLB 0x00-0x1E
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x50 jal        FUN_80303060
        0x00, 0x00, 0x00, 0x00,             # +0x54 _nop

        # init TLB entry 0x1F
        # (assumed to be the same across all builds)
        0x24, 0x04, 0x00, 0x1f,             # +0x58 li         a0,0x1f
        0x3c, 0x05, 0x00, 0x1f,             # +0x5C lui        a1,0x1f
        0x34, 0xa5, 0xe0, 0x00,             # +0x60 ori        a1,a1,0xe000
        0x00, 0x00, 0x30, 0x21,             # +0x64 clear      a2
        0x24, 0x07, 0xff, 0xff,             # +0x68 li         a3,-0x1
        0x24, 0x02, 0xff, 0xff,             # +0x6C li         v0,-0x1
        0xaf, 0xa0, 0x00, 0x10,             # +0x70 sw         zero,local_18(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x74 jal        FUN_80302f40
        0xaf, 0xa2, 0x00, 0x14,             # +0x78 _sw        v0,local_14(sp)
        
        # setup pointer to RNC packed main code block
        0x3c, 0x11, WILDCARD, WILDCARD, # +0x7C lui        s1,0xe6
        0x26, 0x31, WILDCARD, WILDCARD, # +0x80 addiu      s1,s1,-0x6538
    ]) \
    .const_op32_hi16("data_35c", 0x04) \
    .const_op32_lo16("data_35c", 0x08) \
    .const_op32_hi16("data_360", 0x14) \
    .const_op32_lo16("data_360", 0x18) \
    .const_op32_hi16("data_364", 0x20) \
    .const_op32_lo16("data_364", 0x24) \
    .const_op32_hi16("data_368", 0x30) \
    .const_op32_lo16("data_368", 0x34) \
    .const_op32_hi16("payload_rom_address", 0x7C) \
    .const_op32_lo16("payload_rom_address", 0x80) \
    .build()

NBAJAM2K_ENTRY_POINT_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x04, WILDCARD, WILDCARD, # lui        a0,0x13
        0x24, 0x84, WILDCARD, WILDCARD, # addiu      a0,a0,0x53f0
        0x00, 0x80, 0xf8, 0x09,         # jalr       a0=>SUB_001353f0
    ]) \
    .const_op32_hi16("entrypoint", 0) \
    .const_op32_lo16("entrypoint", 4) \
    .build()


def nbajam2k_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None

    if NBAJAM2K_BOOT_PATTERN.compare(rom.boot_exe(), preamble.crt_entry_point() - ipc) is False:
        return None
    
    logger.info("found NBA Jam 2000 TLB mapper and RNC unpacker")

    builder = BffiBuilder()

    tlb = BffiTlb()
    for i in range(0,0x1F):
        entry = BffiTlbEntry()
        entry.pagemask(0)
        entry.entryhi(0x80000000)
        entry.entrylo0(0)
        entry.entrylo1(0)

        tlb.entry(i, entry)
    
    entry1f = BffiTlbEntry()
    entry1f.pagemask(0x1fe000)
    entry1f.entryhi(0)
    entry1f.entrylo0(1)
    entry1f.entrylo1(0x1F)
    tlb.entry(0x1F, entry1f)

    builder.initial_tlb(tlb)

    consts = NBAJAM2K_BOOT_PATTERN.consts(ipc, rom.boot_exe(), preamble.crt_entry_point() - ipc)
    
    data_35c = consts["data_35c"].get_value()
    data_360 = consts["data_360"].get_value()
    data_364 = consts["data_364"].get_value()
    data_368 = consts["data_368"].get_value()

    payload_rom_address = consts["payload_rom_address"].get_value()
    
    logger.info(\
"""magic values table as follows:
    0x8000035c = %08x
    0x80000360 = %08x
    0x80000364 = %08x
    0x80000368 = %08x
""",data_35c,data_360,data_364,data_368)
    
    magic_values = struct.pack(">IIII", data_35c, data_360, data_364, data_368)
    builder.fix(0x8000035c, magic_values, segment_id=0)

    logger.info("RNC payload in ROM at 0x%08x, checking it.", payload_rom_address)
    if rom.read_bytes(payload_rom_address, 4) != b'RNC\x01':
        logger.error("payload does not use RNC type 1 compression")
        return None

    payload_compressed_size = struct.unpack(">I", rom.read_bytes(payload_rom_address + 8, 4))[0]
    
    logger.info("payload compressed size is %d byte(s)", payload_compressed_size)
    payload = rom.read_bytes(payload_rom_address, 18 + payload_compressed_size)

    # HACK: NBA Jam 2000 (E) [!] has an invalid payload CRC16,
    # so we recalculate it here so that check always passes
    if rom.sha256() == "76778e298da9b3929c1659c2374d19df1d542fb2db89ff5be7d53c7dfa267fca":
        logger.info("NBA Jam 2000 PAL detected, forcing RNC payload CRC recalc")
        fixed_crc = crc16(payload, 18, payload_compressed_size)
        logger.info("fixed CRC-16 is %04x", fixed_crc)
        payload = bytearray(payload)
        payload[14:16] = struct.pack(">H", fixed_crc)

    logger.info("Unpacking RNC payload...")
    payload = rnc_unpack(payload)
    if payload is None:
        logger.error("Error unpacking RNC-packed bootexe")
        return None
    logger.info("RNC decompress succeeded. uncompressed payload is %d bytes (0x%08x)", len(payload), len(payload))

    if NBAJAM2K_ENTRY_POINT_PATTERN.compare(payload) is False:
        logger.error("entry point in payload didn't match expected")
        return None
    
    entrypoint = NBAJAM2K_ENTRY_POINT_PATTERN.consts(0x00100000, payload)["entrypoint"].get_value()
    if tlb.virtual_to_physical(entrypoint) is None:
        logger.error("TLB configuration is bad! entry point %08x is not mapped!", entrypoint)
        return None
    
    logger.info("real executable entry point is 0x%08x", entrypoint)

    # TODO: kill hardcoding here
    builder.fix(0x80000400, payload, segment_id=1)

    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(entrypoint)

    # main code segment immediately jumps to TLB-mapped space,
    # where we find code that's almost identical to Allstar Baseball '99,
    # which clears the BSS space and starts the game.
    # we can reuse that signature to grab the BSS space
    if ALLSTAR99_REAL_ENTRY_POINT_PATTERN.compare(payload, entrypoint - 0x100400) is False:
        logger.error("code at entrypoint was not the BSS init code we expected...")
        return None

    bssconsts = ALLSTAR99_REAL_ENTRY_POINT_PATTERN.consts(0x100000, payload, entrypoint - 0x100400)
    bss_start = bssconsts["bss_start"].get_value()
    bss_end = bssconsts["bss_end"].get_value()
    
    logger.info("BSS section at 0x%08x~0x%08x", bss_start, bss_end)
    builder.bss(bss_start, bss_end-bss_start)

    return builder.build()

# ------------------------------------------------------------------------------------------
#
# All-Star Baseball 2000, All-Star Baseball 2001
#
# Similar to NBA Jam 2000.
# Initialize some magic values (to various resources), RNC decompress the main code segment,
# jump to the entry point, which then trampolines us into TLB-mapped space to start the game.
#
# The main difference is the TLB being setup by the preamble, meaning no TLB init code here
# and thus a different code signature.
#
# ------------------------------------------------------------------------------------------

ALLSTAR2K_BOOT_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xd8,             # +0x00 addiu      sp,sp,-0x28
        0x3c, 0x04, WILDCARD, WILDCARD,     # +0x04 lui        a0,0x0          <-- 8000035c (also pointer to RNC payload size)
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x08 addiu      a0,a0,0x1978    <-- 8000035c
        0x27, 0xa5, 0x00, 0x10,             # +0x0C addiu      a1,sp,0x10
        0x24, 0x06, 0x00, 0x04,             # +0x10 li         a2,0x4
        0x3c, 0x03, 0x80, 0x00,             # +0x14 lui        v1,0x8000
        0x24, 0x63, 0x03, 0x1c,             # +0x18 addiu      v1,v1,0x31c
        0x3c, 0x02, WILDCARD, WILDCARD,     # +0x1C lui        v0,0x0          <-- 80000360 (also RNC payload)
        0xaf, 0xb1, 0x00, 0x1c,             # +0x20 sw         s1,local_c(sp)
        0x24, 0x51, WILDCARD, WILDCARD,     # +0x24 addiu      s1,v0,0x4270    <-- 80000360
        0x3c, 0x02, WILDCARD, WILDCARD,     # +0x28 lui        v0,0xf2         <-- 80000364
        0x24, 0x42, WILDCARD, WILDCARD,     # +0x2C addiu      v0,v0,-0x55a0   <-- 80000364
        0xaf, 0xbf, 0x00, 0x24,             # +0x30 sw         ra,local_4(sp)
        0xaf, 0xb2, 0x00, 0x20,             # +0x34 sw         s2,local_8(sp)
        0xaf, 0xb0, 0x00, 0x18,             # +0x38 sw         s0,local_10(sp)
        0xac, 0x62, 0x00, 0x48,             # +0x3C sw         v0,0x48(v1)
        0x3c, 0x02, WILDCARD, WILDCARD,     # +0x40 lui        v0,0xfa        <-- 80000368
        0x24, 0x42, WILDCARD, WILDCARD,     # +0x44 addiu      v0,v0,0x5510   <-- 80000368
        0xac, 0x64, 0x00, 0x40,             # +0x48 sw         a0,0x40(v1)
        0xac, 0x71, 0x00, 0x44,             # +0x4C sw         s1,0x44(v1)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x50 jal        FUN_80300330
        0xac, 0x62, 0x00, 0x4c,             # +0x54 sw        v0,0x4c(v1)
        0x02, 0x20, 0x20, 0x21,             # +0x58 move       a0,s1
        0x3c, 0x05, 0x80, 0x20,             # +0x5C lui        a1,0x8020
        0x8f, 0xb2, 0x00, 0x10,             # +0x60 lw         s2,local_18(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x64 jal        FUN_80300330
        0x24, 0x06, 0x00, 0x04,             # +0x68 _li        a2,0x4
    ]) \
    .const_op32_hi16("data_35c", 0x04) \
    .const_op32_lo16("data_35c", 0x08) \
    .const_op32_hi16("data_360", 0x1C) \
    .const_op32_lo16("data_360", 0x24) \
    .const_op32_hi16("data_364", 0x28) \
    .const_op32_lo16("data_364", 0x2C) \
    .const_op32_hi16("data_368", 0x40) \
    .const_op32_lo16("data_368", 0x44) \
    .build()

# same as NBA Jam 2000, but with an extra NOP for no god damned reason!!!
ALLSTAR2K_ENTRY_POINT_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x04, WILDCARD, WILDCARD, # lui        a0,0x13
        0x24, 0x84, WILDCARD, WILDCARD, # addiu      a0,a0,0x53f0
        0x00, 0x00, 0x00, 0x00,         # useless NOP
        0x00, 0x80, 0xf8, 0x09,         # jalr       a0=>SUB_001353f0
    ]) \
    .const_op32_hi16("entrypoint", 0) \
    .const_op32_lo16("entrypoint", 4) \
    .build()

# different registers here, to piss us off!!
ALLSTAR2K_REAL_ENTRY_POINT_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xe0,             # +0x00 addiu  sp,sp,-0x20
        0xaf, 0xbf, 0x00, 0x1c,             # +0x04 sw     ra,local_4(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x08 jal    FUN_80017c18    <-- another BSS section clear-er
        0xaf, 0xb0, 0x00, 0x18,             # +0x0C _sw    s0,local_8(sp)
        0x3c, 0x02, 0x80, WILDCARD,         # +0x10 lui    v1,0x8006       <-- BSS start
        0x24, 0x43, WILDCARD, WILDCARD,     # +0x14 addiu  v1,v1,0x7770
        0x3c, 0x02, 0x80, WILDCARD,         # +0x18 lui    a0,0x800b       <-- BSS end
        0x24, 0x44, WILDCARD, WILDCARD,     # +0x1C addiu  a0,a0,-0x2b28
    ]) \
    .const_op32_hi16("bss_start", 0x10) \
    .const_op32_lo16("bss_start", 0x14) \
    .const_op32_hi16("bss_end", 0x18) \
    .const_op32_lo16("bss_end", 0x1C) \
    .build()

def allstar2k_unpack(rom: N64Rom, ipc: int) -> Bffi:
    tlb, preamble = tlb_try_detect_preamble(rom, ipc)
    if None in [ tlb, preamble ]:
        return None
    
    bootstub_entry_point_phys = tlb.virtual_to_physical(preamble.crt_entry_point()) + 0x80000000

    if ALLSTAR2K_BOOT_PATTERN.compare(rom.boot_exe(), bootstub_entry_point_phys-ipc) is False:
        return None
    
    logger.info("found All-Star Baseball 2000 unpacker")

    consts = ALLSTAR2K_BOOT_PATTERN.consts(ipc, rom.boot_exe(), bootstub_entry_point_phys-ipc)

    data_35c = consts["data_35c"].get_value()
    data_360 = consts["data_360"].get_value()
    data_364 = consts["data_364"].get_value()
    data_368 = consts["data_368"].get_value()
    
    payload_size = struct.unpack(">I", rom.read_bytes(data_35c, 4))[0]
    payload_rom_address = data_360

    logger.info("RNC-compressed main segment in ROM at 0x%08x (size %d bytes)", payload_rom_address, payload_size)

    payload = rom.read_bytes(payload_rom_address, payload_size)
    logger.info("Unpacking RNC payload...")
    payload = rnc_unpack(payload, skipping_input_checksum=True)
    if payload is None:
        logger.error("Error unpacking RNC-packed bootexe")
        return None
    logger.info("RNC decompress succeeded. uncompressed payload is %d bytes (0x%08x)", len(payload), len(payload))

    if ALLSTAR2K_ENTRY_POINT_PATTERN.compare(payload) is False:
        logger.error("entry point in payload didn't match expected")
        return None
    
    entrypoint = ALLSTAR2K_ENTRY_POINT_PATTERN.consts(0x00100000, payload)["entrypoint"].get_value()
    if tlb.virtual_to_physical(entrypoint) is None:
        logger.error("TLB configuration is bad! entry point %08x is not mapped!", entrypoint)
        return None
    
    logger.info("real executable entry point is 0x%08x (=0x%08x)", entrypoint, tlb.virtual_to_physical(entrypoint)+0x80000000)

    if ALLSTAR2K_REAL_ENTRY_POINT_PATTERN.compare(payload, entrypoint - 0x100400) is False:
        logger.error("code at entrypoint was not the BSS init code we expected...")
        return None

    bssconsts = ALLSTAR2K_REAL_ENTRY_POINT_PATTERN.consts(0x100000, payload, entrypoint - 0x100400)
    bss_start = bssconsts["bss_start"].get_value()
    bss_end = bssconsts["bss_end"].get_value()
    
    logger.info("BSS section at 0x%08x~0x%08x", bss_start, bss_end)

    builder = BffiBuilder()
    builder.initial_tlb(tlb)
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(entrypoint)

    magic_values = struct.pack(">IIII", data_35c, data_360, data_364, data_368)
    builder.fix(0x8000035c, magic_values, segment_id=0)
    builder.fix(0x80000400, payload, segment_id=1)

    builder.bss(bss_start, bss_end-bss_start)

    return builder.build()

# ------------------------------------------------------------------------------------------
#
# South Park - Chef's Luv Shack
#
# Another variant on NBA Jam 2000, but it sets the audio sample rate to 22050 Hz
# in the init stub just to be a dick.
#
# ------------------------------------------------------------------------------------------

CHEF_BOOT_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xd8,             # +0x00 addiu  sp,sp,-0x28
        0x24, 0x04, 0x56, 0x22,             # +0x04 li     a0,0x5622   (=22050 Hz)
        0x3c, 0x05, 0x80, 0x00,             # +0x08 lui    a1,0x8000
        0x24, 0xa5, 0x03, 0x1c,             # +0x0C addiu  a1,a1,0x31c
        0xaf, 0xb0, 0x00, 0x18,             # +0x10 sw     s0,local_10(sp)
        0x3c, 0x10, WILDCARD, WILDCARD,     # +0x14 lui    s0,0x0         <-- 8000035c (also pointer to RNC payload size)
        0x26, 0x10, WILDCARD, WILDCARD,     # +0x18 addiu  s0,s0,0x5000   <-- 8000035c
        0x3c, 0x02, WILDCARD, WILDCARD,     # +0x1C lui    v0,0x0         <-- 80000360
        0x24, 0x42, WILDCARD, WILDCARD,     # +0x20 addiu  v0,v0,0x5678   <-- 80000360
        0x3c, 0x03, WILDCARD, WILDCARD,     # +0x24 lui    v1,0xee        <-- 80000364
        0x24, 0x63, WILDCARD, WILDCARD,     # +0x28 addiu  v1,v1,-0x43d0  <-- 80000364
        0xaf, 0xbf, 0x00, 0x24,             # +0x2C sw     ra,local_4(sp)
        0xaf, 0xb2, 0x00, 0x20,             # +0x30 sw     s2,local_8(sp)
        0xaf, 0xb1, 0x00, 0x1c,             # +0x34 sw     s1,local_c(sp)
        0xac, 0xa2, 0x00, 0x44,             # +0x38 sw     v0,0x44(a1)
        0x3c, 0x02, WILDCARD, WILDCARD,     # +0x3C lui    v0,0xee       <-- 80000368
        0x24, 0x42, WILDCARD, WILDCARD,     # +0x40 addiu  v0,v0,0x6628  <-- 80000368
        0xac, 0xa3, 0x00, 0x48,             # +0x44 sw     v1,0x48(a1)
        0x00, 0x62, 0x18, 0x26,             # +0x48 xor    v1,v1,v0
        0x00, 0x03, 0x90, 0x2b,             # +0x4C sltu   s2,zero,v1
        0xac, 0xb0, 0x00, 0x40,             # +0x50 sw     s0,0x40(a1)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x54 jal    FUN_80300a60
        0xac, 0xa2, 0x00, 0x4c,             # +0x58 _sw    v0,0x4c(a1)
        0x02, 0x00, 0x20, 0x21,             # +0x5C move   a0,s0
        0x27, 0xa5, 0x00, 0x10,             # +0x60 addiu  a1,sp,0x10
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x64 jal    FUN_8030041c
        0x24, 0x06, 0x00, 0x04,             # +0x68 _li    a2,0x4
        0x3c, 0x02, WILDCARD, WILDCARD,     # +0x6C lui    v0,0xf6        <-- RNC payload address in ROM
        0x24, 0x51, WILDCARD, WILDCARD,     # +0x70 addiu  s1,v0,-0x42e0  <-- RNC payload address in ROM
        0x02, 0x20, 0x20, 0x21,             # +0x74 move   a0,s1
        0x3c, 0x05, 0x80, 0x18,             # +0x78 lui    a1,0x8018
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x7C jal    FUN_8030041c
        0x24, 0x06, 0x00, 0x14,             # +0x80 _li    a2,0x14
    ]) \
    .const_op32_hi16("data_35c", 0x14) \
    .const_op32_lo16("data_35c", 0x18) \
    .const_op32_hi16("data_360", 0x1C) \
    .const_op32_lo16("data_360", 0x20) \
    .const_op32_hi16("data_364", 0x24) \
    .const_op32_lo16("data_364", 0x28) \
    .const_op32_hi16("data_368", 0x3C) \
    .const_op32_lo16("data_368", 0x40) \
    .const_op32_hi16("payload_rom_address", 0x6C) \
    .const_op32_lo16("payload_rom_address", 0x70) \
    .build()

CHEF_REAL_ENTRY_POINT_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xe0,         # addiu      sp,sp,-0x20
        0x3c, 0x02, 0x80, WILDCARD,     # lui        v0,0x800c      <-- BSS start
        0x24, 0x43, WILDCARD, WILDCARD, # addiu      v1,v0,0x6050
        0x3c, 0x02, 0x80, WILDCARD,     # lui        v0,0x8010      <-- BSS end
        0x24, 0x44, WILDCARD, WILDCARD, # addiu      a0,v0,0x47a8
    ]) \
    .const_op32_hi16("bss_start", 0x04) \
    .const_op32_lo16("bss_start", 0x08) \
    .const_op32_hi16("bss_end", 0x0C) \
    .const_op32_lo16("bss_end", 0x10) \
    .build()

def chef_unpack(rom: N64Rom, ipc: int) -> Bffi:
    tlb, preamble = tlb_try_detect_preamble(rom, ipc)
    if None in [ tlb, preamble ]:
        return None
    
    bootstub_entry_point_phys = tlb.virtual_to_physical(preamble.crt_entry_point()) + 0x80000000

    if CHEF_BOOT_PATTERN.compare(rom.boot_exe(), bootstub_entry_point_phys-ipc) is False:
        return None
    
    logger.info("found Chef's Luv Shack unpacker")

    consts = CHEF_BOOT_PATTERN.consts(ipc, rom.boot_exe(), bootstub_entry_point_phys-ipc)

    data_35c = consts["data_35c"].get_value()
    data_360 = consts["data_360"].get_value()
    data_364 = consts["data_364"].get_value()
    data_368 = consts["data_368"].get_value()
        
    logger.info(\
"""magic values table as follows:
    0x8000035c = %08x
    0x80000360 = %08x
    0x80000364 = %08x
    0x80000368 = %08x
""",data_35c,data_360,data_364,data_368)
    
    payload_rom_address = consts["payload_rom_address"].get_value()
    
    payload_size = struct.unpack(">I", rom.read_bytes(payload_rom_address + 8, 4))[0]

    logger.info("RNC-compressed main segment in ROM at 0x%08x (size %d bytes)", payload_rom_address, payload_size)

    payload = rom.read_bytes(payload_rom_address, payload_size + 18)
    logger.info("Unpacking RNC payload...")
    payload = rnc_unpack(payload)
    if payload is None:
        logger.error("Error unpacking RNC-packed bootexe")
        return None
    logger.info("RNC decompress succeeded. uncompressed payload is %d bytes (0x%08x)", len(payload), len(payload))

    # TLB-related weirdness; seems there's the option that the payload could set up
    # more TLB stuff before we enter TLB space. in practice we jump to TLB-mapped space immediately
    entrypoint = 0x80000400 if data_364 == data_368 else 0x00100400
    logger.info("real executable entry point is 0x%08x (=0x%08x)", entrypoint, tlb.virtual_to_physical(entrypoint)+0x80000000)

    phys_entrypoint = tlb.virtual_to_physical(entrypoint)
    if CHEF_REAL_ENTRY_POINT_PATTERN.compare(payload, phys_entrypoint - 0x400) is False:
        logger.error("code at entrypoint was not the BSS init code we expected...")
        return None
    
    bssconsts = CHEF_REAL_ENTRY_POINT_PATTERN.consts(0x100000, payload, entrypoint - 0x100400)
    bss_start = bssconsts["bss_start"].get_value()
    bss_end = bssconsts["bss_end"].get_value()
    
    logger.info("BSS section at 0x%08x~0x%08x", bss_start, bss_end)

    builder = BffiBuilder()
    builder.initial_tlb(tlb)
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(entrypoint)

    magic_values = struct.pack(">IIII", data_35c, data_360, data_364, data_368)
    builder.fix(0x8000035c, magic_values, segment_id=0)
    builder.fix(0x80000400, payload, segment_id=1)

    builder.bss(bss_start, bss_end-bss_start)

    return builder.build()
