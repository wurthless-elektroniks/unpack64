'''
Bomberman 64 and Bomberman 64 - The Second Attack

Split from hudson.py due to complexity
'''

import logging
import struct

from compression.lzssbomberman import lzssbomberman_decompress

from bffi import BffiBuilder, Bffi, BffiTlb, BffiTlbEntry
from n64rom import N64Rom
from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi
from signature import SignatureBuilder, WILDCARD
from tlbutil import tlbutil_pack_entrylo

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------
#
# Bomberman 64 (the one that *is* Baku Bomberman)
# 
# This is a game where you wonder what the hell was wrong with the programmers.
# What we see here, compared to a lot of other games covered by this project, is the
# exact opposite of elegance and more of a case where they overcomplicated things.
# In other words, it's dogshit.
# 
# The bootexe initializes several vector tables that can be hooked whenever the game wants,
# so function calls can be redirected to other modules or for debugging. They aren't always
# used though, osInvalICache() is called directly by the overlay loaders.
#
# At 80000450 is a function that loads a very small stub following the bootexe
# (in ROM at 0x1CBC0) and then sets up the TLB to point the 4k page at 0x00000000 to it.
# Then, to call routines in those vectors, the game will do a jr $zero with $t0 set to
# the function ID it wants to call. It reminds me a bit of the 68000 A-trap functionality,
# but implemented in the dumbest way possible, because in a memory protected system,
# you do NOT want the zero address to point to anything useful (NullPointerException in Java
# comes to mind). Using $gp for calling a global vector handler would have been a better choice.
#
# The actual overlay load routine is at 0x80000698, and it takes the arguments
# $a0 = RAM address, $a1 = load size, $a2 = ROM address. But the way the overlays
# are loaded is convoluted.
#
# 80000870 loads the 256-byte mini-overlay table from ROM at 0x030000.
# The main thread then uses this to load another table; entry 2 determines
# location and entry 3 determines its size. Shift each left by 0x0B to get
# the actual 32-bit values. Ignore entries 0 and 1, they point to code/resources
# already in memory at that point.
#
# The main loop constantly executes 8000083c, which loads an overlay and
# runs it. In practice the only overlay used is id=2, which is our main
# segment. The rest are compressed with some LZSS variant.
#
# And where does that LZSS variant live? I'm glad you asked.
#
# 0x80292bd0 is the LZSS-ish decompress routine, and its implementation is
# in compression/lzssbomberman.py. I stole that from the BM64 decomp project,
# but it's confirmed against the real code.
#
# Sub-overlays are pointed to by a table in ROM at 0x030800, which is loaded
# by 0x80226860. Each entry is two bytes; entry[0] << 0x11 = ROM base address
# and entry[1] << 0x0B = size of sub-overlay. In practice the sizeof field is always 0.
# If entry[0] is 0, assume that sub-overlay slot is unwired.
#
# 0x8022691c is the compressed sub-overlay loader. Overlays load to the same
# location every time (0x80043000 on U version) and only one can be loaded
# at a time. Using the index passed, get the sub-overlay entry, compute its ROM
# address, then read it in.
# 
# Now we have a sub-overlay blob header with a structure that doesn't make much logical sense.
# - 4 bytes data start offset relative to start of file (should be 0x2008)
# - 4 bytes always 0x400
# - 4 bytes start offset of some header data relative to data start offset
# - 4 bytes end offset of header data relative to data start offset
# - several 32-bit words terminated with 0xFFFFFFFF
#
# The "some header data" is:
# - 1 byte number of entries:
# - 3 byte tuples mapping entries within this sub-overlay blob to global sub-overlay UIDs
#   - 2 bytes global sub-overlay ID
#   - 1 byte entry ID (1, 2, ..., n)
#
# Getting the offsets and sizeofs for the compressed overlays is annoying because
# the entries don't seem to follow an easily identifiable structure.
# Cheating with the handy list of overlays from the bm64 decomp project
# https://github.com/Bomberhackers/bm64/blob/master/tools/bm64decompress.cpp
# means we can compute the offsets with three fingers:
# - If finger[0] + finger[1] == finger[2], then
#   start_offset = finger[0]
#   end_offset   = finger[2]
#   set read pointer to finger[2]
#
# - If finger[0] + finger[1] != finger[2] and finger[2] != 0xFFFFFFFF:
#   start_offset = finger[0]
#   end_offset   = finger[1]
#   set read pointer to finger[1]
#
# - If finger[0] + finger[1] != finger[2] and finger[2] == 0xFFFFFFFF:
#   start_offset = finger[0]
#   end_offset   = start_offset + finger[1]
#   stop reading
#
# Uncompressed size is a 4 byte uint32 at the start of each compressed entry.
#
# Anyway, that's that bastard game dealt with.
#
# ----------------------------------------------------------------------

# have to capture the zerojump handler
BM64_ZEROPAGE_INIT_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xd8,             # +0x00 addiu      sp,sp,-0x28
        0x3c, 0x08, 0x80, WILDCARD,         # +0x04 lui        t0,0x8004 <-- load address (physical)
        0x3c, 0x06, 0x00, WILDCARD,         # +0x08 lui        a2,0x2 <-- ROM start address
        0x3c, 0x0e, 0x00, WILDCARD,         # +0x0C lui        t6,0x2 <-- ROM end address
        0xaf, 0xbf, 0x00, 0x1c,             # +0x10 sw         ra,local_c(sp)
        0x25, 0xce, WILDCARD, WILDCARD,     # +0x14 addiu      t6,t6,-0x3310
        0x24, 0xc6, WILDCARD, WILDCARD,     # +0x18 addiu      a2,a2,-0x3440
        0x25, 0x08, WILDCARD, WILDCARD,     # +0x1C addiu      t0,t0,0x2000
        0x01, 0x00, 0x20, 0x25,             # or         a0,t0,zero
        0xaf, 0xa8, 0x00, 0x24,             # sw         t0,local_4(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # jal        FUN_80000698
        0x01, 0xc6, 0x28, 0x23,             # _subu      a1,t6,a2
    ]) \
    .const_op32_hi16("zeropage_load_address", 0x04) \
    .const_op32_lo16("zeropage_load_address", 0x1C) \
    .const_op32_hi16("zeropage_rom_start_address", 0x08) \
    .const_op32_lo16("zeropage_rom_start_address", 0x18) \
    .const_op32_hi16("zeropage_rom_end_address", 0x0C) \
    .const_op32_lo16("zeropage_rom_end_address", 0x14) \
    .build()
    
BM64_OVERLAY_TABLE_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xe8,             # addiu      sp,sp,-0x18
        0xaf, 0xbf, 0x00, 0x14,             # sw         ra,local_4(sp)
        0x3c, 0x05, 0x80, WILDCARD,         # lui        a1,0x8002
        0x24, 0xa5, WILDCARD, WILDCARD,     # addiu      a1,a1,-0x6070
        0x0c, WILDCARD, WILDCARD, WILDCARD, # jal        FUN_80001a30 <-- zerovector table install
        0x24, 0x04, 0x00, 0x03,             # _li        a0,0x3

        0x3c, 0x04, 0x80, WILDCARD,         # lui        a0,0x8002    <-- overlay table load address
        0x24, 0x84, WILDCARD,  WILDCARD,    # addiu      a0,a0,0x4820
        0x24, 0x05, 0x01, 0x00,             # li         a1,0x100     <-- 256 bytes
        0x0c, WILDCARD, WILDCARD, WILDCARD, # jal        FUN_80000698 <-- overlay load fcn
        0x3c, 0x06, 0x00, 0x03,             # _lui       a2,0x3       <-- from ROM @ 0x030000
        0x8f, 0xbf, 0x00, 0x14,             # lw         ra,local_4(sp)
        0x27, 0xbd, 0x00, 0x18,             # addiu      sp,sp,0x18
        0x03, 0xe0, 0x00, 0x08,             # jr         ra
        0x00, 0x00, 0x00, 0x00,             # _nop
    ]) \
    .build()

BM64_MAINLOOP_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x03, 0x80, WILDCARD,         # +0x00 lui        v1,0x8002 <-- overlay table
        0x24, 0x63, WILDCARD, WILDCARD,     # +0x04 addiu      v1,v1,0x4820
        0x90, 0x62, 0x00, 0x02,             # +0x08 lbu        v0,0x2(v1)
        0x3c, 0x10, 0x80, WILDCARD,         # +0x0C lui        s0,0x8022 <-- main overlay load address (part 1)
        0x00, 0x02, 0x7a, 0xc0,             # +0x10 sll        t7,v0,0xb
        0x15, 0xe0, 0x00, 0x02,             # +0x14 bne        t7,zero,LAB_80001844
        0x01, 0xe0, 0x10, 0x25,             # +0x18 _or        v0,t7,zero
        0x3c, 0x02, 0x00, 0x08,             # +0x1C lui        v0,0x8
        0x90, 0x65, 0x00, 0x03,             # +0x20 lbu        a1,0x3(v1)
        0x36, 0x10, WILDCARD, WILDCARD,     # +0x24 ori        s0,s0,0x5800 <-- main overlay load address (part 2)
        0x3c, 0x01, 0x00, 0x04,             # +0x28 lui        at,0x4
        0x00, 0x41, 0x30, 0x21,             # +0x2C addu       a2,v0,at
        0x00, 0x50, 0x20, 0x21,             # +0x30 addu       a0,v0,s0
        0x00, 0x05, 0xc2, 0xc0,             # +0x34 sll        t8,a1,0xb
        0x03, 0x00, 0x28, 0x25,             # +0x38 or         a1,t8,zero
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x3C jal        FUN_80000698
        0x3c, 0x02, 0x00, 0x08,             # +0x40 _lui       v0,0x8
        0x3c, 0x11, 0x80, WILDCARD,         # +0x44 lui        s1,0x8002
        0x26, 0x31, WILDCARD, WILDCARD,     # +0x48 addiu      s1,s1,0x668
        0x8e, 0x44, 0x00, 0x00,             # +0x4C lw         a0,0x0(s2)
        0x02, 0x00, 0x28, 0x25,             # +0x50 or         a1,s0,zero
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x54 jal        FUN_8000083c <-- load/exec overlay
        0x02, 0x20, 0x30, 0x25,             # +0x58 _or        a2,s1,zero
        0x10, 0x00, 0xff, 0xfc,             # +0x5C b          LAB_80001874
        0x8e, 0x44, 0x00, 0x00,             # +0x60 _lw        a0,0x0(s2)
    ]) \
    .const_op32_hi16("main_overlay_load_address", 0x0C) \
    .const_op32_lo16("main_overlay_load_address", 0x24) \
    .build()

BM64_LOAD_SUB_OVERLAY_TABLE_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xe8,             # +0x00 addiu      sp,sp,-0x18
        0xaf, 0xbf, 0x00, 0x14,             # +0x04 sw         ra,local_4(sp)
        0x3c, 0x05, 0x80, WILDCARD,         # +0x08 lui        a1,0x802a
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x0C addiu      a1,a1,-0xa30
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x10 jal        FUN_80297d30 
        0x24, 0x04, 0x00, 0x0b,             # +0x14 _li        a0,0xb
        0x3c, 0x03, 0x80, WILDCARD,         # +0x18 lui        v1,0x802a
        0x24, 0x63, WILDCARD, WILDCARD,     # +0x1C addiu      v1,v1,0x5320
        0x24, 0x02, 0xff, 0xff,             # +0x20 li         v0,-0x1
        0xac, 0x62, 0x00, 0x00,             # +0x24 sw         v0,0x0(v1)
        0x24, 0x0e, 0xff, 0xff,             # +0x28 li         t6,-0x1
        0x3c, 0x01, 0x80, WILDCARD,         # +0x2C lui        at,0x802a
        0xac, 0x2e, WILDCARD, WILDCARD,     # +0x30 sw         t6,offset DAT_802a5324(at)
        0x3c, 0x01, 0x80, WILDCARD,         # +0x34 lui        at,0x802a
        0xac, 0x22, WILDCARD, WILDCARD,     # +0x38 sw         v0,offset DAT_802a5328(at)
        0x8c, 0x6f, 0x00, 0x00,             # +0x3C lw         t7,0x0(v1)
        0x3c, 0x04, 0x80, WILDCARD,         # +0x40 lui        a0,0x801a
        0x14, 0x4f, 0x00, 0x08,             # +0x44 bne        v0,t7,LAB_802268c8
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x48 _addiu     a0,a0,-0x4f30
        0x3c, 0x06, 0x00, WILDCARD,         # +0x4C lui        a2,0x3       <-- sub-overlay table ROM address
        0x34, 0xc6, WILDCARD, WILDCARD,     # +0x50 ori        a2,a2,0x800
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x54 jal        80297ec0
        0x24, 0x05, 0x10, 0x00,             # +0x58 _li        a1,0x1000
    ]) \
    .const_op32_hi16("sub_overlay_table_rom_address", 0x4C) \
    .const_op32_lo16("sub_overlay_table_rom_address", 0x50) \
    .build()

BM64_SUB_OVERLAY_READ_UNCOMPRESSED_SIZE_CLEAR_CACHES_PATTERN = SignatureBuilder() \
    .pattern([
        0x24, 0x05, 0x00, 0x04,             # +0x00 li         a1,0x4
        0x24, 0x06, 0x00, 0x01,             # +0x04 li         a2,0x1
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x08 jal        fread?
        0x00, 0x40, 0x38, 0x25,             # +0x0C _or        a3,v0,zero
        0x3c, 0x04, 0x80, 0x04,             # +0x10 lui        a0,0x8004
        0x34, 0x84, 0x30, 0x00,             # +0x14 ori        a0,a0,0x3000
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x18 jal        FUN_80297d58 <-- thunk vector 0x104
        0x3c, 0x05, 0x00, 0x02,             # +0x1C _lui       a1,0x2
    ]) \
    .const_op32_hi16("sub_overlay_load_address", 0x10) \
    .const_op32_lo16("sub_overlay_load_address", 0x14) \
    .build()

def _bm64_suboverlay_extract_entries(blob: bytes,
                                     blob_base: int,
                                     num_entries: int):
    

    # bomberman 64 uses 0x2008, bomberman 2 uses 0x8008
    data_start_offset = struct.unpack(">I", blob[:4])[0]

    lzssheader_size = 8 if data_start_offset == 0x8008 else 4
   
    read_offset = 0x10

    entries = {}

    for i in range(num_entries):
        finger_0, finger_1, finger_2 = struct.unpack(">III", blob[read_offset:read_offset+0x0C])
        if finger_0 + finger_1 == finger_2:
            start_offset = finger_0
            end_offset   = finger_2
            read_offset += 8
        elif finger_2 != 0xFFFFFFFF:
            start_offset = finger_0
            end_offset   = finger_1
            read_offset += 4
        else:
            start_offset = finger_0
            end_offset   = finger_0 + finger_1
        
        start_offset += data_start_offset
        end_offset += data_start_offset

        logger.info("blob entry %d = blob 0x%08x-0x%08x / ROM 0x%08x-0x%08x",
                    i,
                    start_offset,
                    end_offset,
                    blob_base+start_offset,
                    blob_base+end_offset)

        entry = blob[start_offset:end_offset]
        decompressed_size = struct.unpack(">I", entry[:4])[0]
        logger.info("decompressed size of entry is: %d", decompressed_size)

        entry = lzssbomberman_decompress(entry[lzssheader_size:], decompressed_size)

        entries[i] = entry

        if finger_2 == 0xFFFFFFFF:
            break
        
        i += 1
    
    return entries

def _bm64_parse_sub_overlay_table(sub_overlay_table: bytes):
    sub_overlay_base_blob_addresses = {}
    for i in range(0x800):
        sub_overlay_page     = sub_overlay_table[(i * 2)]

        # should be always be 0 for bm64
        # for bomberman 2 it will either be 0 or 0x20
        sub_overlay_subpage  = sub_overlay_table[(i * 2) + 1]
        
        if sub_overlay_page == 0:
            # it's not wired
            continue
        
        # that's just the base page address - sometimes the page size is more than 128k!
        sub_overlay_base_blob_addresses[i] = (sub_overlay_page * 0x020000) + (sub_overlay_subpage * 0x800)
    return sub_overlay_base_blob_addresses

def _bm64_init_tlb(entryhi: int,
                   zeropage_address: int) -> BffiTlb:
    if (zeropage_address & 0xFFF) != 0:
        raise RuntimeError("zeropage address not 4kbytes aligned")

    tlb = BffiTlb()
    for i in range(0x01,0x20):
        entry = BffiTlbEntry()
        entry.pagemask(0)
        entry.entryhi(0x80000000)
        entry.entrylo0(1)
        entry.entrylo1(1)

        tlb.entry(i, entry)

    entry_00 = BffiTlbEntry()
    entry_00.pagemask(0) # 4kbytes page
    entry_00.entryhi(entryhi) # at 0x00000000 or 0x10000000
    entry_00.entrylo0( tlbutil_pack_entrylo(zeropage_address & 0x00FFFFFF, 0x1F) )
    entry_00.entrylo1( 1 )
    tlb.entry(0x00, entry_00)

    tlb.wired(1)
    tlb.context(0)

    return tlb

def _bm64_parse_mapping_table(blob: bytes):
    blobdata_start_offset, _, should_be_zero, mapping_table_end_offset = \
            struct.unpack(">IIII", blob[0x00:0x10])
    
    if blobdata_start_offset not in [ 0x2008, 0x8008 ]:
        raise RuntimeError(f"invalid blobdata start offset: {blobdata_start_offset:08x}")

    if should_be_zero != 0:
        raise RuntimeError("should_be_zero was NOT zero!")
        
    mapping_table = blob[blobdata_start_offset:blobdata_start_offset+mapping_table_end_offset]
    
    num_suboverlays = mapping_table[0]
    logger.info("suboverlay mapping table has %d entries", num_suboverlays)

    expected_mapping_table_size = 1 + (num_suboverlays * 3)
    if expected_mapping_table_size != len(mapping_table):

        if (expected_mapping_table_size & 1) == 1:
            expected_mapping_table_size += 1

        if expected_mapping_table_size != len(mapping_table):
            logger.info("num_overlays field was lying to us!! (%d != %d)",
                        (1 + num_suboverlays*3),
                        len(mapping_table))
            
            num_suboverlays = int((len(mapping_table)-1) / 3)
            logger.info("overriding num_suboverlays -> %d", num_suboverlays)

    local_to_global_mappings = {}
    for i in range(num_suboverlays):
        expected_entry_id = i + 1

        suboverlay_guid, entry_id = struct.unpack(">HB", mapping_table[1 + (i*3): 1 + (i*3) + 3])
        if entry_id != expected_entry_id:
            # they should be in ascending order or else something has gone wrong
            raise RuntimeError(f"entry_id should be {i} but was {entry_id}")

        local_to_global_mappings[i] = suboverlay_guid
    
    return local_to_global_mappings

def _bm64_assert_local_to_global_mappings_valid(
        local_to_global_mappings: dict,
        sub_overlay_base_blob_addresses: dict,
        sub_overlay_must_match_address: int
    ):
    for local_id,global_id in local_to_global_mappings.items():
        if global_id not in sub_overlay_base_blob_addresses:
            raise RuntimeError("suboverlay guid {global_id:04x} was not registered in the suboverlay table!")
        
        if sub_overlay_base_blob_addresses[global_id] != sub_overlay_must_match_address:
            raise RuntimeError("suboverlay guid {global_id:04x} is stored in the wrong suboverlay blob! "+
                                f"(should be {sub_overlay_must_match_address:08x}, was {sub_overlay_base_blob_addresses[global_id]:08x})")

        logger.info("validated guid entry %04x OK: blob %08x entry %d", global_id, sub_overlay_must_match_address, local_id)

def bomberman64_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    builder = BffiBuilder()
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    bootexe = rom.boot_exe()[:earliest_bss-ipc]

    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.fix(ipc, bootexe)

    # overlay table load has to be there, obvs
    if BM64_OVERLAY_TABLE_LOAD_PATTERN.find(bootexe) is None:
        return None

    logger.info("found Bomberman 64 overlay table load function")
    overlay_table = rom.read_bytes(0x030000, 0x100)

    # dump the zeropage/zerojump handler and setup the TLB
    zeropage_init_offset = BM64_ZEROPAGE_INIT_PATTERN.find(bootexe)
    if zeropage_init_offset is None:
        logger.error("can't find zeropage load/init function")
        return None
    
    consts = BM64_ZEROPAGE_INIT_PATTERN.consts(ipc, bootexe, zeropage_init_offset)
    zeropage_load_address      = consts["zeropage_load_address"].get_value()
    zeropage_rom_start_address = consts["zeropage_rom_start_address"].get_value()
    zeropage_rom_end_address   = consts["zeropage_rom_end_address"].get_value()

    logger.info("zeropage in ROM 0x%08x-0x%08x, loads to 0x%08x",
                zeropage_rom_start_address,
                zeropage_rom_end_address,
                zeropage_load_address)
    
    zeropage = rom.read_bytes(zeropage_rom_start_address, zeropage_rom_end_address-zeropage_rom_start_address)

    builder.initial_tlb(_bm64_init_tlb(0x00000000, zeropage_load_address))
    builder.fix(0, zeropage)

    mainloop_offset = BM64_MAINLOOP_PATTERN.find(bootexe)
    if mainloop_offset is None:
        logger.error("can't find mainloop")
        return None
    
    consts = BM64_MAINLOOP_PATTERN.consts(ipc, bootexe, mainloop_offset)
    main_overlay_load_address = consts["main_overlay_load_address"].get_value()

    # read both the main segment and the table that goes after it.
    # in practice they're right next to each other in the ROM,
    # but we mimic the original code here.
    # even if they were in different ROM locations, the main table
    # loads immediately after the main segment.
    main_segment_rom_address = 2 << 0x11
    main_segment_size        = 0x080000 if overlay_table[2] == 0 else overlay_table[2] << 0x0B

    logger.info("main segment: ROM 0x%08x-0x%08x -> RAM 0x%08x",
                main_segment_rom_address,
                main_segment_rom_address + main_segment_size,
                main_overlay_load_address)

    # the J version has the "main table" integrated into the main segment itself,
    # and uses the second load as a BSS clear.
    main_table_rom_address   = main_segment_size + 0x040000
    main_table_size          = overlay_table[3] << 0x0B

    logger.info("main table: ROM 0x%08x-0x%08x -> RAM 0x%08x",
                main_table_rom_address,
                main_table_rom_address + main_table_size,
                main_overlay_load_address + main_segment_size)

    main_segment = rom.read_bytes(main_segment_rom_address, main_segment_size)
    main_table   = rom.read_bytes(main_table_rom_address, main_table_size)

    merged_main_segment = main_segment + main_table
    builder.fix(main_overlay_load_address, merged_main_segment)

    # now we need to look for the sub-overlay stuff
    # first try to get the table out of ROM
    sub_overlay_table_loader_offset = BM64_LOAD_SUB_OVERLAY_TABLE_PATTERN.find(merged_main_segment)
    if sub_overlay_table_loader_offset is None:
        logger.error("can't find sub-overlay table loader")
        return None
    
    consts = BM64_LOAD_SUB_OVERLAY_TABLE_PATTERN.consts(main_overlay_load_address,
                                                        merged_main_segment,
                                                        sub_overlay_table_loader_offset)
    sub_overlay_table_rom_address = consts["sub_overlay_table_rom_address"].get_value()

    logger.info("sub-overlay table in ROM at 0x%08x",
                sub_overlay_table_rom_address)
    
    sub_overlay_read_uncompressed_size_offset = BM64_SUB_OVERLAY_READ_UNCOMPRESSED_SIZE_CLEAR_CACHES_PATTERN.find(merged_main_segment)
    if sub_overlay_read_uncompressed_size_offset is None:
        logger.info("can't find sub-overlay load address")
        return None

    consts = BM64_SUB_OVERLAY_READ_UNCOMPRESSED_SIZE_CLEAR_CACHES_PATTERN.consts(main_overlay_load_address,
                                                        merged_main_segment,
                                                        sub_overlay_read_uncompressed_size_offset)
    sub_overlay_load_address = consts["sub_overlay_load_address"].get_value()

    logger.info("sub-overlays will load to: 0x%08x", sub_overlay_load_address)

    sub_overlay_table = rom.read_bytes(sub_overlay_table_rom_address, 0x1000)
    sub_overlay_base_blob_addresses = _bm64_parse_sub_overlay_table(sub_overlay_table)
    
    # now we have the IDs of the overlays we should expect,
    # and the blobs they should load from.
    # now let's read and parse the blobs
    logger.info("found %d suboverlay blobs", len(set(sub_overlay_base_blob_addresses.values())))

    overlays_dumped = []
    for sub_overlay_blob_base in set(sub_overlay_base_blob_addresses.values()):
        logger.info("read suboverlay blob at 0x%08x...", sub_overlay_blob_base)

        # read maximum of 256kbytes because some pages will overrun the 128k limit
        sub_overlay_blob = rom.read_bytes(sub_overlay_blob_base, 0x040000)
        local_to_global_mappings = _bm64_parse_mapping_table(sub_overlay_blob)

        _bm64_assert_local_to_global_mappings_valid(local_to_global_mappings,
                                                    sub_overlay_base_blob_addresses,
                                                    sub_overlay_blob_base)
        
        suboverlay_entries = _bm64_suboverlay_extract_entries(sub_overlay_blob,
                                         sub_overlay_blob_base,
                                         len(local_to_global_mappings.keys()))
        
        for local_id, data in suboverlay_entries.items():
            global_id = local_to_global_mappings[local_id]

            builder.seg(sub_overlay_load_address, data, segment_id=global_id)
            overlays_dumped.append(global_id)

    # final pass: check that we've dumped all the overlays we need
    missing_count = 0
    for uid, blob_address in sub_overlay_base_blob_addresses.items():
        if uid not in overlays_dumped:
            logger.warning("overlay not dumped! uuid %04x, check blob 0x%08x", uid, blob_address)
            missing_count += 1

    logger.info("dumped %d suboverlays, %d still missing (might not be present)", len(overlays_dumped), missing_count)

    return builder.build()

# ----------------------------------------------------------------------
#
# Bomberman 64 - The Second Attack
# 
# This is a "one step forward, two steps back" story. For starters, they've
# unified the boot and main segments into one bootexe so there's no need to load
# more segments later. The zeropage crap returns, but is more sensibly mapped to
# 0x10000000 this time. However, this game ends up using the TLB for much more
# than a syscall-like handler this time.
#
# Boot segment:
# - 80000698 is the readcart routine (same args as bm64)
# - 80000450 loads the zerojump handler to 0x801D0000. Unlike BM64 they instead
#            map the zerojump page to 0x10000000.
# - 80002730 is lzssbomberman decompress, taking params $a0 = input file handle,
#            $a1 = output pointer, $a2 = decompressed size
# - 800024c0 is the suboverlay load routine.
# - 80002228 loads the suboverlay table from ROM 0x0FF000 to RAM.
# - 800026ec swaps a new suboverlay in at 0x80250000. It's declared as a
#            zerojump routine. Since all overlays seem to load to fixed addresses,
#            I'm not sure if this is ever used.
# - 800516bc allocates TLB entries in the 0x40000000~0x5FFFFFFF and loads overlays there.
# - 80051630 tests if the module (which loads in TLB space) can be loaded to TLB-mapped space.
#            $a0 = number of 8kbyte pages, $a1 = where to load it to.
# - 80051168 looks for a free TLB entry and wires it.
#
# Compression can either be lzssbomberman or Yay0. Detecting Yay0 is simple,
# just look at the first word and compare it to 'Yay0'. The suboverlays however
# will *ALWAYS* be lzssbomberman.
#
# Suboverlays are loaded to TLB-mapped space. Each suboverlay starts with the instruction sequence
# "lui v0,XXXX / jr ra / addiu v0,v0,XXXX" which returns the entry point for that module.
# Extracting the uppermost 8 bits of that 32-bit word should tell you where it loads
# without having to trace through all the overlay loader code.
#
# The lzssbomberman header has changed slightly. The first four bytes of the compressed data
# are still the uncompressed size in bytes, but that is followed by another four bytes containing
# the sizeof some extended data. That extra word doesn't seem to be used by the game; the loader
# code will just fseek() past it.
#
# ----------------------------------------------------------------------

BOMBERMAN2_SUB_OVERLAY_TABLE_READ_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x04, 0x80, WILDCARD,         # lui        a0,0x800f
        0x14, 0x4f, 0x00, 0x08,             # bne        v0,t7,LAB_80002290
        0x24, 0x84, WILDCARD, WILDCARD,     # _addiu     a0,a0,-0xdb0
        0x3c, 0x06, 0x00, 0x0f,             # lui        a2,0xf
        0x34, 0xc6, 0xf0, 0x00,             # ori        a2,a2,0xf000
        0x0c, WILDCARD, WILDCARD, WILDCARD, # jal        readcart
        0x24, 0x05, 0x10, 0x00,             # _li        a1,0x1000
    ]) \
    .build()

# all suboverlays will start with this.
# we can grab the TLB base offset from there
BOMBERMAN2_SUB_OVERLAY_ENTRYPOINT_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x02, WILDCARD, WILDCARD, # lui        v0,0x4300
        0x03, 0xe0, 0x00, 0x08,         # jr         ra
        0x24, 0x42, WILDCARD, WILDCARD, # _addiu     v0,v0,0xf50
    ]) \
    .const_op32_hi16("v0_address", 0x00) \
    .const_op32_lo16("v0_address", 0x08) \
    .build()

def bomberman2_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    builder = BffiBuilder()
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    bootexe = rom.boot_exe()[:earliest_bss-ipc]

    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.fix(ipc, bootexe)

    if BOMBERMAN2_SUB_OVERLAY_TABLE_READ_PATTERN.find(bootexe) is None:
        return None
    
    logger.info("found Bomberman 2 suboverlay table load")

    # TODO: de-copypaste this
    zeropage_init_offset = BM64_ZEROPAGE_INIT_PATTERN.find(bootexe)
    if zeropage_init_offset is None:
        logger.error("can't find zeropage load/init function")
        return None
    
    consts = BM64_ZEROPAGE_INIT_PATTERN.consts(ipc, bootexe, zeropage_init_offset)
    zeropage_load_address      = consts["zeropage_load_address"].get_value()
    zeropage_rom_start_address = consts["zeropage_rom_start_address"].get_value()
    zeropage_rom_end_address   = consts["zeropage_rom_end_address"].get_value()

    logger.info("zeropage in ROM 0x%08x-0x%08x, loads to 0x%08x",
                zeropage_rom_start_address,
                zeropage_rom_end_address,
                zeropage_load_address)
    
    zeropage = rom.read_bytes(zeropage_rom_start_address, zeropage_rom_end_address-zeropage_rom_start_address)

    builder.initial_tlb(_bm64_init_tlb(0x10000000, zeropage_load_address))
    builder.fix(0x10000000, zeropage)

    # suboverlay table is at 0x0FF000. let's read it
    suboverlay_table = rom.read_bytes(0x0FF000, 0x1000)
    sub_overlay_base_blob_addresses = _bm64_parse_sub_overlay_table(suboverlay_table)
    logger.info("found %d suboverlay blobs", len(set(sub_overlay_base_blob_addresses.values())))

    overlays_dumped = []

    for suboverlay_blob_address in set(sub_overlay_base_blob_addresses.values()):
        blob = rom.read_bytes(suboverlay_blob_address, 0x040000)
        local_to_global_mappings = _bm64_parse_mapping_table(blob)

        _bm64_assert_local_to_global_mappings_valid(local_to_global_mappings,
                                                    sub_overlay_base_blob_addresses,
                                                    suboverlay_blob_address)
        
        # mappings are valid, let's dump some overlays
        suboverlay_entries = _bm64_suboverlay_extract_entries(blob,
                                         suboverlay_blob_address,
                                         len(local_to_global_mappings.keys()))
        
        for local_id, data in suboverlay_entries.items():
            global_id = local_to_global_mappings[local_id]

            # detect load address
            # each should have a lui v0/jr $ra/addiu $v0
            if BOMBERMAN2_SUB_OVERLAY_ENTRYPOINT_PATTERN.compare(data) is False:
                raise RuntimeError("sub overlay did not start with expected lui/jr ra/addiu sequence")
            
            consts = BOMBERMAN2_SUB_OVERLAY_ENTRYPOINT_PATTERN.consts(0, data)
            v0_address = consts["v0_address"].get_value()
            suboverlay_load_address = v0_address & 0xFF000000

            logger.info("suboverlay %04x loads to 0x%08x (entry point: 0x%08x)",
                        global_id, 
                        suboverlay_load_address,
                        v0_address)
            builder.seg(suboverlay_load_address, data, segment_id=global_id)
            overlays_dumped.append(global_id)
    
    missing_count = 0
    for uid, blob_address in sub_overlay_base_blob_addresses.items():
        if uid not in overlays_dumped:
            logger.warning("overlay not dumped! uuid %04x, check blob 0x%08x", uid, blob_address)
            missing_count += 1

    logger.info("dumped %d suboverlays, %d still missing (might not be present)", len(overlays_dumped), missing_count)

    return builder.build()
