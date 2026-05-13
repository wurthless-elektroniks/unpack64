'''
Various Acclaim games that don't use the Iguana RNC unpacker
but do need special cases added.

Most of these games are built off the Turok 2 codebase and are Expansion Pak
enhanced. They use the TLB, so a fixed 2 MB of code is mapped at all times,
usually at 0x00200000. If the Expansion Pak is present, the game's main code
overlay will be loaded in one shot to high memory and mapped to 0x00400000.
If not, then the game will cache 4k chunks of code in RAM and use TLB miss
exceptions to load new chunks in on demand, similar to how the Factor 5 games
do it. 
'''

import logging

from bffi import Bffi,BffiBuilder,BffiSectionType,BffiTlbEntry
from n64rom import N64Rom
from signature import SignatureBuilder, WILDCARD
from tlb import tlb_try_detect_preamble, tlb_pack_entrylo

logger = logging.getLogger(__name__)


# ----------------------------------------------------------------------
#
# Armorines - Project S.W.A.R.M., built off the Turok 2 engine
# TLB game with a custom BSS clear loop
#
# Fairly strange ROM to RAM copy routine going across multiple ranges, reading the ROM directly.
# Debugging it in MAME though seemed to do nothing.
# Meanwhile, the BSS segment is cleared in physical memory space.
#
# Later in the boot, 0x0C6000-0x103800 is loaded somewhere in high memory
# (0x80780000 with expansion pak) and then TLB entry 0 will point 0x00400000-0x0047FFFF to it.
#
# ----------------------------------------------------------------------

ARMORINES_SYSTEMBOOT_CHECK_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x11, 0x80, WILDCARD,          # lui        s1,0x800c
        0x26, 0x31, WILDCARD, WILDCARD,      # addiu      s1,s1,-0x7480
        0x02, 0x20, 0x20, 0x21,              # move       a0,s1
        0x27, 0xb0, 0x00, 0x10,              # addiu      s0,sp,0x10
        0x0c, WILDCARD, WILDCARD, WILDCARD,  # jal        memcmp
        0x02, 0x00, 0x28, 0x21,              # _move      a1,s0
    ]) \
    .const_op32_hi16("sysboot_magic_address", 0x00) \
    .const_op32_lo16("sysboot_magic_address", 0x04) \
    .build()

ARMORINES_BSS_PRELUDE_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x05, 0x80, WILDCARD,      # +0x00 lui        a1,0x800c
        0x24, 0xa5, WILDCARD, WILDCARD,  # +0x04  addiu     a1,a1,0x4000
        0x3c, 0x03, 0x80, WILDCARD,      # +0x08  lui       v1,0x8014
        0x24, 0x63, WILDCARD, WILDCARD,  # +0x0C  addiu     v1,v1,0x0
        0x00, 0xa3, 0x10, 0x2b,          # sltu       v0,a1,v1
        0x10, 0x40, 0x00, 0x43,          # beq        v0,zero,LAB_0029314c
    ]) \
    .const_op32_hi16("bss_start", 0x00) \
    .const_op32_lo16("bss_start", 0x04) \
    .const_op32_hi16("bss_end", 0x08) \
    .const_op32_lo16("bss_end", 0x0C) \
    .build()

ARMORINES_MAIN_SEGMENT_SETUP_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x12, WILDCARD, WILDCARD, # lui        s2,0xc
        0x26, 0x52, WILDCARD, WILDCARD, # addiu      s2,s2,0x6000
        0xae, 0x22, WILDCARD, WILDCARD, # sw         v0=>DAT_8011aef8,0xcc4(s1)=>DAT_8011afe8
        0x3c, 0x02, 0xb0, 0x00,         # lui        v0,0xb000
        0x02, 0x42, 0x10, 0x25,         # or         v0,s2,v0
    ]) \
    .const_op32_hi16("main_segment_rom_address", 0x00) \
    .const_op32_lo16("main_segment_rom_address", 0x04) \
    .build()

# tiny bit below the main segment setup pattern
ARMORINES_LOAD_AND_MAP_MAIN_SEGMENT_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x04, 0x80, WILDCARD,         # lui        a0,0x800d     <-- handle to something
        0x24, 0x84, WILDCARD, WILDCARD,     # addiu      a0,a0,0x1cd8
        0x3c, 0x06, 0x00, WILDCARD,         # +0x08 lui        a2,0x4
        0x24, 0xc6, WILDCARD, WILDCARD,     # +0x0C addiu      a2,a2,-0x3520 <-- segment load size
        0x0c, WILDCARD, WILDCARD, WILDCARD, # jal        FUN_00201dbc 
        0x02, 0x80, 0x38, 0x21,             # _move      a3,s4
        
        # TLB setup code must match this exactly
        # or else it's not using the Turok 2 mappings
        0x12, 0x80, 0x00, 0x0f,             # beq        s4,zero,LAB_0028da48
        0x00, 0x00, 0x20, 0x21,             # _clear     a0
        0x3c, 0x05, 0x00, 0x07,             # lui        a1,0x7        <-- pagemask (should be 0x07e000 i.e., 256kbytes pages)
        0x34, 0xa5, 0xe0, 0x00,             # ori        a1,a1,0xe000
        0x3c, 0x06, 0x00, 0x40,             # lui        a2,0x40       <-- entryhi virtual address (should be 0x00400000)
        0x3c, 0x07, 0x80, 0x00,             # lui        a3,0x8000     <-- a3 is entrylo0 (mapping 0x00400000-0x0043FFFF)
        0x02, 0x87, 0x38, 0x21,             # addu       a3,s4,a3
        0x3c, 0x02, 0x80, 0x04,             # lui        v0,0x8004     <-- v0 is entrylo1 (mapping 0x00400000-0x0043FFFF)
        0x02, 0x82, 0x10, 0x21,             # addu       v0,s4,v0
        0xaf, 0xa2, 0x00, 0x10,             # sw         v0,local_20(sp)
        0x24, 0x02, 0x00, 0x07,             # li         v0,0x7
        0x0c, WILDCARD, WILDCARD, WILDCARD, # jal        FUN_0028ee40
    ]) \
    .const_op32_hi16("main_segment_size", 0x08) \
    .const_op32_lo16("main_segment_size", 0x0C) \
    .build()

def armorines_unpack(rom: N64Rom, ipc: int) -> Bffi:
    tlb, preamble = tlb_try_detect_preamble(rom, ipc)
    if None in [ tlb, preamble ]:
        return None
    
    entry_point_phys = tlb.virtual_to_physical(preamble.crt_entry_point())
    if entry_point_phys is None:
        logger.error("entry point in unmapped TLB space!!")
        return None
    entry_point_phys += 0x80000000

    bootexe = rom.boot_exe()

    check_pattern_offset = ARMORINES_SYSTEMBOOT_CHECK_PATTERN.find(bootexe, entry_point_phys - ipc)
    if check_pattern_offset is None:
        return None
    consts = ARMORINES_SYSTEMBOOT_CHECK_PATTERN.consts(ipc, bootexe, check_pattern_offset)
    sysboot_magic_address = consts["sysboot_magic_address"].get_value()

    sysboot_magic_offset = sysboot_magic_address-ipc

    # this string should be "sexysteve" on boot
    sysboot_magic = bootexe[sysboot_magic_offset:sysboot_magic_offset+9]
    if sysboot_magic != b'sexysteve':
        logger.error("sexy steve not present")
        return None

    bss_prelude_offset = ARMORINES_BSS_PRELUDE_PATTERN.find(bootexe, check_pattern_offset)
    if bss_prelude_offset is None:
        return None

    logger.info("found Turok 2 / Armorines boot stub")
    consts = ARMORINES_BSS_PRELUDE_PATTERN.consts(ipc, bootexe, bss_prelude_offset)
    bss_start = consts["bss_start"].get_value()
    bss_end   = consts["bss_end"].get_value()

    logger.info("BSS: 0x%08x-0x%08x", bss_start, bss_end)
    bootexe = bootexe[:bss_start-ipc]

    main_segment_setup_offset = ARMORINES_MAIN_SEGMENT_SETUP_PATTERN.find(bootexe)
    if main_segment_setup_offset is None:
        logger.info("can't find main segment setup")
        return None
    
    consts = ARMORINES_MAIN_SEGMENT_SETUP_PATTERN.consts(ipc, bootexe, main_segment_setup_offset)
    main_segment_rom_address = consts["main_segment_rom_address"].get_value() & 0x03FFFFFF

    loadmap_mainseg_offset = ARMORINES_LOAD_AND_MAP_MAIN_SEGMENT_PATTERN.find( bootexe, main_segment_setup_offset)
    if loadmap_mainseg_offset is None:
        logger.error("can't find segment load and TLB map setup")
        return None
    consts = ARMORINES_LOAD_AND_MAP_MAIN_SEGMENT_PATTERN.consts(ipc, bootexe, loadmap_mainseg_offset)
    main_segment_size = consts["main_segment_size"].get_value() & 0x03FFFFFF

    logger.info("main segment in ROM at 0x%08x-0x%08x",
                main_segment_rom_address,
                main_segment_rom_address+main_segment_size)

    main_segment = rom.read_bytes(main_segment_rom_address, main_segment_size)

    # we will load this segment to 0x80380000
    tlb_0 = BffiTlbEntry()
    tlb_0.pagemask(0x07e000)
    tlb_0.entryhi(0x00400000)
    tlb_0.entrylo0( tlb_pack_entrylo(0x00380000, 0x1F) )
    tlb_0.entrylo1( tlb_pack_entrylo(0x003C0000, 0x1F) )
    tlb.entry(0, tlb_0)

    if tlb.virtual_to_physical(0x00400000) != 0x00380000 or \
       tlb.virtual_to_physical(0x00440000) != 0x003C0000:
        raise RuntimeError("TLB mapping is incorrect, report bug. "
                           f"{tlb.virtual_to_physical(0x00400000):08x} "
                           f"{tlb.virtual_to_physical(0x00440000):08x} ")

    logger.info("will map 0x80380000-0x803FFFFF to 0x00400000 for the main segment")

    builder = BffiBuilder()
    builder.initial_tlb(tlb)
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.fix(ipc, bootexe)
    builder.fix(0x00400000, main_segment)
    builder.bss(bss_start, bss_end-bss_start)

    # TODO: turok 2 needs more segments

    return builder.build()

# ----------------------------------------------------------------------
#
# South Park
# Similar to Turok 2
# 
# This game will try to re-read the first 1 MB of cartridge space in its boot routine.
# There's not much point in doing this other than to slow down the boot,
# or maybe to cause problems if someone tries to overwrite the bootexe
# with a horrible crack intro. This can be patched out very easily however.
#
# Once the game is running it will load the main overlay at 0xC4000 to high
# memory and then set up TLB entry 0 to point 0x00400000 at it.
#
# ----------------------------------------------------------------------

# different register usage / jump location than turok 2
SOUTHPARK_BSS_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x03, 0x80, WILDCARD,     # +0x00 lui        v1,0x800c
        0x24, 0x63, WILDCARD, WILDCARD, # +0x04 addiu      v1,v1,0x2000
        0x3c, 0x04, 0x80, WILDCARD,     # +0x08 lui        a0,0x8012
        0x24, 0x84, WILDCARD, WILDCARD, # +0x0C addiu      a0,a0,-0x2000
        0x00, 0x64, 0x10, 0x2b,         # sltu       v0,v1,a0
        0x10, 0x40, 0x00, 0x06,         # beq        v0,zero,LAB_0022bd74
    ]) \
    .const_op32_hi16("bss_start", 0x00) \
    .const_op32_lo16("bss_start", 0x04) \
    .const_op32_hi16("bss_end", 0x08) \
    .const_op32_lo16("bss_end", 0x0C) \
    .build()

# hardcodes 0xB0xx prefix in lui instead of ORing to a base address
SOUTHPARK_MAIN_SEGMENT_SETUP_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x05, 0xb0, WILDCARD,     # lui        a1,0xb00c
        0x24, 0xa5, WILDCARD, WILDCARD, # addiu      a1,a1,0x4000
        0xae, 0x22, WILDCARD, WILDCARD, # sw         v0,0xcc4(s1)
        0x3c, 0x02, 0xb0, 0x00,         # lui        v0,0xb000
    ]) \
    .const_op32_hi16("main_segment_rom_address", 0x00) \
    .const_op32_lo16("main_segment_rom_address", 0x04) \
    .build()

def southpark_unpack(rom: N64Rom, ipc: int) -> Bffi:
    tlb, preamble = tlb_try_detect_preamble(rom, ipc)
    if None in [ tlb, preamble ]:
        return None
    
    entry_point_phys = tlb.virtual_to_physical(preamble.crt_entry_point())
    if entry_point_phys is None:
        logger.error("entry point in unmapped TLB space!!")
        return None
    entry_point_phys += 0x80000000

    # sexy steve is not present (and presumably not welcome) in south park
    # so we'll search for the BSS range instead

    bootexe = rom.boot_exe()

    bss_offset = SOUTHPARK_BSS_PATTERN.find(bootexe)
    if bss_offset is None:
        return None
    
    consts = SOUTHPARK_BSS_PATTERN.consts(ipc, bootexe, bss_offset)
    bss_start = consts["bss_start"].get_value()
    bss_end   = consts["bss_end"].get_value()

    logger.info("found South Park BSS init, BSS is at: 0x%08x-0x%08x", bss_start, bss_end)

    bootexe = bootexe[:bss_start-ipc]

    main_segment_setup_offset = SOUTHPARK_MAIN_SEGMENT_SETUP_PATTERN.find(bootexe)
    if main_segment_setup_offset is None:
        logger.info("can't find main segment setup")
        return None
    
    consts = SOUTHPARK_MAIN_SEGMENT_SETUP_PATTERN.consts(ipc, bootexe, main_segment_setup_offset)
    main_segment_rom_address = consts["main_segment_rom_address"].get_value() & 0x03FFFFFF

    # everything past this point is a copypaste of the armorines code above.
    # TODO: unify this later, or find some way to clean it up

    loadmap_mainseg_offset = ARMORINES_LOAD_AND_MAP_MAIN_SEGMENT_PATTERN.find( bootexe, main_segment_setup_offset)
    if loadmap_mainseg_offset is None:
        logger.error("can't find segment load and TLB map setup")
        return None
    consts = ARMORINES_LOAD_AND_MAP_MAIN_SEGMENT_PATTERN.consts(ipc, bootexe, loadmap_mainseg_offset)
    main_segment_size = consts["main_segment_size"].get_value() & 0x03FFFFFF

    logger.info("main segment in ROM at 0x%08x-0x%08x",
                main_segment_rom_address,
                main_segment_rom_address+main_segment_size)

    main_segment = rom.read_bytes(main_segment_rom_address, main_segment_size)

    # we will load this segment to 0x80380000
    tlb_0 = BffiTlbEntry()
    tlb_0.pagemask(0x07e000)
    tlb_0.entryhi(0x00400000)
    tlb_0.entrylo0( tlb_pack_entrylo(0x00380000, 0x1F) )
    tlb_0.entrylo1( tlb_pack_entrylo(0x003C0000, 0x1F) )
    tlb.entry(0, tlb_0)

    if tlb.virtual_to_physical(0x00400000) != 0x00380000 or \
       tlb.virtual_to_physical(0x00440000) != 0x003C0000:
        raise RuntimeError("TLB mapping is incorrect, report bug. "
                           f"{tlb.virtual_to_physical(0x00400000):08x} "
                           f"{tlb.virtual_to_physical(0x00440000):08x} ")

    logger.info("will map 0x80380000-0x803FFFFF to 0x00400000 for the main segment")

    builder = BffiBuilder()
    builder.initial_tlb(tlb)
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.fix(ipc, bootexe)
    builder.fix(0x00400000, main_segment)
    builder.bss(bss_start, bss_end-bss_start)

    # TODO: just like turok 2, more segments are currently at large.
    # find the function that loads them, and dump 'em out

    return builder.build()

# ----------------------------------------------------------------------
#
# Turok 3 - Shadow of Oblivion
#
# This game makes it clear as to why these games are trying to read from the ROM
# at startup: because the main executable code could be larger than the 1 MB
# that IPL3 can load.
#
# Sexy Steve has also been fired and in his place the game uses the
# extremely boring magic string "BootNotDone".
#
# ----------------------------------------------------------------------

TUROK3_EXTENDED_ROM_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x06, 0xb0, WILDCARD,     # +0x00 lui        a2,0xb010
        0x34, 0xc6, WILDCARD, WILDCARD, # +0x04 ori        a2,a2,0x1000
        0x3c, 0x05, 0x80, WILDCARD,     # +0x08 lui        a1,0x8010
        0x34, 0xa5, WILDCARD, WILDCARD, # +0x0C ori        a1,a1,0x400
        0x3c, 0x07, 0xa4, 0x60,         # +0x10 lui        a3,0xa460
        0x34, 0xe7, 0x00, 0x10,         # +0x14 ori        a3=>DAT_a4600010,a3,0x10
        0x3c, 0x04, 0x00, WILDCARD,     # +0x18 lui        a0,0x1
        0x34, 0x84, WILDCARD, WILDCARD, # +0x1C ori        a0,a0,0xffff
    ]) \
    .const_op32_hi16("extload_rom_address", 0x00) \
    .const_op32_lo16("extload_rom_address", 0x04) \
    .const_op32_hi16("extload_ram_address", 0x08) \
    .const_op32_lo16("extload_ram_address", 0x0C) \
    .const_op32_hi16("extload_num_words",   0x18) \
    .const_op32_lo16("extload_num_words",   0x1C) \
    .build()

TUROK3_BSS_PRELUDE_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x02, 0x80, WILDCARD,     # +0x00 lui   v0,0x8011     <-- BSS start
        0x24, 0x42, WILDCARD, WILDCARD, # +0x04 addiu v0,v0,0x4b60
        0x3c, 0x03, 0x80, WILDCARD,     # +0x08 lui   v1,0x8000
        0x00, 0x43, 0x28, 0x25,         # +0x0C or    a1,v0,v1
        0x3c, 0x02, 0x80, WILDCARD,     # +0x10 lui   v0,0x8019     <-- BSS end
        0x24, 0x42, WILDCARD, WILDCARD, # +0x14 addiu v0,v0,0x0
        0x00, 0x43, 0x18, 0x25,         # +0x18 or    v1,v0,v1
        0x00, 0xa3, 0x10, 0x2b,         # +0x1C sltu  v0,a1,v1
    ]) \
    .const_op32_hi16("bss_start", 0x00) \
    .const_op32_lo16("bss_start", 0x04) \
    .const_op32_hi16("bss_end", 0x10) \
    .const_op32_lo16("bss_end", 0x14) \
    .build()

# main segment setup pattern identical to armorines
# so it won't be repeated here

# turok 3 uses 1 MB pages, and will load in oneshot to 0x80700000
# if the expansion pak is detected. otherwise, it will swap in 4k
# chunks and map them as appropriate, similar to the factor 5 and rare games
TUROK3_LOAD_AND_MAP_MAIN_SEGMENT_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x04, 0x80, WILDCARD,         # lui        a0,0x800d     <-- handle to something
        0x24, 0x84, WILDCARD, WILDCARD,     # addiu      a0,a0,0x1cd8
        0x3c, 0x06, 0x00, WILDCARD,         # +0x08 lui        a2,0x4
        0x24, 0xc6, WILDCARD, WILDCARD,     # +0x0C addiu      a2,a2,-0x3520 <-- segment load size
        0x0c, WILDCARD, WILDCARD, WILDCARD, # jal        FUN_00201dbc 
        0x02, 0x80, 0x38, 0x21,             # _move      a3,s4
        
        # TLB setup code must match this exactly
        0x12, 0x80, 0x00, 0x0e,             # beq        s4,zero,LAB_0028da48
        0x00, 0x00, 0x20, 0x21,             # _clear     a0
        0x3c, 0x05, 0x00, 0x1f,             # lui        a1,0x1f        <-- pagemask (should be 0x1fe000 i.e., 1mbytes pages)
        0x34, 0xa5, 0xe0, 0x00,             # ori        a1,a1,0xe000
        0x3c, 0x06, 0x00, 0x40,             # lui        a2,0x40       <-- entryhi virtual address (should be 0x00400000)
        0x3c, 0x07, 0x80, 0x00,             # lui        a3,0x8000     <-- a3 is entrylo0 (mapping 0x00400000-0x0043FFFF)
        0x02, 0x87, 0x38, 0x21,             # addu       a3,s4,a3
        0x24, 0x02, 0xff, 0xff,             # li         v0,-0x1 <-- EntryLo1 = -1 (do not map)
        0xaf, 0xa2, 0x00, 0x10,             # sw         v0,local_20(sp)
        0x24, 0x02, 0x00, 0x07,             # li         v0,0x7
        0x0c, WILDCARD, WILDCARD, WILDCARD, # jal        FUN_002dcd50                                               undefined FUN_002dcd50()
        0xaf, 0xa2, 0x00, 0x14,             # _sw        v0,local_1c(sp)
    ]) \
    .const_op32_hi16("main_segment_size", 0x08) \
    .const_op32_lo16("main_segment_size", 0x0C) \
    .build()

def turok3_unpack(rom: N64Rom, ipc: int) -> Bffi:
    tlb, preamble = tlb_try_detect_preamble(rom, ipc)
    if None in [ tlb, preamble ]:
        return None
    
    entry_point_phys = tlb.virtual_to_physical(preamble.crt_entry_point())
    if entry_point_phys is None:
        logger.error("entry point in unmapped TLB space!!")
        return None
    entry_point_phys += 0x80000000

    bootexe = rom.boot_exe()

    check_pattern_offset = ARMORINES_SYSTEMBOOT_CHECK_PATTERN.find(bootexe, entry_point_phys - ipc)
    if check_pattern_offset is None:
        return None
    consts = ARMORINES_SYSTEMBOOT_CHECK_PATTERN.consts(ipc, bootexe, check_pattern_offset)
    sysboot_magic_address = consts["sysboot_magic_address"].get_value()

    sysboot_magic_offset = sysboot_magic_address-ipc

    # rip sexysteve forever in are hearts
    sysboot_magic = bootexe[sysboot_magic_offset:sysboot_magic_offset+11]
    if sysboot_magic != b'BootNotDone':
        return None

    extload_offset = TUROK3_EXTENDED_ROM_LOAD_PATTERN.find(bootexe, check_pattern_offset)
    if extload_offset is None:
        return None

    bss_prelude_offset = TUROK3_BSS_PRELUDE_PATTERN.find(bootexe, extload_offset)
    if bss_prelude_offset is None:
        return None
    
    logger.info("found Turok 3 bootstub")

    consts = TUROK3_EXTENDED_ROM_LOAD_PATTERN.consts(0x00200400, bootexe, extload_offset)
    extload_rom_address = consts["extload_rom_address"].get_value() & 0x03FFFFFF
    extload_ram_address = consts["extload_ram_address"].get_value()
    extload_sizeof      = (consts["extload_num_words"].get_value() + 1) * 4

    if extload_ram_address != (ipc + 0x100000):
        logger.error("extload RAM address did not follow bootexe")
        return None

    logger.info("game bootexe extends past IPL limit: 0x%08x-0x%08x",
                extload_rom_address,
                extload_rom_address+extload_sizeof)

    bootexe = rom.boot_exe() + rom.read_bytes(extload_rom_address, extload_sizeof)

    consts = TUROK3_BSS_PRELUDE_PATTERN.consts(0x00200400, bootexe, bss_prelude_offset)
    bss_start = consts["bss_start"].get_value()
    bss_end   = consts["bss_end"].get_value()

    logger.info("BSS: 0x%08x-0x%08x", bss_start, bss_end)
    bootexe = bootexe[:bss_start-ipc]

    main_segment_setup_offset = ARMORINES_MAIN_SEGMENT_SETUP_PATTERN.find(bootexe)
    if main_segment_setup_offset is None:
        logger.info("can't find main segment setup")
        return None
    
    consts = ARMORINES_MAIN_SEGMENT_SETUP_PATTERN.consts(ipc, bootexe, main_segment_setup_offset)
    main_segment_rom_address = consts["main_segment_rom_address"].get_value() & 0x03FFFFFF

    loadmap_mainseg_offset = TUROK3_LOAD_AND_MAP_MAIN_SEGMENT_PATTERN.find(bootexe, main_segment_setup_offset)
    if loadmap_mainseg_offset is None:
        logger.error("can't find mainseg load/map")
        return None
    consts = TUROK3_LOAD_AND_MAP_MAIN_SEGMENT_PATTERN.consts(ipc, bootexe, loadmap_mainseg_offset)
    main_segment_size = consts["main_segment_size"].get_value() & 0x03FFFFFF

    logger.info("main segment in ROM at 0x%08x-0x%08x",
                main_segment_rom_address,
                main_segment_rom_address+main_segment_size)

    main_segment = rom.read_bytes(main_segment_rom_address, main_segment_size)

    # it's obvious this needs the expansion pak to play nice
    # so let's load it to expansion pak land
    tlb_0 = BffiTlbEntry()
    tlb_0.pagemask(0x1fe000)
    tlb_0.entryhi(0x00400000)
    tlb_0.entrylo0( tlb_pack_entrylo(0x00700000, 0x1F) )
    tlb_0.entrylo1( 1 )
    tlb.entry(0, tlb_0)

    if tlb.virtual_to_physical(0x00400000) != 0x00700000:
        raise RuntimeError("TLB mapping is incorrect, report bug. "
                           f"{tlb.virtual_to_physical(0x00400000):08x} ")

    logger.info("will map 0x80700000-0x807FFFFF to 0x00400000 for the main segment")

    builder = BffiBuilder()
    builder.required_memory_size(8)
    builder.initial_tlb(tlb)
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.fix(ipc, bootexe)
    builder.fix(0x00400000, main_segment)
    builder.bss(bss_start, bss_end-bss_start)

    return builder.build()

# ----------------------------------------------------------------------
#
# Re-Volt
# Another TLB game
#
# Preamble BSS range is wrong; actual range is cleared at the entry point.
#
# This game does not use the fast/slow swap nonsense that the Iguana
# games do, instead it prefers just using a single fast swap section
# that it maps to 0x00200000. If 8 MB present, it loads it in from ROM
# to 0x80600000 and sets up the TLB to point to it.
#
# Game resources are stored in an ultra-chunky RNC-81 archive which spans
# most of the ROM. It doesn't look like there's any code in there.
#
# ----------------------------------------------------------------------

REVOLT_ENTRY_POINT_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xd8,              # +0x00 addiu      sp,sp,-0x28
        0xaf, 0xb1, 0x00, 0x1c,              # +0x04 sw         s1,local_c(sp)
        0x00, 0x80, 0x88, 0x21,              # +0x08 move       s1,a0
        0x24, 0x04, 0x56, 0x22,              # +0x0C li         a0,0x5622
        0xaf, 0xbf, 0x00, 0x20,              # +0x10 sw         ra,local_8(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD,  # +0x14 jal        FUN_0013a338     boring sample rate init
        0xaf, 0xb0, 0x00, 0x18,              # +0x18 _sw        s0,local_10(sp)
        0x3c, 0x02, 0x00, WILDCARD,          # +0x1C lui        v0,0xd           <-- BSS size in bytes
        0x24, 0x42, WILDCARD, WILDCARD,      # +0x20 addiu      v0,v0,-0x7c4d
        0x00, 0x02, 0x20, 0x82,              # +0x24 srl        a0,v0,0x2
        0x3c, 0x02, 0x00, WILDCARD,          # +0x28 lui        v0,0x6           <-- BSS start (physical)
        0x24, 0x42, WILDCARD, WILDCARD,      # +0x2C addiu      v0,v0,-0x3e50
        0x3c, 0x03, 0x80, 0x00,              # +0x30 lui        v1,0x8000
        0x08, WILDCARD, WILDCARD, WILDCARD,  # +0x34 j          LAB_00106118
        0x00, 0x43, 0x18, 0x25,              # +0x38 _or        v1,v0,v1         <-- kseg-ify the pointer
    ]) \
    .const_op32_hi16("bss_size", 0x1C) \
    .const_op32_lo16("bss_size", 0x20) \
    .const_op32_hi16("bss_start", 0x28) \
    .const_op32_lo16("bss_start", 0x2C) \
    .build()

REVOLT_MAIN_SWAP_INIT_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x03, 0x00, 0x5f,         # +0x00 lui   v1,0x5f       if total memory less than 6 MB,
        0x34, 0x63, 0xff, 0xff,         # +0x04 ori   v1,v1,0xffff  assume no expansion pak
        0x24, 0x02, 0x02, 0x00,         # +0x08 li    v0,0x200
        0xa6, 0x02, WILDCARD, WILDCARD, # +0x0C sh    v0,0x141c(s0)
        0x3c, 0x02, 0xb0, WILDCARD,     # +0x10 lui   v0,0xb006      <-- ROM start address
        0x24, 0x45, WILDCARD, WILDCARD, # +0x14 addiu a1,v0,-0x2000
        0x3c, 0x02, 0xb0, WILDCARD,     # +0x18 lui   v0,0xb00c      <-- ROM end address
        0x24, 0x42, WILDCARD, WILDCARD, # +0x1C addiu v0,v0,0x7f80
        0x00, 0x45, 0x10, 0x23,         # +0x20 subu  v0,v0,a1
        0x24, 0x42, 0xff, 0xff,         # +0x24 addiu v0,v0,-0x1
        0x00, 0x02, 0x13, 0x02,         # +0x28 srl   v0,v0,0xc
        0xa6, 0x02, WILDCARD, WILDCARD, # +0x2C sh    v0,0x141e(s0)
        0x3c, 0x02, 0x80, 0x00,         # +0x30 lui   v0,0x8000
        0x8c, 0x44, 0x03, 0x18,         # +0x34 lw    a0,0x0318(v0)  read osMemSize for memory check
    ]) \
    .const_op32_hi16("mainswap_rom_start", 0x10) \
    .const_op32_lo16("mainswap_rom_start", 0x14) \
    .const_op32_hi16("mainswap_rom_end", 0x18) \
    .const_op32_lo16("mainswap_rom_end", 0x1C) \
    .build()

def revolt_unpack(rom: N64Rom, ipc: int) -> Bffi:
    tlb, preamble = tlb_try_detect_preamble(rom, ipc)
    if None in [ tlb, preamble ]:
        return None
    
    entry_point_phys = tlb.virtual_to_physical(preamble.crt_entry_point())
    if entry_point_phys is None:
        logger.error("entry point in unmapped TLB space!!")
        return None
    entry_point_phys += 0x80000000

    bootexe = rom.boot_exe()

    if REVOLT_ENTRY_POINT_PATTERN.compare(bootexe, entry_point_phys-ipc) is False:
        return None
    
    logger.info("found Re-Volt entry point")

    consts = REVOLT_ENTRY_POINT_PATTERN.consts(ipc, bootexe, entry_point_phys-ipc)

    bss_start = consts["bss_start"].get_value() + 0x80000000
    bss_size  = consts["bss_size"].get_value()

    logger.info("BSS: 0x%08x-0x%08x",
                bss_start,
                bss_start+bss_size)
    
    bootexe = bootexe[:bss_start-ipc]

    main_swap_init_offset = REVOLT_MAIN_SWAP_INIT_PATTERN.find(bootexe)
    if main_swap_init_offset is None:
        logger.error("can't find main swap init code")
        return None
    
    consts = REVOLT_MAIN_SWAP_INIT_PATTERN.consts(ipc, bootexe, main_swap_init_offset)

    mainswap_rom_start = consts["mainswap_rom_start"].get_value() & 0x03FFFFFF
    mainswap_rom_end   = consts["mainswap_rom_end"].get_value() & 0x03FFFFFF

    # game rounds actual load size down to nearest 4k chunk
    # (that's what that srl opcode above was doing)
    mainswap_logical_size = (mainswap_rom_end-mainswap_rom_start) & (~((1 << 0x0C) - 1))
    mainswap_rom_end = mainswap_rom_start + mainswap_logical_size

    logger.info("main swap segment is in ROM at 0x%08x-0x%08x (%d byte(s))",
                mainswap_rom_start,
                mainswap_rom_end,
                mainswap_logical_size)
    
    swap = rom.read_bytes(mainswap_rom_start, mainswap_logical_size)
    
    # TODO: verify that TLB is as expected
    entry00 = BffiTlbEntry()
    entry00.pagemask(0x1fe000)
    entry00.entryhi(0x00200000)
    entry00.entrylo0( tlb_pack_entrylo(0x00600000, 0x1F) )
    entry00.entrylo1(1)
    tlb.entry(0, entry00)

    builder = BffiBuilder()
    builder.required_memory_size(8)
    builder.initial_tlb(tlb)
    builder.bss(bss_start, bss_size)
    builder.fix(ipc, bootexe)
    builder.fix(0x00200000, swap)
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())

    return builder.build()
