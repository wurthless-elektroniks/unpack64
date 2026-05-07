'''
Various Acclaim games that don't use the Iguana RNC unpacker
but do need special cases added.
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
