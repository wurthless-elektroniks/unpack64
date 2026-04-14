'''
Common utility code for games that initialize the TLB prior to execution

Rare games like Goldeneye and Perfect Dark only setup the TLB after the preamble runs,
so this won't be of use there.

Games that use a generic TLB stub:
- Re-Volt: uses a bss init loop as well

Games that need additional helper logic:
- Allstar Baseball 2000: sets up TLB, but then uses RNC unpacker to decompress the boot executable
- NBA Jam 2000: TLB logic is integrated in the RNC unpacker stub rather than the preamble,
  but it's similar to the others. It unmaps pages 0x00~0x1E, then maps page 0x1F. Then it
  unpacks the RNC payload.

- South Park: normal TLB stuff followed by a CRT startup function that is very weird,
  it copies the boot executable to RAM again and initializes its own BSS section before
  it runs osInitialize() and starts the idle thread
- Turok 2: sets up TLB and jumps to the entry point without initializing BSS

'''


import logging
import struct

from n64rom import N64Rom
from bffi import BffiTlb, BffiTlbEntry
from signature import SignatureBuilder, WILDCARD

logger = logging.getLogger(__name__)

# utility stuff, probably will be moved out later.

PAGE_SIZE_LUT = {
    (0x0000 << 13): 4 * 1024,
    (0x0003 << 13): 16 * 1024,
    (0x000F << 13): 64 * 1024,
    (0x003F << 13): 256 * 1024,
    (0x00FF << 13): 1024 * 1024,
    (0x03FF << 13): 4 * 1024 * 1024,
    (0x0FFF << 13): 16 * 1024 * 1024
}

def _entryhi_base_address(entryhi: int, pagemask: int) -> int:
    pass

def _entrylo_valid(entrylo: int) -> bool:
    return (entrylo & 2) != 0

def _entrylo_writable(entrylo: int) -> bool:
    return (entrylo & (1<<10)) != 0

def _entrylo_global(entrylo: int) -> bool:
    return (entrylo & 1) != 0

def _entrylo_page_base(entrylo: int, pagemask: int):
    pass


# generic pattern, sans BSS init stuff, common to turok 2 and revolt.
# clears TLB entries 0x00-0x1E and then initializes entry 0x1F
# before calling the remapped entry point
#
# function takes the following arguments
# - a0       = Index, which should be 0x1F
# - a1       = PageMask
# - a2       = EntryHi
# - a3       = EntryLo0 base physical page (if -1, default to 0)
# - 0x10(sp) = EntryLo1 base physical page (if -1, default to 0)
# - 0x14(sp) = EntryLoX flags
#              bit 0 = global, bit 1 = valid, bit 2 = dirty/read only;
#              typically this value is 7 which sets all three bits.
#              the function ORs this with 0x18 which also sets the
#              cache control bits
#
# a0,a1,a2 are written to cop0 (mtc0) immediately without modifications.
# then:
# - default EntryLo0 to 0x00000001, which sets the global flag.
# - if a3 is not -1, then set EntryLo0 to (a3 << 6) | entrylo_flags
# - default EntryLo1 to 0x00000001
# - if 0x10(sp) not -1, then set EntryLo1 to (0x10(sp) << 6) | entrylo_flags
#
# Re-Volt:
# - pagemask 0x1FE000 (1mbytes pages),
# - EntryLo flags = 7
# - EntryHi  = 0
# - EntryLo0 = -1 --> 0x00000001 (treat as global but map nothing there)
# - EntryLo1 = 0  --> 0x0000001F
# resulting mapping:
#  0x00000000~0x000FFFFF -> wired, but illegal (writing here means bad things happen)
#  0x00100000~0x001FFFFF -> 0x80000000~0x800FFFFF
#
# Turok 2:
# - same pagemask/flags
# - EntryHi  = 0x00200000
# - EntryLo0 = 0x00000000 --> 0x0000001F
# - EntryLo1 = 0x00100000 --> 0x0400001F
# resulting mapping:
# - 0x00200000~0x002FFFFF -> 0x80000000~0x800FFFFF
# - 0x00300000~0x003FFFFF -> 0x80100000~0x801FFFFF
#
# NBA Jam 2000 uses the same function for setting up page 0x1F:
# - pagemask 0x1FE000 (1mbytes pages),
# - EntryLo flags = 7
# - EntryHi  = 0
# - EntryLo0 = -1 --> 0x00000001 (treat as global but map nothing there)
# - EntryLo1 = 0  --> 0x0000001F
# resulting mapping:
#  0x00000000~0x000FFFFF -> wired, but illegal (writing here means bad things happen)
#  0x00100000~0x001FFFFF -> 0x80000000~0x800FFFFF
#

NUSTD_TLB_INIT_PATTERN = SignatureBuilder() \
    .pattern([
        0x24, 0x04, 0x00, 0x1e, # +0x00 li a0,0x1e

        # main TLB init loop (zero entries 0x00-0x1E)
        0x40, 0x08, 0x50, 0x00, # +0x04 mfc0  t0,EntryHi
        0x40, 0x84, 0x00, 0x00, # +0x08 mtc0  a0,Index,0x0
        0x3c, 0x09, 0x80, 0x00, # +0x0C lui   t1,0x8000
        0x40, 0x89, 0x50, 0x00, # +0x10 mtc0  t1,EntryHi,0x0
        0x40, 0x80, 0x10, 0x00, # +0x14 mtc0  zero,EntryLo0,0x0
        0x40, 0x80, 0x18, 0x00, # +0x18 mtc0  zero,EntryLo1,0x0
        0x00, 0x00, 0x00, 0x00, # +0x1C nop
        0x42, 0x00, 0x00, 0x02, # +0x20 tlbwi
        0x00, 0x00, 0x00, 0x00, # +0x24 nop
        0x00, 0x00, 0x00, 0x00, # +0x28 nop
        0x00, 0x00, 0x00, 0x00, # +0x2C nop
        0x00, 0x00, 0x00, 0x00, # +0x30 nop
        0x40, 0x88, 0x50, 0x00, # +0x34 mtc0  t0,EntryHi,0x0
        0x00, 0x00, 0x00, 0x00, # +0x38 nop
        0x14, 0x80, 0xff, 0xf1, # +0x3C bne   a0,zero,LAB_8000040c
        0x20, 0x84, 0xff, 0xff, # +0x40 _addi a0,a0,-0x1

        # pattern here differs based on page 0x1F configuration
        0x24, 0x04, 0x00, 0x1f,             # +0x44 li    a0,0x1f    <-- setup page 0x1F
        0x3c, 0x05, WILDCARD, WILDCARD,     # +0x48 lui   a1,0x1f    <-- pagemask (0x1FE000 = 1mbyte page)
        0x34, 0xa5, WILDCARD, WILDCARD,     # +0x4C ori   a1,a1,0xe000
        WILDCARD, 0x06, WILDCARD, WILDCARD, # +0x50 li/lui a2,0x20          <-- entryhi
        0x24, 0x07, WILDCARD, WILDCARD,     # +0x54 li     a3,0x0           <-- entrylo0 (typically unmapped)
        WILDCARD, 0x09, WILDCARD, WILDCARD, # +0x58 li/lui t1,0x10         <-- entrylo1
        0xaf, 0xa9, WILDCARD, WILDCARD,     # +0x5C sw    t1,0x10(sp)
        0x24, 0x08, 0x00, 0x07,             # +0x60 li    t0,0x7
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x64 jal   FUN_80000488
        0xaf, 0xa8, 0x00, 0x14,             # +0x68 _sw   t0,0x14(sp)
        0x3c, 0x04, WILDCARD, WILDCARD,     # +0x6C lui   a0,0x29          <-- entry point in TLB-mapped page
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x70 addiu a0,a0,-0x2c80
        0x00, 0x80, 0xf8, 0x09,             # jalr  a0
        0x00, 0x00, 0x00, 0x00,             # _nop
        0x00, 0x01, 0x00, 0x8d,             # break 0x402            <-- failsafe in case routine "returns"
    ]) \
    .const_op32_hi16("pagemask", 0x48) \
    .const_op32_lo16("pagemask", 0x4C) \
    .const_op32_imm16("entryhi", 0x50) \
    .const_op32_imm16("entrylo0", 0x54) \
    .const_op32_imm16("entrylo1", 0x58) \
    .const_op32_hi16("entry_point", 0x6C) \
    .const_op32_lo16("entry_point", 0x70) \
    .build()


def tlb_try_detect_singleton(rom: N64Rom, ipc: int):
    tlb_init_loc = NUSTD_TLB_INIT_PATTERN.find(rom.boot_exe()[:0x200], 0)
    if tlb_init_loc is None:
        return None

    # also detect nustd-style stackpointer init and BSS

    consts = NUSTD_TLB_INIT_PATTERN.consts(ipc, rom.boot_exe(), tlb_init_loc)
    logging.info("game maps TLB page 0x1F on startup")

    pagemask    = consts["pagemask"].get_value()
    entryhi     = consts["entryhi"].get_value()
    entrylo0    = consts["entrylo0"].get_value()
    entrylo1    = consts["entrylo1"].get_value()
    entry_point = consts["entry_point"].get_value()

    if pagemask not in PAGE_SIZE_LUT:
        logger.error("page size invalid")
        return None


    tlb = BffiTlb()
    for i in range(0,0x1F):
        entry = BffiTlbEntry()
        entry.pagemask(0)
        entry.entryhi(0x80000000)
        entry.entrylo0(0)
        entry.entrylo1(0)

        tlb.entry(i, entry)


    entry_1f = BffiTlbEntry()
    entry_1f.pagemask(pagemask)
    entry_1f.entryhi(entryhi)
    entry_1f.entrylo0( (entrylo0 << 6) | 0x1F if entrylo0 != -1 else 1 )
    entry_1f.entrylo1( (entrylo1 << 6) | 0x1F if entrylo1 != -1 else 1 )
    tlb.entry(0x1F, entry_1f)

    logger.info(\
"""TLB entry 0x1F initialized
- PageMask  %08x
- EntryHi   %08x
- EntryLo0  %08x
- EntryLo1  %08x
""", entry_1f.pagemask(), entry_1f.entryhi(), entry_1f.entrylo0(), entry_1f.entrylo1())

    # test virtual-to-physical now that the TLB is initialized
    logger.info("entry point is at 0x%08x, checking if we can translate it", entry_point)
    real_entry_point = tlb.virtual_to_physical(entry_point)
    if real_entry_point is None:
        logger.error("sanity check failed! entry point points to unmapped memory space")
        return None
    logger.info("virtual address %08x -> physical address %08x", entry_point, real_entry_point)