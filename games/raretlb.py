'''
Rareware games using the TLB

Games that go here:
- Conker's Bad Fur Day
- GoldenEye 007
- Perfect Dark

These games have been picked apart by the community and are therefore low priority.

Perfect Dark uses virtual memory on 4 MB systems. When the Expansion Pak
is present, it will load the swap segment to RAM in one shot.
'''

import logging
import struct
import zlib

from bffi import BffiBuilder, Bffi, BffiTlb, BffiTlbEntry
from n64rom import N64Rom
from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi
from signature import SignatureBuilder, WILDCARD
from sigutil import pick_pattern, contains_code
from tlbconst import TLB_PAGEMASK_1MBYTES, TLB_PAGEMASK_4MBYTES
from tlbutil import tlbutil_generate_bffi_tlb, tlbutil_pack_entrylo

logger = logging.getLogger(__name__)

# same between Conker and Perfect Dark
# Conker bootexe/OS segment goes at 0x10000000
# Perfect Dark bootexe/OS segment goes at 0x70000000
RARETLB_ENTRY_POINT_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x08, 0x00, 0x7f,         # +0x00 lui        t0,0x7f
        0x35, 0x08, 0xe0, 0x00,         # +0x04 ori        t0,t0,0xe000
        0x40, 0x88, 0x28, 0x00,         # +0x08 mtc0       t0,PageMask,0x0
        0x3c, 0x08, WILDCARD, 0x00,     # +0x0C lui        t0,0x1000 (0x7000 for PD)
        0x40, 0x88, 0x50, 0x00,         # +0x10 mtc0       t0,EntryHi,0x0
        0x24, 0x08, 0x00, 0x1f,         # +0x14 li         t0,0x1f
        0x40, 0x88, 0x10, 0x00,         # +0x18 mtc0       t0,EntryLo0,0x0
        0x3c, 0x08, 0x00, 0x01,         # +0x1C lui        t0,0x1
        0x35, 0x08, 0x00, 0x1f,         # +0x20 ori        t0,t0,0x1f
        0x40, 0x88, 0x18, 0x00,         # +0x24 mtc0       t0,EntryLo1,0x0
        0x24, 0x08, 0x00, 0x00,         # +0x28 li         t0,0x0
        0x40, 0x88, 0x00, 0x00,         # +0x2C mtc0       t0,Index,0x0
        0x00, 0x00, 0x00, 0x00,         # +0x30 nop
        0x42, 0x00, 0x00, 0x02,         # +0x34 tlbwi
        0x00, 0x00, 0x00, 0x00,         # +0x38 nop
        0x00, 0x00, 0x00, 0x00,         # +0x3C nop
        0x00, 0x00, 0x00, 0x00,         # +0x40 nop
        0x3c, 0x08, WILDCARD, WILDCARD, # +0x44 lui        t0,0x1000
        0x25, 0x08, WILDCARD, WILDCARD, # +0x48 addiu      t0,t0,0x1050
        0x01, 0x00, 0x00, 0x08,         # +0x4C jr         t0
        0x00, 0x00, 0x00, 0x00,         # +0x50 _nop
    ]) \
    .const_op32_imm16("tlb_os_base_address", 0x0C) \
    .const_op32_hi16("entry_point", 0x44) \
    .const_op32_lo16("entry_point", 0x48) \
    .build()

# Goldeneye's TLB init entry point was written when there was no expansion pak,
# so it doesn't bother mapping the upper 4 MB of RDRAM.
GOLDENEYE_ENTRY_POINT_PATTERN = SignatureBuilder() \
    .pattern([
        0x24, 0x02, 0x00, 0x01,         # +0x00 li         v0,0x1
        0x24, 0x03, 0x00, 0x00,         # +0x04 li         v1,0x0
        0x24, 0x04, 0x00, 0x00,         # +0x08 li         a0,0x0
        0x3c, 0x05, 0x70, 0x00,         # +0x0C lui        a1,0x7000
        0x24, 0x06, 0x00, 0x1f,         # +0x10 li         a2,0x1f
        0x24, 0x07, 0x00, 0x01,         # +0x14 li         a3,0x1
        0x3c, 0x08, 0x00, 0x7f,         # +0x18 lui        t0,0x7f
        0x35, 0x08, 0xe0, 0x00,         # +0x1C ori        t0,t0,0xe000
        0x40, 0x82, 0x00, 0x00,         # +0x20 mtc0       v0,Index,0x0
        0x00, 0x03, 0x1b, 0x02,         # +0x24 srl        v1,v1,0xc
        0x00, 0x03, 0x19, 0x80,         # +0x28 sll        v1,v1,0x6
        0x00, 0x66, 0x18, 0x21,         # +0x2C addu       v1,v1,a2
        0x40, 0x83, 0x10, 0x00,         # +0x30 mtc0       v1,EntryLo0,0x0
        0x00, 0x04, 0x23, 0x02,         # +0x34 srl        a0,a0,0xc
        0x00, 0x04, 0x21, 0x80,         # +0x38 sll        a0,a0,0x6
        0x00, 0x87, 0x20, 0x21,         # +0x3C addu       a0,a0,a3
        0x40, 0x84, 0x18, 0x00,         # +0x40 mtc0       a0,EntryLo1,0x0
        0x00, 0x05, 0x23, 0x42,         # +0x44 srl        a0,a1,0xd
        0x00, 0x04, 0x23, 0x40,         # +0x48 sll        a0,a0,0xd
        0x40, 0x84, 0x50, 0x00,         # +0x4C mtc0       a0,EntryHi,0x0
        0x40, 0x88, 0x28, 0x00,         # +0x50 mtc0       t0,PageMask,0x0
        0x00, 0x00, 0x00, 0x00,         # +0x54 nop
        0x42, 0x00, 0x00, 0x02,         # +0x58 tlbwi
        0x3c, 0x0a, 0x70, WILDCARD,     # +0x5C lui        t2,0x7000
        0x25, 0x4a, WILDCARD, WILDCARD, # +0x60 addiu      t2,t2,0x510
        0x01, 0x40, 0x00, 0x08,         # +0x64 jr         t2=>LAB_70000510
        0x00, 0x00, 0x00, 0x00,         # +0x6C _nop
    ]) \
    .const_op32_imm16("tlb_os_base_address", 0x0C) \
    .const_op32_hi16("entry_point", 0x5C) \
    .const_op32_lo16("entry_point", 0x60) \
    .build()

def _raretlb_extract_entrypoint_and_page0(ipc: int, bootexe: bytes, entrypoint_address: int) -> tuple[int,int,BffiTlbEntry]:
    entrypoint_offset = entrypoint_address - ipc
    if RARETLB_ENTRY_POINT_PATTERN.compare(bootexe, entrypoint_offset) is False:
        return None, None, None

    consts = RARETLB_ENTRY_POINT_PATTERN.consts(ipc, bootexe, entrypoint_offset)
    tlb_os_base_address = consts["tlb_os_base_address"].get_value()
    entry_point = consts["entry_point"].get_value()
    
    # this TLB setup maps the entire RDRAM space to 0x10xxxxxx
    page0 = BffiTlbEntry()
    page0.pagemask(TLB_PAGEMASK_4MBYTES)            # 4 mbytes page size
    page0.entryhi(tlb_os_base_address)
    page0.entrylo0( tlbutil_pack_entrylo(0x00000000, 0x1F) )
    page0.entrylo1( tlbutil_pack_entrylo(0x00400000, 0x1F) )

    return tlb_os_base_address, entry_point, page0

def _goldeneye_extract_entrypoint_and_page0(ipc: int, bootexe: bytes, entrypoint_address: int) -> tuple[int,int,BffiTlbEntry]:
    entrypoint_offset = entrypoint_address - ipc
    if GOLDENEYE_ENTRY_POINT_PATTERN.compare(bootexe, entrypoint_offset) is False:
        return None, None, None

    consts = GOLDENEYE_ENTRY_POINT_PATTERN.consts(ipc, bootexe, entrypoint_offset)
    tlb_os_base_address = consts["tlb_os_base_address"].get_value()
    entry_point = consts["entry_point"].get_value()
    
    page0 = BffiTlbEntry()
    page0.pagemask(TLB_PAGEMASK_4MBYTES)            # 4 mbytes page size
    page0.entryhi(tlb_os_base_address)  # at 0x70000000
    page0.entrylo0( tlbutil_pack_entrylo(0x00000000, 0x1F) )
    page0.entrylo1( 1 )

    return tlb_os_base_address, entry_point, page0

# ---------------------------------------------------------------
#
# Conker's Bad Fur Day
# 
# A very rude game with a very rude surprise: it's a TLB game.
# Even ruder is that the game is encrypted.
#
# Upon boot the game immediately maps all of RDRAM to 0x10000000, then
# jumps to the real entrypoint in TLB-mapped space.
#
# 0x42450 is the swap segment, starting with a four-byte filesize and an
# encrypted table of contents. The game will immediately seek past this
# to a zlibbed blob at 0x188328, which contains the main code segment (I think).
#
# The swap segment's table of contents has a simple XOR encryption applied to it.
# Each offset is XORed with 0x8039CCCA (applies to both US and European versions).
# Once decoded you'll have all the offsets you'll need to dump the pages out of the
# blob, each of course being zlibbed.
#
# 0x15000000-0x151fc000 is swap space. The game swaps in zlib-compressed 4k pages from
# the resource blob at 0x42450 here.
# 
# 0x16000000: Debug handler. The game will load 0x19ea88 from ROM and map a 256k page
#             to call it. (actual debug handler size 0x4960 bytes)
#
# Rare did not implement Expansion Pak detection for this game, so there's no option
# to one-shot load the swap section to high memory. This slows the game down.
#
# ---------------------------------------------------------------

# same between US/EU versions
CONKER_XORKEY = 0x8039CCCA

CONKER_SWAP_AND_DATA_INIT_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x10, 0x00, WILDCARD,         # +0x00 lui        s0,0x4         <-- swap blob offset
        0x26, 0x10, WILDCARD, WILDCARD,     # +0x04 addiu      s0,s0,0x2450
        0x3c, 0x05, 0x80, WILDCARD,         # +0x08 lui        a1,0x8008
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x0C addiu      a1,a1,0x2b20
        0x02, 0x00, 0x20, 0x25,             # +0x10 or         a0,s0,zero
        0x24, 0x06, 0x00, 0x10,             # +0x14 li         a2,0x10
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x18 jal        readcart
        0x24, 0x07, 0x00, 0x01,             # +0x1C _li        a3,0x1
        0x3c, 0x0c, 0x80, WILDCARD,         # +0x20 lui        t4,0x8008
        0x8d, 0x8c, WILDCARD, WILDCARD,     # +0x24 lw         t4,offset DAT_80082b20(t4) <-- reading first 4 bytes from it
        0x3c, 0x0d, 0x00, WILDCARD,         # +0x28 lui        t5,0x1a <-- expected compressed size of data segment that follows
        0x25, 0xad, WILDCARD, WILDCARD,     # +0x2C addiu      t5,t5,-0x1578
        0x01, 0x90, 0x10, 0x21,             # +0x30 addu       v0,t4,s0
        0x01, 0xa2, 0x18, 0x23,             # +0x34 subu       v1,t5,v0
        0x00, 0x60, 0x20, 0x25,             # +0x38 or         a0,v1,zero
        0xaf, 0xa3, 0x00, 0x28,             # +0x3C sw         v1,local_28(sp)
        0xaf, 0xa2, 0x00, 0x44,             # +0x40 sw         v0,local_c(sp)
        0x24, 0x05, 0x00, 0x01,             # +0x44 li         a1,0x1
        0x24, 0x06, 0x00, 0x02,             # +0x48 li         a2,0x2
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x4C jal        FUN_10003c40
        0x00, 0x00, 0x38, 0x25,             # +0x50 _or        a3,zero,zero
        0xaf, 0xa2, 0x00, 0x40,             # +0x54 sw         v0,local_10(sp)
        0x8f, 0xa4, 0x00, 0x44,             # +0x58 lw         a0,local_c(sp)
        0x00, 0x40, 0x28, 0x25,             # +0x5C or         a1,v0,zero
        0x8f, 0xa6, 0x00, 0x28,             # +0x60 lw         a2,local_28(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x64 jal        readcart
        0x24, 0x07, 0x00, 0x01,             # +0x68 _li        a3,0x1
        0x3c, 0x05, 0x80, WILDCARD,         # +0x6C lui        a1,0x8008  <-- data segment load address
        0x3c, 0x06, 0x80, WILDCARD,         # +0x70 lui        a2,0x8004
        0x8c, 0xc6, WILDCARD, WILDCARD,     # +0x74 lw         a2,-0x7f64(a2)
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x78 addiu      a1=>DAT_80082b20,a1,0x2b20
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x7C jal        inflate
        0x8f, 0xa4, 0x00, 0x40,             # +0x80 _lw        a0,local_10(sp)
    ]) \
    .const_op32_hi16("swap_rom_address", 0x00) \
    .const_op32_lo16("swap_rom_address", 0x04) \
    .const_op32_hi16("dataseg_compressed_size", 0x28) \
    .const_op32_lo16("dataseg_compressed_size", 0x2C) \
    .const_op32_hi16("dataseg_load_address", 0x6C) \
    .const_op32_lo16("dataseg_load_address", 0x78) \
    .build()

# euro version uses different registers. god i love compiler differences
CONKER_EU_SWAP_AND_DATA_INIT_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x10, 0x00, WILDCARD,         # +0x00 lui        s0,0x4
        0x26, 0x10, WILDCARD, WILDCARD,     # +0x04 addiu      s0,s0,0x27b0
        0x3c, 0x05, 0x80, WILDCARD,         # +0x08 lui        a1,0x8008
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x0C addiu      a1=>DAT_80082eb0,a1,0x2eb0
        0x02, 0x00, 0x20, 0x25,             # +0x10 or         a0,s0,zero
        0x24, 0x06, 0x00, 0x10,             # +0x14 li         a2,0x10
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x18 jal        FUN_10004764
        0x24, 0x07, 0x00, 0x01,             # +0x1C _li        a3,0x1
        0x3c, 0x0e, 0x80, WILDCARD,         # +0x20 lui        t6,0x8008
        0x8d, 0xce, WILDCARD, WILDCARD,     # +0x24 lw         t6,offset DAT_80082eb0(t6)
        0x3c, 0x0f, 0x00, WILDCARD,         # +0x28 lui        t7,0x1a
        0x25, 0xef, WILDCARD, WILDCARD,     # +0x2C addiu      t7,t7,-0x1218
        0x01, 0xd0, 0x10, 0x21,             # +0x30 addu       v0,t6,s0
        0x01, 0xe2, 0x18, 0x23,             # +0x34 subu       v1,t7,v0
        0x00, 0x60, 0x20, 0x25,             # +0x38 or         a0,v1,zero
        0xaf, 0xa3, 0x00, 0x28,             # +0x3C sw         v1,local_30(sp)
        0xaf, 0xa2, 0x00, 0x44,             # +0x40 sw         v0,local_14(sp)
        0x24, 0x05, 0x00, 0x01,             # +0x44 li         a1,0x1
        0x24, 0x06, 0x00, 0x02,             # +0x48 li         a2,0x2
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x4C jal        FUN_10003e90
        0x00, 0x00, 0x38, 0x25,             # +0x50 _or        a3,zero,zero
        0xaf, 0xa2, 0x00, 0x40,             # +0x54 sw         v0,local_18(sp)
        0x8f, 0xa4, 0x00, 0x44,             # +0x58 lw         a0,local_14(sp)
        0x00, 0x40, 0x28, 0x25,             # +0x5C or         a1,v0,zero
        0x8f, 0xa6, 0x00, 0x28,             # +0x60 lw         a2,local_30(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x64 jal        FUN_10004764
        0x24, 0x07, 0x00, 0x01,             # +0x68 _li        a3,0x1
        0x3c, 0x05, 0x80, WILDCARD,         # +0x6C lui        a1,0x8008
        0x3c, 0x06, 0x80, WILDCARD,         # +0x70 lui        a2,0x8004
        0x8c, 0xc6, WILDCARD, WILDCARD,     # +0x74 lw         a2,-0x7c04(a2)
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x78 addiu      a1=>DAT_80082eb0,a1,0x2eb0
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x7C jal        FUN_10006530
        0x8f, 0xa4, 0x00, 0x40,             # +0x80 _lw        a0,local_18(sp)
    ]) \
    .const_op32_hi16("swap_rom_address", 0x00) \
    .const_op32_lo16("swap_rom_address", 0x04) \
    .const_op32_hi16("dataseg_compressed_size", 0x28) \
    .const_op32_lo16("dataseg_compressed_size", 0x2C) \
    .const_op32_hi16("dataseg_load_address", 0x6C) \
    .const_op32_lo16("dataseg_load_address", 0x78) \
    .build()

# have to look for this to confirm that the swap space is where it should be
CONKER_TLB_EXCEPTION_HANDLER_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x08, 0x80, WILDCARD,     # lui        t0,0x8003 <-- always 1 because the game always swaps
        0x91, 0x08, WILDCARD, WILDCARD, # lbu        t0,-0x5520(t0)
        0x15, 0x00, 0x01, 0x6e,         # bne        t0,zero,LAB_100061f0
        0x00, 0x00, 0x00, 0x00,         # _nop
        0x40, 0x08, 0x20, 0x00,         # mfc0       t0,Context
        0x3c, 0x09, 0x80, WILDCARD,     # lui        t1,0x8004
        0x25, 0x29, WILDCARD, WILDCARD, # addiu      t1,t1,0x3b40
        0x3c, 0x01, 0x00, WILDCARD,     # lui        at,0xa
        0x34, 0x21, WILDCARD, WILDCARD, # ori        at,at,0x8000
        0x01, 0x21, 0x48, 0x23,         # subu       t1,t1,at
        0x01, 0x09, 0x80, 0x21,         # addu       s0,t0,t1
        0x3c, 0x1e, 0x15, 0x00,         # lui        s8,0x1500 <-- the important part: mapped at 0x15000000
        0x00, 0x08, 0xaa, 0x40,         # sll        s5,t0,0x9
        0x02, 0xbe, 0x08, 0x2a,         # slt        at,s5,s8
    ]) \
    .build()

def _dump_swap(swap: bytes):
    toc_size = struct.unpack(">I", swap[:4])[0] ^ CONKER_XORKEY
    if toc_size != 0x800:
        raise RuntimeError("swap table of contents size mismatch!!")

    swap_out = bytearray()

    offset = 0
    while offset < toc_size:
        start_offset, end_offset = struct.unpack(">II", swap[offset:offset+8])
        if 0 in [start_offset, end_offset]:
            break
        
        start_offset ^= CONKER_XORKEY
        end_offset ^= CONKER_XORKEY

        start_offset -= 4
        end_offset -= 4
        

        page = swap[start_offset:end_offset]
        page_size_decompressed = struct.unpack(">I", page[:4])[0]

        logger.debug("decompress page 0x%08x-0x%08x (expecting size: %d)", start_offset, end_offset, page_size_decompressed)
        page = zlib.decompress(page[4:], wbits=-15)

        if len(page) != page_size_decompressed:
            raise RuntimeError(f"swap page uncompressed size mismatch. expected {page_size_decompressed} got {len(page)}")
        
        swap_out += page

        offset += 4

    return swap_out

def conker_unpack(rom: N64Rom, ipc: int):
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    builder = BffiBuilder()
    earliest_bss_address, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    bootexe = rom.boot_exe()[:earliest_bss_address-ipc]

    tlb_os_base, entry_point, os_page = _raretlb_extract_entrypoint_and_page0(ipc, bootexe, preamble.crt_entry_point())
    if entry_point is None:
        return None
    
    # game looks like it's using the conker/pd tlb scheme at this point
    ipc_tlb = (ipc - 0x80000000) + tlb_os_base

    swap_and_data_init_pattern, swap_and_data_init_offset = \
        pick_pattern(bootexe, [CONKER_EU_SWAP_AND_DATA_INIT_PATTERN, CONKER_SWAP_AND_DATA_INIT_PATTERN])
    
    if swap_and_data_init_offset is None:
        return None
    
    if CONKER_TLB_EXCEPTION_HANDLER_PATTERN.find(bootexe) is None:
        logger.error("TLB exception handler not found")
        return None
    
    logger.info("found Conker swap/data init at 0x%08x", ipc_tlb + swap_and_data_init_offset)

    consts = swap_and_data_init_pattern.consts(ipc_tlb, bootexe, swap_and_data_init_offset)
    
    swap_rom_address         = consts["swap_rom_address"].get_value()
    dataseg_compressed_size  = consts["dataseg_compressed_size"].get_value()
    dataseg_load_address     = consts["dataseg_load_address"].get_value()

    swap_size = struct.unpack(">I", rom.read_bytes(swap_rom_address, 4))[0]

    dataseg_rom_address = swap_rom_address + swap_size

    logger.info("swap blob in ROM 0x%08x-0x%08x",
                swap_rom_address,
                swap_rom_address + swap_size)
    
    swap = rom.read_bytes(swap_rom_address + 4, swap_size - 4)

    swap_decompressed = _dump_swap(swap)

    logger.info("data segment in ROM 0x%08x-0x%08x",
                dataseg_rom_address,
                dataseg_rom_address + dataseg_compressed_size)
    
    dataseg_size_inflated = struct.unpack(">I", rom.read_bytes(dataseg_rom_address, 4))[0]

    dataseg = rom.read_bytes(dataseg_rom_address + 4, dataseg_compressed_size - 4)

    # TODO: inflate code checks for 11 72 and skips over it if present.
    # the zlibbed payload doesn't have it though, so we ignore that corner case

    dataseg = zlib.decompress(dataseg, wbits=-15)

    # TODO: define a standard swap format for BFFI. for now, we will just
    # map the swap segment to expansion pak space
    swap_page = BffiTlbEntry()
    swap_page.pagemask(TLB_PAGEMASK_1MBYTES)  # two 1 mbyte pages
    swap_page.entryhi(0x15000000)
    swap_page.entrylo0(tlbutil_pack_entrylo(0x00600000, 0x1F))
    swap_page.entrylo1(tlbutil_pack_entrylo(0x00700000, 0x1F))

    # TODO: dump debug crash handler

    tlb = tlbutil_generate_bffi_tlb({
        0: os_page,
        1: swap_page
        })
    builder.initial_tlb(tlb)

    builder.initial_program_counter(entry_point)
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.required_memory_size(8)
    builder.fix(ipc, bootexe)
    builder.fix(dataseg_load_address, dataseg)
    builder.fix(0x15000000, swap_decompressed)

    return builder.build()

# ---------------------------------------------------------------
#
# Goldeneye 007
#
# The game that was considered the gold standard for console FPSes
# only because Halo didn't exist yet.
#
# Part of the bootexe is zlibbed (11 72 headered). To decompress it, the game copies it and
# and the inflate routines to higher memory (without flushing the instruction cache!!)
# and inflates it to where it sat originally.  Since that's not exciting enough,
# the game will also override exception handlers installed by osInitialize() so that the
# virtual memory scheme can do its job.
#
# The virtual memory scheme is pretty boring stuff once you are used to reverse engineering
# the swap setups these games have. Everything in ROM past the end of the boot segment, including
# its deflated portions, is mapped in 8 kbyte pages, but only about 1 MB of that is actually
# the swap segment. The remainder of the ROM, including resources, is DMA'd in using readcart routines.
# 
# I cheated and used the decomp for this.
# Read it here: https://gitlab.com/kholdfuzion/goldeneye_src
#
# ---------------------------------------------------------------

GOLDENEYE_RETURN_STUB_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x02, WILDCARD, WILDCARD, # lui        v0,0x3
        0x03, 0xe0, 0x00, 0x08,         # jr         ra
        0x24, 0x42, WILDCARD, WILDCARD, # _addiu     v0,v0,0x3590
    ]) \
    .const_op32_hi16("result", 0) \
    .const_op32_lo16("result", 8) \
    .build()

GOLDENEYE_REAL_ENTRY_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xc0,             # +0x00 addiu      sp,sp,-0x40
        0xaf, 0xbf, 0x00, 0x24,             # +0x04 sw         ra,local_1c(sp)
        0xaf, 0xb1, 0x00, 0x20,             # +0x08 sw         s1,local_20(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x0C jal        get_csegmentSegmentStart
        0xaf, 0xb0, 0x00, 0x1c,             # +0x10 _sw        s0,local_24(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x14 jal        get_cdataSegmentRomStart
        0x00, 0x40, 0x80, 0x25,             # +0x18 _or        s0,v0,zero
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x1C jal        get_cdataSegmentRomEnd
        0xaf, 0xa2, 0x00, 0x34,             # +0x20 _sw        v0,local_c(sp)
        0x8f, 0xae, 0x00, 0x34,             # +0x24 lw         t6,local_c(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x28 jal        get_inflateSegmentRomStart
        0x00, 0x4e, 0x88, 0x23,             # +0x2C _subu      s1,v0,t6
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x30 jal        get_inflateSegmentRomEnd
        0xaf, 0xa2, 0x00, 0x28,             # +0x34 _sw        v0,local_18(sp)
    ]) \
    .xref_j_imm26("get_csegmentSegmentStart", 0x0C) \
    .xref_j_imm26("get_cdataSegmentRomStart", 0x14) \
    .xref_j_imm26("get_cdataSegmentRomEnd", 0x1C) \
    .xref_j_imm26("get_inflateSegmentRomStart", 0x28) \
    .xref_j_imm26("get_inflateSegmentRomEnd", 0x30) \
    .build()

# game swaps in 8kbytes pages
GOLDENEYE_ROM_SWAP_PATTERN = SignatureBuilder() \
    .pattern([
        0x24, 0x01, 0x00, WILDCARD,         # +0x00 li         at,0x5a <-- total # of pages
        0x00, 0x41, 0x00, 0x1b,             # +0x04 divu       v0,at
        0x00, 0x00, 0x20, 0x10,             # +0x08 mfhi       a0
        0x3c, 0x03, 0x80, WILDCARD,         # +0x0C lui        v1,0x8002
        0x24, 0x63, WILDCARD, WILDCARD,     # +0x10 addiu      v1,v1,0x30d4
        0xac, 0x64, WILDCARD, WILDCARD,     # +0x14 sw         a0,0x0(v1)=>DAT_800230d4
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x18 jal        FUN_70001954 <-- tries to free up a page
        0x00, 0x80, 0x80, 0x25,             # +0x1C _or        s0,a0,zero
        0x8f, 0xa2, 0x00, 0x28,             # +0x20 lw         v0,local_28(sp)
        0x3c, 0x19, 0x80, WILDCARD,         # +0x24 lui        t9,0x8006
        0x8f, 0x39, WILDCARD, WILDCARD,     # +0x28 lw         t9,-0x1b58(t9)
        0x3c, 0x01, 0x00, 0xff,             # +0x2C lui        at,0xff
        0x34, 0x21, 0xe0, 0x00,             # +0x30 ori        at,at,0xe000
        0x00, 0x10, 0x43, 0x40,             # +0x34 sll        t0,s0,0xd
        0x3c, 0x0a, 0x00, WILDCARD,         # +0x38 lui        t2,0x3 <-- swap location in ROM
        0x00, 0x41, 0x48, 0x24,             # +0x3C and        t1,v0,at
        0x25, 0x4a, WILDCARD, WILDCARD,     # +0x40 addiu      t2,t2,0x4b30
        0x03, 0x28, 0x20, 0x21,             # +0x44 addu       a0,t9,t0
        0xaf, 0xa4, 0x00, 0x34,             # +0x48 sw         a0,local_1c(sp)
        0x01, 0x2a, 0x28, 0x21,             # +0x4C addu       a1,t1,t2
        0x01, 0x20, 0x10, 0x25,             # +0x50 or         v0,t1,zero
        0xaf, 0xa9, 0x00, 0x24,             # +0x54 sw         t1,local_2c(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x58 jal        FUN_70005c1c
        0x24, 0x06, 0x20, 0x00,             # +0x5C _li        a2,0x2000
    ]) \
    .const_op32_imm16("num_pages", 0x00) \
    .const_op32_hi16("swap_rom_address", 0x38) \
    .const_op32_lo16("swap_rom_address", 0x40) \
    .build()

def _get_return_value(ipc_tlb, bootexe, address):
    offset = address - ipc_tlb
    if (0 <= offset < len(bootexe)) is False:
        raise RuntimeError("outta bounds!!")

    if GOLDENEYE_RETURN_STUB_PATTERN.compare(bootexe, offset) is False:
        raise RuntimeError(f"data at bootexe+0x{offset:08x} (virtual 0x{ipc_tlb+offset:08x}) didn't match expected signature")
    consts = GOLDENEYE_RETURN_STUB_PATTERN.consts(ipc_tlb, bootexe, offset)
    return consts["result"].get_value()

def goldeneye_unpack(rom: N64Rom, ipc: int):
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    builder = BffiBuilder()
    earliest_bss_address, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    bootexe = rom.boot_exe()[:earliest_bss_address-ipc]

    tlb_os_base, entry_point, os_page = _goldeneye_extract_entrypoint_and_page0(ipc, bootexe, preamble.crt_entry_point())
    if entry_point is None:
        return None
    
    ipc_tlb = (ipc - 0x80000000) + tlb_os_base

    entry_point_offset = entry_point - ipc_tlb
    
    if GOLDENEYE_REAL_ENTRY_PATTERN.compare(bootexe, entry_point_offset) is False:
        return None
    
    logger.info("found Goldeneye entry point")

    romswap_offset = GOLDENEYE_ROM_SWAP_PATTERN.find(bootexe)
    if romswap_offset is None:
        raise RuntimeError("romswap not found")

    xrefs = GOLDENEYE_REAL_ENTRY_PATTERN.xrefs(ipc_tlb, bootexe, entry_point_offset)

    csegment_start            = _get_return_value(ipc_tlb, bootexe, xrefs["get_csegmentSegmentStart"].get_address())
    cdatasegment_rom_start    = _get_return_value(ipc_tlb, bootexe, xrefs["get_cdataSegmentRomStart"].get_address())
    cdatasegment_rom_end      = _get_return_value(ipc_tlb, bootexe, xrefs["get_cdataSegmentRomEnd"].get_address())

    # the swap segment, which contains the game code, will have its own inflate routines.
    # the bootloader's inflate code is called only once at init, and then never again.
    cinflatesegment_rom_start = _get_return_value(ipc_tlb, bootexe, xrefs["get_inflateSegmentRomStart"].get_address())
    cinflatesegment_rom_end   = _get_return_value(ipc_tlb, bootexe, xrefs["get_inflateSegmentRomEnd"].get_address())

    logger.info("compressed data segment: ROM 0x%08x-0x%08x -> RAM 0x%08x",
                cdatasegment_rom_start,
                cdatasegment_rom_end,
                csegment_start)
    
    dataseg = rom.read_bytes(cdatasegment_rom_start, cdatasegment_rom_end - cdatasegment_rom_start)
    if dataseg[:2] != bytes([0x11, 0x72]):
        raise RuntimeError("dataseg didn't start with rarezip magic 11 72")
    dataseg = zlib.decompress(dataseg[2:], wbits=-15)

    # the dataseg wipes out part of the bootexe, so rebuild the bootexe
    csegment_start_offset = csegment_start - ipc
    csegment_end_offset   = (csegment_start - ipc) + len(dataseg)

    len_bootexe_before = len(bootexe)
    bootexe = bootexe[:csegment_start_offset] + dataseg

    logger.info("bootexe rebuilt. 0x%08x-0x%08x original, 0x%08x-0x%08x decompressed",
                ipc,
                ipc+csegment_start_offset,
                ipc+csegment_start_offset,
                ipc+csegment_start_offset+csegment_end_offset)
    
    # the now-extended bootexe chewed up some of the bss segment, so adjust bss accordingly

    # now let's dump the swap segment.
    # the swap scheme used here means that pretty much the rest of ROM can be treated as virtual memory,
    # but the game does not do this. it prefers to copy resources from ROM using DMA.
    # so, we'll need to make a guess as to where the swap segment actually ends.
    consts = GOLDENEYE_ROM_SWAP_PATTERN.consts(ipc_tlb, bootexe, romswap_offset)
    swap_rom_address = consts["swap_rom_address"].get_value()

    logger.info("swap segment in ROM at 0x%08x", swap_rom_address)

    swap = bytearray([])
    
    # keep copying while we still find MIPS bytecode
    offset = swap_rom_address
    while True:
        page = rom.read_bytes(offset, 0x2000)
        if contains_code(page) is False:
            break
        offset += 0x2000

    logger.info("swap looks like it occupies 0x%08x-0x%08x",
                swap_rom_address,
                offset)
    
    swap_page = BffiTlbEntry()
    swap_page.entryhi(0x7F000000)
    swap_page.pagemask(TLB_PAGEMASK_1MBYTES) # should not be more than 1 mb, i think
    swap_page.entrylo0(tlbutil_pack_entrylo(0x00700000, 0x1F))
    swap_page.entrylo1(1)

    tlb = tlbutil_generate_bffi_tlb({
        0: os_page,
        1: swap_page
    })

    builder.initial_tlb(tlb)

    # TODO: WRONG! goldeneye should NOT require the expansion pak!
    # this is only here until BFFI supports swap segments natively!
    builder.required_memory_size(8) 

    builder.fix(tlb_os_base, bootexe)
    builder.fix(0x7F000000, swap)

    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(entry_point)

    return builder.build()
