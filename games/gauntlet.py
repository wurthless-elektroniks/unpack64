'''
Gauntlet Legends

This is another TLB game. To make things more annoying, it maps its page in kernel space.
8020008C will map physical address 0x00000000~0x007FFFFF to 0xE0000000~0xE07FFFFF,
which effectively maps the entire RDRAM space to a TLB page for no good reason.

This game also has a basic ROM filesystem. For the main game code (named "game"),
the following structure applies:
- +0x00: 16 bytes name of file
- +0x10: 4 bytes location in ROM
- +0x14: 4 bytes size
- +0x18: 4 bytes load address
- +0x1C: 4 bytes something else
- +0x20: 4 bytes BSS start location
- +0x24: 4 bytes BSS size in bytes
- +0x28: 8 bytes unused (always zero)

The boot stub loads "game" into memory then uses zlib to inflate it to its
final load address in TLB-mapped memory.

The last thing the bootstub does is copy the file table to TLB-mapped memory,
then it calls the entry point at 0x80002850. The code expects a0 to have been
set by something earlier in the boot (by IPL3 or earlier).

Ghidra's decompiler choked HARD on the boot stub, thinking that the thing
ended up in an infinite loop, and refused to decompile further until I had put
nops into place. Good stuff all around.
'''

import logging
import struct
import zlib

from bffi import Bffi, BffiBuilder, BffiTlb, BffiTlbEntry
from n64rom import N64Rom
from preamble import identify_preamble
from signature import SignatureBuilder, WILDCARD
from tlbconst import TLB_PAGEMASK_4MBYTES

logger = logging.getLogger(__name__)

GAUNTLET_BOOTSTUB_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xd8,          # +0x00 addiu      sp,sp,-0x28
        0x3c, 0x03, 0x80, WILDCARD,      # +0x04 lui        v1,0x8020
        0x24, 0x63, WILDCARD, WILDCARD,  # +0x08 addiu      v1,v1,0x2c4
        0xaf, 0xbf, 0x00, 0x20,          # +0x0C sw         ra,local_8(sp)
        0xaf, 0xb3, 0x00, 0x1c,          # +0x10 sw         s3,local_c(sp)
        0xaf, 0xb2, 0x00, 0x18,          # +0x14 sw         s2,local_10(sp)
        0xaf, 0xb1, 0x00, 0x14,          # +0x18 sw         s1,local_14(sp)
        0xaf, 0xb0, 0x00, 0x10,          # +0x1C sw         s0,local_18(sp)
        0x8c, 0x62, 0x00, 0x00,          # +0x20 lw         v0,0x0(v1)  <-- number of entries in file table
        0x00, 0x80, 0x98, 0x21,          # +0x24 move       s3,a0
        0x10, 0x40, 0x00, 0x0f,          # +0x28 beq        v0,zero,LAB_80200174
        0x24, 0x10, 0x00, 0x01,          # +0x2C _li        s0,0x1
        0x24, 0x72, 0xFF, 0xEC,          # +0x30 addiu      s2,v1,-0x14 <-- start of block to be copied to higher RAM
        0x24, 0x63, 0x00, 0x1C,          # +0x34 addiu      v1,v1,0x1c  <-- start of filesystem table
    ]) \
    .const_op32_hi16("filetable_initial_offset", 0x04) \
    .const_op32_lo16("filetable_initial_offset", 0x08) \
    .build()

# here just as a sanity check, to make sure we aren't assigning an arbitrary TLB
GAUNTLET_BOOTSTUB_TLB_MAPPER = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xd8,     # addiu      sp,sp,-0x28
        0xaf, 0xb0, 0x00, 0x18,     # sw         s0,local_10(sp)
        0x00, 0x00, 0x80, 0x21,     # clear      s0
        0xaf, 0xb1, 0x00, 0x1c,     # sw         s1,local_c(sp)
        0x24, 0x11, 0xff, 0xff,     # li         s1,-0x1
        0xaf, 0xbf, 0x00, 0x20,     # sw         ra,local_8(sp)
        0x02, 0x00, 0x20, 0x21,     # move       a0,s0
        
        0x00, 0x00, 0x28, 0x21,     # clear      a1
        0x3c, 0x06, 0x80, 0x00,     # lui        a2,0x8000
        0x24, 0x07, 0xff, 0xff,     # li         a3,-0x1
        0xaf, 0xb1, 0x00, 0x10,     # sw         s1,local_18(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # jal        FUN_802018b0                                               undefined FUN_802018b0()
        0xaf, 0xb1, 0x00, 0x14,     # _sw        s1,local_14(sp)
        0x26, 0x10, 0x00, 0x01,     # addiu      s0,s0,0x1
        0x2a, 0x02, 0x00, 0x20,     # slti       v0,s0,0x20
        0x14, 0x40, 0xff, 0xf7,     # bne        v0,zero,LAB_802000a8
        0x02, 0x00, 0x20, 0x21,     # _move      a0,s0
        0x24, 0x04, 0x00, 0x1e,     # li         a0,0x1e
        0x3c, 0x05, 0x00, 0x7f,     # lui        a1,0x7f
        0x34, 0xa5, 0xe0, 0x00,     # ori        a1,a1,0xe000
        0x3c, 0x06, 0xe0, 0x00,     # lui        a2,0xe000
        0x00, 0x00, 0x38, 0x21,     # clear      a3
        0x3c, 0x02, 0x00, 0x40,     # lui        v0,0x40
        0xaf, 0xa2, 0x00, 0x10,     # sw         v0,local_18(sp)
        0x24, 0x02, 0xff, 0xff,     # li         v0,-0x1
        0x0c, WILDCARD, WILDCARD, WILDCARD, # jal        FUN_802018b0                                               undefined FUN_802018b0()
        0xaf, 0xa2, 0x00, 0x14,     # _sw        v0,local_14(sp)
        0x8f, 0xbf, 0x00, 0x20,     # lw         ra,local_8(sp)
        0x8f, 0xb1, 0x00, 0x1c,     # lw         s1,local_c(sp)
        0x8f, 0xb0, 0x00, 0x18,     # lw         s0,local_10(sp)
        0x03, 0xe0, 0x00, 0x08,     # jr         ra
        0x27, 0xbd, 0x00, 0x28,     # _addiu     sp,sp,0x28
    ]) \
    .build()

GAUNTLET_BOOTSTUB_COPYFILETABLE_AND_START_GAME_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x05, 0x80, 0x20,             # 0x00 lui        a1,0x8020
        0x24, 0xa5, 0x02, 0xb0,             # 0x04 addiu      a1,a1,0x2b0
        0x3c, 0x04, 0xe0, WILDCARD,         # 0x08 lui        a0,0xe013
        0x24, 0x84, WILDCARD, WILDCARD,     # 0x0C addiu      a0,a0,0x1c0
        0x24, 0x03, 0x01, 0xdf,             # 0x10 li         v1,0x1df
        0x24, 0x06, 0xff, 0xff,             # 0x14 li         a2,-0x1
        0x90, 0xa2, 0x00, 0x00,             # 0x18 lbu        v0,0x0(a1)
        0x24, 0xa5, 0x00, 0x01,             # 0x1C addiu      a1,a1,0x1
        0x24, 0x63, 0xff, 0xff,             # 0x20 addiu      v1,v1,-0x1
        0xa0, 0x82, 0x00, 0x00,             # 0x24 sb         v0,0x0(a0)
        0x14, 0x66, 0xff, 0xfb,             # 0x28 bne        v1,a2,LAB_80200274
        0x24, 0x84, 0x00, 0x01,             # 0x2C _addiu     a0,a0,0x1
        0x0c, WILDCARD, WILDCARD, WILDCARD, # 0x30 jal        SUB_80002850
        0x02, 0x60, 0x20, 0x21,             # 0x34 _move      a0,s3
    ]) \
    .const_op32_hi16("filetable_dest_address", 0x08) \
    .const_op32_lo16("filetable_dest_address", 0x0C) \
    .xref_j_imm26("entry_point", 0x30) \
    .build()

def gauntlet_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    bootstub_address = preamble.crt_entry_point()
    if GAUNTLET_BOOTSTUB_PATTERN.compare(rom.boot_exe(), bootstub_address - ipc) is False:
        return None

    if GAUNTLET_BOOTSTUB_TLB_MAPPER.find(rom.boot_exe()) is None:
        return None

    copyfile_startgame_offset = GAUNTLET_BOOTSTUB_COPYFILETABLE_AND_START_GAME_PATTERN.find(rom.boot_exe())
    if copyfile_startgame_offset is None:
        return None

    copyfile_startgame_consts = GAUNTLET_BOOTSTUB_COPYFILETABLE_AND_START_GAME_PATTERN.consts(ipc, rom.boot_exe(), copyfile_startgame_offset)
    copyfile_startgame_xrefs = GAUNTLET_BOOTSTUB_COPYFILETABLE_AND_START_GAME_PATTERN.xrefs(ipc, rom.boot_exe(), copyfile_startgame_offset)
    filetable_dest_address = copyfile_startgame_consts["filetable_dest_address"].get_value()
    entry_point = copyfile_startgame_xrefs["entry_point"].get_address()

    logger.info("found Gauntlet Legends loader")

    consts = GAUNTLET_BOOTSTUB_PATTERN.consts(ipc, rom.boot_exe(), bootstub_address - ipc)
    filetable_initial_offset = consts["filetable_initial_offset"].get_value()

    filetable_ramcopy_start_address = filetable_initial_offset - 0x14
    filetable_start_address = filetable_initial_offset + 0x1C

    filetable_num_files = struct.unpack(">I", rom.boot_exe()[filetable_initial_offset - ipc:(filetable_initial_offset - ipc) + 4])[0] 
    logger.info("found %d files in filetable", filetable_num_files)

    game_rom_address       = None
    game_load_address      = None
    game_compressed_size   = None
    game_bss_start = None
    game_bss_size  = None

    for i in range(filetable_num_files):
        offset = (filetable_start_address - ipc) + (i * 0x30)
        filename = rom.boot_exe()[offset:offset+0x10]
        if filename == b'game\0\0\0\0\0\0\0\0\0\0\0\0':
            game_rom_address, game_compressed_size, game_load_address, _, game_bss_start, game_bss_size = \
                struct.unpack(">IIIIII", rom.boot_exe()[offset+0x10:offset+0x28])
        
    if game_rom_address is None:
        logger.error("unable to find 'game' in filetable")
        return None
    
    logger.info("zlib-compressed game code is in ROM at 0x%08x, size %d", game_rom_address, game_compressed_size)
    compressed_payload = rom.read_bytes(game_rom_address, game_compressed_size)

    logger.info("inflating payload...")
    payload = zlib.decompress(compressed_payload, wbits = -15)
    expected_decompressed_size = game_bss_start - game_load_address

    if len(payload) != expected_decompressed_size:
        logger.error("decompress error. expected decompressed size %d, got %d",
                     expected_decompressed_size, len(payload))

    logger.info("payload inflated OK. decompressed to %d bytes", expected_decompressed_size)

    # let's map the ENTIRE RDRAM SPACE to some TLB page... great job guys!!!
    tlb = BffiTlb()
    for i in range(0x20):
        tlb_entry = BffiTlbEntry()
        tlb_entry.pagemask(0)
        tlb_entry.entryhi(0x80000000)
        tlb_entry.entrylo0(1)
        tlb_entry.entrylo1(1)
        tlb.entry(i, tlb_entry)

    tlb_entry_1e = BffiTlbEntry()
    tlb_entry_1e.pagemask(TLB_PAGEMASK_4MBYTES)
    tlb_entry_1e.entryhi(0xE0000000)
    tlb_entry_1e.entrylo0( (0 >> 6) | 0x1F )
    tlb_entry_1e.entrylo1( (0x400000 >> 6) | 0x1F )
    tlb.entry(0x1E, tlb_entry_1e)

    game_load_address_phys = tlb.virtual_to_physical(game_load_address)
    game_bss_start_phys = tlb.virtual_to_physical(game_bss_start)

    if game_load_address_phys is None or game_bss_start_phys is None:
        logger.error("problem setting up TLB!!")
        return None
    
    logger.info(\
"""final details before we build us a BFFI:
- game loads to 0x%08x ~ 0x%08x
- bss at 0x%08x ~ 0x%08x
- filesystem table is copied to 0x%08x
- entry point at 0x%08x""",
    game_load_address,
    game_load_address + expected_decompressed_size,
    game_bss_start,
    game_bss_start + game_bss_size,
    filetable_dest_address,
    entry_point)

    builder = BffiBuilder()
    builder.initial_tlb(tlb)
    builder.fix(filetable_dest_address, rom.boot_exe()[filetable_ramcopy_start_address-ipc:(filetable_ramcopy_start_address+0x1e0)-ipc] )
    builder.fix(game_load_address, payload)
    builder.bss(game_bss_start, game_bss_size)

    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(entry_point)

    return builder.build()
