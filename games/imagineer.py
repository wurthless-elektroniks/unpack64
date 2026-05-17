'''
Imagineer
Also various games by Genki since Imagineer treated them like an internal development team
'''

import logging
import struct

from compression.lzss import lzss_decompress

from bffi import Bffi, BffiBuilder
from n64rom import N64Rom
from preamble import preamble_extract_bss_sections_to_bffi, identify_preamble
from signature import SignatureBuilder, WILDCARD
from sigutil import pick_pattern

logger = logging.getLogger(__name__)

# ------------------------------------------
#
# Sim City 2000 (Japan)
#
# Main thread sets up a pointer to the overlay table, then the
# function at 0x80058c94 swaps between overlays.
#
# The table entry format is:
# - +0x00 - ROM start address
# - +0x04 - ROM end address
# - +0x08 - RAM load address
# - +0x0C - BSS start address (unused)
# - +0x10 - BSS end address (unused)
# - +0x14 - unused (this game does not use compression)
# - +0x18 - unused (this game does not use compression)
#
# ------------------------------------------

SIMCITY_MAIN_THREAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0x90,             # +0x00 addiu      sp,sp,-0x70
        0xaf, 0xbf, 0x00, 0x64,             # +0x04 sw         ra,local_c(sp)
        0xaf, 0xa4, 0x00, 0x70,             # +0x08 sw         a0,local_res0(sp)
        0xaf, 0xb0, 0x00, 0x60,             # +0x0C sw         s0,local_10(sp)
        0x3c, 0x04, 0x80, WILDCARD,         # +0x10 lui        a0,0x8009
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x14 jal        FUN_80058b70
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x18 _addiu     a0=>PTR_DAT_8008eab0,a0,-0x1550
        0x0c, WILDCARD, WILDCARD, WILDCARD, # jal        FUN_80057780
        0x00, 0x00, 0x00, 0x00,             # _nop
        0x3c, 0x10, 0x80, 0x00,             # lui        s0,0x8000
        0x8e, 0x10, 0x03, 0x00,             # lw         s0,offset DAT_80000300(s0)
        0x00, 0x00, 0x00, 0x00,             # nop
    ]) \
    .const_op32_hi16("overlay_table_address", 0x10) \
    .const_op32_lo16("overlay_table_address", 0x18) \
    .build()

# rally challenge 2000 uses the same overlay loader, but it doesn't
# setup the overlay table pointer until later in the main thread
RALLY2000_MAIN_THREAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x00, 0x62, 0x88, 0x21,             # +0x00 addu       s1,v1,v0
        0x02, 0x20, 0x20, 0x21,             # +0x04 move       a0,s1
        0x00, 0x00, 0x28, 0x21,             # +0x08 clear      a1
        0x02, 0x02, 0x80, 0x23,             # +0x0C subu       s0,s0,v0
        0x02, 0x03, 0x80, 0x23,             # +0x10 subu       s0,s0,v1
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x14 jal        FUN_80095910
        0x02, 0x00, 0x30, 0x21,             # +0x18 _move      a2,s0
        0x02, 0x20, 0x20, 0x21,             # +0x1C move       a0,s1
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x20 jal        FUN_80070bd0
        0x02, 0x00, 0x28, 0x21,             # +0x24 _move      a1,s0
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x28 jal        FUN_80071000
        0x24, 0x04, 0x00, 0x60,             # +0x2C _li        a0,0x60
        0x3c, 0x04, 0x80, WILDCARD,         # +0x30 lui        a0,0x8008
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x34 addiu      a0=>LAB_800788bc,a0,-0x7744
        0x24, 0x05, 0x07, 0xd0,             # +0x38 li         a1,0x7d0
        0x24, 0x06, 0x10, 0x00,             # +0x3C li         a2,0x1000
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x40 jal        FUN_80071240
        0x00, 0x00, 0x38, 0x21,             # +0x44 _clear     a3
        0x3c, 0x04, 0x80, WILDCARD,         # +0x48 lui        a0,0x800b
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x4C addiu      a0=>PTR_DAT_800a8d5c,a0,-0x72a4 <-- overlay table address
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x50 jal        FUN_8007bd60
        0x00, 0x00, 0x00, 0x00,             # +0x54 _nop
    ]) \
    .const_op32_hi16("overlay_table_address", 0x48) \
    .const_op32_lo16("overlay_table_address", 0x4C) \
    .build()

# same deal with fighter's destiny 2; mainloop is rearranged
# and the pattern has to change with it.
# this time there's annoying obfuscation with the game setting up
# pointers to pointers or something like it.
FIGHTERS_DESTINY_2_MAIN_THREAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x24, 0x02, 0x00, 0x01,             # +0x00 li         v0,0x1
        0x3c, 0x01, 0x80, WILDCARD,         # +0x04 lui        at,0x800e
        0xa0, 0x22, WILDCARD, WILDCARD,     # +0x08 sb         v0,-0x7c74(at)=>DAT_800d838c
        0x3c, 0x04, 0x80, WILDCARD,         # +0x0C lui        a0,0x8004
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x10 jal        FUN_80006a94
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x14 _addiu     a0=>PTR_DAT_8003ecf0,a0,-0x1310
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x18 jal        FUN_80006f58
        0x02, 0x20, 0x20, 0x21,             # +0x1C _move      a0,s1
    ]) \
    .const_op32_hi16("overlay_table_address", 0x0C) \
    .const_op32_lo16("overlay_table_address", 0x14) \
    .build()

def simcity_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    builder = BffiBuilder()
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)

    bootexe = rom.boot_exe()[:earliest_bss-ipc]

    builder.fix(ipc, bootexe)
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.initial_stack_pointer(preamble.initial_stack_pointer())

    main_thread_pattern, main_thread_offset = pick_pattern(bootexe,
                                                           [SIMCITY_MAIN_THREAD_PATTERN,
                                                            RALLY2000_MAIN_THREAD_PATTERN,
                                                            FIGHTERS_DESTINY_2_MAIN_THREAD_PATTERN])

    if main_thread_pattern is None:
        return None
    
    consts = main_thread_pattern.consts(ipc, bootexe, main_thread_offset)
    overlay_table_address = consts["overlay_table_address"].get_value()

    logger.info("found Imagineer/Genki Sim City 2000-style overlay table at 0x%08x", overlay_table_address)

    overlay_table_offset = overlay_table_address - ipc

    dumped_overlays = []

    while True:
        rom_start_address, \
        rom_end_address, \
        ram_load_address, \
        bss_start_address, \
        bss_end_address, \
        _, \
        _, = struct.unpack(">IIIIIII", bootexe[overlay_table_offset:overlay_table_offset+0x1C])

        if (ram_load_address >> 24) != 0x80:
            break

        overlay_table_offset += 0x1C

        tup = (rom_start_address, rom_end_address, ram_load_address)
        if tup in dumped_overlays:
            continue
        dumped_overlays.append(tup)

        seg = rom.read_bytes(rom_start_address, rom_end_address-rom_start_address)

        # skip loading resources that ain't code
        if STACK_MOVE_BACK_PATTERN.find(seg) is None:
            continue

        logger.info("overlay: ROM 0x%08x-0x%08x -> RAM 0x%08x",
                    rom_start_address,
                    rom_end_address,
                    ram_load_address)
        if bss_start_address != 0:
            # in case this code pops up in other games....
            logger.info("overlay bss: 0x%08x-0x%08x", bss_start_address, bss_end_address)
        
        seg = rom.read_bytes(rom_start_address, rom_end_address-rom_start_address)
        builder.seg(ram_load_address, seg)
    
    return builder.build()

# ------------------------------------------
#
# Chou Kuukan Night Pro Yakyuu King
#
# This code sucks. They've separated their resource tables into compressed (with LZSS)
# and uncompressed resources. It's not complex, but is annoying to read.
#
# For the first 0x69 (not shitposting, that's the number) entries in the table:
# - +0x00 entry ID (we're looking for an entry in this table matching that ID)
# - +0x04 corresponding entry ID in LZSS table
#
# 0x8025ecbc is that first table to scan.
#
# The main resource table is at 0x8025e080. Its format is:
# - +0x00 - ROM start address
# - +0x04 - ROM end address
# - +0x08 - RAM load address
#
# For LZSS-compressed entries, we use two indices into the resource table,
# and this setup is a bit similar to the Zelda virtual ROM address thing.
# The normal entry ID ROM range is if that entry was NOT compressed,
# but the LZSS entry ID is actually where to read from.
# So the uncompressed size is the virtual end address minus the virtual start address.
#
# All other entries in the table do not use this nonsense.
#
# Finally, the game hardcodes two BSS clears instead of stuffing them in the table,
# probably to save memory. They are:
# - 0x12: 0x801aa080, 0x7ac0 bytes
# - 0x78: 0x80346490, 0x3c040 bytes
#
# ------------------------------------------

YAKYUUKING_LOAD_RESOURCE_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xb0,         # +0x00 addiu      sp,sp,-0x50
        0xaf, 0xbf, 0x00, 0x2c,         # +0x04 sw         ra,local_24(sp)
        0xaf, 0xa4, 0x00, 0x50,         # +0x08 sw         a0,local_res0(sp)
        0xaf, 0xb0, 0x00, 0x28,         # +0x0C sw         s0,local_28(sp)
        0xaf, 0xa0, 0x00, 0x34,         # +0x10 sw         zero,local_1c(sp)
        0x8f, 0xae, 0x00, 0x34,         # +0x14 lw         t6,local_1c(sp)
        0x3c, 0x18, 0x80, WILDCARD,     # +0x18 lui        t8,0x8026 <-- LZSS mappings
        0x00, 0x0e, 0x78, 0xc0,         # +0x1C sll        t7,t6,0x3
        0x03, 0x0f, 0xc0, 0x21,         # +0x20 addu       t8,t8,t7
        0x8f, 0x18, WILDCARD, WILDCARD, # +0x24 lw         t8,-0x1344(t8)
        0x8f, 0xb9, 0x00, 0x50,         # +0x28 lw         t9,local_res0(sp)
        0x00, 0x00, 0x00, 0x00,         # +0x2C nop
        0x17, 0x19, 0x00, 0x16,         # +0x30 bne        t8,t9,LAB_802458e8
        0x00, 0x00, 0x00, 0x00,         # +0x34 _nop
        0x00, 0x19, 0x40, 0x80,         # +0x38 sll        t0,t9,0x2
        0x01, 0x19, 0x40, 0x23,         # +0x3C subu       t0,t0,t9
        0x3c, 0x09, 0x80, WILDCARD,     # +0x40 lui        t1,0x8026
        0x25, 0x29, WILDCARD, WILDCARD, # +0x44 addiu      t1,t1,-0x1f80 <-- main overlay table
    ]) \
    .const_op32_hi16("lzss_mapping_table_address", 0x18) \
    .const_op32_lo16("lzss_mapping_table_address", 0x24) \
    .const_op32_hi16("resource_table_address", 0x40) \
    .const_op32_lo16("resource_table_address", 0x44) \
    .build()

STACK_MOVE_BACK_PATTERN = SignatureBuilder() \
    .bits(   bytes([0x27, 0xBD, 0x80, 0x00])) \
    .andmask(bytes([0xFF, 0xFF, 0x80, 0x00])) \
    .build()

def yakyuuking_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    builder = BffiBuilder()
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)

    bootexe = rom.boot_exe()[:earliest_bss-ipc]

    builder.fix(ipc, bootexe)
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.initial_stack_pointer(preamble.initial_stack_pointer())

    load_resource_offset = YAKYUUKING_LOAD_RESOURCE_PATTERN.find(bootexe)
    if load_resource_offset is None:
        return None
    
    logger.info("found Imagineer/Genki Yakyuu King LZSS loader at 0x%08x", load_resource_offset+ipc)

    consts = YAKYUUKING_LOAD_RESOURCE_PATTERN.consts(ipc, bootexe, load_resource_offset)
    lzss_mapping_table_address = consts["lzss_mapping_table_address"].get_value()
    resource_table_address = consts["resource_table_address"].get_value()

    # parse LZSS table mappings first
    # TODO: remove hardcoding. i don't think another game uses this driver yet,
    # but if it does, this code has to be made more universal

    lzss_mapping_table_offset = lzss_mapping_table_address - ipc
    lzss_resource_lookups = {}
    for _ in range(0x69):
        normal_id, lzss_id = struct.unpack(">II", bootexe[lzss_mapping_table_offset:lzss_mapping_table_offset+8])
        lzss_mapping_table_offset += 8
        if normal_id in lzss_resource_lookups:
            raise RuntimeError(f"id {normal_id} already registered in LZSS lookup table!")
        lzss_resource_lookups[normal_id] = lzss_id
    
    resource_table_base_offset = resource_table_address - ipc
    resource_id = 0
    while True:
        resource_table_offset = (resource_table_base_offset + (resource_id * 0x0C))

        uncompressed_rom_start_address, \
        uncompressed_rom_end_address, \
        ram_load_address = struct.unpack(">III", bootexe[resource_table_offset:resource_table_offset+0x0C])

        if (ram_load_address >> 24) != 0x80:
            break

        if resource_id in lzss_resource_lookups:
            lzss_table_offset = (resource_table_base_offset + (lzss_resource_lookups[resource_id] * 0x0C))

            compressed_rom_start_address, \
            compressed_rom_end_address, \
            _ = struct.unpack(">III", bootexe[lzss_table_offset:lzss_table_offset+0x0C])

            payload = rom.read_bytes(compressed_rom_start_address, compressed_rom_end_address-compressed_rom_start_address)
            payload = lzss_decompress(payload)

            expected_payload_size = uncompressed_rom_end_address-uncompressed_rom_start_address
            
            # FIXME: expected payload size is always less than actual decompressed size.
            # might be a bug or some LZSS variation i missed.
            # if len(payload) > expected_payload_size:
                # with open("private/yakuuking_debug.bin", "wb") as f:
                    # f.write(payload)
                # raise RuntimeError(f"decompress failed, expected {expected_payload_size} and got {len(payload)}")
                        
            payload = payload[:uncompressed_rom_end_address-uncompressed_rom_start_address]

            if STACK_MOVE_BACK_PATTERN.find(payload) is not None:
                logger.info("compressed resource %02x: ROM 0x%08x-0x%08x/VROM 0x%08x-0x%08x -> RAM 0x%08x",
                        resource_id,
                        compressed_rom_start_address,
                        compressed_rom_end_address,
                        uncompressed_rom_start_address,
                        uncompressed_rom_end_address,
                        ram_load_address)
                
                # TODO: this game does not compress any overlays; this code path is left
                # here in case it's reused on another game or if someone wants to dump
                # the game's resources.
        else:
            payload = rom.read_bytes(uncompressed_rom_start_address, uncompressed_rom_end_address-uncompressed_rom_start_address)

            if STACK_MOVE_BACK_PATTERN.find(payload) is not None:
                logger.info("uncompressed resource %02x: ROM 0x%08x-0x%08x -> RAM 0x%08x",
                            resource_id,
                            uncompressed_rom_start_address,
                            uncompressed_rom_end_address,
                            ram_load_address)
                
                builder.seg(ram_load_address, payload)
        
        resource_id += 1

    return builder.build()

# ------------------------------------------
#
# MRC - Multi Racing Championship
#
# Seems Genki got the memo about the LZSS lookup table thing not being
# the cleanest idea, so this game makes its resource table a lot cleaner.
#
# Entry structure is the same as Sim City 2000, but with compression supported this time:
#
# +0x00 - uncompressed ROM start address
# +0x04 - uncompressed ROM end address
# +0x08 - RAM load address
# +0x0C - BSS start address
# +0x10 - BSS end address
# +0x14 - compressed ROM start address (0 if uncompressed)
# +0x18 - compressed ROM end address (0 if uncompressed)
# 
# Compression is still LZSS.
#
# ------------------------------------------

MRC_LOAD_RESOURCE_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xa8,             # +0x00 addiu      sp,sp,-0x58
        0xaf, 0xbf, 0x00, 0x24,             # +0x04 sw         ra,local_34(sp)
        0xaf, 0xa4, 0x00, 0x58,             # +0x08 sw         a0,local_res0(sp)
        0x8f, 0xae, 0x00, 0x58,             # +0x0C lw         t6,local_res0(sp)
        0x3c, 0x18, 0x80, WILDCARD,         # +0x10 lui        t8,0x8009
        0x00, 0x0e, 0x78, 0xc0,             # +0x14 sll        t7,t6,0x3
        0x01, 0xee, 0x78, 0x23,             # +0x18 subu       t7,t7,t6
        0x00, 0x0f, 0x78, 0x80,             # +0x1C sll        t7,t7,0x2
        0x27, 0x18, WILDCARD, WILDCARD,     # +0x20 addiu      t8,t8,-0x1d0
        0x01, 0xf8, 0xc8, 0x21,             # addu       t9,t7,t8
        0x8f, 0x28, 0x00, 0x04,             # lw         t0,0x4(t9)=>DAT_8008fe34
        0x8f, 0x29, 0x00, 0x00,             # lw         t1,0x0(t9)=>DAT_8008fe30
        0x8f, 0x24, 0x00, 0x08,             # lw         a0,0x8(t9)=>DAT_8008fe38
        0x0c, WILDCARD, WILDCARD, WILDCARD, # jal        FUN_800770e0
        0x01, 0x09, 0x28, 0x23,             # _subu      a1,t0,t1
        0x8f, 0xaa, 0x00, 0x58,             # lw         t2,local_res0(sp)
    ]) \
    .const_op32_hi16("resource_table_address", 0x10) \
    .const_op32_lo16("resource_table_address", 0x20) \
    .build()

def mrc_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    builder = BffiBuilder()
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)

    bootexe = rom.boot_exe()[:earliest_bss-ipc]

    builder.fix(ipc, bootexe)
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.initial_stack_pointer(preamble.initial_stack_pointer())

    load_resource_offset = MRC_LOAD_RESOURCE_PATTERN.find(bootexe)
    if load_resource_offset is None:
        return None
    
    logger.info("found Imagineer/Genki MRC LZSS loader at 0x%08x", load_resource_offset+ipc)

    consts = MRC_LOAD_RESOURCE_PATTERN.consts(ipc, bootexe, load_resource_offset)
    resource_table_address = consts["resource_table_address"].get_value()

    resource_table_base_offset = resource_table_address - ipc

    resource_id = 0

    while True:
        resource_table_offset = resource_table_base_offset + (resource_id * 0x1C)

        uncompressed_rom_start_address, \
        uncompressed_rom_end_address, \
        ram_load_address, \
        bss_start_address, \
        bss_end_address, \
        compressed_rom_start_address, \
        compressed_rom_end_address = struct.unpack(">IIIIIII", bootexe[resource_table_offset:resource_table_offset+0x1C])

        if (ram_load_address >> 24) != 0x80:
            break

        if compressed_rom_start_address != 0:
            payload = rom.read_bytes(compressed_rom_start_address, compressed_rom_end_address-compressed_rom_start_address)
            payload = lzss_decompress(payload)
            
            expected_payload_size = uncompressed_rom_end_address-uncompressed_rom_start_address

            if STACK_MOVE_BACK_PATTERN.find(payload) is not None:
                logger.info("compressed resource %02x: ROM 0x%08x-0x%08x/VROM 0x%08x-0x%08x -> RAM 0x%08x, BSS 0x%08x-0x%08x",
                        resource_id,
                        compressed_rom_start_address,
                        compressed_rom_end_address,
                        uncompressed_rom_start_address,
                        uncompressed_rom_end_address,
                        ram_load_address,
                        bss_start_address,
                        bss_end_address)
                
                # seems this game actually does compress an overlay...
                builder.seg(ram_load_address, payload)

        else:
            payload = rom.read_bytes(uncompressed_rom_start_address, uncompressed_rom_end_address-uncompressed_rom_start_address)

            if STACK_MOVE_BACK_PATTERN.find(payload) is not None:
                logger.info("uncompressed resource %02x: ROM 0x%08x-0x%08x -> RAM 0x%08x, BSS 0x%08x-0x%08x",
                            resource_id,
                            uncompressed_rom_start_address,
                            uncompressed_rom_end_address,
                            ram_load_address,
                            bss_start_address,
                            bss_end_address)
                
                builder.seg(ram_load_address, payload)

        resource_id += 1

    return builder.build()


# ------------------------------------------
#
# Fighter's Destiny
#
# The overlay loader's been changed a bit, and for the worse.
#
# Instead of passing the overlay an index, you have to pass it the struct directly.
# It is in this form:
#
# +0x00 - RAM load address
# +0x04 - ROM start address
# +0x08 - ROM end address
# +0x0C - code section range start?
# +0x10 - code section range end?
# +0x14 - data section range start?
# +0x18 - data section range end?
# +0x1C - unused
# +0x20 - unused
#
# ...for a total of 0x24 bytes.
#
# The programmers then proceeded to defeat the whole point of avoiding indices
# by computing them directly in the main thread. There's still a table in RAM,
# but the compiler computes the pointers ahead of time.
#
# The other problem is even worse. The overlay loader will check the code/data
# ranges and clear caches within those ranges if they are not zero, but in the
# final build of the game, those ranges are always set to zero. The game therefore
# never clears code/data caches before running a new overlay, and that introduces
# cache coherency hazard.
#
# What a god damn disaster.
#
# There is no BSS or compression used on this game, though they made room for it.
#
# ------------------------------------------

FIGHTERS_DESTINY_MAIN_THREAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x8f, 0xb9, 0x00, 0x70,             # +0x00 lw         t9,0x70(sp)
        0x3c, 0x18, 0x80, WILDCARD,         # +0x04 lui        t8,0x8029      <-- overlay table base
        0x00, 0x19, 0x78, 0xc0,             # +0x08 sll        t7,t9,0x3
        0x01, 0xf9, 0x78, 0x21,             # +0x0C addu       t7,t7,t9
        0x00, 0x0f, 0x78, 0x80,             # +0x10 sll        t7,t7,0x2
        0x27, 0x18, WILDCARD, WILDCARD,     # +0x14 addiu      t8,t8,-0x4b60
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x18 jal        FUN_8025c4d0
        0x01, 0xf8, 0x20, 0x21,             # +0x1C _addu      a0,t7,t8
    ]) \
    .const_op32_hi16("overlay_table_address", 0x04) \
    .const_op32_lo16("overlay_table_address", 0x14) \
    .build()

def fightersdestiny_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    builder = BffiBuilder()
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)

    bootexe = rom.boot_exe()[:earliest_bss-ipc]

    builder.fix(ipc, bootexe)
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    
    main_thread_pattern, main_thread_offset = pick_pattern(bootexe,
                                                           [FIGHTERS_DESTINY_MAIN_THREAD_PATTERN])

    if main_thread_pattern is None:
        return None
    
    consts = main_thread_pattern.consts(ipc, bootexe, main_thread_offset)
    overlay_table_address = consts["overlay_table_address"].get_value()

    logger.info("found Imagineer/Genki Fighters Destiny-style overlay table at 0x%08x", overlay_table_address)

    overlay_table_offset = overlay_table_address - ipc

    while True:
        ram_load_address, \
        rom_start_address, \
        rom_end_address, \
        _, \
        _, \
        _, \
        _, \
        _, \
        _ = struct.unpack(">IIIIIIIII", bootexe[overlay_table_offset:overlay_table_offset+0x24])

        if (ram_load_address >> 24) != 0x80:
            break

        overlay_table_offset += 0x24

        logger.info("found overlay: ROM 0x%08x-0x%08x -> RAM 0x%08x",
                    rom_start_address,
                    rom_end_address,
                    ram_load_address)
        
        seg = rom.read_bytes(rom_start_address, rom_end_address-rom_start_address)
        builder.seg(ram_load_address, seg)

    return builder.build()

