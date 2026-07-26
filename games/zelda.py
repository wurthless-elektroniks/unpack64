'''
Zelda - Ocarina of Time / Majora's Mask
And also Dobutsu no Mori / Animal Forest because it uses the same framework

This framework relies heavily on Yaz0 compression, and everyone's favorite,
dynamically loaded segments. Maybe the EAD guys should've hollered down the
hall to the English gentlemen to use their USO framework so I didn't have to
write this.

While the USO loader is far more debugging friendly, including an explicit list
of modules, their names, and what they're supposed to import and export,
the Zelda modules provide none of this explicitly. Instead the modules are compiled
as if to load into a virtual address range above 0x80800000. Then, it's up to whatever
loads them to not only know where those modules are supposed to be loaded in virtual RAM,
but also where important functions (init, destroy, etc.) are located so that the engine
can call them. This makes this loader setup maximally unfriendly to dump.

The virtual RAM setup should in theory allow for importing symbols from other overlays,
but it doesn't appear that the games do this. Dobutsu no Mori uses hi16/lo16 relocs that
look like they're referencing other overlays, but the decomp project points out that the
compiler actually stapled a large offset onto those relocs. Additionally, the relocator
does not check if a virtual address belongs to the module it's loading or not.
As all evidence here shows this doesn't support a native import scheme, I'm leaving
import support out of this.

The Zelda community has reverse engineered these games almost completely so
there's not much point adding this to unpack64, but I have to be as thorough
as possible...

Decomp links for reference:
- https://github.com/zeldaret/oot
- https://github.com/zeldaret/mm
- https://github.com/zeldaret/af
    - https://github.com/zeldaret/af/blob/main/src/boot/O2/loadfragment2.c describes the loader scheme

Other references:
- https://wiki.cloudmodding.com/oot/Filesystem
- https://wiki.cloudmodding.com/oot/Overlays
- https://github.com/mzxrules/vg64tools/blob/master/n64/z_snippets/z_ovl_adapt.c
'''

import logging
import struct

from compression.yaz0 import yaz0_decompress

from .zeldavrom import zeldavrom_inflate_virtual_rom, zeldavrom_dmatable_present
from .zeldadll import ZeldaDllEntry, zeldadll_load_from_rom, zeldadll_parse_relocations

from bffi import Bffi,BffiBuilder
from n64rom import N64Rom
from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi, Preamble
from reloc import RelocatableBinary,  apply_relocations
from signature import SignatureBuilder, WILDCARD, Signature

logger = logging.getLogger(__name__)

SPAM = False

def _zelda_decode_dll_entries_generic(dll_table_blob: bytes,
                                      entry_consumer,
                                      max_entries: int | None = None,
                                      dedupe: bool = False) -> list[ZeldaDllEntry]:
    offset = 0
    entries: list[ZeldaDllEntry] = []
    while True:
        parsed_entry, num_bytes = entry_consumer(dll_table_blob[offset:])
        if num_bytes is None:
            logger.debug("end of table: offset 0x%08x", offset)
            break
        if parsed_entry is not None:
            entries.append(parsed_entry)

            if max_entries is not None and len(entries) >= max_entries:
                break

        offset += num_bytes

    # dedupe list on the way out
    return list(set(entries)) if dedupe else entries

# ------------------------------------------------
#
# Dobutsu no Mori (Animal Forest)
#
# Main executable is Yaz0 compressed.
#
# ------------------------------------------------

DOBUTSU_DMAMGR_INIT_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xe0,             # +0x00 addiu      sp,sp,-0x20
        0xaf, 0xbf, 0x00, 0x1c,             # +0x04 sw         ra,local_4(sp)
        0x3c, 0x04, 0x00, WILDCARD,         # +0x08 lui        a0,0x2 <-- ROM table start
        0x3c, 0x0e, 0x00, WILDCARD,         # +0x0C lui        t6,0x2 <-- ROM table end
        0x25, 0xce, WILDCARD, WILDCARD,     # +0x10 addiu      t6,t6,0x7130
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x14 addiu      a0,a0,-0x62c0
        0x3c, 0x05, 0x80, WILDCARD,         # lui        a1,0x8004
        0x24, 0xa5, WILDCARD, WILDCARD,     # addiu      a1=>DAT_80044690,a1,0x4690
        0x0c, WILDCARD, WILDCARD, WILDCARD, # jal        DmaMgr_DmaRomToRam
        0x01, 0xc4, 0x30, 0x23,             # _subu      a2,t6,a0
    ]) \
    .const_op32_hi16("rom_dma_table_start", 0x08) \
    .const_op32_lo16("rom_dma_table_start", 0x14) \
    .const_op32_hi16("rom_dma_table_end", 0x0C) \
    .const_op32_lo16("rom_dma_table_end", 0x10) \
    .build()

# see decomp, boot/idle.c, Main_ThreadEntry()
DOBUTSU_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x02, 0x00, WILDCARD,         # +0x00 lui        v0,0x67       <-- ROM start address
        0x3c, 0x0e, 0x00, WILDCARD,         # +0x04 lui        t6,0x74       <-- ROM end address
        0x24, 0x45, WILDCARD, WILDCARD,     # +0x08 addiu      a1,v0,0x5720
        0x25, 0xce, WILDCARD, WILDCARD,     # +0x0C addiu      t6,t6,-0xb30
        0x3c, 0x04, 0x80, WILDCARD,         # +0x10 lui        a0,0x8005     <-- load address
        0x3c, 0x07, 0x80, WILDCARD,         # +0x14 lui        a3,0x8004
        0x24, 0x0f, 0x00, 0x35,             # +0x18 li         t7,0x35
        0xaf, 0xaf, 0x00, 0x10,             # +0x1C sw         t7,0x10(sp)
        0x24, 0xe7, WILDCARD, WILDCARD,     # +0x20 addiu      a3,a3,-0x2e70
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x24 addiu      a0,a0,0x1a80
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x28 jal        DmaMgr_RequestSyncDebug
        0x01, 0xc5, 0x30, 0x23,             # +0x2C _subu      a2,t6,a1
        0x3c, 0x04, 0x80, WILDCARD,         # +0x30 lui        a0,0x8012     <-- BSS start
        0x3c, 0x18, 0x80, WILDCARD,         # +0x34 lui        t8,0x8015     <-- BSS end
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x38 addiu      a0,a0,-0x47d0
        0x27, 0x18, WILDCARD, WILDCARD,     # +0x3C addiu      t8,t8,0x24c0
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x40 jal        bzero
        0x03, 0x04, 0x28, 0x23,             # +0x44 _subu      a1,t8,a0
    ]) \
    .const_op32_hi16("yaz0_rom_start_address", 0x00) \
    .const_op32_lo16("yaz0_rom_start_address", 0x08) \
    .const_op32_hi16("yaz0_rom_end_address", 0x04) \
    .const_op32_lo16("yaz0_rom_end_address", 0x0C) \
    .const_op32_hi16("mainseg_load_address", 0x10) \
    .const_op32_lo16("mainseg_load_address", 0x24) \
    .const_op32_hi16("bss_start", 0x30) \
    .const_op32_lo16("bss_start", 0x38) \
    .const_op32_hi16("bss_end", 0x34) \
    .const_op32_lo16("bss_end", 0x3C) \
    .build()

# see decomp, src/code/graph.c, game_get_next_game_dlftbl()
DOBUTSU_GAMESTATE_DLL_TABLE_LOOKUP_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xe8,             # +0x00 addiu      sp,sp,-0x18
        0xaf, 0xbf, 0x00, 0x14,             # +0x04 sw         ra,local_4(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x08 jal        FUN_800d368c
        0x00, 0x00, 0x00, 0x00,             # +0x0C _nop
        0x3c, 0x0e, 0x80, 0x80,             # +0x10 lui        t6,0x8080
        0x25, 0xce, WILDCARD, WILDCARD,     # +0x14 addiu      t6,t6,0x2a2c
        0x14, 0x4e, WILDCARD, WILDCARD,     # +0x18 bne        v0,t6,LAB_800d3bb0
        0x8f, 0xbf, 0x00, 0x14,             # +0x1C _lw        ra,local_4(sp)
        0x3c, 0x02, 0x80, WILDCARD,         # +0x20 lui        v0,0x8010    <-- DLL table base
        0x10, 0x00, WILDCARD, WILDCARD,     # +0x24 b          LAB_800d3c8c
        0x24, 0x42, 0x6e, 0x20,             # +0x28 _addiu     v0,v0,0x6e20 
    ]) \
    .const_op32_hi16("dll_table_base", 0x20) \
    .const_op32_lo16("dll_table_base", 0x28) \
    .build()

# see decomp, src/code/m_actor.c, Actor_info_make_actor()
DOBUTSU_ACTOR_DLL_TABLE_LOOKUP_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0x90,         # +0x00 addiu      sp,sp,-0x70
        0xaf, 0xa6, 0x00, 0x78,         # +0x04 sw         param_3,local_res8(sp)
        0x00, 0x06, 0x34, 0x00,         # +0x08 sll        param_3,param_3,0x10
        0x00, 0x06, 0x34, 0x03,         # +0x0C sra        param_3,param_3,0x10
        0xaf, 0xbf, 0x00, 0x4c,         # +0x10 sw         ra,local_24(sp)
        0xaf, 0xb0, 0x00, 0x48,         # +0x14 sw         s0,local_28(sp)
        0xaf, 0xa4, 0x00, 0x70,         # +0x18 sw         param_1,local_res0(sp)
        0xaf, 0xa5, 0x00, 0x74,         # +0x1C sw         param_2,local_res4(sp)
        0xaf, 0xa7, 0x00, 0x7c,         # +0x20 sw         param_4,local_resc(sp)
        0x8f, 0xa8, 0x00, 0x70,         # +0x24 lw         t0,local_res0(sp)
        0x3c, 0x0f, 0x80, WILDCARD,     # +0x28 lui        t7,0x8010 <-- actor table base (entry 0 = dummy)
        0x25, 0xef, WILDCARD, WILDCARD, # +0x2C addiu      t7,t7,0xc90
    ]) \
    .const_op32_hi16("dll_table_base", 0x28) \
    .const_op32_lo16("dll_table_base", 0x2C) \
    .build()

# same struct for oot
def _dobutsu_consume_gamestate_dll_entry(data: bytes) -> tuple[ZeldaDllEntry, int]:
    _, vrom_start, vrom_end, vram_start, \
    vram_end, _, init_fcn_address, destroy_fcn_address, \
    _, _, _, _ = struct.unpack(">IIIIIIIIIIII", data[0:4*12])

    # skip blank entries (oot has several in its gamestate table)
    if vrom_start == vrom_end == vram_start == vram_end == 0:
        return None, 4*12

    if (vram_start & 0xFF800000) != 0x80800000:
        return None, None

    exports = {
        'init': init_fcn_address,
        'destroy': destroy_fcn_address
    }

    entry = ZeldaDllEntry(vrom_start,
                          vrom_end,
                          vram_start,
                          vram_end,
                          exports=exports)
    
    return entry, 4*12

# matches zelda oot structure too
def _dobutsu_consume_actor_dll_entry(data: bytes) -> tuple[ZeldaDllEntry, int]:

    vrom_start, vrom_end, vram_start, vram_end, \
    _, actor_profile_struct_addr, _, _ = struct.unpack(">IIIIIIII", data[0:4*8])

    # skip blank entries
    if vrom_start == vrom_end == vram_start == vram_end == 0:
        return None, 4*8

    if (vram_start & 0xFF800000) != 0x80800000:
        logger.debug("actor dll: breaking. vrom 0x%08x-0x%08x vram 0x%08x-0x%08x",
                     vrom_start,
                     vrom_end,
                     vram_start,
                     vram_end)
        return None, None
    
    entry = ZeldaDllEntry(vrom_start,
                          vrom_end,
                          vram_start,
                          vram_end)
    
    return entry, 4*8

def dobutsu_unpack(rom: N64Rom, ipc: int):
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    if zeldavrom_dmatable_present(rom, ipc, preamble) is False:
        return None

    logger.info("zelda dma table found!")

    builder = BffiBuilder()
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)

    bootexe = rom.boot_exe()[:earliest_bss-ipc]

    builder.fix(ipc, bootexe)
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.initial_stack_pointer(preamble.initial_stack_pointer())

    dma_init_pattern_offset = DOBUTSU_DMAMGR_INIT_PATTERN.find(bootexe)
    load_pattern_offset = DOBUTSU_LOAD_PATTERN.find(bootexe)
    if None in [ dma_init_pattern_offset, load_pattern_offset ]:
        return None

    logger.info("found Dobutsu no Mori mainthread at 0x%08x", ipc+load_pattern_offset)
    logger.info("DMA manager init at 0x%08x", ipc+dma_init_pattern_offset)

    consts = DOBUTSU_DMAMGR_INIT_PATTERN.consts(ipc, bootexe, dma_init_pattern_offset)
    rom_dma_table_start = consts["rom_dma_table_start"].get_value()
    rom_dma_table_end = consts["rom_dma_table_end"].get_value()
    
    logger.info("DMA table in ROM at 0x%08x-0x%08x",
                rom_dma_table_start,
                rom_dma_table_end)
    
    consts = DOBUTSU_LOAD_PATTERN.consts(ipc, bootexe, load_pattern_offset)
    yaz0_rom_start_address = consts["yaz0_rom_start_address"].get_value()
    yaz0_rom_end_address = consts["yaz0_rom_end_address"].get_value()
    mainseg_load_address = consts["mainseg_load_address"].get_value()
    bss_start = consts["bss_start"].get_value()
    bss_end = consts["bss_end"].get_value()

    logger.info("main segment Yaz0: ROM 0x%08x-0x%08x -> decompress to RAM 0x%08x (bss 0x%08x-0x%08x)",
                yaz0_rom_start_address,
                yaz0_rom_end_address,
                mainseg_load_address,
                bss_start,
                bss_end)

    logger.info("decompressing the payload...")
    payload = rom.read_bytes(yaz0_rom_start_address, yaz0_rom_end_address-yaz0_rom_start_address)
    payload = yaz0_decompress(payload)

    builder.bss(bss_start, bss_end-bss_start)
    builder.fix(mainseg_load_address, payload)

    # find gamestate DLLs
    gamestate_dll_lookup_offset = DOBUTSU_GAMESTATE_DLL_TABLE_LOOKUP_PATTERN.find(payload)
    if gamestate_dll_lookup_offset is None:
        logger.error("cannot find gamestate DLL lookup function")
        return None
    
    consts = DOBUTSU_GAMESTATE_DLL_TABLE_LOOKUP_PATTERN.consts(mainseg_load_address, payload, gamestate_dll_lookup_offset)
    gamestate_dll_table_base = consts["dll_table_base"].get_value()
    logger.info("gamestate dll table base at 0x%08x", gamestate_dll_table_base)

    # find actor DLLs
    actor_dll_lookup_offset = DOBUTSU_ACTOR_DLL_TABLE_LOOKUP_PATTERN.find(payload)
    if actor_dll_lookup_offset is None:
        logger.error("cannot find actor DLL lookup function")
        return None
    
    consts = DOBUTSU_ACTOR_DLL_TABLE_LOOKUP_PATTERN.consts(mainseg_load_address, payload, actor_dll_lookup_offset)
    actor_dll_table_base = consts["dll_table_base"].get_value() + (4*8) # because first entry is a dummy entry
    logger.info("actor dll table base at 0x%08x", actor_dll_table_base)


    logger.info("inflating virtual ROM...")
    virtual_rom = zeldavrom_inflate_virtual_rom(rom, rom_dma_table_start)

    gamestate_dll_entries = _zelda_decode_dll_entries_generic(payload[(gamestate_dll_table_base - mainseg_load_address):], _dobutsu_consume_gamestate_dll_entry)
    actor_dll_entries = _zelda_decode_dll_entries_generic(payload[(actor_dll_table_base - mainseg_load_address):], _dobutsu_consume_actor_dll_entry)


    modules: list[tuple[int,int,RelocatableBinary]] = []
    module_relocs: list[list[int]] = []
    for dll_entry in gamestate_dll_entries + actor_dll_entries:
        vrom_start = dll_entry.vrom_start()
        vrom_end   = dll_entry.vrom_end()
        vram_start = dll_entry.vram_start()
        vram_end   = dll_entry.vram_end()
        
        logger.info("found DLL module: VROM 0x%08x-0x%08x -> VRAM 0x%08x-0x%08x",
            vrom_start,
            vrom_end,
            vram_start,
            vram_end)
        
        dll_binary, reloc_words = zeldadll_load_from_rom(virtual_rom, vrom_start, vrom_end, vrom_end)

        if (vram_start+dll_binary.sizeof()) != vram_end:
            logger.info("adjusting vram_end from 0x%08x to 0x%08x", vram_end, vram_start+dll_binary.sizeof())

        modules.append((vram_start,vram_start+dll_binary.sizeof(),dll_binary))
        module_relocs.append(reloc_words)
    
    # now that modules are loaded, we can parse the reloc lists
    for i, modtuple in enumerate(modules):
        module_vram_start, _, module = modtuple

        logger.info("parse relocs for module #%d (=0x%08x)",
                    i,
                    modules[i][0])
        relocs = zeldadll_parse_relocations(module, module_vram_start, module_relocs[i])

        relocs_applied = apply_relocations(0,
                                           module,
                                           relocs,
                                           ignoring_offsets_in_binary=True)


        # TODO: define relocs/modules in the BFFI format
        builder.seg(0,
                    module.contents(),
                    i)

    return builder.build()

# ------------------------------------------------
#
# Zelda - Ocarina of Time
#
# The main code segment is compressed within the virtual ROM segment, so
# the full virtual ROM must be inflated first.
#
# ------------------------------------------------

ZELDA_OOT_MAIN_SEGMENT_RUNNER_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x07, 0x00, WILDCARD,         # +0x00 lui        a3,0xa8 <-- VROM start
        0x3c, 0x0e, 0x00, WILDCARD,         # +0x04 lui        t6,0xb9 <-- VROM end
        0x24, 0xe5, WILDCARD, WILDCARD,     # +0x08 addiu      a1,a3,0x7000
        0x25, 0xce, WILDCARD, WILDCARD,     # +0x0C addiu      t6,t6,-0x52d0
        0x3c, 0x04, 0x80, WILDCARD,         # +0x10 lui        a0,0x8001 <-- load address
        0xaf, 0xa2, 0x00, 0x18,             # +0x14 sw         v0,0x18(sp)
        0xaf, 0xa3, 0x00, 0x1c,             # +0x18 sw         v1,0x1c(sp)
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x1C addiu      a0,a0,0x10a0
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x20 jal        FUN_80000df0   
        0x01, 0xc5, 0x30, 0x23,             # +0x24 _subu      a2,t6,a1
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x28 jal        FUN_800048c0
        0x00, 0x00, 0x00, 0x00,             # +0x2C _nop
        0x8f, 0xb8, 0x00, 0x18,             # +0x30 lw         t8,0x18(sp)
        0x8f, 0xb9, 0x00, 0x1c,             # +0x34 lw         t9,0x1c(sp)
        0x3c, 0x04, 0x80, WILDCARD,         # +0x38 lui        a0,0x8011 <-- main segment BSS start
        0x3c, 0x0f, 0x80, WILDCARD,         # +0x3C lui        t7,0x8013 <-- main segment BSS end
        0x03, 0x02, 0x40, 0x23,             # +0x40 subu       t0,t8,v0
        0x03, 0x23, 0x08, 0x2b,             # +0x44 sltu       at,t9,v1
        0x01, 0x01, 0x40, 0x23,             # +0x48 subu       t0,t0,at
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x4C addiu      a0,a0,0x4dd0
        0x25, 0xef, WILDCARD, WILDCARD,     # +0x50 addiu      t7,t7,-0x41d0
        0x03, 0x23, 0x48, 0x23,             # +0x54 subu       t1,t9,v1
        0xaf, 0xa9, 0x00, 0x1c,             # +0x58 sw         t1,0x1c(sp)
        0xaf, 0xa8, 0x00, 0x18,             # +0x5C sw         t0,0x18(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x60 jal        bzero         
        0x01, 0xe4, 0x28, 0x23,             # +0x64 _subu      a1,t7,a0
    ]) \
    .const_op32_hi16("vrom_start", 0x00) \
    .const_op32_lo16("vrom_start", 0x08) \
    .const_op32_hi16("vrom_end", 0x04) \
    .const_op32_lo16("vrom_end", 0x0C) \
    .const_op32_hi16("load_address", 0x10) \
    .const_op32_lo16("load_address", 0x1C) \
    .const_op32_hi16("bss_start", 0x38) \
    .const_op32_lo16("bss_start", 0x4C) \
    .const_op32_hi16("bss_end", 0x3C) \
    .const_op32_lo16("bss_end", 0x50) \
    .build()

# see decomp, src/code/graph.c, Graph_ThreadEntry() (v1.0 US @ 0x800a1934)
ZELDA_OOT_GAMESTATE_DLL_TABLE_LOOKUP_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xfc, 0xc8,         # +0x00 addiu      sp,sp,-0x338
        0xaf, 0xb0, 0x00, 0x18,         # +0x04 sw         s0,local_320(sp)
        0x3c, 0x10, 0x80, WILDCARD,     # +0x08 lui        s0,0x800f <-- gamestate dll table address
        0xaf, 0xb1, 0x00, 0x1c,         # +0x0C sw         s1,local_31c(sp)
        0x27, 0xb1, 0x00, 0x40,         # +0x10 addiu      s1,sp,0x40
        0x26, 0x10, WILDCARD, WILDCARD, # +0x14 addiu      s0,s0,0x1340
        0xaf, 0xbf, 0x00, 0x2c,         # +0x18 sw         ra,local_30c(sp)
        0xaf, 0xb4, 0x00, 0x28,         # +0x1C sw         s4,local_310(sp)
        0xaf, 0xb3, 0x00, 0x24,         # +0x20 sw         s3,local_314(sp)
        0xaf, 0xb2, 0x00, 0x20,         # +0x24 sw         s2,local_318(sp)
        0xaf, 0xa4, 0x03, 0x38,         # +0x28 sw         a0,local_res0(sp)
    ]) \
    .const_op32_hi16("dll_table_base", 0x08) \
    .const_op32_lo16("dll_table_base", 0x14) \
    .build()

# see decomp, src/code/z_actor.c, Actor_Spawn(). (v1.0 US @ 0x80025110)
# code similar to dobutsu's actor loader but the function does a lot more
ZELDA_OOT_ACTOR_DLL_TABLE_LOOKUP_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xa8,         # +0x00 addiu      sp,sp,-0x58
        0xaf, 0xa6, 0x00, 0x60,         # +0x04 sw         param_3,local_res8(sp)
        0x00, 0x06, 0x34, 0x00,         # +0x08 sll        param_3,param_3,0x10
        0x00, 0x06, 0x34, 0x03,         # +0x0C sra        param_3,param_3,0x10
        0xaf, 0xbf, 0x00, 0x24,         # +0x10 sw         ra,local_34(sp)
        0xaf, 0xb0, 0x00, 0x20,         # +0x14 sw         s0,local_38(sp)
        0xaf, 0xa4, 0x00, 0x58,         # +0x18 sw         param_1,local_res0(sp)
        0xaf, 0xa5, 0x00, 0x5c,         # +0x1C sw         param_2,local_res4(sp)
        0xaf, 0xa7, 0x00, 0x64,         # +0x20 sw         param_4,local_resc(sp)
        0x8f, 0xb9, 0x00, 0x58,         # +0x24 lw         t9,local_res0(sp)
        0x3c, 0x0f, 0x80, WILDCARD,     # +0x28 lui        t7,0x800f
        0x25, 0xef, WILDCARD, WILDCARD, # +0x2C addiu      t7,t7,-0x7ad0
    ]) \
    .const_op32_hi16("dll_table_base", 0x28) \
    .const_op32_lo16("dll_table_base", 0x2C) \
    .build()


def zeldaoot_unpack(rom: N64Rom, ipc: int):
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    if zeldavrom_dmatable_present(rom, ipc, preamble) is False:
        return None

    logger.info("zelda dma table found!")

    builder = BffiBuilder()
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)

    bootexe = rom.boot_exe()[:earliest_bss-ipc]

    builder.fix(ipc, bootexe)
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.initial_stack_pointer(preamble.initial_stack_pointer())

    main_segment_runner_offset = ZELDA_OOT_MAIN_SEGMENT_RUNNER_PATTERN.find(bootexe)
    if main_segment_runner_offset is None:
        return None

    logger.info("found Zelda OoT main segment runner at 0x%08x",
                ipc+main_segment_runner_offset)


    consts = ZELDA_OOT_MAIN_SEGMENT_RUNNER_PATTERN.consts(ipc, bootexe, main_segment_runner_offset)
    vrom_start = consts["vrom_start"].get_value()
    vrom_end = consts["vrom_end"].get_value()
    load_address = consts["load_address"].get_value()
    bss_start = consts["bss_start"].get_value()
    bss_end = consts["bss_end"].get_value()

    logger.info("main segment: VROM 0x%08x-0x%08x -> RAM 0x%08x (bss 0x%08x-0x%08x)",
                vrom_start,
                vrom_end,
                load_address,
                bss_start,
                bss_end)

    logger.info("inflating virtual ROM... (this will take a bit)")
    virtual_rom = zeldavrom_inflate_virtual_rom(rom, (earliest_bss-ipc) + 0x1000)

    main_segment = virtual_rom.read_bytes(vrom_start, vrom_end - vrom_start)
    builder.fix(load_address, main_segment)

    # find gamestate DLLs
    gamestate_dll_lookup_offset = ZELDA_OOT_GAMESTATE_DLL_TABLE_LOOKUP_PATTERN.find(main_segment)
    if gamestate_dll_lookup_offset is None:
        logger.error("cannot find gamestate DLL lookup function")
        return None
    
    consts = ZELDA_OOT_GAMESTATE_DLL_TABLE_LOOKUP_PATTERN.consts(load_address, main_segment, gamestate_dll_lookup_offset)
    gamestate_dll_table_base = consts["dll_table_base"].get_value() + (4*12) # because first entry is a dummy entry
    logger.info("gamestate dll table base at 0x%08x", gamestate_dll_table_base)

    # find actor DLL table
    actor_dll_lookup_offset = ZELDA_OOT_ACTOR_DLL_TABLE_LOOKUP_PATTERN.find(main_segment)
    if actor_dll_lookup_offset is None:
        logger.error("cannot find actor DLL lookup function")
        return None
    
    consts = ZELDA_OOT_ACTOR_DLL_TABLE_LOOKUP_PATTERN.consts(load_address, main_segment, actor_dll_lookup_offset)
    actor_dll_table_base = consts["dll_table_base"].get_value() + (4*8) # because first entry is a dummy entry
    logger.info("actor dll table base at 0x%08x", actor_dll_table_base)

    # skipping first entry of gamestate table because there's a null entry there
    gamestate_dll_entries = _zelda_decode_dll_entries_generic(main_segment[(gamestate_dll_table_base - load_address):],
                                                              _dobutsu_consume_gamestate_dll_entry)

    logger.info("got %d gamestate dlls", len(gamestate_dll_entries))

    # oot v1.0 actor list contains 0x1D6 entries, many are unused
    # so there should be approx 426 entries dumped from this table.
    # see https://wiki.cloudmodding.com/oot/Actor_Overlay_Table/NTSC_1.0
    actor_dll_entries = _zelda_decode_dll_entries_generic(main_segment[(actor_dll_table_base - load_address):], _dobutsu_consume_actor_dll_entry)
    logger.info("got %d actor dlls", len(actor_dll_entries))

    # TODO: other overlay types

    modules: list[tuple[int,int,RelocatableBinary]] = []
    module_relocs: list[list[int]] = []
    for dll_entry in gamestate_dll_entries + actor_dll_entries:
        vrom_start = dll_entry.vrom_start()
        vrom_end   = dll_entry.vrom_end()
        vram_start = dll_entry.vram_start()
        vram_end   = dll_entry.vram_end()
        
        logger.info("found DLL module: VROM 0x%08x-0x%08x -> VRAM 0x%08x-0x%08x",
            vrom_start,
            vrom_end,
            vram_start,
            vram_end)
        
        dll_binary, reloc_words = zeldadll_load_from_rom(virtual_rom, vrom_start, vrom_end)

        if (vram_start+dll_binary.sizeof()) != vram_end:
            logger.info("adjusting vram_end from 0x%08x to 0x%08x", vram_end, vram_start+dll_binary.sizeof())

        modules.append((vram_start,vram_start+dll_binary.sizeof(),dll_binary))
        module_relocs.append(reloc_words)
    
    # now that modules are loaded, we can parse the reloc lists
    for i, modtuple in enumerate(modules):
        module_vram_start, _, module = modtuple

        logger.info("parse relocs for module #%d (=0x%08x)",
                    i,
                    modules[i][0])
        relocs = zeldadll_parse_relocations(module, module_vram_start, module_relocs[i])

        relocs_applied = apply_relocations(0,
                                           module,
                                           relocs,
                                           ignoring_offsets_in_binary=True,
                                           bal_for_jal=True)


        # TODO: define relocs/modules in the BFFI format
        builder.seg(0,
                    module.contents(),
                    i)


    return builder.build()
