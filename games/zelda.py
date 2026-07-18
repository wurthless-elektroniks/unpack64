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

from bffi import Bffi,BffiBuilder
from datautil import unpack_uint32_be
from n64rom import N64Rom, ROMENDIANNESS_BIG
from mips import decode_imm16_rt_rs_target_register, decode_imm16_rt_rs_offset_register
from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi, Preamble
from reloc import RelocSection, RelocType, Reloc, RelocatableBinary, demunge_mips_hilo_offset
from signature import SignatureBuilder, WILDCARD, Signature
from sigutil import pick_pattern, contains_code

logger = logging.getLogger(__name__)

SPAM = False

ZELDA_RELOC_SECTION_TYPES_LUT = {
    # 0 is illegal
    1: RelocSection.TEXT,
    2: RelocSection.DATA,
    3: RelocSection.RODATA
    # some docs mention BSS, but that's impossible because the sectiontype field is only 2 bits
}

# matches ELF standard
ZELDA_RELOC_TYPES_LUT = {
    2: RelocType.R_MIPS_32,
    4: RelocType.R_MIPS_26,
    5: RelocType.R_MIPS_HI16,
    6: RelocType.R_MIPS_LO16
}

# the parser keeps track of which hi16/lo16 pairings go to which registers
# so it's better for us to use a dedicated class for hi16 stuff
class ZeldaHi16:
    def __init__(self,
                 instruction: int,
                 section: RelocSection,
                 offset: int):
        
        self._instruction = instruction
        self._section = section
        self._offset = offset
        self._applied = False

    def instruction(self):
        return self._instruction
    
    def section(self):
        return self._section
    
    def offset(self):
        return self._offset

    def applied(self, new_applied: bool | None = False):
        if new_applied is not None:
            self._applied = new_applied
        return self._applied

# generic; can be adapted for different datastructures.
class ZeldaDllEntry:
    def __init__(self,
                 vrom_start: int,
                 vrom_end: int,
                 vram_start: int,
                 vram_end: int,
                 exports: dict[str,int] = {}):
        self._vrom_start = vrom_start
        self._vrom_end = vrom_end
        self._vram_start = vram_start
        self._vram_end = vram_end
        self._exports = exports

    def vrom_start(self):
        return self._vrom_start

    def vrom_end(self):
        return self._vrom_end

    def vram_start(self):
        return self._vram_start
    
    def vram_end(self):
        return self._vram_end

    def exports(self):
        return dict(self._exports)

# ------------------------------------------------
#
# Common stuff: virtual ROM setup, relocations, etc.
#
# ------------------------------------------------

def _zelda_framework_signature_matches(first_16: bytes):
    return first_16 == bytes([0x00,0x00,0x00,0x00,
                              0x00,0x00,0x10,0x60,
                              0x00,0x00,0x00,0x00,
                              0x00,0x00,0x00,0x00,
                            ])

def _zelda_framework_is_used(rom: N64Rom,
                             ipc: int,
                             preamble: Preamble):

    # DMA table immediately follows boot segment in ROM
    # this is true for zelda oot, dobutsu
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, None)
    dmatable_rom_offset = (earliest_bss - ipc) + 0x1000

    first_16 = rom.read_bytes(dmatable_rom_offset, 0x10)
    return _zelda_framework_signature_matches(first_16)

def _zelda_parse_dma_table(rom: N64Rom,
                           dmadata_table_offset: int):
    
    table_entries = []
    vrom_sizeof = 0

    while True:
        vrom_start, \
        vrom_end, \
        prom_start, \
        prom_end = struct.unpack(">IIII", rom.read_bytes(dmadata_table_offset, 0x10))

        dmadata_table_offset += 0x10

        # if all zero, treat as EOF (animal forest does this)
        if vrom_start == vrom_end == prom_start == prom_end == 0:
            break
        
        if vrom_sizeof > vrom_end:
            raise RuntimeError("vrom entries appear to be out of order... report bug")

        table_entries.append( (vrom_start, vrom_end, prom_start, prom_end) )
    
    return table_entries

# the zelda framework has a "virtual ROM" setup where data can be addressed
# within compressed blobs or at arbitrary ROM addresses.
# typically the dmatable is located right after the bootexe.
def _zelda_inflate_virtual_rom(rom: N64Rom,
                               dmadata_table_offset: int) -> N64Rom:
    # tuple: address -> data
    vrom_chunks: list[tuple[int,bytes]] = []

    vrom_sizeof = 0

    # first entry is the ROM header, IPL3 stub, and preamble.
    first_16 = rom.read_bytes(dmadata_table_offset, 0x10)
    if _zelda_framework_signature_matches(first_16) is False:
        raise RuntimeError("zelda dma table didn't match expected format")

    table_entries = _zelda_parse_dma_table(rom, dmadata_table_offset)
    vrom_sizeof = table_entries[-1][1]
    logger.info("vrom size is %d (0x%08x) byte(s)",
                vrom_sizeof,
                vrom_sizeof)

    for vrom_start, vrom_end, prom_start, prom_end in table_entries:
        # if prom_end == 0, file's uncompressed, else it's Yaz0 compressed
        if prom_start == prom_end == 0xFFFFFFFF:
            # majora's mask: prom_start/prom_end being -1 means file is unwired.
            # fill that region with zeroes instead
            if SPAM:
                logger.info("VROM 0x%08x-0x%08x: file entry is unwired", vrom_start, vrom_end)

            sizeof = vrom_end - vrom_start
            vrom_chunks.append( (vrom_start, bytes([0] * sizeof)) )

        if prom_end == 0:
            sizeof = vrom_end - vrom_start
            data = rom.read_bytes(prom_start, sizeof)

            if SPAM:
                logger.info("VROM 0x%08x-0x%08x = uncompressed 0x%08x-0x%08x",
                            vrom_start,
                            vrom_end,
                            prom_start,
                            prom_start + sizeof)
            
            vrom_chunks.append( (vrom_start, data) )

        else:
            sizeof = prom_end - prom_start
            data = rom.read_bytes(prom_start, sizeof)
            
            # should be Yaz0 (iQue games use zlib, but I am not supporting them)
            data = yaz0_decompress(data)

            if data is None:
                raise RuntimeError("compressed chunk in vrom was NOT Yaz0")

            if SPAM:
                logger.info("VROM 0x%08x-0x%08x = Yaz0 at 0x%08x-0x%08x",
                            vrom_start,
                            vrom_end,
                            prom_start,
                            prom_end)

            vrom_chunks.append( (vrom_start, data) )

    # now build the VROM
    vrom_data = bytearray([0] * vrom_sizeof)
    for vrom_address, data in vrom_chunks:
        vrom_data[vrom_address:vrom_address+len(data)] = data

    # what we should do here is patch the table now that all resources are
    # uncompressed, but that won't do much because the games might hardcode
    # addresses to random resources including the main game code.
    # so let's just return the virtual ROM

    return N64Rom(vrom_data, ROMENDIANNESS_BIG)

def _zelda_lookup_binary_id_by_virtual_address(address: int,
                                               all_binaries: list[tuple[int,int,RelocatableBinary]]) -> int | None:
    for i, tup in enumerate(all_binaries):
        vram_start, vram_end, _ = tup
        if vram_start <= address < vram_end:
            return i
    return None

def _zelda_parse_relocations(binary: RelocatableBinary,
                             reloc_words: list[int],
                             all_binaries: list[int,int,RelocatableBinary]):

    #
    # bits 31,30 are section IDs.
    #
    # %00 - illegal (give up)
    # %01 - .text
    # %10 - .data
    # %11 - .rodata
    # 
    # bits 29-24: reloc type. should match ELF standard, or problems will happen.
    # imm32, imm26, hi16, lo16 are to be expected.
    #
    # bits 23-0: offset within section of reloc
    #
    # the target offsets are absolute offsets in virtual RAM, so we have to keep track
    # of where each binary loads (hence all_binaries). if there's a call outside of the
    # current module's range, we treat it as an import.
    #
    # after parsing the relocs, the target absolute offsets have to be destroyed prior to
    # applying the reloc list we've just generated. this function does not do that because
    # that's an unwanted side-effect.
    #

    hi16s: dict[int,ZeldaHi16] = {}
    relocs = []

    for reloc_word in reloc_words:
        reloc_section_raw = reloc_word >> 30
        if reloc_section_raw == 0:
            raise RuntimeError("illegal reloc entry: section type was 0")

        reloc_section = ZELDA_RELOC_SECTION_TYPES_LUT[reloc_section_raw]
        reloc_type    = ZELDA_RELOC_TYPES_LUT[(reloc_word & 0x3F000000) >> 24]
        reloc_offset  = reloc_word & 0x00FFFFFF

        reloc_absolute_offset = binary.section_base_offset(reloc_section) + reloc_offset

        original_instruction = binary.read32(reloc_absolute_offset)

        if reloc_type == RelocType.R_MIPS_26:
            target_absolute_offset = ((original_instruction & 0x03FFFFFF) << 2) + 0x80000000

            bin_id = _zelda_lookup_binary_id_by_virtual_address(target_absolute_offset,
                                                                all_binaries)
            if bin_id is None:
                raise RuntimeError(f"R_MIPS_26: import from not-yet-loaded module at address 0x{target_absolute_offset:08x}")

            remote_bin              = all_binaries[bin_id][2]
            remote_bin_load_address = all_binaries[bin_id][0]
            module_id = -1 if remote_bin == binary else bin_id

            target_section, target_offset = remote_bin.absolute_offset_to_section_and_offset(target_absolute_offset - remote_bin_load_address)            
            
            if None in [target_section, target_offset]:
                raise RuntimeError(f"illegal target offset {target_absolute_offset:08x} opcode {original_instruction:08x}")

            relocs.append( Reloc(RelocType.R_MIPS_26,
                                 reloc_section,
                                 reloc_offset,
                                 target_section,
                                 target_offset,
                                 target_module_id=module_id
                                 ))
        
        elif reloc_type == RelocType.R_MIPS_32:
            target_absolute_offset = original_instruction

            bin_id = _zelda_lookup_binary_id_by_virtual_address(target_absolute_offset,
                                                                all_binaries)
            if bin_id is None:
                raise RuntimeError(f"R_MIPS_32: import from not-yet-loaded module at address 0x{target_absolute_offset:08x}")

            remote_bin              = all_binaries[bin_id][2]
            remote_bin_load_address = all_binaries[bin_id][0]
            module_id = -1 if remote_bin == binary else bin_id

            target_section, target_offset = remote_bin.absolute_offset_to_section_and_offset(target_absolute_offset - remote_bin_load_address)
            if None in [target_section, target_offset]:
                raise RuntimeError(f"illegal target offset! vram address = 0x{target_absolute_offset:08x}")

            relocs.append( Reloc(RelocType.R_MIPS_32,
                                 reloc_section,
                                 reloc_offset,
                                 target_section,
                                 target_offset
                                 ))

        elif reloc_type == RelocType.R_MIPS_HI16:
            # queue for incoming lo16; do not decode yet
            register = decode_imm16_rt_rs_target_register(original_instruction)

            hi16s[register] = \
                ZeldaHi16(original_instruction,
                          reloc_section,
                          reloc_offset)

        elif reloc_type == RelocType.R_MIPS_LO16:
            offset_register = decode_imm16_rt_rs_offset_register(original_instruction)
            if offset_register not in hi16s:
                raise RuntimeError("lo16 without matching hi16!")

            hi16 = hi16s[offset_register]
            last_hi16_instruction = hi16.instruction()
            target_absolute_offset = demunge_mips_hilo_offset(last_hi16_instruction, original_instruction)
            
            bin_id = _zelda_lookup_binary_id_by_virtual_address(target_absolute_offset,
                                                                all_binaries)
            if bin_id is None:
                raise RuntimeError(f"R_MIPS_HI16/R_MIPS_LO16: import from not-yet-loaded module at address 0x{target_absolute_offset:08x}")

            remote_bin              = all_binaries[bin_id][2]
            remote_bin_load_address = all_binaries[bin_id][0]
            module_id = -1 if remote_bin == binary else bin_id

            target_section, target_offset = remote_bin.absolute_offset_to_section_and_offset(target_absolute_offset - remote_bin_load_address)
            if None in [target_section, target_offset]:
                raise RuntimeError(f"hi16/lo16: illegal target offset. absolute target +0x{target_absolute_offset:06x} hi16 {last_hi16_instruction:08x} lo16 {original_instruction:08x}")

            if hi16.applied() is False:
                relocs.append(Reloc(RelocType.R_MIPS_HI16,
                                    hi16.section(),
                                    hi16.offset(),
                                    target_section,
                                    target_offset,
                                    target_module_id = module_id))
                hi16.applied(True)

            relocs.append(Reloc(RelocType.R_MIPS_LO16,
                reloc_section,
                reloc_offset,
                target_section,
                target_offset,
                target_module_id = module_id))
        else:
            raise RuntimeError("illegal reloc type")

    return relocs

def _zelda_load_dll_from_rom(rom: N64Rom,
                             dll_code_start_offset: int,
                             dll_code_end_offset: int,
                             dll_headers_offset: int) -> tuple[RelocatableBinary,list[int]]:
    headers = rom.read_bytes(dll_headers_offset, 0x14)

    text_size, data_size, rodata_size, bss_size, num_relocs = \
                struct.unpack(">IIIII", headers)
    
    # relocs will be parsed later, since we don't know if this DLL calls other modules yet.
    # for now, dump them to ints so they can be enumerated easily.
    relocs_bytes = rom.read_bytes(dll_headers_offset + 0x14, num_relocs * 4)
    relocs = []
    for i in range(num_relocs):
        relocs.append( unpack_uint32_be(relocs_bytes[i*4:(i+1)*4]) )

    bindata = rom.read_bytes(dll_code_start_offset, dll_code_end_offset-dll_code_start_offset) + bytes([0] * bss_size)

    # binary is flattened already, so the order will be text/data/rodata, in that order
    segment_ranges = []
    offs = 0
    for section_type, section_size in [
        (RelocSection.TEXT, text_size),
        (RelocSection.DATA, data_size),
        (RelocSection.RODATA, rodata_size),
        (RelocSection.BSS, bss_size)
        ]:
        if section_size == 0:
            continue

        segment_ranges.append( (offs, offs + section_size, section_type) )
        offs += section_size

    bin = RelocatableBinary(bindata, segment_ranges)
    return bin, relocs

def _zelda_decode_dll_entries_generic(dll_table_blob: bytes, entry_consumer) -> list[ZeldaDllEntry]:
    offset = 0
    entries = []
    while True:
        parsed_entry, num_bytes = entry_consumer(dll_table_blob[offset:])
        if parsed_entry is None:
            return entries
        entries.append(parsed_entry)
        offset += num_bytes

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

def _dobutsu_consume_gamestate_dll_entry(data: bytes) -> tuple[ZeldaDllEntry, int]:
    _, vrom_start, vrom_end, vram_start, \
    vram_end, _, init_fcn_address, destroy_fcn_address, \
    _, _, _, _ = struct.unpack(">IIIIIIIIIIII", data[0:4*12])

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


def dobutsu_unpack(rom: N64Rom, ipc: int):
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    if _zelda_framework_is_used(rom, ipc, preamble) is False:
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
    dll_lookup_offset = DOBUTSU_GAMESTATE_DLL_TABLE_LOOKUP_PATTERN.find(payload)
    if dll_lookup_offset is None:
        logger.error("cannot find gamestate DLL lookup function")
        return None
    
    consts = DOBUTSU_GAMESTATE_DLL_TABLE_LOOKUP_PATTERN.consts(mainseg_load_address, payload, dll_lookup_offset)
    dll_table_base = consts["dll_table_base"].get_value()
    logger.info("gamestate dll table base at 0x%08x", dll_table_base)

    logger.info("inflating virtual ROM...")
    virtual_rom = _zelda_inflate_virtual_rom(rom, rom_dma_table_start)

    gamestate_dll_entries = _zelda_decode_dll_entries_generic(payload[(dll_table_base - mainseg_load_address):], _dobutsu_consume_gamestate_dll_entry)

    modules: list[tuple[int,int,RelocatableBinary]] = []
    module_relocs: list[list[int]] = []
    for gamestate_dll_entry in gamestate_dll_entries:
        vrom_start = gamestate_dll_entry.vrom_start()
        vrom_end   = gamestate_dll_entry.vrom_end()
        vram_start = gamestate_dll_entry.vram_start()
        vram_end   = gamestate_dll_entry.vram_end()
        
        logger.info("game segment: VROM 0x%08x-0x%08x -> VRAM 0x%08x-0x%08x",
            vrom_start,
            vrom_end,
            vram_start,
            vram_end)
        
        gameseg_dll_binary, gameseg_reloc_words = _zelda_load_dll_from_rom(virtual_rom, vrom_start, vrom_end, vrom_end)

        modules.append((vram_start,vram_end,gameseg_dll_binary))
        module_relocs.append(gameseg_reloc_words)
    
    # now that modules are loaded, we can parse the reloc lists
    for i, modtuple in enumerate(modules):
        _, _, module = modtuple

        relocs = _zelda_parse_relocations(module, module_relocs[i], modules)
        for reloc in relocs:
            logger.debug("%s", reloc)

    # TODO: define relocs/modules in the BFFI format

    return builder.build()
