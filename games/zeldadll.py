'''
Dynamically loaded overlay scheme used by the Zelda 64 framework

Split out of zelda.py to keep that shorter (we have to add game-specific signature matching
for all the overlay table types...)
'''

import logging
import struct

from datautil import unpack_uint32_be
from mips import decode_imm16_rt_rs_target_register, decode_imm16_rt_rs_offset_register
from n64rom import N64Rom, ROMENDIANNESS_BIG
from reloc import RelocSection, RelocType, Reloc, RelocatableBinary, demunge_mips_hilo_offset, apply_relocations

logger = logging.getLogger(__name__)

# ------------------------------------------------

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

    def __eq__(self, value):
        if not isinstance(value, ZeldaDllEntry):
            return False

        return self._vrom_start == value.vrom_start() and \
               self._vrom_end   == value.vrom_end() and \
               self._vram_start == value.vram_start() and \
               self._vram_end   == value.vram_end()

    def __hash__(self):
        return hash(f"{self._vrom_start}/{self._vrom_end}/{self._vram_start}/{self._vram_end}")

def zeldadll_parse_relocations(binary: RelocatableBinary,
                               binary_vram_start: int,
                               reloc_words: list[int]):

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

    last_hi16_register = None

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

            target_section, target_offset = binary.absolute_offset_to_section_and_offset(target_absolute_offset - binary_vram_start)            
            
            if None in [target_section, target_offset]:
                raise RuntimeError(f"illegal target offset {target_absolute_offset:08x} opcode {original_instruction:08x}")
                
            relocs.append( Reloc(RelocType.R_MIPS_26,
                                 reloc_section,
                                 reloc_offset,
                                 target_section,
                                 target_offset
                                 ))
        
        elif reloc_type == RelocType.R_MIPS_32:
            target_absolute_offset = original_instruction

            target_section, target_offset = binary.absolute_offset_to_section_and_offset(target_absolute_offset - binary_vram_start)   
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

            target_section, target_offset = binary.absolute_offset_to_section_and_offset(target_absolute_offset - binary_vram_start)
            if None in [target_section, target_offset]:
                # dlls will often reference addresses out of bounds as compiler optimizations.
                # for those, pick the last section before/after that offset and use that as the relative target
                target_section       = binary.section_types_present()[0 if target_absolute_offset < binary_vram_start else -1]
                target_section_base  = binary_vram_start + binary.section_base_offset(target_section)

                target_offset = target_absolute_offset - target_section_base

                logger.warning("hi16/lo16, %s%#+6x reference to absolute offset 0x%08x, which is out of bounds. reloc will point to %s%#+6x.",
                               reloc_section.printable(),
                               reloc_offset,
                               target_absolute_offset,
                               target_section.printable(),
                               target_offset)

            # write hi16 entry if the offset register changed from the last hi16 reloc,
            # or if it hasn't been applied yet
            if offset_register != last_hi16_register or not hi16.applied():
                relocs.append(Reloc(RelocType.R_MIPS_HI16,
                                hi16.section(),
                                hi16.offset(),
                                target_section,
                                target_offset))

                last_hi16_register = offset_register
                hi16.applied(True)
                    
            relocs.append(Reloc(RelocType.R_MIPS_LO16,
                reloc_section,
                reloc_offset,
                target_section,
                target_offset))
        else:
            raise RuntimeError("illegal reloc type")

    return relocs

def zeldadll_load_from_rom(rom: N64Rom,
                             dll_code_start_offset: int,
                             dll_code_end_offset: int,
                             dll_headers_offset: int | None = None) -> tuple[RelocatableBinary,list[int]]:

    # dobutsu stores its headers in a different block, but oot doesn't.
    if dll_headers_offset is None:
        backseek = unpack_uint32_be( rom.read_bytes(dll_code_end_offset - 4, 4) )
        logger.debug("header backseek value: 0x%08x", backseek)
        dll_headers_offset = dll_code_end_offset - backseek

        # move this pointer back so we don't need to write the relocation data again
        dll_code_end_offset = dll_headers_offset

    headers = rom.read_bytes(dll_headers_offset, 0x14)

    text_size, data_size, rodata_size, bss_size, num_relocs = \
                struct.unpack(">IIIII", headers)
    
    # relocs will be parsed later, since we don't know if this DLL calls other modules yet.
    # for now, dump them to ints so they can be enumerated easily.
    relocs_bytes = rom.read_bytes(dll_headers_offset + 0x14, num_relocs * 4)
    relocs = []

    logger.debug("found %d reloc(s)", num_relocs)
    for i in range(num_relocs):
        relocs.append( unpack_uint32_be(relocs_bytes[i*4:(i+1)*4]) )

    bindata = rom.read_bytes(dll_code_start_offset, dll_code_end_offset-dll_code_start_offset) + bytes([0] * bss_size)

    if bss_size != 0:
        logger.info("bss adjust: sizeof before %d, sizeof after %d",
                    dll_code_end_offset-dll_code_start_offset,
                    len(bindata))

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

    if len(bindata) != offs:
        raise RuntimeError("dll size mismatch")

    bin = RelocatableBinary(bindata, segment_ranges)
    return bin, relocs
