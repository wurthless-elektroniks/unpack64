'''
Common relocation utilty code for stuff that needs it.
'''

import logging
from enum import Enum
import struct

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------------------------

# these match the ELF standard
# only imm32, imm26, hi16 and lo16 should be seen in N64 games
class RelocType(Enum):
    R_MIPS_32      = 2
    R_MIPS_26      = 4
    R_MIPS_HI16    = 5
    R_MIPS_LO16    = 6

class RelocSection(Enum):
    TEXT   = 0
    RODATA = 1
    DATA   = 2
    BSS    = 3

    def printable(self):
        return f".{self.name.lower()}"

class Reloc:
    def __init__(self,
                 type: RelocType,
                 section: RelocSection,
                 section_offset: int,
                 target_section: RelocSection,
                 target_section_offset: int,
                 target_module_id: int = -1
                 ):
        '''
        
        - target_module_id: If not -1, then the target is in another module that may or
          may not be loaded when the relocation is to be applied. Default is -1
          (reloc is local).
        '''

        self._type             = type
        self._section          = section
        self._section_offset   = section_offset
        self._target_module_id = target_module_id
        self._target_section   = target_section
        self._target_section_offset = target_section_offset

    def type(self):
        return self._type

    def section(self) -> RelocSection:
        return self._section

    def section_offset(self) -> int:
        return self._section_offset

    def target_module_id(self) -> int:
        return self._target_module_id
    
    def target_section(self) -> RelocSection:
        return self._target_section
    
    def target_section_offset(self) -> int:
        return self._target_section_offset

# to be fed into apply_relocations() to enforce pass-by-reference
# and to simplify calling
class RelocatableBinary:
    def __init__(self,
                 contents: bytes,
                 section_base_offsets: dict[RelocSection,int]):

        self._contents = bytearray(contents)
        self._section_base_offsets = section_base_offsets
        pass

    def section_base_offset(self, section: RelocSection):
        return self._section_base_offsets[section]
    
    def read32(self, offset: int) -> int:
        return struct.unpack(">I", self._contents[offset:offset+4])[0]

    def write32(self, offset: int, data: int | bytes):
        if isinstance(data, bytes):
            if len(data) != 4:
                raise RuntimeError("write32: len(data) != 4")
            self._contents[offset:offset+4] = data
        elif isinstance(data, int):
            self._contents[offset:offset+4] = struct.pack(">I", data)
        else:
            raise RuntimeError("typeof data not bytes or int")

# ------------------------------------------------------------------------------------

def _sign_extend_imm16_value(opcode: int) -> int:
    return struct.unpack(">hh", struct.pack(">I", opcode))[1]

def _autodetect_bytes_or_int(v: bytes | int) -> int:
    if isinstance(v, bytes):
        return struct.unpack(">I", v)[0]
    elif isinstance(v, int):
        return v
    else:
        raise RuntimeError("type of v not bytes or int")

def demunge_mips_hilo_offset(hi16_op: bytes | int, lo16_op: bytes | int) -> int:
    '''
    Demunges a hi16/lo16 offset from two instructions.
    Assumes lo16 will be an opcode that works on signed integers
    (addiu, lui, etc.).
    '''
    hi16_instruction = _autodetect_bytes_or_int(hi16_op)
    lo16_instruction = _autodetect_bytes_or_int(lo16_op)

    hi16 = hi16_instruction & 0xFFFF
    lo16_sign_extended = _sign_extend_imm16_value(lo16_instruction)

    return (hi16 << 16) + lo16_sign_extended

def munge_mips_hilo_offset(offset: int) -> tuple[int,int]:
    '''
    Takes an offset and munges it into hi16/lo16 offset pairings.
    Assumes lo16 will be an opcode that works on signed integers
    (addiu, lui, etc.).
    '''
    # we keep the lo16 bits pretty much the same because of the 2's complement
    # nature of what we've just done above.
    # with an address of 8005C6E0:
    #
    # hi16 = 80060000
    # lo16 = FFFFC6E0
    #
    # adding them together produces 8005C6E0.
    if (offset & 0x8000) != 0:
        offset += 0x00010000
    return (offset >> 16), offset & 0xFFFF


# ------------------------------------------------------------------------------------

def apply_relocations(flattened_binary_load_address: int,
                      flattened_binary: RelocatableBinary,
                      relocs: list[Reloc],
                      foreign_module_section_offset_maps: dict[int,dict[RelocSection,int]] | None = None) -> list[tuple[Reloc,bytes]]:

    '''
    Applies relocations to a flattened binary and returns a list of changes made.

    The reason we must use a flattened binary, instead of random sections at random load addresses,
    is because some loaders (the Paradigm loader in particular) have malformed relocation data that
    expects sections to be loaded in sequence, rather than in random locations.
    '''

    # these are relocs that were applied, and the original opcodes (or imm32 data)
    relocs_applied: list[tuple[Reloc,int]] = []

    last_hi16_offset      = None
    last_hi16_relocation  = None
    last_hi16_instruction = None
    
    for reloc in relocs:
        reloc_type = reloc.type()
        
        reloc_offset = flattened_binary.section_base_offset(reloc.section()) + reloc.section_offset()
        original_instruction = struct.unpack(">I",flattened_binary_load_address[reloc_offset:reloc_offset+4])[0]
        
        if reloc.target_module_id() == -1:
            # target is a local
            target_section = reloc.target_section()

            
            target_offset = flattened_binary.section_base_offset(target_section) + reloc.target_section_offset()
            if (0 <= target_offset <= len(flattened_binary)):
                raise RuntimeError("absolute offset went outside of the flattened binary map")

            target_address = flattened_binary_load_address + target_offset

        else:
            # target is a global
            
            # the 1080 USO loader is the only DLL scheme I know about, and it's a lazy load,
            # so we don't necessarily need to resolve imports right away
            if foreign_module_section_offset_maps is None or \
               reloc.target_module_id() not in foreign_module_section_offset_maps:
                logger.warning("not relocating %s:%s+0x%08x: foreign module id %d not loaded")
                continue

            raise RuntimeError("global importing currently unimplemented")

        #
        # determine relocation type and make patches
        #
        if reloc_type == RelocType.R_MIPS_26:
            hibits = original_instruction & 0xFC000000
            lo26   = original_instruction & 0x03FFFFFF

            unpatched_offset = (lo26 << 2)
            patched_offset = unpatched_offset + (target_address & 0x03FFFFFF)

            patched_instruction = hibits | (patched_offset >> 2)

            logger.debug("R_MIPS_26: at 0x%06x (%s+0x%06x) change %08x to %08x",
                reloc_offset,
                reloc.section().printable(),
                reloc.section_offset(),
                original_instruction,
                patched_instruction)
            
            relocs_applied.append( (reloc, original_instruction) )     
            flattened_binary.write32(reloc_offset, patched_instruction)
            
        elif reloc_type == RelocType.R_MIPS_32:
            patched_instruction = original_instruction + target_address

            logger.debug("R_MIPS_32: at 0x%06x (%s+0x%06x) change %08x to %08x",
                reloc_offset,
                reloc.section().printable(),
                reloc.section_offset(),
                original_instruction,
                patched_instruction)

            relocs_applied.append( (reloc, original_instruction) )     
            flattened_binary.write32(reloc_offset, patched_instruction)
        
        elif reloc_type == RelocType.R_MIPS_HI16:
            # the hi16 instruction will "latch" until another hi16 is found.
            last_hi16_offset = reloc_offset
            last_hi16_instruction = original_instruction
            last_hi16_relocation  = reloc

            logger.debug("R_MIPS_HI16 at 0x%06x (%s+0x%06x). delaying until lo16 hit",
                        reloc_offset,
                        reloc.section().printable(),
                        reloc.section_offset())
            
            # no patches to be applied on this iteration
    
        elif reloc_type == RelocType.R_MIPS_LO16:
            if last_hi16_relocation is not None:
                offset = demunge_mips_hilo_offset(last_hi16_instruction, original_instruction)
                absolute_address = target_address + offset

                patched_hi16_value, patched_lo16_value = munge_mips_hilo_offset(absolute_address)
                patched_hi16_instruction = (last_hi16_instruction & 0xFFFF0000) + patched_hi16_value
                patched_lo16_instruction = (original_instruction  & 0xFFFF0000) + patched_lo16_value

                logger.debug("R_MIPS_HI16: at 0x%06x (%s+0x%06x) change %08x to %08x",
                             reloc_offset,
                             last_hi16_relocation.section().printable(),
                             last_hi16_relocation.section_offset(),
                             last_hi16_instruction,
                             patched_hi16_instruction)
                
                relocs_applied.append( (last_hi16_relocation, last_hi16_instruction) )     
                flattened_binary.write32(last_hi16_offset, patched_hi16_instruction)

                logger.debug("R_MIPS_LO16: at 0x%06x (%s+0x%06x) change %08x to %08x",
                             reloc_offset,
                             reloc.section().printable(),
                             reloc.section_offset(),
                             original_instruction,
                             patched_lo16_instruction)
                
                relocs_applied.append( (reloc, original_instruction) )     
                flattened_binary.write32(reloc_offset, patched_lo16_instruction)

                last_hi16_relocation = None
            else:
                # TODO: find modules that try to do this out of all games using dyanimc loaders
                # and confirm that this should never happen
                raise RuntimeError("encountered lo16 without hi16 directly preceding it")

        else:
            raise RuntimeError("illegal relocation type")
        
    return relocs_applied
