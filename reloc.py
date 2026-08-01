'''
Common relocation utilty code for stuff that needs it.
'''

import logging
from enum import Enum
import struct

from mips import INSTRUCTION_JAL_TEMPLATE, INSTRUCTION_JMP_TEMPLATE

from datautil import unpack_uint32_be

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

    FLAT   = 9

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
    
    def __str__(self):
        return f"{self._type.name}: {self._section.printable()}{self._section_offset:+x}->{self._target_section.printable()}{self._target_section_offset:+x}"

# to be fed into apply_relocations() to enforce pass-by-reference
# and to simplify calling
class RelocatableBinary:
    def __init__(self,
                 contents: bytes,
                 section_ranges: list[tuple[int,int,RelocSection]]):

        self._contents = bytearray(contents)

        self._section_ranges = section_ranges
        
        self._section_base_offsets = {}
        for section_start, _, section_type in section_ranges:
            self._section_base_offsets[section_type] = section_start

        pass

    def absolute_offset_to_section_and_offset(self, offset: int) -> tuple[RelocSection|None,int|None]:
        '''
        Lookup section_id+offset from an absolute offset.
        '''
        for range_start, range_end, section_type in self._section_ranges:
            if range_start <= offset <= range_end:
                return section_type, offset-range_start
        return None, None
    
    def sizeof(self):
        return len(self._contents)
    
    def section_base_offset(self, section: RelocSection):
        if section not in self._section_base_offsets:
            return None
        return self._section_base_offsets[section]
    
    def read32(self, offset: int) -> int:
        return unpack_uint32_be(self._contents[offset:offset+4])

    def write32(self, offset: int, data: int | bytes):
        if isinstance(data, bytes):
            if len(data) != 4:
                raise RuntimeError("write32: len(data) != 4")
            self._contents[offset:offset+4] = data
        elif isinstance(data, int):
            self._contents[offset:offset+4] = struct.pack(">I", data)
        else:
            raise RuntimeError("typeof data not bytes or int")

    def section_types_present(self) -> list[RelocSection]:
        return list(self._section_base_offsets.keys())

    def contents(self) -> bytes:
        return bytes(self._contents)

# ------------------------------------------------------------------------------------

def _sign_extend_imm16_value(opcode: int) -> int:
    return struct.unpack(">hh", struct.pack(">I", opcode))[1]

def _autodetect_bytes_or_int(v: bytes | int) -> int:
    if isinstance(v, bytes) or isinstance(v, bytearray):
        return unpack_uint32_be(v)
    elif isinstance(v, int):
        return v
    else:
        raise RuntimeError(f"type of v not bytes or int (got: {type(v)})")

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

def _log_reloc_application(reloc: Reloc,
                           reloc_offset,
                           original_instruction,
                           patched_instruction):
    logger.debug("%s: at 0x%06x (%s+0x%06x) change %08x to %08x (%s:%s%+#09x)",
        reloc.type().name,
        reloc_offset,
        reloc.section().printable(),
        reloc.section_offset(),
        original_instruction,
        patched_instruction,
        "local" if reloc.target_module_id() == -1 else f"mod-{reloc.target_module_id():04x}",
        reloc.target_section().printable(),
        reloc.target_section_offset())

def apply_relocations(flattened_binary_load_address: int,
                      flattened_binary: RelocatableBinary,
                      relocs: list[Reloc],
                      foreign_module_section_offset_maps: dict[int,dict[RelocSection,int]] | None = None,
                      ignoring_offsets_in_binary: bool = False,
                      bal_for_jal: bool = False) -> list[tuple[Reloc,int,int]]:

    '''
    Applies relocations to a flattened binary and returns a list of changes made.

    The reason we must use a flattened binary, instead of random sections at random load addresses,
    is because some loaders (the Paradigm loader in particular) have malformed relocation data that
    expects sections to be loaded in sequence, rather than in random locations.

    VERY IMPORTANT NOTE! This relocation routine uses simple hi16 latching as opposed to the register-by-register
    approach seen in the Zelda dynamic loader. The caller MUST ensure that hi16/lo16 pairings are listed in the
    correct order or you will get invalid results!

    Parameters:

    - foreign_module_section_offset_maps: Dict pointing module_id -> {reloc_section, load_address}
      so we know where foreign module sections (which we import from) are supposed to be loaded.
      Default is None (no imports).
      
      The relocator will assume that a foreign module is a load-later if one of its sections loads
      to 0x00000000. Otherwise, it assumes that module is to be loaded alongside this one and will
      try to statically link against it.

    - ignoring_offsets_in_binary: If true, the relocator will ignore whatever offset is present at the
      reloc location and assume a base target offset of zero instead. This means if we have an imm26
      instruction like `0c003fc1`, the relocator will ignore the offset and pretend as if it was `0c000000`.

    - bal_for_jal: If true, the relocator will try to rewrite imm26 instructions as relative branches,
      so `j` becomes an unconditional branch and `jal` becomes `bal`. The imm26 relocs can then be removed
      from the final output relocation table to save space.

    Returns a list of changes made as tuples (reloc, original_instruction, patched_instruction).
    '''

    # these are relocs that were applied, and the original opcodes (or imm32 data)
    relocs_applied: list[tuple[Reloc, int, int]] = []

    last_hi16_offset      = None
    last_hi16_relocation  = None
    last_hi16_instruction = None
    
    for reloc in relocs:
        reloc_type = reloc.type()
        
        reloc_offset = flattened_binary.section_base_offset(reloc.section()) + reloc.section_offset()
        original_instruction = flattened_binary.read32(reloc_offset)

        target_is_global = False
        
        if reloc.target_module_id() == -1:
            # target is a local
            target_section = reloc.target_section()

            if flattened_binary.section_base_offset(target_section) is None:
                raise RuntimeError(f"reloc pointed to target section {target_section.printable()}, which doesn't exist!")

            target_offset = flattened_binary.section_base_offset(target_section) + reloc.target_section_offset()

            if (0 <= target_offset <= flattened_binary.sizeof()) is False and \
                ignoring_offsets_in_binary is False:
                raise RuntimeError("absolute offset went outside of the flattened binary map")

            target_address = flattened_binary_load_address + target_offset

        else:
            # while the 1080 uso loader can lazy-load modules and apply relocations later,
            # we still need to have all of the modules loaded in memory here
            if foreign_module_section_offset_maps is None or \
               reloc.target_module_id() not in foreign_module_section_offset_maps:
                raise RuntimeError(f"foreign module {reloc.target_module_id():04x} not loaded!")

            foreign_section_offset_map = foreign_module_section_offset_maps[reloc.target_module_id()]

            # if the other module loads to 0x00000000, then that's a sign
            # that the target is to be loaded later.
            # otherwise, the target module is assumed to be loaded alongside this one,
            # so we can branch into it
            if 0x00000000 in foreign_section_offset_map.values():

                logger.debug("treating import from module 0x%04x as a load-later: %s%+#9x",
                             reloc.target_module_id(),
                             reloc.target_section().printable(),
                             reloc.target_section_offset())
                target_is_global = True

            target_address = foreign_section_offset_map[reloc.target_section()] + reloc.target_section_offset()

        #
        # determine relocation type and make patches
        #
        if reloc_type == RelocType.R_MIPS_26:
            hibits = original_instruction & 0xFC000000
            lo26   = original_instruction & 0x03FFFFFF

            if hibits not in [INSTRUCTION_JAL_TEMPLATE, INSTRUCTION_JMP_TEMPLATE]:
                raise RuntimeError("illegal imm26 instruction")

            unpatched_offset = 0 if ignoring_offsets_in_binary else (lo26 << 2)
            patched_offset = unpatched_offset + (target_address & 0x03FFFFFF)

            # should be -4, confirmed against ghidra
            relative_branch_offset = ((target_address - (reloc_offset + flattened_binary_load_address)) - 4) >> 2

            # bal-for-jal is for locals only
            if not target_is_global and (-0x8000 < relative_branch_offset < 0x8000) and bal_for_jal:
                base_instruction = None

                if hibits == INSTRUCTION_JAL_TEMPLATE:
                    # bgezal $zero,offset
                    base_instruction = 0b000001_00000_10001_00000000_00000000
                elif hibits == INSTRUCTION_JMP_TEMPLATE:
                    # beq $zero,$zero,offset
                    base_instruction = 0b000100_00000_00000_00000000_00000000
                else:
                    raise RuntimeError("shouldn't be here")

                patched_instruction = base_instruction | (relative_branch_offset & 0xFFFF)

            else:
                if not target_is_global and bal_for_jal:
                    logger.debug("bal_for_jal: target offset out of bounds, will write an imm26 instruction instead")
                patched_instruction = hibits | (patched_offset >> 2)

            _log_reloc_application(reloc, reloc_offset, original_instruction, patched_instruction)
            relocs_applied.append( (reloc, original_instruction, patched_instruction) )     
            flattened_binary.write32(reloc_offset, patched_instruction)
            
        elif reloc_type == RelocType.R_MIPS_32:
            patched_instruction = (0 if ignoring_offsets_in_binary else original_instruction) + target_address
            
            _log_reloc_application(reloc, reloc_offset, original_instruction, patched_instruction)
            relocs_applied.append( (reloc, original_instruction, patched_instruction) )
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
                offset = 0 if ignoring_offsets_in_binary else demunge_mips_hilo_offset(last_hi16_instruction, original_instruction)

                absolute_address = target_address + offset

                patched_hi16_value, patched_lo16_value = munge_mips_hilo_offset(absolute_address)
                patched_hi16_instruction = (last_hi16_instruction & 0xFFFF0000) + patched_hi16_value
                patched_lo16_instruction = (original_instruction  & 0xFFFF0000) + patched_lo16_value

                _log_reloc_application(last_hi16_relocation, last_hi16_offset, last_hi16_instruction, patched_hi16_instruction)                
                relocs_applied.append( (last_hi16_relocation, last_hi16_instruction, patched_hi16_instruction) )
                flattened_binary.write32(last_hi16_offset, patched_hi16_instruction)

                _log_reloc_application(reloc, reloc_offset, original_instruction, patched_lo16_instruction)
                relocs_applied.append( (reloc, original_instruction, patched_lo16_instruction) )     
                flattened_binary.write32(reloc_offset, patched_lo16_instruction)

                # last_hi16_relocation = None
            else:
                # TODO: find modules that try to do this out of all games using dyanimc loaders
                # and confirm that this should never happen
                raise RuntimeError("encountered lo16 without hi16 directly preceding it")

        else:
            raise RuntimeError("illegal relocation type")
        
    return relocs_applied

def strip_bal_for_jal_substitutions(changes_made: list[tuple[Reloc,int,int]]) -> list[tuple[Reloc,int,int]]:
    '''
    Removes bal-for-jal substitutions from the changes-made list returned by apply_relocations().

    apply_relocations() does not do this on its own, because there's a chance an unresolved import has happened
    and the relocation couldn't be applied.
    '''
    filtered = []

    for reloc, instruction_before, instruction_after in changes_made:
        if reloc.type() != RelocType.R_MIPS_26 or \
            (instruction_before & 0xFC000000) == (instruction_after & 0xFC000000):
            filtered.append( (reloc, instruction_before, instruction_after) )
            continue

    return filtered
