'''
Pokemon Stadium

Another dynamic loader scheme. This is very similar to the Zelda framework
in that it uses a virtual RAM scheme and 32-bit relocation words, but is simplified
somewhat, with all modules being flattened out of the gate (everything is sectionless).

There are two important differences from Zelda which make dumping the overlays more annoying:
- This virtual RAM scheme allows importing from other modules, so we need to load
  all modules before applying relocations.

- There are no main overlay tables; the overlay load functions are called with hardcoded
  values dropped there by the linker. To avoid having to do a million pattern matches,
  this file instead searches through the ROM for the modules and dumps them that way.

Other notes:
- Pokemon Stadium uses a very simple IPL3 protection check in its mainloop; it checks
  that the data at 0xE38 is equal to 0x828A, which it should be if a dirty pirate didn't change the
  CIC on us. If it's different, the game shits the bed.

References:
- https://github.com/pret/pokestadium/blob/master/src/memmap.c
'''

import logging
import struct

from bffi import Bffi, BffiBuilder
from datautil import unpack_uint32_be
from mips import decode_imm16_rt_rs_target_register, decode_imm16_rt_rs_offset_register
from n64rom import N64Rom
from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi
from reloc import RelocType, RelocatableBinary, demunge_mips_hilo_offset, Reloc, RelocSection, apply_relocations
from signature import SignatureBuilder, WILDCARD

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------------------------

# these match the ELF standard, as usual
POKESTADIUM_RELOC_TYPES_LUT = {
    2: RelocType.R_MIPS_32,
    4: RelocType.R_MIPS_26,
    5: RelocType.R_MIPS_HI16,
    6: RelocType.R_MIPS_LO16
}

# another zelda loader behavior it has: hi16/lo16 pairings are grouped by register used
class PokeStadiumHi16:
    def __init__(self,
                 instruction: int,
                 offset: int):
        
        self._instruction = instruction
        self._offset = offset
        self._applied = False

    def instruction(self):
        return self._instruction
    
    def offset(self):
        return self._offset

    def applied(self, new_applied: bool | None = False):
        if new_applied is not None:
            self._applied = new_applied
        return self._applied

# ------------------------------------------------------------------------------------

# reloc tables have useless relocs pointing to the statically-mapped boot segment
def _is_address_in_vram_space(address: int) -> bool:
    return 0x81000000 <= address < 0x90000000

def _get_module_id_from_vram_address(address: int) -> int:
    return ((address & 0x0FF00000) >> 0x14) - 0x10

def _module_id_to_vram_address(id: int) -> int:
    return 0x80000000 + ((id + 0x10) << 0x14)

def _get_offset_from_vram_address(address: int) -> int:
    # strict 1 MB limit, it seems
    return address & 0x000FFFFF

# relocation word format:
# bit 31 - not sure, appears unused
# bits 30-24 - relocation type (very wasteful)
#   - values again match the ELF standard
# low 24 bits are the offset

def _assert_module_id_not_negative(module_id: int, source_address: int):
    if module_id < 0x00:
        raise RuntimeError(f"OOPS! negative module id! source address was {source_address:08x}")

def _complain_module_not_loaded(reloc_type,
                                this_module_id,
                                target_module_id,
                                target_absolute_offset):
    # TODO: if this turns out to be a parser bug, then fix the bug and panic instead
    logger.warning("%s: module 0x%04x makes reference to module 0x%04x (0x%08x), which isn't present. ignoring reloc!!",
                    reloc_type.name,
                    this_module_id,
                    target_module_id,
                    target_absolute_offset)


def pokestadium_parse_relocations(binary: RelocatableBinary,
                                  this_module_id: int,
                                  reloc_words: list[int],
                                  known_module_ids: set):

    hi16s: dict[int,PokeStadiumHi16] = {}
    relocs = []

    last_hi16_register = None

    for reloc_word in reloc_words:
        reloc_type             = POKESTADIUM_RELOC_TYPES_LUT[(reloc_word & 0x7F000000) >> 24]
        reloc_absolute_offset  = reloc_word & 0x00FFFFFF

        original_instruction = binary.read32(reloc_absolute_offset)

        if reloc_type == RelocType.R_MIPS_26:
            target_absolute_offset = ((original_instruction & 0x03FFFFFF) << 2) + 0x80000000
            if not _is_address_in_vram_space(target_absolute_offset):
                logger.info("R_MIPS_26: reloc points outside vram space to 0x%08x, ignoring", target_absolute_offset)
                continue
            
            target_module_id      = _get_module_id_from_vram_address(target_absolute_offset)
            if target_module_id not in known_module_ids:
                _complain_module_not_loaded(reloc_type, this_module_id, target_module_id, target_absolute_offset)
                continue
                
            _assert_module_id_not_negative(target_module_id, target_absolute_offset)
            target_module_offset  = _get_offset_from_vram_address(target_absolute_offset)

            relocs.append(Reloc(RelocType.R_MIPS_26,
                                RelocSection.FLAT,
                                reloc_absolute_offset,
                                RelocSection.FLAT,
                                target_module_offset,
                                target_module_id=-1 if target_module_id == this_module_id else target_module_id))

        elif reloc_type == RelocType.R_MIPS_32:
            target_absolute_offset = original_instruction
            if not _is_address_in_vram_space(target_absolute_offset):
                logger.info("R_MIPS_32: reloc points outside vram space to 0x%08x, ignoring", target_absolute_offset)
                continue

            target_module_id      = _get_module_id_from_vram_address(target_absolute_offset)
            if target_module_id not in known_module_ids:
                _complain_module_not_loaded(reloc_type, this_module_id, target_module_id, target_absolute_offset)
                continue
            _assert_module_id_not_negative(target_module_id, target_absolute_offset)
            target_module_offset  = _get_offset_from_vram_address(target_absolute_offset)

            
            relocs.append(Reloc(RelocType.R_MIPS_32,
                                RelocSection.FLAT,
                                reloc_absolute_offset,
                                RelocSection.FLAT,
                                target_module_offset,
                                target_module_id=-1 if target_module_id == this_module_id else target_module_id))

        elif reloc_type == RelocType.R_MIPS_HI16:
            # queue for incoming lo16; do not decode yet
            register = decode_imm16_rt_rs_target_register(original_instruction)

            hi16s[register] = \
                PokeStadiumHi16(original_instruction, reloc_absolute_offset)

        elif reloc_type == RelocType.R_MIPS_LO16:
            offset_register = decode_imm16_rt_rs_offset_register(original_instruction)
            if offset_register not in hi16s:
                raise RuntimeError("lo16 without matching hi16!")

            hi16 = hi16s[offset_register]
            last_hi16_instruction = hi16.instruction()
            target_absolute_offset = demunge_mips_hilo_offset(last_hi16_instruction, original_instruction)

            if not _is_address_in_vram_space(target_absolute_offset):
                logger.info("R_MIPS_HI16/LO16: reloc points outside vram space to 0x%08x, ignoring", target_absolute_offset)
                continue

            target_module_id      = _get_module_id_from_vram_address(target_absolute_offset)
            if target_module_id not in known_module_ids:
                _complain_module_not_loaded(reloc_type, this_module_id, target_module_id, target_absolute_offset)
                continue
        
            _assert_module_id_not_negative(target_module_id, target_absolute_offset)
            target_module_offset  = _get_offset_from_vram_address(target_absolute_offset)

            if offset_register != last_hi16_register or not hi16.applied():
                relocs.append(Reloc(RelocType.R_MIPS_HI16,
                                RelocSection.FLAT,
                                hi16.offset(),
                                RelocSection.FLAT,
                                target_module_offset,
                                target_module_id=-1 if target_module_id == this_module_id else target_module_id))

                last_hi16_register = offset_register
                hi16.applied(True)
                    
            relocs.append(Reloc(RelocType.R_MIPS_LO16,
                                RelocSection.FLAT,
                                reloc_absolute_offset,
                                RelocSection.FLAT,
                                target_module_offset,
                                target_module_id=-1 if target_module_id == this_module_id else target_module_id))
        else:
            raise RuntimeError("illegal reloc type")
        
    return relocs


# overlay format:
# - 8 bytes module entry point jump stub (has to be relocated)
#   - this also hints at the module ID
#   - one of the relocs should point here too
# - 8 bytes ascii 'FRAGMENT'
# - 4 bytes offset to code segment (always linked .text / .data / .rodata)
# - 4 bytes offset to reloc table
# - 4 bytes total ROM size
# - 4 bytes total RAM size
#
# all RAM space following the code segment (total_ram_size - reloc_offset) is bss space
def pokestadium_read_module(rom: N64Rom,
                            module_offset: int):
    if rom.read_bytes(module_offset+8, 8) != b'FRAGMENT':
        return None

    header = rom.read_bytes(module_offset, 0x20)

    entry_jump_instruction_a, \
    entry_jump_instruction_b, \
    _, \
    _, \
    header_size, \
    reloc_table_offset, \
    module_size_in_rom, \
    module_size_in_ram = struct.unpack(">IIIIIIII", header)

    full_module = rom.read_bytes(module_offset, module_size_in_rom)

    if (entry_jump_instruction_a & 0xFC000000) != 0x08000000:
        raise RuntimeError("entry instruction was not a jmp imm26!")

    load_address = (((entry_jump_instruction_a & 0x03FFFFFF) << 2) + 0x80000000) & 0xFFF00000
    module_id = _get_module_id_from_vram_address(load_address)
    
    code_segment = full_module[header_size:reloc_table_offset] 
    reloc_table = full_module[reloc_table_offset:]
    num_relocs = unpack_uint32_be(reloc_table[:4])

    reloc_words = []
    for i in range(num_relocs):
        offset = (i+1)*4
        reloc_words.append( unpack_uint32_be(reloc_table[offset:offset+4]) )

    bin = RelocatableBinary(header + code_segment + bytes([0] * (module_size_in_ram-reloc_table_offset)),
                            [ (0, module_size_in_ram, RelocSection.FLAT) ])
    
    return module_id, bin, reloc_words

# ------------------------------------------------------------------------------------

# @ 0x80004454 in pokemon stadium us v1.0
# $a0 = module id, $a1 = module ROM start address, $a2 = module ROM end address
POKESTADIUM_OVERLAY_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xe0,             # addiu      sp,sp,-0x20
        0xaf, 0xa4, 0x00, 0x20,             # sw         a0,local_res0(sp)
        0xaf, 0xa5, 0x00, 0x24,             # sw         a1,local_res4(sp)
        0x00, 0xa0, 0x20, 0x25,             # or         a0,a1,zero
        0xaf, 0xbf, 0x00, 0x14,             # sw         ra,local_c(sp)
        0xaf, 0xa6, 0x00, 0x28,             # sw         a2,local_res8(sp)
        0x00, 0xc0, 0x28, 0x25,             # or         a1,a2,zero
        0x00, 0x00, 0x30, 0x25,             # or         a2,zero,zero
        0x0c, WILDCARD, WILDCARD, WILDCARD, # jal        FUN_80003dc4
        0x00, 0x00, 0x38, 0x25,             # _or        a3,zero,zero
        0x10, 0x40, 0x00, 0x05,             # beq        v0,zero,LAB_80004494
        0x00, 0x40, 0x28, 0x25,             # _or        a1,v0,zero
    ]) \
    .build()

# @ 0x80029008 in pokemon stadium us v1.0
#
# $a0 = module id, $a1 = module ROM start address, $a2 = module ROM end address,
# $a3 = param0, 0x10($sp) = param1
POKESTADIUM_OVERLAY_LOAD_AND_CALL_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xe0,             # addiu      sp,sp,-0x20
        0xaf, 0xbf, 0x00, 0x14,             # sw         ra,local_c(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # jal        overlay_load (as above)
        0xaf, 0xa7, 0x00, 0x2c,             # _sw        a3,local_resc(sp)
        0xaf, 0xa2, 0x00, 0x18,             # sw         v0,local_8(sp)
        0x8f, 0xa4, 0x00, 0x2c,             # lw         a0,local_resc(sp)
        0x00, 0x40, 0xf8, 0x09,             # jalr       v0
        0x8f, 0xa5, 0x00, 0x30,             # _lw        a1,local_res10(sp)
        0xaf, 0xa2, 0x00, 0x1c,             # sw         v0,local_4(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # jal        FUN_80002620
        0x8f, 0xa4, 0x00, 0x18,             # _lw        a0,local_8(sp)
        0x8f, 0xbf, 0x00, 0x14,             # lw         ra,local_c(sp)
        0x8f, 0xa2, 0x00, 0x1c,             # lw         v0,local_4(sp)
        0x27, 0xbd, 0x00, 0x20,             # addiu      sp,sp,0x20
        0x03, 0xe0, 0x00, 0x08,             # jr         ra
        0x00, 0x00, 0x00, 0x00,             # _nop
    ]) \
    .build()

def pokestadium_unpack(rom: N64Rom, ipc: int) -> Bffi:
    # boilerplate stuff
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None

    builder = BffiBuilder()
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)

    bootexe = rom.boot_exe()[:earliest_bss-ipc]

    builder.fix(ipc, bootexe)
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.initial_stack_pointer(preamble.initial_stack_pointer())

    overlay_load_offset = POKESTADIUM_OVERLAY_LOAD_PATTERN.find(bootexe)
    overlay_load_and_call_offset = POKESTADIUM_OVERLAY_LOAD_AND_CALL_PATTERN.find(bootexe)
    
    if None in [overlay_load_offset, overlay_load_and_call_offset]:
        return None

    logger.info("found Pokemon Stadium dynamic loader")

    # we need to cheat here since there is so much hardcoding of offsets and module ids.
    # search through the ROM for modules ("fragments").
    #
    # this is tremendously shitty code but i'm not adding a sizeof() function to the N64Rom
    # class yet, because zelda's stupid vrom scheme could cause N64Rom to be subclassed at
    # some point.
    offset = 0
    rom_offset = 0x1000 + (earliest_bss-ipc)
    rom_contents = rom.read_bytes_until_end(0x1000 + (earliest_bss-ipc))

    # gather modules BEFORE applying relocations (remember that modules can reference each other)
    modules = {}
    while offset < len(rom_contents):
        chunk = rom_contents[offset:offset+0x10]
        if chunk[0x8:0x10] != b'FRAGMENT':
            offset += 0x10
            rom_offset += 0x10
            continue

        module_size = unpack_uint32_be(rom_contents[offset+0x18:offset+0x1C])

        module_id, bin, reloc_words = pokestadium_read_module(rom, rom_offset)

        if module_id in modules:
            raise RuntimeError(f"module id {module_id:02x} defined twice!")

        logger.info("module id %02x @ ROM 0x%08x", module_id, rom_offset)

        # relocations can't be parsed yet; have to gather all modules first.

        modules[module_id] = (bin, reloc_words)

        offset += module_size
        rom_offset += module_size

    # pretending all other modules load at 0x00000000
    foreign_module_offset_maps = {}
    for module_id in modules.keys():
        foreign_module_offset_maps[module_id] = { RelocSection.FLAT: 0 }

    # relocate all modules to 0x00000000 and shove them into the BFFI
    for module_id, tuppy in modules.items():
        bin, reloc_words = tuppy

        apply_relocations(0,
                          bin,
                          pokestadium_parse_relocations(bin,
                                                        module_id,
                                                        reloc_words,
                                                        modules.keys()),
                          foreign_module_section_offset_maps=foreign_module_offset_maps,
                          ignoring_offsets_in_binary=True,
                          bal_for_jal=True)

        # TODO: actually write import list and relocation tables
        builder.seg(0, bin.contents(), segment_id=module_id)

    return builder.build()
