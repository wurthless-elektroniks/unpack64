'''
Paradigm Entertainment presents the most spaghetti code loader of all time

Pilotwings and Aero Fighters Assault use a static code loader, but from
F-1 World Grand Prix onward we have to deal with a dynamic loader.

The loader uses files in ROM to boot things. It's a little complex,
and it didn't help that Ghidra choked on this again and completely missed
the ROM read address.

Each file starts with:
- 4 bytes "FORM"
- 4 bytes length of data to follow, including the filetype
- 4 bytes filetype
- file data follows

File structures are:

- MODU indicates this is a code overlay. This system uses relocatable overlays
  (big surprise).
    - COMM (0x434F4D4D), four bytes length, nn bytes data
      The parser always reads 0x24 bytes data, the last 4 are zero padding
      These fields specify section start/end points, BSS size, and
      the section entry point.

      COMM section structure in MODU files:
      +0x00
      +0x04 - entry point within code section
      +0x08 - code size
      +0x0C - rodata size
      +0x10 - data size
      +0x14 - bss size
      +0x18 - number of relocs in RELA section
      +0x1C - executable unique ID
      +0x20
      +0x24 - zero padding

    - CODE (0x434F4445), four bytes length, nn bytes data

    - MDBG, four bytes section length (typically 0x20),
      then the filename of the object file.
      The parser ignores this.
    
    - RELA (0x52454C41), four bytes length, nn bytes data

    - PAD\x20, followed by four bytes section length (typically 4),
    then four zero bytes.

    F1 World Grand Prix compresses its sections:

    - GZIP, four bytes section type (expect CODE, RELA), 4 bytes uncompressed length,
      MIO0, standard MIO0 header and file format (despite being called GZIP, it's MIO0)

'''

import logging
import struct

from enum import Enum

from compression.mio0 import mio0_decompress

from bffi import Bffi,BffiBuilder,BffiSectionType, BffiTlb, BffiTlbEntry
from n64rom import N64Rom
from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi
from reloc import demunge_mips_hilo_offset, munge_mips_hilo_offset
from signature import SignatureBuilder, WILDCARD

logger = logging.getLogger(__name__)

# -----------------------------------------------
class PdmexeSectionType(Enum):
    TEXT   = 0
    RODATA = 1
    DATA   = 2
    BSS    = 3

class PdmexeFileSectionType(Enum):
    CODE = 0x434F4445
    COMM = 0x434F4D4D
    RELA = 0x52454C41

class PdmexeRelocType(Enum):
    HI16    = 0
    LO16    = 1
    IMM26   = 2
    SKIP    = 3
    SKIP_B  = 4
    IMM32   = 5
    IMM32_B = 6

BASE_SECTION_LUT = [
    PdmexeSectionType.TEXT,
    PdmexeSectionType.DATA,
    PdmexeSectionType.RODATA,
]

TARGET_SECTION_LUT = [
    PdmexeSectionType.TEXT,
    PdmexeSectionType.RODATA,
    PdmexeSectionType.DATA,
    PdmexeSectionType.BSS
]

class PdmexeReloc:
    def __init__(self):
        self._reloc_type     : PdmexeRelocType    = None
        self._reloc_section  : PdmexeSectionType  = None
        self._reloc_offset   : int                = None
        self._target_section : PdmexeSectionType  = None
        self._target_offset  : int                = None

    def reloc_type(self) -> PdmexeRelocType:
        return self._reloc_type
    
    def reloc_section(self) -> PdmexeSectionType:
        return self._reloc_section

    def reloc_offset(self) -> int:
        return self._reloc_offset
    
    def target_section(self) -> PdmexeSectionType:
        return self._target_section
    
    def target_offset(self) -> int:
        return self._target_offset
class Pdmexe:
    def __init__(self):
        self._module_id       = None
        self._module_filename = None
        self._entry_point     = None
        self._sections : dict[PdmexeSectionType, bytes] = {}
        self._relocs: list[PdmexeReloc] = []

    def module_id(self) -> int:
        return self._module_id

    def module_filename(self) -> str:
        return self._module_filename

    def entry_point(self) -> int:
        return self._entry_point

    def section_size(self, section_type: PdmexeSectionType) -> int:
        return 0 if section_type not in self._sections else len(self._sections[section_type])

    def section(self, section_type: PdmexeSectionType) -> bytes:
        return None if section_type not in self._sections else self._sections[section_type]

    def relocs(self):
        return self._relocs

def _calc_base_address(section: PdmexeSectionType,
                       offset_in_section: int,
                       text_size: int,
                       rodata_size: int,
                       data_size: int,
                       allow_bss: bool):
    
    if section == PdmexeSectionType.TEXT:
        return offset_in_section
    elif section == PdmexeSectionType.RODATA:
        return offset_in_section + text_size
    elif section == PdmexeSectionType.DATA:
        return offset_in_section + text_size + rodata_size
    elif section == PdmexeSectionType.BSS:
        if allow_bss is False:
            raise RuntimeError("attempt to use BSS for a base address when not allowed to")
        return offset_in_section + text_size + rodata_size + data_size

def _relocate_and_flatten_module(module: Pdmexe,
                                 load_address: int) -> tuple[bytes,int]:
    flattened_code = bytearray()

    text_size   = module.section_size(PdmexeSectionType.TEXT)
    rodata_size = module.section_size(PdmexeSectionType.RODATA)
    data_size   = module.section_size(PdmexeSectionType.DATA)
    bss_size    = module.section_size(PdmexeSectionType.BSS)

    if text_size != 0:
        flattened_code += module.section(PdmexeSectionType.TEXT)

    if rodata_size != 0:
        flattened_code += module.section(PdmexeSectionType.RODATA)

    if data_size != 0:
        flattened_code += module.section(PdmexeSectionType.DATA)

    if bss_size != 0:
        flattened_code += bytes([0] * bss_size)

    for reloc in module.relocs():
        patch_address = _calc_base_address(reloc.reloc_section(),
                                            reloc.reloc_offset(),
                                            text_size,
                                            rodata_size,
                                            data_size,
                                            False)
        
        base_dest_address = _calc_base_address(reloc.target_section(),
                                            reloc.target_offset(),
                                            text_size,
                                            rodata_size,
                                            data_size,
                                            True)
            
        dest_address = load_address + base_dest_address
        
        reloc_type = reloc.reloc_type()
        if reloc_type == PdmexeRelocType.HI16:
            if dest_address & 0x8000:
                dest_address += 0x00010000
            flattened_code[patch_address + 2:patch_address + 4] = struct.pack(">H", (dest_address >> 16) & 0xFFFF)
        elif reloc_type == PdmexeRelocType.LO16:
            flattened_code[patch_address + 2:patch_address + 4] = struct.pack(">H", dest_address & 0xFFFF)
        elif reloc_type == PdmexeRelocType.IMM26:
            instruction = struct.unpack(">I", flattened_code[patch_address:patch_address + 4])[0] & 0xFC000000
            instruction += (dest_address & 0x03FFFFFF) >> 2
            flattened_code[patch_address:patch_address + 4] = struct.pack(">I", instruction)
        elif reloc_type == PdmexeRelocType.IMM32:
            flattened_code[patch_address:patch_address + 4] = struct.pack(">I", dest_address)
        else:
            raise RuntimeError("unrecognized reloc type!")

    return flattened_code[:text_size+rodata_size+data_size], bss_size

def _parse_relocs(reloc_section: bytes,
                  num_relocs: int,
                  other_sections: dict[PdmexeSectionType,bytes]):
    
    offset = 0

    relocs = []
    last_hi16 = None
    while offset < (num_relocs*4):
        reloc_word = struct.unpack(">I", reloc_section[offset:offset+4])[0]

        reloc_type           = PdmexeRelocType( (reloc_word & 0x03C00000) >> 22 )
        
        # offset of instruction to be molested
        reloc_offset         = (reloc_word & 0x003FFFFF) << 1
        reloc_base_section   = BASE_SECTION_LUT[ (reloc_word & 0x0C000000) >> 26 ]
        reloc_target_section = TARGET_SECTION_LUT[ (reloc_word & 0xF0000000) >> 28 ]
        
        reloc = PdmexeReloc()
        # pylint: disable=protected-access
        reloc._reloc_type     = reloc_type
        reloc._reloc_section  = reloc_base_section
        reloc._reloc_offset   = reloc_offset
        reloc._target_section = reloc_target_section

        # recover offsets ahead of time
        base_section_contents = other_sections[reloc_base_section]

        dest_offset = None
        if reloc_type == PdmexeRelocType.HI16:
            last_hi16 = reloc
        elif reloc_type == PdmexeRelocType.LO16:
            
            if last_hi16._reloc_section != reloc_base_section:
                raise RuntimeError("hi16/lo16 assigned to different sections")

            # FIXME: some modules trip this check
            # - beetle racing: caranim.o
            # - f1 world grandprix 2: f1paddock_rom.o
            if last_hi16._target_section != reloc_target_section:
                logger.error("hi16/lo16 point to different target sections, abandoning load. hi16 %s/lo16 %s",
                             last_hi16._target_section,
                             reloc_target_section)
                return None

            hi16_offset = last_hi16._reloc_offset
            lo16_offset = reloc_offset

            dest_offset = demunge_mips_hilo_offset(base_section_contents[hi16_offset:hi16_offset+4],
                                                base_section_contents[lo16_offset:lo16_offset+4])
        

            if dest_offset > len(other_sections[reloc_target_section]):
                raise RuntimeError("hi16/lo16 pointed out of bounds")

            if last_hi16._target_offset is None:
                last_hi16._target_offset = dest_offset

            reloc._target_offset = dest_offset
        elif reloc_type == PdmexeRelocType.IMM26:
            dest_offset = (struct.unpack(">I", base_section_contents[reloc_offset:reloc_offset+4])[0] & 0x03FFFFFF) << 2
            reloc._target_offset = dest_offset

        elif reloc_type == PdmexeRelocType.IMM32:
            dest_offset = struct.unpack(">I", base_section_contents[reloc_offset:reloc_offset+4])[0]
            reloc._target_offset = dest_offset
        else:
            raise RuntimeError("unexpected reloc type")

        if dest_offset is not None and dest_offset > len(other_sections[reloc_target_section]):
            raise RuntimeError("relocation pointed out of bounds")

        relocs.append(reloc)
        offset += 4

    return relocs

def _read_module(module_contents: bytes) -> Pdmexe:
    offset = 0

    file_sections = {}

    module_filename = "<anonymous>"

    while offset < len(module_contents):
        headertype, datasize = struct.unpack(">II", module_contents[offset:offset+8])
        offset += 8
        data = module_contents[offset:offset + datasize]
        offset += datasize

        if headertype == 0x50414420: # PAD\x20
            # skip padding sections
            continue

        if headertype == 0x475A4950: # GZIP
            payload, _ = mio0_decompress(data[8:])
            data = data[:8] + payload
            headertype, datasize = struct.unpack(">II", data[:8])
            file_sections[PdmexeFileSectionType(headertype)] = payload

        elif headertype in [PdmexeFileSectionType.CODE.value,
                            PdmexeFileSectionType.COMM.value,
                            PdmexeFileSectionType.RELA.value ]:
            # CODE, COMM, RELA -> store for later parsing
            file_sections[PdmexeFileSectionType(headertype)] = data

        elif headertype == 0x4D444247: # MDBG
            module_filename = data.decode('ascii')
        elif headertype == 0:
            break
        else:
            raise RuntimeError(f"illegal header in module: {headertype:08x}")

    if PdmexeFileSectionType.COMM not in file_sections:
        raise RuntimeError("couldn't find COMM section in overlay module!")
    
    _00, \
    entry_point, \
    text_size, \
    rodata_size, \
    data_size, \
    bss_size, \
    num_relocs, \
    module_id, \
    _20 = struct.unpack(">IIIIIIIII", file_sections[PdmexeFileSectionType.COMM][:0x24])

    logger.info("module 0x%08x (%s)", module_id, module_filename)
    logger.info("\ttext %d bytes, rodata %d bytes, data %d bytes, bss %d bytes",
                text_size, rodata_size, data_size, bss_size)
    logger.info("\tentry point at .text+0x%06x", entry_point)
    logger.info("\tcontains %d relocation(s)", num_relocs)

    if PdmexeFileSectionType.CODE not in file_sections:
        raise RuntimeError("overlay module has no code section!")
    
    # the CODE section is text/rodata/data all in one (with bss following them
    # when loaded in RAM), so split them up
    split_offset = 0
    flattened_code_section = file_sections[PdmexeFileSectionType.CODE]

    sections: dict[PdmexeSectionType,bytes] = {}
    for section_type, section_size in [
        (PdmexeSectionType.TEXT, text_size),
        (PdmexeSectionType.RODATA, rodata_size),
        (PdmexeSectionType.DATA, data_size)
    ]:
        if section_size == 0:
            continue
        sections[section_type] = flattened_code_section[split_offset:split_offset+section_size]
        
        split_offset += section_size

    if bss_size != 0:
        sections[PdmexeSectionType.BSS] = bytes([0] * bss_size)

    # load relocations if there are any
    relocs = []
    if num_relocs != 0:
        if PdmexeFileSectionType.RELA not in file_sections:
            raise RuntimeError("overlay module needs relocations, but no relocation section was loaded!")
        relocs = _parse_relocs(file_sections[PdmexeFileSectionType.RELA],
                               num_relocs,
                               sections)
        
        if relocs is None:
            return None
        
    exe = Pdmexe()
    exe._module_id = module_id
    exe._entry_point = entry_point
    exe._module_filename = module_filename
    exe._sections = sections
    exe._relocs = relocs

    return exe
    

EXECUTABLE_HEADER_PATTERN = SignatureBuilder() \
    .pattern([
        0x46, 0x4F, 0x52, 0x4D,
        WILDCARD, WILDCARD, WILDCARD, WILDCARD,
        0x4D, 0x4F, 0x44, 0x55
    ]) \
    .build()

def _load_all_modules_from_rom(rom: N64Rom,
                               filesystem_start_address: int):
    
    modules: dict[int,Pdmexe] = {}

    offset = filesystem_start_address
    while True:
        headertype, datasize, filetype = struct.unpack(">III", rom.read_bytes(offset, 12))

        # beetle adventure racing has a filesystem table and a "everything else" table.
        # the filesystem table ends with eight zeros, so read past them
        if headertype == 0:
            offset += 4
            continue

        if headertype != 0x464F524D:
            logger.info("filesystem ended at 0x%08x", offset)
            break
        
        contents = rom.read_bytes(offset + 12, datasize - 4)
        offset += 8 + datasize

        if filetype == 0x4D4F4455:
            exe = _read_module(contents)

            if exe is None:
                logger.error("error loading module!")
                continue

            modules[exe.module_id()] = exe

    logger.info("loaded %d module(s) from filesystem OK.", len(modules))

    return modules

# -----------------------------------------------

BEETLE_LOAD_EXECUTABLE_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xe8,             # +0x00 addiu      sp,sp,-0x18
        0xaf, 0xbf, 0x00, 0x14,             # +0x04 sw         ra,local_4(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x08 jal        FUN_80003494
        0x00, 0x00, 0x00, 0x00,             # +0x0C _nop
        0x24, 0x01, 0xff, 0xff,             # +0x10 li         at,-0x1
        0x14, 0x41, 0x00, 0x03,             # +0x14 bne        v0,at,LAB_80003544
        0x00, 0x40, 0x20, 0x25,             # +0x18 _or        a0,v0,zero
        0x10, 0x00, 0x00, 0x03,             # +0x1C b          LAB_8000354c
        0x00, 0x00, 0x10, 0x25,             # +0x20 _or        v0,zero,zero
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x24 jal        FUN_8000355c   
        0x00, 0x00, 0x00, 0x00,             # +0x28 _nop
        0x8f, 0xbf, 0x00, 0x14,             # +0x2C lw         ra,local_4(sp)
        0x27, 0xbd, 0x00, 0x18,             # +0x30 addiu      sp,sp,0x18
        0x03, 0xe0, 0x00, 0x08,             # +0x34 jr         ra
        0x00, 0x00, 0x00, 0x00,             # +0x38 _nop
    ]) \
    .build()

# beetle only loads one exe, "game"
BEETLE_MAIN_EXE_LOAD_CALL_PATTERN_A = SignatureBuilder() \
    .pattern([
        0x3c, 0x04, WILDCARD, WILDCARD,          # +0x00 lui        a0,0x6761
        WILDCARD, WILDCARD, WILDCARD, WILDCARD,  # +0x04 sw         zero,offset DAT_80025ce8(at)
        0x0c, WILDCARD, WILDCARD, WILDCARD,      # +0x08 jal        FUN_80003520
        0x34, 0x84, WILDCARD, WILDCARD,          # +0x0C _ori       a0,a0,0x6d65
    ]) \
    .const_op32_hi16("game_exe_id", 0x00) \
    .const_op32_lo16("game_exe_id", 0x0C) \
    .xref_j_imm26("load_exe_address", 0x08) \
    .build()

# f1 loads a lot more exes
BEETLE_MAIN_EXE_LOAD_CALL_PATTERN_B = SignatureBuilder() \
    .pattern([
        0x3c, 0x04, WILDCARD, WILDCARD,          # +0x00 lui        a0,0x6761
        0x0c, WILDCARD, WILDCARD, WILDCARD,      # +0x04 jal        FUN_80003520
        0x34, 0x84, WILDCARD, WILDCARD,          # +0x08 _ori       a0,a0,0x6d65
    ]) \
    .const_op32_hi16("game_exe_id", 0x00) \
    .const_op32_lo16("game_exe_id", 0x08) \
    .xref_j_imm26("load_exe_address", 0x04) \
    .build()

BEETLE_FILESYSTEM_BASE_SETUP_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x04, WILDCARD, WILDCARD,   # +0x00 lui        a0,0x3
        0x3c, 0x01, WILDCARD, WILDCARD,   # +0x04 lui        at,0x8004
        0x00, 0x55, 0x70, 0x23,           # +0x08 subu       t6,v0,s5
        0x3c, 0x0f, WILDCARD, WILDCARD,   # +0x0C lui        t7,0x3
        0x24, 0x84, WILDCARD, WILDCARD,   # +0x10 addiu      a0,a0,0x34f0
    ]) \
    .const_op32_hi16("filesystem_base_address", 0x00) \
    .const_op32_lo16("filesystem_base_address", 0x10) \
    .build()


def _find_exes_loaded_by_pattern(segment: bytes,
                                 segment_load_address: int,
                                 load_exe_fcn_address: int,
                                 pattern):
    
    ids = []
    offset = 0
    while offset != None:
        offset = pattern.find(segment, offset)
        if offset is None:
            return ids
        
        xrefs  = pattern.xrefs(segment_load_address, segment, offset)
        if xrefs["load_exe_address"].get_address() != load_exe_fcn_address:
            offset += 4
            continue

        consts = pattern.consts(segment_load_address, segment, offset)
        ids.append( consts["game_exe_id"].get_value() )
        offset += 4

def _find_exes_loaded(segment: bytes,
                      segment_load_address: int,
                      load_exe_fcn_address: int):
                                 
    exe_ids = []

    for pattern in [ BEETLE_MAIN_EXE_LOAD_CALL_PATTERN_A,
                     BEETLE_MAIN_EXE_LOAD_CALL_PATTERN_B ]:
        exe_ids += _find_exes_loaded_by_pattern(segment,
                                                segment_load_address,
                                                load_exe_fcn_address,
                                                pattern)

    return exe_ids

def beetle_unpack(rom: N64Rom, ipc: int):
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    builder = BffiBuilder()

    earliest_bss, bss_total_size = preamble_extract_bss_sections_to_bffi(preamble, builder)
    bootexe = rom.boot_exe()[:earliest_bss-ipc]

    builder.fix(ipc, bootexe)
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())

    load_exe_offset = BEETLE_LOAD_EXECUTABLE_PATTERN.find(bootexe)
    if load_exe_offset is None:
        return None
    
    logger.info("found Paradigm Entertainment dynamic loader")

    exes_loaded = _find_exes_loaded(bootexe, ipc, load_exe_offset + ipc)
    logger.info("boot segment loads %d executable(s)", len(exes_loaded))

    filesystem_base_setup_offset = BEETLE_FILESYSTEM_BASE_SETUP_PATTERN.find(bootexe)
    if filesystem_base_setup_offset is None:
        logger.error("unable to find filesystem base")
        return None
    
    consts = BEETLE_FILESYSTEM_BASE_SETUP_PATTERN.consts(ipc, bootexe, filesystem_base_setup_offset)

    filesystem_base_address = consts["filesystem_base_address"].get_value()
    logger.info("filesystem starts in ROM at 0x%08x", filesystem_base_address)

    modules = _load_all_modules_from_rom(rom, filesystem_base_address)

    # TODO: convert this to use BFFI dynamic loading if and when that's ever supported
    load_address = earliest_bss + bss_total_size
    logger.info("Statically linking modules into RAM at 0x%08x", load_address)
    for module_id in exes_loaded:
        if module_id not in modules:
            # HACK: Indy Racing 2000 attempts to load "UVD2" which doesn't exist in the ROM.
            # could be a debugging leftover that they forgot to remove from the final build.
            if (module_id & 0xFFFFFF00) == 0x55564400:
                logger.warning("attempt to load nonexistant/not loaded module UVDx (0x%08x), ignoring!",
                               module_id)
                continue

            logger.error("module id 0x%08x wasn't in the filesystem!", module_id)
            return None
        
        module = modules[module_id]

        logger.info("statically relocating module 0x%08x (%s) to 0x%08x",
                    module_id,
                    module.module_filename(),
                    load_address)
        
        code, bss_size = _relocate_and_flatten_module(module, load_address)
        code_size = len(code)
        code_and_bss_size = code_size + bss_size
        logger.info("\tcode:  0x%08x-0x%08x", load_address, load_address + code_size)
        logger.info("\tbss:   0x%08x-0x%08x", load_address + code_size, load_address + code_and_bss_size)
        logger.info("\tentry: 0x%08x", load_address + module.entry_point())

        builder.fix(load_address, code)
        builder.bss(load_address + code_size, bss_size)

        load_address += code_and_bss_size

    if load_address >= 0x80400000:
        logger.warning("total loaded boot code went outside of 4 MB RDRAM space!")
    if load_address > 0x80800000:
        logger.error("RDRAM space exhausted!!")
        return None

    # load other modules as seg sections
    for module_id, module in modules.items():
        if module_id in exes_loaded:
            continue
        
        logger.info("relocating dynload module 0x%08x (%s) to 0x00000000",
                    module_id,
                    module.module_filename())
        
        code, bss_size = _relocate_and_flatten_module(module, 0x00000000)
        code = code + bytes([0] * bss_size)

        builder.seg(0, code)

    return builder.build()

# -----------------------------------------------
#
# Pilotwings 64 / Aero Fighters Assault
#
# Clears additional BSS section and copies the main code segment to RAM.
# The filesystem is only used for resources (I hope).
#
# TODO: doublecheck these guys for additional code segments.
# pilotwings in particular looks a bit small (only 530k)
#
# -----------------------------------------------

# Pilotwings loads the overlay before clearing BSS
PILOTWINGS_MAIN_OVERLAY_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xe8,             # +0x00 addiu      sp,sp,-0x18
        0xaf, 0xa4, 0x00, 0x18,             # +0x04 sw         a0,0x18(sp)
        0x3c, 0x05, WILDCARD, WILDCARD,     # +0x08 lui        a1,0x5
        0x3c, 0x0e, WILDCARD, WILDCARD,     # +0x0C lui        t6,0xe
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x10 addiu      a1,a1,0x1e30
        0xaf, 0xbf, 0x00, 0x14,             # +0x14 sw         ra,0x14(sp)
        0x25, 0xce, WILDCARD, WILDCARD,     # +0x18 addiu      t6,t6,-0x18e0
        0x3c, 0x04, 0x80, WILDCARD,         # +0x1C lui        a0,0x802d
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x20 addiu      a0,a0,-0x5700
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x24 jal        FUN_8022a760
        0x01, 0xc5, 0x30, 0x23,             # +0x28 _subu      a2,t6,a1
        0x3c, 0x04, 0x80, WILDCARD,         # +0x2C lui        a0,0x8035
        0x3c, 0x0f, 0x80, WILDCARD,         # +0x30 lui        t7,0x8038
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x34 addiu      a0,a0,0x71f0
        0x25, 0xef, WILDCARD, WILDCARD,     # +0x38 addiu      t7,t7,0x5e0
        0x01, 0xe4, 0x30, 0x23,             # +0x3C subu       a2,t7,a0
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x40 jal        FUN_8022aa80
        0x00, 0x00, 0x28, 0x25,             # +0x44 _or        a1,zero,zero
    ]) \
    .const_op32_hi16("rom_start_address", 0x08) \
    .const_op32_lo16("rom_start_address", 0x10) \
    .const_op32_hi16("rom_end_address", 0x0C) \
    .const_op32_lo16("rom_end_address", 0x18) \
    .const_op32_hi16("load_address", 0x1C) \
    .const_op32_lo16("load_address", 0x20) \
    .const_op32_hi16("bss_start", 0x2C) \
    .const_op32_lo16("bss_start", 0x34) \
    .const_op32_hi16("bss_end",   0x30) \
    .const_op32_lo16("bss_end",   0x38) \
    .build()

# Aerofighters clears BSS then loads the overlay
AEROFIGHTERS_MAIN_OVERLAY_LOAD_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xe8,             # +0x00 addiu  sp,sp,-0x18
        0xaf, 0xa4, 0x00, 0x18,             # +0x04 sw     a0,0x18(sp)
        0x3c, 0x04, 0x80, WILDCARD,         # +0x08 lui    a0,0x8032 <-- bss start
        0x3c, 0x0e, 0x80, WILDCARD,         # +0x0C lui    t6,0x8035 <-- bss end
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x10 addiu  a0,a0,0x33c0
        0xaf, 0xbf, 0x00, 0x14,             # +0x14 sw     ra,0x14(sp)
        0x25, 0xce, WILDCARD, WILDCARD,     # +0x18 addiu  t6,t6,-0x6ad0
        0x01, 0xc4, 0x30, 0x23,             # +0x1C subu   a2,t6,a0
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x20 jal    memset
        0x00, 0x00, 0x28, 0x25,             # +0x24 _or    a1,zero,zero
        0x3c, 0x05, WILDCARD, WILDCARD,     # +0x28 lui    a1,0x5          <-- ROM start address
        0x3c, 0x0f, WILDCARD, WILDCARD,     # +0x2C lui    t7,0x12         <-- ROM end address
        0x24, 0xa5, WILDCARD, WILDCARD,     # +0x30 addiu  a1,a1,0x7d20
        0x25, 0xef, WILDCARD, WILDCARD,     # +0x34 addiu  t7,t7,-0x7970
        0x3c, 0x04, 0x80, WILDCARD,         # +0x38 lui    a0,0x8028       <-- RAM load address
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x3C addiu  a0=>,a0,0x7430
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x40 jal    read_rom
        0x01, 0xe5, 0x30, 0x23              # +0x44 _subu  a2,t7,a1
    ]) \
    .const_op32_hi16("bss_start", 0x08) \
    .const_op32_lo16("bss_start", 0x10) \
    .const_op32_hi16("bss_end",   0x0C) \
    .const_op32_lo16("bss_end",   0x18) \
    .const_op32_hi16("rom_start_address", 0x28) \
    .const_op32_lo16("rom_start_address", 0x30) \
    .const_op32_hi16("rom_end_address", 0x2C) \
    .const_op32_lo16("rom_end_address", 0x34) \
    .const_op32_hi16("load_address", 0x38) \
    .const_op32_lo16("load_address", 0x3C) \
    .build()


def _pick_pattern(bootexe: bytes):
    pattern_offset = AEROFIGHTERS_MAIN_OVERLAY_LOAD_PATTERN.find(bootexe)
    if pattern_offset is not None:
        return AEROFIGHTERS_MAIN_OVERLAY_LOAD_PATTERN, pattern_offset
    
    pattern_offset = PILOTWINGS_MAIN_OVERLAY_LOAD_PATTERN.find(bootexe)
    if pattern_offset is not None:
        return PILOTWINGS_MAIN_OVERLAY_LOAD_PATTERN, pattern_offset

    return None, None

def aerofighters_unpack(rom: N64Rom, ipc: int):
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None

    builder = BffiBuilder()

    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())

    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    bootexe = rom.boot_exe()[:earliest_bss-ipc]

    pattern, main_overlay_load_offset = _pick_pattern(bootexe)
    if pattern is None:
        return None
    
    logger.info("found Paradigm Entertainment Pilotwings/Aero Fighters-style main segment bootstrap")
    consts = pattern.consts(ipc, bootexe, main_overlay_load_offset)

    bss_start           = consts["bss_start"].get_value()
    bss_end             = consts["bss_end"].get_value()
    rom_start_address   = consts["rom_start_address"].get_value()
    rom_end_address     = consts["rom_end_address"].get_value()
    load_address        = consts["load_address"].get_value()

    logger.info("main segment bss 0x%08x-0x%08x", bss_start, bss_end)
    logger.info("main segment in ROM at 0x%08x-0x%08x, loads to 0x%08x", rom_start_address, rom_end_address, load_address)
    
    main_segment = rom.read_bytes(rom_start_address, rom_end_address-rom_start_address)

    builder.bss(bss_start, bss_end-bss_start)
    builder.fix(load_address, main_segment)

    return builder.build()
