'''
"USO" (Ultra Sixtyfour Operating System?), used by 1080 Snowboarding

What a gigantic pain in the ass this is. Custom OS, relocatable executables,
filesystem tables, functions being called through pointers... Absolute torture.

For 1080 US/JP, the filesystems are
- "mainuso" in ROM from 0xD9FDB0~0xE984B0 (contains boot executable)
- "rom" in ROM from 0xB7C0~0xD9FDB0 (resources)

There are two main filetypes in the filesystem: .uso and .bin.
.bin is just a normal binary file; nothing is special about it.

.uso is basically "let's use ELF without actually using ELF". These files
separate their contents into different sections. Many are just data files
with relocation data so they can point to other stuff loaded in memory, but
many are code overlays, and this includes the boot executable ("bootup.uso").

When an .uso file is loaded, it'll have an entry registered in RDRAM along with
its sections. When loading symbols, local symbols are simply a pointer within a
section, and imports represent an index from the remote file's symbol table.
The game can't load all its files in one shot, so if it sees a file isn't loaded
when parsing its symbol section, it simply says "we have N unresolved imports"
and moves on.

The contents of any of these files may be optionally compressed. I'm not sure
how compression works just yet, but I do know that bootup.uso is completely
uncompressed.

Very special thanks must go to Giles Goddart and Colin Reed for leaving a ton
of debug strings in the ROM, as well as leaving a partially working debug
console still functional.
'''

from enum import Enum
import logging
import struct

from bffi import BffiBuilder
from n64rom import N64Rom
from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi
from signature import SignatureBuilder, WILDCARD
from strutil import extract_cstring

logger = logging.getLogger(__name__)

# relocations are applied by the function at 80001edc.
# 80001edc takes the following parameters
# - $a0 = file entry we are parsing relocations for
#         0x3C($a0) will point to the symbol section
# - $a1 = pointer to start of section we're applying relocs to
# - $a2 = pointer to reloc table
# - $a3 = number of entries in reloc table
class USORelocType(Enum):
    MIPS_JUMP_IMM_26 = 1
    '''
    Immediate 26-bit address (already divided by 4) with the upper 6
    bits, i.e., the instruction type, almost certainly set to a J or JAL instruction.

    Read the instruction, mask off the lower 26 bits (AND with 0x3FFFFFFF),
    add it to the relocation offset (divided by 4), then AND with the
    upper 6 bits to form the final instruction.
    '''

    MIPS_HI16   = 3
    '''
    hi16 instruction; containing the upper 16 bits of a 32 bit address.
    Typically a lui instruction.
    '''

    MIPS_LO16   = 2
    '''
    lo16 instruction; containing the lower 16 bits of a 32 bit address.
    Typically an ori or addiu instruction.
    '''

    MIPS_IMM_32 = 4
    '''
    Immediate 32-bit word.
    
    Read the word currently at this address, add it to the relocation offset, and write it back.
    '''

    # all others illegal

class USOFilesystemEntryType(Enum):
    INFO         = 0x0
    '''
    File information. This entry type indicates start of file.
    '''

    SYM          = 0x1
    '''
    Symbol table. Must be defined if relocations are used within this file,
    or if something else imports something from us.
    '''

    TEXT_RELOC   = 0x2
    DATA_RELOC   = 0x3
    RODATA_RELOC = 0x4

    TEXT         = 0x5
    '''
    .text (code) section.
    '''
    
    DATA         = 0x6
    '''
    .data section.
    '''

    RODATA       = 0x7
    '''
    .rodata (read-only data) section.
    There's no memory protection in N64 games, so this can actually be written to.
    '''

    BSS          = 0x8
    '''
    Your usual BSS section. Allocate this number of bytes on the heap
    and set 'em all to zero. Though BSS entries in the USO filesystem
    have a size set to them, the parser only uses this to set up the
    section. 
    '''

    ENTRYSYM     = 0x9
    '''
    Entry point offset in the text section to jump to (I think).
    Only bootup.uso should have this; the code overlays don't.
    '''

    ENDOFFILE    = 0xA
    '''
    End of filesystem. Do not walk the filesystem past this point.
    '''

    END          = 0xB
    '''
    End of file. Expect INFO or ENDOFFILE next.
    '''

    BINARYDATASECTION = 0xC
    '''
    Raw data. If reading an executable, this section type is illegal.
    '''

    DISKINFO = 0xD
    '''
    "Diskinfo" section, which is unused in 1080. Might have been intended for 64DD
    or debugging stuff.
    '''
class USOSymbolType(Enum):
    UNUSED = 0
    '''
    Ignore if 0.
    '''

    IMPORT = 1
    '''
    This symbol is an import. The first 16 bits of the symbol entry will be the file number
    to import from. When filesystems are loaded at boot, they'll all get a global file number,
    with bootup.uso being file number 0.
    '''

    GLOBAL_A = 2
    '''
    If encountered, then the section ID will be one of the entries in USOFilesystemEntryType
    (TEXT, DATA, RODATA or BSS), and the offset will point within there.
    '''

    UNWIRED = 3
    '''
    When encountered, the "entry valid" flag is immediately set to True, and
    the entry is otherwise untouched.
    '''

    GLOBAL_B = 4
    '''
    Functionally identical to GLOBAL_A.
    '''
class USORelocEntry:
    def __init__(self, entry_bytes: bytes):
        self._word_a, \
        self._offset, \
        self._original_instruction = struct.unpack(">III", entry_bytes)

    def serialize(self):
        return struct.pack(">III", self._word_a, self._offset, self._original_instruction)

    def symbol_id(self):
        '''
        Return entry in symbol section that this reloc points to.
        '''
        return self._word_a >> 4
    
    def type(self) -> USORelocType:
        return USORelocType(self._word_a & 7)

    def wired(self, new_wired: bool | None = None):
        '''
        Whether the reloc has been applied or not.
        '''
        if new_wired is not None:
            self._word_a &= ~(8)
            self._word_a |= 8 if new_wired is True else 0

        return (self._word_a & 8) != 0

    def offset(self):
        '''
        If the reloc is not wired, then this is an offset within the section
        we're about to apply it to. If it is wired, then it's a literal address.
        '''
        return self._offset
    
    def original_instruction(self, new_original_instruction: int | None = None):
        '''
        If this reloc is wired, then this contains the original instruction,
        which we can drop back into place when we unload a DLL that the reloc
        points to, or if we want to shuffle the segment around in memory.

        If this reloc is not wired, it typically contains 1 (just an integer).
        '''
        if new_original_instruction is not None:
            self._original_instruction = new_original_instruction

        return self._original_instruction

class USOSymbolEntry:
    def __init__(self, entry_bytes: bytes):
        self._word_a, self._offset, self._word_c = struct.unpack(">III", entry_bytes)

    def serialize(self):
        return struct.pack(">III", self._word_a, self._offset, self._word_c)

    def wired(self, new_wired: bool | None = None):
        if new_wired:
            self._word_a &= ~(0x00080000)
            self._word_a |= 0x00080000 if new_wired else 0

        return ((self._word_a >> 16) & 8) != 0
    
    def symbol_type(self) -> USOSymbolType:
        return USOSymbolType((self._word_a >> 16) & 7)

    def is_import(self):
        return self.symbol_type() == USOSymbolType.IMPORT

    def local_section_type(self):
        if self.is_import():
            return None
        return USOFilesystemEntryType((self._word_a >> 16) >> 4)

    def offset(self, new_offset: int | None = None):
        '''
        If entry is not wired and is a local, this is the offset within the section.
        If entry is not wired and is a global, this is the offset of that symbol (typically 0).
        If entry is wired, this is the absolute address of the symbol in memory.
        '''
        if new_offset is not None:
            self._offset = new_offset

        return self._offset
    
    def remote_file_id(self) -> int | None:
        '''
        If this symbol is an import, returns the remote file ID.
        Otherwise, returns None.
        '''
        if self.is_import() is False:
            return None
        return (self._word_a >> 16) >> 4

    def remote_symbol_id(self) -> int | None:
        '''
        If this symbol is an import, returns the remote symbol ID.
        Otherwise, returns None.
        '''
        if self.is_import() is False:
            return None
        return self._word_c >> 16

class USOFile:
    def __init__(self,
                 parent_filesystem: str,
                 filename: str,
                 contents: dict,
                 load_order: list[USOFilesystemEntryType]):
        self._parent_filesystem = parent_filesystem
        self._filename = filename
        self._contents = contents
        self._load_order = load_order

    def parent_filesystem(self):
        return self._parent_filesystem
    
    def filename(self):
        return self._filename
    
    def path(self):
        return self.parent_filesystem() + '/' + self.filename()
    
    def section(self, sectiontype: USOFilesystemEntryType, new_contents: bytes | None = None):
        if new_contents is not None:
            self._contents[sectiontype] = bytes(new_contents)
        return bytes(self._contents[sectiontype]) if sectiontype in self._contents else None

    def load_order(self):
        return self._load_order

# ------------------------------------------------------------

def sign_extend_imm16_value(opcode: int) -> int:
    return struct.unpack(">hh", struct.pack(">I", opcode))[1]

def _read_filesystem_header(rom: N64Rom, read_pointer: int) -> tuple[int,USOFilesystemEntryType,int,int]:
    entry = rom.read_bytes(read_pointer, 0x0C)
    read_pointer += 0x0C
    entry_type, num_bytes, something = struct.unpack(">III", entry)
    return read_pointer, USOFilesystemEntryType(entry_type), num_bytes, something

# 80002650 parses the symbol section
def _parse_symbols(symbol_section: bytes) -> list[USOSymbolEntry]:
    symbols = []

    for i in range( int(len(symbol_section) / 12) ):
        symbol_entry = symbol_section[i*12:(i+1)*12]
        symbol = USOSymbolEntry(symbol_entry)
        symbols.append(symbol)

    return symbols

def _parse_relocs(symbol_section: bytes) -> list[USORelocEntry]:
    symbols = []

    for i in range( int(len(symbol_section) / 12) ):
        symbol_entry = symbol_section[i*12:(i+1)*12]
        symbol = USORelocEntry(symbol_entry)
        symbols.append(symbol)

    return symbols

def _read_file_contents(rom: N64Rom, read_offset: int) -> tuple[int,dict[USOFilesystemEntryType,bytes],list]:
    '''
    Read file contents into a dict.
    '''
    sections = {}

    load_order = []

    while True:
        read_offset, \
        entry_type, \
        num_bytes, \
        something = _read_filesystem_header(rom, read_offset)

        if entry_type in [ USOFilesystemEntryType.INFO, USOFilesystemEntryType.ENDOFFILE ]:
            raise RuntimeError(f"hit unexpected header of type {entry_type.name} at 0x{read_offset:08x}!")
        
        if entry_type == USOFilesystemEntryType.END:
            # end of file
            return read_offset, sections, load_order
        
        load_order.append(entry_type)
        if entry_type == USOFilesystemEntryType.BSS:
            sections[USOFilesystemEntryType.BSS] = bytes([0] * num_bytes)
        else:
            data = rom.read_bytes(read_offset, num_bytes)
            sections[entry_type] = data
            read_offset += num_bytes

def _extract_files_in_filesystem(rom: N64Rom, read_offset: int, parent_filesystem: str) -> list[USOFile]:
    files = []
    while True:
        read_offset, \
        entry_type, \
        num_bytes, \
        something = _read_filesystem_header(rom, read_offset)

        if entry_type == USOFilesystemEntryType.ENDOFFILE:
            # end of filesystem
            return files

        # we need to find a file entry node here
        if entry_type != USOFilesystemEntryType.INFO:
            raise RuntimeError(f"unexpected entry type at 0x{read_offset:08x}: {entry_type.name}")

        node = rom.read_bytes(read_offset, num_bytes)
        read_offset += num_bytes
        if node[:4] != b'\x12\x34\x56\x78':
            raise RuntimeError("filenode data did not start with 0x12345678")

        filename = node[0x0C:].partition(b'\x00')[0].decode("ascii")

        read_offset, contents, load_order = _read_file_contents(rom, read_offset)

        if not contents:
            continue
        
        files.append(USOFile(parent_filesystem, filename, contents, load_order))


def _extract_all_files(rom: N64Rom,
                       ipc: int,
                       filesystem_mount_command_table_address: int) -> tuple[int, list[USOFile]]:
    '''
    Extracts filesystem contents. Returns the heap base address and a list of all files.
    '''

    bootexe = rom.boot_exe()

    heap_base_addr = None
    all_files = []
    offset = filesystem_mount_command_table_address - ipc

    while True:
        filename_ptr, rom_start_address, rom_end_address, heap_base, _ = \
            struct.unpack(">IIIII", bootexe[offset:offset+(4*5)])
        
        if filename_ptr == 0:
            return heap_base_addr, all_files
        
        if heap_base != 0:
            if heap_base_addr is not None:
                raise RuntimeError("heap base address set multiple times")
            heap_base_addr = heap_base

        filesystem_name = extract_cstring(bootexe[filename_ptr-ipc:])
        all_files += _extract_files_in_filesystem(rom, rom_start_address, filesystem_name)

        offset += (4*5)

def _wire_local_symbols(file: USOFile,
                        base_addresses = {}):
    
    symbols = _parse_symbols(file.section(USOFilesystemEntryType.SYM))

    for symbol in symbols:
        if symbol.wired():
            continue

        if symbol.is_import():
            continue
            
        symbol_type = symbol.symbol_type()
        if symbol_type == USOSymbolType.UNUSED:
            continue

        # symbol is in memory, so mark it wired
        symbol.wired(True)

        # parser does nothing else with this kind of symbol;
        # it just marks it wired then abandons it
        if symbol_type == USOSymbolType.UNWIRED:
            continue

        local_section_type = symbol.local_section_type()
        if local_section_type not in base_addresses:
            raise RuntimeError("symbol points to local section that doesn't exist!")

        new_offset = symbol.offset() + base_addresses[local_section_type]
        logger.debug("wire symbol: %s+0x%08x = 0x%08x",
                     local_section_type.name,
                     symbol.offset(),
                     new_offset)

        symbol.offset(new_offset)

    new_symbol_section = bytearray()
    for symbol in symbols:
        new_symbol_section += symbol.serialize()
    
    file.section(USOFilesystemEntryType.SYM, new_symbol_section)


def _relocate_file(file: USOFile,
                   files: list[USOFile]):

    symbol_blob = file.section(USOFilesystemEntryType.SYM)
    if symbol_blob is None:
        raise RuntimeError("file {file.path()} has no symbols loaded")

    symbols = _parse_symbols(symbol_blob)

    for reloc_section_type, section_type in [
                            (USOFilesystemEntryType.TEXT_RELOC, USOFilesystemEntryType.TEXT),
                            (USOFilesystemEntryType.DATA_RELOC, USOFilesystemEntryType.DATA),
                            (USOFilesystemEntryType.RODATA_RELOC, USOFilesystemEntryType.RODATA)
                            ]:
        reloc_section  = file.section(reloc_section_type)
        if reloc_section is None:
            continue
        
        section = file.section(section_type)
        if section is None:
            raise RuntimeError("orphaned reloc section")

        writable_section = bytearray(section)

        last_hi16_offset      = 0
        last_hi16_instruction = 0
        last_hi16_relocation  = None

        relocs = _parse_relocs(reloc_section)
        for reloc in relocs:
            symbol_id = reloc.symbol_id()
            if (0 <= symbol_id <= len(symbols)) is False:
                raise RuntimeError("symbol {symbol_id} is out of bounds!!")
            symbol = symbols[symbol_id]

            if symbol.is_import():
                if (0 <= symbol.remote_file_id() < len(files)) is False:
                    raise RuntimeError(f"symbol import file index out of range ({symbol.remote_file_id()})")
            
                # skip imports because nothing else is loaded yet
                continue

            if symbol.wired() is False:
                raise RuntimeError("symbol should have been wired by now!")
                
            symbol_type = symbol.symbol_type()
            if symbol_type == USOSymbolType.UNUSED:
                continue

            if symbol_type == USOSymbolType.UNWIRED:
                continue

            # the symbol is wired, so we'll have its absolute address
            symbol_target_offset  = symbol.offset()
            reloc_offset = reloc.offset()

            original_instruction = struct.unpack(">I",writable_section[reloc_offset:reloc_offset+4])[0]
            patched_instruction: int = None
            reloc_type = reloc.type()
            if reloc_type == USORelocType.MIPS_JUMP_IMM_26:
                hibits = original_instruction & 0xFC000000
                lo26   = original_instruction & 0x03FFFFFF

                unpatched_offset = (lo26 << 2)
                patched_offset = unpatched_offset + (symbol_target_offset & 0x03FFFFFF)

                patched_instruction = hibits | (patched_offset >> 2)

                logger.debug("mips imm26: change %08x to %08x / offset 0x%08x -> 0x%08x",
                                original_instruction,
                                patched_instruction,
                                unpatched_offset,
                                patched_offset + 0x80000000)

            elif reloc_type == USORelocType.MIPS_IMM_32:
                patched_instruction = original_instruction + symbol_target_offset
                logger.debug("mips imm32: change %08x to %08x",
                    original_instruction,
                    patched_instruction)
                
            elif reloc_type == USORelocType.MIPS_HI16:
                # hitting a hi16 means a lo16 must follow or it will
                # never be applied
                last_hi16_offset = reloc_offset
                
                # the hi16 instruction will "latch" until another hi16 is found.
                last_hi16_instruction = original_instruction
                last_hi16_relocation  = reloc

                logger.debug("mips hi16: delaying")
                continue

            elif reloc_type == USORelocType.MIPS_LO16:
                imm16 = original_instruction & 0xFFFF

                last_hi16_imm16 = last_hi16_instruction & 0xFFFF
                lo16_sign_extended = sign_extend_imm16_value(original_instruction)
                
                # this code is very annoying to disassemble if you don't know that
                # the SRA instruction is being abused to sign-extend 16-bit words
                # and that the hi16 and lo16 values are loaded using lh, which
                # sign extends them.
                absolute_offset = \
                    (last_hi16_imm16 << 16) + lo16_sign_extended + symbol_target_offset
                
                logger.debug("mips lo16: absolute offset 0x%08x (hi16 %08x lo16 %08x sym %08x)",
                                absolute_offset,
                                (last_hi16_imm16 << 16),
                                lo16_sign_extended & 0xFFFFFFFF,
                                symbol_target_offset
                                )

                if last_hi16_offset != 0:
                    absolute_offset_hi16 = \
                        (absolute_offset - sign_extend_imm16_value(absolute_offset & 0xFFFF)) >> 16

                    patched_hi16_instruction = \
                        (last_hi16_instruction & 0xFFFF0000) | absolute_offset_hi16

                    logger.debug("mips hi16: change %08x -> %08x (imm16: %04x -> %04x)",
                                    last_hi16_instruction,
                                    patched_hi16_instruction,
                                    last_hi16_imm16,
                                    absolute_offset_hi16)

                    writable_section[last_hi16_offset:last_hi16_offset+4] = struct.pack(">I", patched_hi16_instruction)
                    reloc.original_instruction(last_hi16_instruction)
                    reloc.wired(True)

                    # forget the original hi16 location now that we've applied it
                    # because all lo16s until we hit another hi16 will reuse the hi16 instruction
                    # that we have latched right now
                    last_hi16_offset = 0

                # we keep the lo16 bits pretty much the same because of the 2's complement
                # nature of what we've just done above.
                # with an address of 8005C6E0:
                #
                # hi16 = 80060000
                # lo16 = FFFFC6E0
                #
                # adding them together produces 8005C6E0.
                absolute_offset_lo16 = absolute_offset & 0xFFFF

                patched_instruction = (original_instruction & 0xFFFF0000) | absolute_offset_lo16

                logger.debug("mips lo16: change %08x -> %08x (imm16: %04x -> %04x)",
                                original_instruction,
                                patched_instruction,
                                imm16,
                                absolute_offset_lo16)

            writable_section[reloc_offset:reloc_offset+4] = struct.pack(">I", patched_instruction)
            reloc.original_instruction(original_instruction)
            reloc.wired(True)

        # end of relocation apply loop
        # write the patched section text/data/rodata section back
        file.section(section_type, writable_section)

        # also write back the updated reloc section now that they're wired
        updated_reloc_section = bytearray()
        for reloc in relocs:
            updated_reloc_section += reloc.serialize()
        file.section(reloc_section_type, updated_reloc_section)

# ------------------------------------------------------------

TENEIGHTY_BOOT_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x05, 0x80, 0x00,             # +0x00 lui   a1,0x8000
        0x8c, 0xa5, 0x03, 0x18,             # +0x04 lw    a1,offset DAT_80000318(a1) <-- osMemSize?
        0x27, 0xbd, 0xff, 0xe8,             # +0x08 addiu sp,sp,-0x18
        0x3c, 0x04, 0x80, WILDCARD,         # +0x0C lui   a0,0x8001      <-- filesystem list
        0x3c, 0x01, 0x80, 0x00,             # +0x10 lui   at,0x8000
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x14 addiu a0,a0,-0x5da0
        0xaf, 0xbf, 0x00, 0x14,             # +0x18 sw    ra,0x14(sp)
        0x00, 0xa1, 0x70, 0x21,             # +0x1C addu  t6,a1,at
        0x0c, 0x00, 0x06, 0x65,             # +0x20 jal   init_os_basics
        0xac, 0x8e, 0x00, 0x10,             # +0x24 _sw   t6,0x10(a0)   <-- pointer to end of RDRAM
        0x3c, 0x04, 0x80, WILDCARD,         # +0x28 lui    a0,0x8001     <-- boot exe path
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x2C jal    load_program
        0x24, 0x84, WILDCARD, WILDCARD,     # +0x30 _addiu a0,a0,-0x5a64
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x34 jal    boot
        0x00, 0x00, 0x00, 0x00,             # +0x38 _nop
    ]) \
    .const_op32_hi16("filesystem_list_ptr", 0x0C) \
    .const_op32_lo16("filesystem_list_ptr", 0x14) \
    .const_op32_hi16("bootexe_filename_ptr", 0x28) \
    .const_op32_lo16("bootexe_filename_ptr", 0x30) \
    .build()


def uso_unpack(rom: N64Rom, ipc: int):
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    if TENEIGHTY_BOOT_PATTERN.compare(rom.boot_exe(), preamble.crt_entry_point() - ipc) is False:
        return None
    
    logger.info("found 1080 Snowboarding USO dynamic loader")

    consts = TENEIGHTY_BOOT_PATTERN.consts(ipc, rom.boot_exe(), preamble.crt_entry_point() - ipc)
    filesystem_list_ptr = consts["filesystem_list_ptr"].get_value()
    bootexe_filename_ptr = consts["bootexe_filename_ptr"].get_value()

    bootexe_filename = extract_cstring(rom.boot_exe()[bootexe_filename_ptr-ipc:])

    heap_base, files = _extract_all_files(rom, ipc, filesystem_list_ptr)

    logger.info("USO system heap starts at 0x%08x", heap_base)
    logger.info("%d files loaded from filesystems", len(files))
    logger.info("game boots from: %s", bootexe_filename)

    bootexe_file = None
    for f in files:
        if f.path() == bootexe_filename:
            bootexe_file = f
            break
    
    if bootexe_file is None:
        logger.error("can't find boot executable")
        return None
    
    base_pointer = heap_base
    base_addresses = {}

    logger.info("rough idea of how bootexe will be loaded:")
    non_bss_length = 0
    for section_type in bootexe_file.load_order():
        base_addresses[section_type] = base_pointer

        section_length = len(bootexe_file.section(section_type))

        base_pointer += section_length
        logger.info("\tsection %s, 0x%08x-0x%08x", section_type.name, base_addresses[section_type], base_pointer)

    # pass 1: wire all symbols for sections we just loaded
    _wire_local_symbols(bootexe_file, base_addresses)

    # pass 2: apply relocations
    _relocate_file(bootexe_file, files)

    # TODO: load other modules and process imports... for now i'm exhausted

    # TODO: in the future, the BFFI file format has to support relocations
    # so that it can store relocations for 1080 as well as the zelda games.
    # for now, we can fake a statically-loaded bootexe.

    logger.info("loaded and relocated bootexe OK. it's BFFI time bitch.")

    builder = BffiBuilder()
    earliest_bss_address, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    builder.fix(ipc, rom.boot_exe()[:earliest_bss_address-ipc])

    for section_type in bootexe_file.load_order():
        if section_type == USOFilesystemEntryType.BSS:
            builder.bss(base_addresses[section_type],
                len(bootexe_file.section(section_type)))
        else:
            builder.fix(base_addresses[section_type],
                        bootexe_file.section(section_type))
    
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())

    return builder.build()
