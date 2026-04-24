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

from n64rom import N64Rom
from preamble import identify_preamble
from signature import SignatureBuilder, WILDCARD

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

    MIPS_HI16   = 2
    '''
    hi16 instruction; containing the upper 16 bits of a 32 bit address.
    Typically a lui instruction.
    '''

    MIPS_LO16   = 3
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

    def symbol_id(self):
        '''
        Return entry in symbol section that this reloc points to.
        '''
        return self._word_a >> 4
    
    def wired(self):
        '''
        Whether the reloc has been applied or not.
        '''
        return (self._word_a & 8) != 0

    def offset(self):
        '''
        If the reloc is not wired, then this is an offset within the section
        we're about to apply it to. If it is wired, then it's a literal address.
        '''
        return self._offset
    
    def original_instruction(self):
        '''
        If this reloc is wired, then this contains the original instruction,
        which we can drop back into place when we unload a DLL that the reloc
        points to, or if we want to shuffle the segment around in memory.

        If this reloc is not wired, it typically contains 1 (just an integer).
        '''
        return self._original_instruction

class USOSymbolEntry:
    def __init__(self, entry_bytes: bytes):
        self._word_a, self._offset, self._word_c = struct.unpack(">III", entry_bytes)

    def wired(self):
        return ((self._word_a >> 16) & 8) != 0
    
    def symbol_type(self) -> USOSymbolType:
        return USOSymbolType((self._word_a >> 16) & 7)

    def is_import(self):
        return self.symbol_type() == USOSymbolType.IMPORT

    def local_section_type(self):
        if self.is_import():
            return None
        return USOFilesystemEntryType((self._word_a >> 16) >> 4)

    def offset(self):
        '''
        If entry is not wired and is a local, this is the offset within the section.
        If entry is not wired and is a global, this is the offset of that symbol (typically 0).
        If entry is wired, this is the absolute address of the symbol in memory.
        '''
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

def _read_filesystem_header(rom: N64Rom, read_pointer: int) -> tuple[int,USOFilesystemEntryType,int,int]:
    entry = rom.read_bytes(read_pointer, 0x0C)
    read_pointer += 0x0C
    entry_type, num_bytes, something = struct.unpack(">III", entry)
    return read_pointer, USOFilesystemEntryType(entry_type), num_bytes, something

def _dump_relocs(reloc_section: bytes, symbols: list):
    for i in range( int(len(reloc_section) / 12) ):
        reloc_entry = reloc_section[i*12:(i+1)*12]
        control_word, offset, original_instruction = struct.unpack(">III", reloc_entry)

        logger.info("\t\treloc: sym %08x type %s offset %08x orig %08x",
                    control_word >> 4,
                    USORelocType(control_word & 7),
                    offset,
                    original_instruction)
        
        if symbols is not None:
            symbol = symbols[control_word >> 4]
            logger.info("\t\t\tassoc symbol: valid=%s sid %02x offset %08x import=%s id %08x",
                        symbol.entry_valid(),
                        symbol.section_id(),
                        symbol.offset(),
                        symbol.is_import(),
                        symbol.id())


# 80002650 parses the symbol section
def _parse_symbols(symbol_section: bytes) -> bytes:
    symbols = []

    for i in range( int(len(symbol_section) / 12) ):
        symbol_entry = symbol_section[i*12:(i+1)*12]
        symbol = USOSymbolEntry(symbol_entry)
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

def _extract_cstring(data: bytes):
    return data.partition(b'\x00')[0].decode('ascii')

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

        filesystem_name = _extract_cstring(bootexe[filename_ptr-ipc:])
        all_files += _extract_files_in_filesystem(rom, rom_start_address, filesystem_name)

        offset += (4*5)


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

    bootexe_filename = _extract_cstring(rom.boot_exe()[bootexe_filename_ptr-ipc:])

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
    
