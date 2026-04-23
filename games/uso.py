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

logger = logging.getLogger(__name__)

# relocations are applied by the function at 80001edc.
# they are in the format:
# - 4 bytes
#   - bits 0~2 are the relocation type. AND with 7 to get it
# - 4 bytes
# - 4 bytes
class USORelocType(Enum):
    MIPS_JUMP_IMM_26 = 1

    MIPS_HI16   = 2

    MIPS_LO16   = 3

    # guessed, might not be right
    MIPS_IMM_32 = 4

    # all others illegal

class USOFilesystemEntryType(Enum):
    INFO         = 0x0
    '''
    File information. This entry type indicates start of file.
    '''

    SYM          = 0x1
    TEXT_RELOC   = 0x2
    DATA_RELOC   = 0x3
    RODATA_RELOC = 0x4
    TEXT         = 0x5
    DATA         = 0x6
    RODATA       = 0x7

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

def _read_filesystem_header(rom: N64Rom, read_pointer: int) -> tuple[int,USOFilesystemEntryType,int,int]:
    entry = rom.read_bytes(read_pointer, 0x0C)
    read_pointer += 0x0C
    entry_type, num_bytes, something = struct.unpack(">III", entry)
    return read_pointer, USOFilesystemEntryType(entry_type), num_bytes, something

def _read_file(rom: N64Rom, read_offset: int) -> tuple[int,bytes]:
    output = bytearray()
    while True:
        read_offset, \
        entry_type, \
        num_bytes, \
        something = _read_filesystem_header(rom, read_offset)

        if entry_type in [ USOFilesystemEntryType.INFO, USOFilesystemEntryType.ENDOFFILE ]:
            raise RuntimeError(f"hit unexpected header of type {entry_type.name} at 0x{read_offset:08x}!")
        
        if entry_type == USOFilesystemEntryType.END:
            # end of file
            return read_offset, output
        
        logger.info("\tentry type %s, size %d", entry_type.name, num_bytes)

        if entry_type != USOFilesystemEntryType.BSS:
            #output += rom.read_bytes(read_offset, num_bytes)
            data = rom.read_bytes(read_offset, num_bytes)
            # with open(f"private/1080boot_{entry_type.name}.bin", "wb") as f:
            #     f.write(data)

            output += data
        
            read_offset += num_bytes


def _walk_filesystem(rom: N64Rom, read_offset: int): 
    while True:
        read_offset, \
        entry_type, \
        num_bytes, \
        something = _read_filesystem_header(rom, read_offset)

        if entry_type == USOFilesystemEntryType.ENDOFFILE:
            # end of filesystem
            return

        # we need to find a file entry node here
        if entry_type != USOFilesystemEntryType.INFO:
            raise RuntimeError(f"unexpected entry type at 0x{read_offset:08x}: {entry_type.name}")

        node = rom.read_bytes(read_offset, num_bytes)
        read_offset += num_bytes
        if node[:4] != b'\x12\x34\x56\x78':
            raise RuntimeError("filenode data did not start with 0x12345678")

        filename = node[0x0C:].partition(b'\x00')[0].decode("ascii")

        logger.info("found file: %s", filename)
    
        read_offset, data = _read_file(rom, read_offset)

        if filename == "bootup.uso":
            with open("private/1080_payload.bin", "wb") as f:
                f.write(data)


    pass



def _mount_filesystems(bootexe: bytes,
                       ipc: int,
                       filesystem_mount_command_table_offset: int):


    # for 1080 there should be only two filesystem records:
    # "mainuso" and "rom".
    offset = filesystem_mount_command_table_offset - ipc
    while bootexe[offset:offset+4] != b'\0\0\0\0':
        # each entry is:
        # - 4 bytes pointer to string naming this filesystem
        # - 4 bytes start address of blob in ROM
        # - 4 bytes end address of blob in ROM
        # - 4 bytes heap start address (if 0, ignore this field)
        # - 4 bytes ???

        # function at 80000a98:
        # - read 12 bytes at the start of the filesystem, which are:
        #   - 4 bytes important (return value of this function is 0 if this value was 0x10)
        #   - 4 bytes number of bytes that should be read
        #   - 4 bytes something
        #
        # - read next number of bytes
        # - the first 4 bytes of what we read just now should be 0x12345678;
        #   if they aren't, then this is invalid. otherwise, return 1
        # 

        pass

def uso_unpack(rom: N64Rom, ipc: int):
    _walk_filesystem(rom, 0xD9FDB0)
    _walk_filesystem(rom, 0xB7C0)
