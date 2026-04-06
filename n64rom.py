'''
Class representing N64 ROM.
This is a dumb class so it can't autodetect CIC, entrypoints, etc. 
'''

from zlib import crc32
import os
import hashlib
import struct
import zipfile
import logging

logger = logging.getLogger(__name__)

ROMENDIANNESS_BIG     = 'be'
ROMENDIANNESS_LITTLE  = 'le'
ROMENDIANNESS_MIDDLE  = 'me'

ADVANCEDHEADER_SAVETYPE_USE_RTC     = 0x80
ADVANCEDHEADER_SAVETYPE_REGION_FREE = 0x40
ADVANCEDHEADER_SAVETYPE_4K_EEPROM   = 0x01
ADVANCEDHEADER_SAVETYPE_16K_EEPROM  = 0x02
ADVANCEDHEADER_SAVETYPE_256K_SRAM   = 0x03
ADVANCEDHEADER_SAVETYPE_768K_SRAM   = 0x04
ADVANCEDHEADER_SAVETYPE_FLASH       = 0x05
ADVANCEDHEADER_SAVETYPE_1M_SRAM     = 0x06

class N64RomHeader(object):
    '''
    Easily manipulable N64 ROM header.
    '''
    def __init__(self, headerbytes: bytearray):
        self._bytes = headerbytes

    def game_name(self) -> str:
        '''
        Return game name as string, e.g., "SUPER MARIO 64".

        This is decoded as Shift-JIS. Japanese games occasionally use Shift-JIS to indicate their titles.
        Shift-JIS is also ASCII-compatible, which makes our life easier.
        '''
        return self._bytes[0x20:0x34].decode("shift-jis")

    def game_id(self) -> str:
        '''
        Return the 4 byte cart ID.
        This is a concatenation of media format, cart id, country code.
        e.g., NSME.

        To change this value, use media_format(), cart_id(), country_code().
        '''
        return self.media_format()+self.cart_id()+self.country_code()

    def media_format(self, new_media_format: str|None = None) -> str:
        return self._bytes[0x3B:0x3C].decode("ascii")

    def cart_id(self, new_cart_id: str|None = None) -> str:
        return self._bytes[0x3C:0x3E].decode("ascii")
    
    def country_code(self, new_country_code: str|None = None) -> str:
        return self._bytes[0x3E:0x3F].decode("ascii")

    def initial_pc(self, new_initial_pc: int | None = None) -> int:
        '''
        Return initial program counter/boot executable load address.
        This is often scrambled by the CIC, so use the appropriate CIC type
        to properly decode or encode this value.
        '''
        if new_initial_pc is not None:
            if (0x80000400 <= new_initial_pc < 0x80400000) is False:
                raise RuntimeError("illegal new_initial_pc. should be between 0x80000400~0x803FFFFF, got 0x{new_initial_pc:08x}")
            if (new_initial_pc & 0x3) != 0:
                raise RuntimeError("illegal new_initial_pc. must be 4-byte aligned, got 0x{new_initial_pc:08x}")
            self._bytes[0x08:0x0C] = struct.pack("!I",new_initial_pc)

        return struct.unpack("!I",self._bytes[0x08:0x0C])[0]

    def crc(self, new_crc: list | None = None) -> list:
        '''
        Return expected boot executable checksum as list of two 32-bit ints.
        '''
        return struct.unpack("!II",self._bytes[0x10:0x18])

    def is_extended(self) -> bool:
        '''
        Return True if this uses the Advanced Homebrew ROM Header.
        '''
        return self.cart_id() == "ED"


class N64Rom:
    '''
    Contains a big-endian, non-byteswapped ROM.
    '''
    def __init__(self, rombytes: bytearray, endianness: str):
        self._bytes  = rombytes
        self._sha256 = None
        self._crc32  = None
        self._endianness = endianness

    def sha256(self) -> str:
        '''
        Return SHA-256 hash of the entire ROM.
        '''
        if self._sha256 is None:
            self._sha256 = hashlib.sha256(self._bytes).hexdigest()
        return self._sha256
    
    def crc32(self) -> int:
        '''
        Return CRC-32 checksum of the entire ROM.
        '''
        return crc32(self._bytes)

    def header(self, new_header: N64RomHeader | None = None) -> N64RomHeader:
        if new_header is not None:
            # TODO
            pass
        return N64RomHeader(self._bytes[0:0x40])

    def boot_exe(self, new_boot_exe: bytearray | None = None) -> bytearray:
        '''
        Return boot executable as a bytearray.
        '''
        if new_boot_exe is not None:
            # TODO
            pass

        return self._bytes[0x1000:0x101000]

    def ipl3(self, new_ipl3: bytearray | None = None):
        '''
        Return IPL3 boot stub.
        '''
        if new_ipl3 is not None:
            # TODO
            pass

        return self._bytes[0x40:0x1000]

    def read_bytes(self, offset, count) -> bytearray:
        # TODO: bounds check?
        return self._bytes[offset:offset+count]

    def write_bytes(self, offset, count):
        pass

    def deep_copy(self):
        '''
        Make deep copy of this N64 ROM.
        Typically called before we apply patches.
        '''
        pass

    def endianness(self):
        '''
        Return endianness of this ROM image.
        Default is ROMENDIANNESS_BIG.

        Remember that the ROM will already be byteswapped when loaded.
        '''
        return self._endianness

def _valid_rom_size(size):
    '''
    Valid ROM size is between 4 MiB (32 mbit) and 64 MiB (256 mbit),
    and ROM must also be an even number of megabits.
    '''
    return (0x00400000 <= size <= 0x04000000) and \
           (size & 0x01FFFF) == 0

def _logerror_invalid_romsize(size):
    logger.error("ROM image size is inconsistent with commercially released software.\n" \
        "\tmin romsize   0x00400000\n" \
        "\tmax romsize   0x04000000\n" \
        "\tthis rom was  0x%08x\n",size)

def load_rom_from_buffer(buf: bytearray) -> N64Rom | None:
    '''
    Creates N64Rom instance from the given bytearray.
    '''
    # no (commercial) game is less than 4 mbytes.
    if _valid_rom_size(len(buf)) is False:
        _logerror_invalid_romsize(len(buf))
        return None

    magic = buf[0:4]

    endianness = None
    outbuf = None
    if magic == bytearray([0x80, 0x37, 0x12, 0x40]):
        # Big endian (typical extension: .z64)
        endianness = ROMENDIANNESS_BIG
        outbuf = buf
    elif magic == bytearray([0x40, 0x12, 0x37, 0x80]):
        # Little endian (typical extension: .v64)
        logger.info("Byte swapping little-endian ROM image...")
        outbuf = bytearray(len(buf))
        for i in range(0, len(buf) >> 2):
            offs = i * 4
            swapped = [
                buf[offs+3],
                buf[offs+2],
                buf[offs+1],
                buf[offs+0],
            ]
            outbuf[offs+0] = swapped[0]
            outbuf[offs+1] = swapped[1]
            outbuf[offs+2] = swapped[2]
            outbuf[offs+3] = swapped[3]
        endianness = ROMENDIANNESS_LITTLE
    elif magic == bytearray([0x37, 0x80, 0x40, 0x12]):
        # Middle endian (typical extension: .n64)
        logger.info("Byte swapping middle-endian ROM image...")
        outbuf = bytearray(len(buf))
        for i in range(0, len(buf) >> 1):
            offs = i * 2
            swapped = [
                buf[offs+1],
                buf[offs+0],
            ]
            outbuf[offs+0] = swapped[0]
            outbuf[offs+1] = swapped[1]
        endianness = ROMENDIANNESS_MIDDLE
    else:
        logger.error("loaded buffer does not start with the N64 header magic word, data is probably not a N64 ROM")
        return None
    return N64Rom(outbuf, endianness)

def load_rom(path: str) -> N64Rom | None:
    '''
    Load N64 ROM from given path. Return N64Rom on success, None on failure.
    If the ROM file isn't in z64 big-endian format, it will be byteswapped.
    '''
    # read entire file into one big bytebuffer
    buf = None
    with open(path,"rb") as f:
        # validating the filesize first of course!
        f.seek(0, os.SEEK_END)
        flen = f.tell()
        if _valid_rom_size(flen) is False:
            _logerror_invalid_romsize(flen)
            return None
        f.seek(0, os.SEEK_SET)

        buf = f.read()

    return load_rom_from_buffer(buf)

def load_rom_from_zip(path: str) -> N64Rom | None:
    '''
    Open the given .zip file, then look for the first valid-looking N64 ROM inside of it.
    '''
    try:
        with zipfile.ZipFile(path, "r") as archive:
            # open first file that looks like it's a valid ROM
            for zinf in archive.infolist():
                if (zinf.filename.endswith(".z64") or zinf.filename.endswith(".v64") or zinf.filename.endswith(".n64")) and \
                    _valid_rom_size(zinf.file_size):
                    logger.info("load_rom_from_zip: reading from: %s", zinf.filename)
                    return load_rom_from_buffer(archive.read(zinf))
                
            logger.error("zipfile does not contain anything that looks like a valid N64 ROM")
            return None
    except Exception as e:
        raise e
