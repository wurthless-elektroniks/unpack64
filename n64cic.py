'''
CIC identification/checksumming

Much of this is based on Parasyte's implementation.
See http://n64dev.org/n64crc.html
'''

import struct
from zlib import crc32

from n64rom import N64Rom

def rol32(val: int, count: int):
    v = val & 0xFFFFFFFF
    for _ in range(0, count):
        v <<= 1
        if v >= 0x0100000000:
            v = (v | 1) & 0xFFFFFFFF
    return v

class N64CIC():
    '''
    Common implementation of a N64 CIC functionality.
    '''
    def __init__(self, cictype: str, seed: int):
        self._type = cictype
        self._seed = seed

    def name(self) -> str:
        '''
        Gets the name of thie CIC type, e.g., "6101".
        '''
        return self._type

    def entry_point(self, n64rom: N64Rom):
        '''
        Get "real" program entry point.
        Default implementation returns ipc from header directly.
        '''
        return n64rom.header().initial_pc()
 
    def calc_checksum(self, bootexe: bytearray):
        '''
        Calc boot checksum.
        '''
        # create table of 6 32-bit words, all initialized to the seed
        csum_words = [
            self._seed,
            self._seed,
            self._seed,
            self._seed,
            self._seed,
            self._seed,
        ]

        for i in range(0, int(0x100000 / 4)):
            # read Nth 32-bit word
            d = struct.unpack("!I",bootexe[(i*4):(i*4)+4])[0]
            
            if (csum_words[5] + d) >= 0x0100000000:
                csum_words[3] += 1
            csum_words[5] = (csum_words[5] + d) & 0xFFFFFFFF

            csum_words[2] ^= d
            r = rol32(d, d & 0x1F)

            csum_words[4] = (csum_words[4] + r) & 0xFFFFFFFF

            if csum_words[1] > d:
                csum_words[1] ^= r
            else:
                csum_words[1] ^= csum_words[5] ^ d

            csum_words = self._checksum_apply_magic(i, bootexe, csum_words, d)

        return self._checksum_final(csum_words)

    # pylint: disable=unused-argument
    def _checksum_apply_magic(self,
                              dword_count: int,
                              bootexe: bytearray,
                              csum_words: list, d: int) -> list:
        '''
        Extension point for 6105 CIC, which looks up a magic word in a table.
        Returns modified csum_words object
        '''
        csum_words[0] = (csum_words[0] + (csum_words[4] ^ d)) & 0xFFFFFFFF
        return csum_words

    def _checksum_final(self, csum_words: list) -> list:
        '''
        Finalize checksum calculation into a 64-bit value.
        Return list of two 32-bit words.
        
        Default implementation applies to 6101/6102/6105 CICs.
        '''
        retval = [0,0]
        retval[0] = csum_words[5] ^ csum_words[3] ^ csum_words[2]
        retval[1] = csum_words[4] ^ csum_words[1] ^ csum_words[0]
        return retval

class N646103CIC(N64CIC):
    def __init__(self):
        super().__init__("6103", 0xA3886759)

    def entry_point(self, n64rom):
        return super().entry_point(n64rom) - 0x100000

    def _checksum_final(self, csum_words):
        retval = [0,0]
        retval[0] = ((csum_words[5] ^ csum_words[3]) + csum_words[2]) & 0xFFFFFFFF
        retval[1] = ((csum_words[4] ^ csum_words[1]) + csum_words[0]) & 0xFFFFFFFF
        return retval

# bastard
class N646105CIC(N64CIC):
    def __init__(self, ipl3):
        super().__init__("6105", 0xDF26F436)
        self._ipl3 = ipl3

    def _checksum_apply_magic(self, dword_count, bootexe, csum_words, d):
        magic_offset = 0x0710 + ((dword_count * 4) & 0xFF)
        magic_value = struct.unpack("!I",self._ipl3[magic_offset:magic_offset+4])[0]
        csum_words[0] = (csum_words[0] + (magic_value ^ d)) & 0xFFFFFFFF
        return csum_words

class N646106CIC(N64CIC):
    def __init__(self):
        super().__init__("6106", 0x1FEA617A)

    def entry_point(self, n64rom):
        return super().entry_point(n64rom) - 0x200000

    def _checksum_final(self, csum_words):
        retval = [0,0]
        retval[0] = ((csum_words[5] * csum_words[3]) + csum_words[2]) & 0xFFFFFFFF
        retval[1] = ((csum_words[4] * csum_words[1]) + csum_words[0]) & 0xFFFFFFFF
        return retval
    
# 7102 CIC for Lylat Wars (Europe/Australia)
# added here to suppress warnings and to make the bootexe load correctly
class N647102CIC(N64CIC):
    def __init__(self):
        super().__init__("7102", 0xF8CA4DDC)

    def entry_point(self, n64rom):
        return 0x80000480

cics = {}
IPL3_6102_CRC32 = 0x90BB6CB5
cics[0x6170A4A1] = N64CIC("6101", 0xF8CA4DDC)      # 6101 (seed identical to 6102)
cics[IPL3_6102_CRC32] = N64CIC("6102", 0xF8CA4DDC) # 6102 (most common)
cics[0x0B050EE0] = N646103CIC() # 6103
# there is no 6104
# 6105 handled in get_cic() below
cics[0xACC8580A] = N646106CIC() # 6106
cics[0x009e9ea3] = N647102CIC()

def get_cic(n64rom: N64Rom) -> N64CIC:
    '''
    Attempts CIC identification, and returns respective N64CIC subclass.
    If the CIC is not identified, returns a 6102.
    '''
    ipl3 = n64rom.ipl3()
    crc = crc32(ipl3)

    if crc == 0x98BC2C86:
        # special case for 6105 because we need access to the ipl3 code
        return N646105CIC(ipl3)

    if crc not in cics:
        print(f"WARNING: IPL3 not recognized (CRC-32 is 0x{crc:08x}). CIC type defaulting to 6102.")
        return cics[IPL3_6102_CRC32]

    return cics[crc]
