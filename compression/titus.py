'''
Titus RLE compression

Based in part on Zoinkitty's implementation
https://github.com/jombo23/N64-Tools/blob/master/GEDecompressor/SupermanDecoder.cpp


Data begins at +0x11.
Note that if the magic value isn't there, then we assume that this is headerless
and start reading the compressed data immediately.

The N64 routine reads in a circular 0x400 byte buffer. Every time it wraps,
it reads another 0x400 bytes from the cartridge.

The original code is also heavily unrolled by the compiler, and as I am not
masochistic enough to replicate it here, it's copy pasted code time.
'''

import struct

class TitusState:
    def __init__(self, input_buffer: bytes):
        self._input_buffer = input_buffer
        self._input_offset = 0
        
        self._bitbuffer = 0
        self._bits_on_buffer = 0
        self.repopulate_flags()
        
    def read_byte(self):
        b = 0 if self._input_offset >= len(self._input_buffer) else self._input_buffer[self._input_offset]
        self._input_offset += 1
        return b

    def repopulate_flags(self):
        b0 = self.read_byte()
        b1 = self.read_byte()

        # in the original code it will load 0x8000FFFF or something to the bitbuffer
        # and on every rightshift it will check if bit 15 is 0.
        # in zoinkitty's implementation the stop bit is bit 16 and
        # read_flag() below makes sure the stop flag is in bit 1 or above.
        # all this is doing is checking if there are 16 bits on the buffer
        # and repopulating the bitbuffer if it is empty.
        # so let's cut the fancy crap and make this code readable
        self._bitbuffer = (b1 << 8) | b0
        self._bits_on_buffer = 16


    def read_flag(self):
        flag_before_shift = (self._bitbuffer & 1) != 0
        self._bitbuffer >>= 1
        self._bits_on_buffer -= 1

        if self._bits_on_buffer == 0:
            self.repopulate_flags()
        
        return flag_before_shift

    def read_bits(self,
                  count: int,
                  existing_bitbuffer: int = 0) -> int:
        bits = existing_bitbuffer
        for _ in range(count):
            bits = (bits << 1) | (1 if self.read_flag() is True else 0)
        return bits

def _backseek_common(output_buffer: bytes,
                     bank: int, 
                     backseek: int,
                     count : int,
                     output_size: int = 0):
    
    backseek_pointer = (bank << 8) | backseek

    backseek_pointer &= 0xFFFFFFFF
    if backseek_pointer != 0 and (backseek_pointer & 0x80000000) == 0:
        raise RuntimeError(f"backseek_pointer was not 0 or negative: {backseek_pointer:08x} (bank {bank:08x} backseek {backseek:08x})")

    # *now* treat the thing as a signed int
    backseek_pointer = struct.unpack(">i", struct.pack(">I",backseek_pointer))[0]

    backseek_position = len(output_buffer) + backseek_pointer
    for _ in range(count):
        if output_size > 0 and len(output_buffer) >= output_size:
            return output_buffer
        
        output_buffer.append( output_buffer[backseek_position] )
        backseek_position += 1
    
    return output_buffer

def titus_decompress(input_buffer: bytes,
                     output_size: int = 0) -> bytes:
    output_buffer = bytearray()
    state = TitusState(input_buffer[0x11:])

    while (output_size <= 0) or (len(output_buffer) < output_size):
        # while we keep hitting 1 bits, copy bytes to output
        if state.read_flag():
            output_buffer.append(state.read_byte())
            if output_size > 0 and len(output_buffer) == output_size:
                return output_buffer
            continue
        
        # hitting a 0 bit means a backseek operation needs to happen.
        # read the next bit
        v = state.read_flag()

        # NOTE: both of these are signed but the sign will not be applied until later
        backseek = state.read_byte()
        bank = 0xFFFFFFFF

        if v is False:
            # 0b00 = two-byte backseek
            if state.read_flag() is True:
                bank = state.read_bits(3, existing_bitbuffer=bank) - 1
            else: # NOT elif!
                if backseek == 0xFF:
                    return output_buffer

            output_buffer = _backseek_common(output_buffer, bank, backseek, 2)
            continue
            
        # v was true (bitstream so far was 0b01); that means we have to do a lot of value crunching
        # before we know what to dump
        bank = state.read_bits(1, existing_bitbuffer=bank)
        
        if state.read_flag() is False:
            # have to swap banks again
            temp = 2
            for _ in range(3):
                if state.read_flag() is True:
                    break
                bank = state.read_bits(1, existing_bitbuffer=bank)
                temp <<= 1
            bank -= temp
        
        # big tree o' bits to try figuring out the run length
        # 0b01- so far
        # 0b01-1 = 3 bytes
        # 0b01-01 = 4 bytes
        # 0b01-001 = 5 bytes
        # 0b01-0001 = 6 bytes
        # 0b01-00001x = 7 or 8 bytes depending on if x is set or not
        # 0b01-000001 = 0x11+x bytes (x is read from the buffer)
        # 0b01-000000xxx = 9+x bytes (x is a 3 bit immediate value)
        zero_count = 0
        for _ in range(6):
            if state.read_flag() is True:
                break
            zero_count += 1
        
        zerocount_to_bytecount = {
            0 : 3,
            1 : 4,
            2 : 5,
            3 : 6,
            4 : lambda state: 0x07 + state.read_bits(1),
            5 : lambda state: 0x11 + state.read_byte(),
            6 : lambda state: 0x09 + state.read_bits(3)
        }

        count = zerocount_to_bytecount[zero_count]
        if not isinstance(count, int):
            # pylint:disable=not-callable
            # (because it IS callable and None should never be seen here)
            count = count(state)

        # with the count established, it's backseek time
        output_buffer = _backseek_common(output_buffer, bank, backseek, count)

    # fall-through condition if loop breaks
    return output_buffer
