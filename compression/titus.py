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
        
        self._flags = 0
        self.repopulate_flags()
        
    def read_byte(self):
        b = 0 if self._input_offset >= len(self._input_buffer) else self._input_buffer[self._input_offset]
        self._input_offset += 1
        return b

    def repopulate_flags(self):
        b0 = self.read_byte()
        b1 = self.read_byte()

        self._flags = 0x010000 | (b1 << 8) | b0

    def read_flag(self):
        flag_before_shift = (self._flags & 1) != 0
        self._flags >>= 1

        if self._flags < 2:
            self.repopulate_flags()
        
        return flag_before_shift

def _backseek_common(output_buffer: bytes,
                     bank: int, 
                     backseek: int,
                     count : int,
                     output_size: int = 0):
    
    backseek = (bank << 8) | backseek

    if backseek != 0 and (backseek & 0x80000000) == 0:
        raise RuntimeError("backseek was not 0 or negative")
    
    # *now* treat the thing as a signed int
    backseek = struct.unpack(">i", struct.pack(">I",backseek))[0]

    backseek_position = len(output_buffer) + backseek
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
                for _ in range(3):
                    bank = (bank << 1) | 1 if state.read_flag() is True else 0
                bank -= 1
            else: # NOT elif!
                if backseek == 0xFF:
                    return output_buffer

            output_buffer = _backseek_common(output_buffer, bank, backseek, 2)
            continue
            
        # v was true (bitstream so far was 0b01); that means we have to do a lot of value crunching
        # before we know what to dump
        bank = (bank << 1) | 1 if state.read_flag() is True else 0

        if state.read_flag() is False:
            # have to swap banks again
            temp = 2
            for _ in range(3):
                if state.read_flag() is True:
                    break
                bank = (bank << 1) | 1 if state.read_flag() is True else 0
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
            4 : lambda state: 8 if state.read_flag() is True else 7,
            5 : lambda state: 0x11 + state.read_byte()
        }

        count = None
        if zero_count == 6:
            bits = 0
            for _ in range(3):
                bits <<= 1
                bits |= 1 if state.read_flag() is True else 0
            count = 9 + bits
        else:
            count = zerocount_to_bytecount[zero_count]
            if not isinstance(count, int):
                # pylint:disable=not-callable
                # (because it IS callable and None should never be seen here)
                count = count(state)

        # with the count established, it's backseek time
        output_buffer = _backseek_common(output_buffer, bank, backseek, count)

    # fall-through condition if loop breaks
    return output_buffer
