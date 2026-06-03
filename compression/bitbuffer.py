'''
Common bitstream/bitbuffer handling
'''

from typing import Callable
from enum import Enum

class BitstreamReadOrder(Enum):
    L_TO_R = 12345678

    R_TO_L = 87654321

class BitbufferEmptyBehavior(Enum):
    RETURN_NONE = 0
    RETURN_ZERO = 1
    RETURN_ONE  = 2

    THROW_EXCEPTION = 3

class BufferedBits:
    '''
    Simple "buffered bits" object. Can be used in a bitstream or standalone if a full bitstream
    implementation is not required.
    '''
    def __init__(self,
        read_order: BitstreamReadOrder,
        bits: int,
        num_bits: int,
        empty_behavior: BitbufferEmptyBehavior = BitbufferEmptyBehavior.RETURN_NONE):

        self._read_order = read_order
        self._num_bits_on_buffer = num_bits
        self._empty_behavior = empty_behavior
        if num_bits <= 0:
            self._leftmost_bit = 0
            self._rightmost_bit = 0
            self._bitbuffer = 0
            return

        self._bitbuffer = bits
        self._leftmost_bit  = (num_bits - 1)
        self._rightmost_bit = 0

    def is_empty(self):
        return self._num_bits_on_buffer <= 0

    def next_bit(self) -> bool | None:
        '''
        Read next bit from buffer and advance the buffer by 1.
        Returns True (1) or False (0) when not end-of-file.
        When end-of-file, returns behavior specified by empty_behavior on construct
        (by default returns None).
        '''
        if self.is_empty():
            if self._empty_behavior == BitbufferEmptyBehavior.THROW_EXCEPTION:
                raise RuntimeError("attempt to read past end of bufferedbits")

            return {
                BitbufferEmptyBehavior.RETURN_NONE: None,
                BitbufferEmptyBehavior.RETURN_ZERO: 0,
                BitbufferEmptyBehavior.RETURN_ONE:  1,
            }[self._empty_behavior]
        
        bit = None
        if self._read_order == BitstreamReadOrder.L_TO_R:
            bit = self._bitbuffer & (1 << self._leftmost_bit) != 0
            self._bitbuffer <<= 1
        elif self._read_order == BitstreamReadOrder.R_TO_L:
            bit = self._bitbuffer & (1 << self._rightmost_bit) != 0
            self._bitbuffer >>= 1
        else:
            raise RuntimeError("illegal readorder!")
        
        self._num_bits_on_buffer -= 1

        self._bitbuffer &= ((1 << (self._leftmost_bit + 1)) - 1)
        return bit

EMPTY_BUFFERED_BITS = BufferedBits(BitstreamReadOrder.L_TO_R, 0, 0)

class Bitstream:
    '''
    Basic bitstream. Can be extended to inherit all methods, or used standalone with an
    optional read callback to repopulate the buffer when it is empty.
    '''
    def __init__(self,
                 read_function: Callable[[], BufferedBits] | None = None):
        self._bitbuffer = EMPTY_BUFFERED_BITS
        self._read_function = read_function

    def _refill(self):
        if self._read_function is None:
            raise RuntimeError("attempt to read past end of bitbuffer with no callback set")
        self._bitbuffer = self._read_function()

    def read_bit_bool(self):
        '''
        Read single bit as a boolean.
        '''
        if self._bitbuffer.is_empty():
            self._refill()
        return self._bitbuffer.next_bit()
    
    def read_bit(self):
        '''
        Read single bit as an integer. Returns 1 or 0.
        '''
        return 1 if self.read_bit_bool() else 0

    def read_bits(self,
                  count: int,
                  existing_bits: int = 0) -> int:
        '''
        Read n bits from buffer in the native order of the stream and return them as an integer.

        For i=0...n, shift bits left once, then OR with the next bit.

        If the bitstream is read right-to-left, with bitbuffer = 0b11_10_01_00 and count = 8,
        then the result will be 0b00_10_01_11.

        If the bitstream is read left-to-right, with bitbuffer = 0b11_10_01_00 and count = 8,
        then the result will be 0b11_10_01_00.
        '''
        bits = existing_bits
        for _ in range(count):
            bits <<= 1
            bits |= self.read_bit()
        return bits
    
    def read_bits_lifo(self, count: int):
        '''
        Read n bits from buffer in the inverse order of the stream and return them as an integer.

        With bits=0 and for i=0...n, bits |= (input_bit << i).

        If the bitstream is read right-to-left, with bitbuffer = 0b11_10_01_00 and count = 8,
        then the result will be 0b11_10_01_00.

        If the bitstream is read left-to-right, with bitbuffer = 0b11_10_01_00 and count = 8,
        then the result will be 0b00_10_01_11.
        '''
        bits = 0
        for i in range(count):
            bits |= (self.read_bit() << i)
        return bits

    def count_zero_bits(self, max_count: int) -> int:
        '''
        Count number of zero bits until a 1 bit is hit or until max_count bits have been read.
        '''
        count = 0
        for _ in range(max_count):
            if self.read_bit_bool():
                break
            count += 1
        return count

    def is_empty(self):
        '''
        Return True if the bitbuffer is empty.
        '''
        return self._bitbuffer.is_empty()

class BufferBitstreamReader(Bitstream):
    '''
    A simple bitstream reader that reads an input buffer one byte (8 bits) at a time.
    '''

    def __init__(self,
                 input_buffer: bytes,
                 read_order: BitstreamReadOrder):
        super().__init__(read_function=self._read_next_byte)
        self._read_order = read_order
        self._input_buffer = input_buffer
        self._input_pointer = 0

    def eof(self) -> bool:
        '''
        Return True if input pointer is at or past the end of the buffer.
        '''
        return self._input_pointer >= len(self._input_buffer)
    
    def read_byte(self) -> int:
        '''
        Read byte directly from the input buffer, bypassing the bitbuffer.
        '''
        if self.eof():
            return 0

        byte = self._input_buffer[self._input_pointer]
        self._input_pointer += 1
        return byte

    def _read_next_byte(self):
        return BufferedBits(self._read_order, self.read_byte(), 8)
