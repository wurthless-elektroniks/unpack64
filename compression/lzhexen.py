'''
LZH variant used by Hexen

This is LZH but with a larger lookahead buffer (F=128) and a bitstream read right-to-left.

See also: https://github.com/Erick194/HexenN64Tool/blob/main/src/HexenLZHuff.cpp

TODO: unify this and lzh.py? lots of it is the same
'''

import logging

logger = logging.getLogger(__name__)

LZH_N = 4096
LZH_F = 128
LZH_THRESHOLD = 2
LZH_N_CHAR = 256 - LZH_THRESHOLD + LZH_F
LZH_T = LZH_N_CHAR * 2 - 1
LZH_R = LZH_T-1
LZH_MAX_FREQ = 0x8000

# identical to stock lzh
D_CODE = bytes([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
    0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A,
    0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B,
    0x0C, 0x0C, 0x0C, 0x0C, 0x0D, 0x0D, 0x0D, 0x0D,
    0x0E, 0x0E, 0x0E, 0x0E, 0x0F, 0x0F, 0x0F, 0x0F,
    0x10, 0x10, 0x10, 0x10, 0x11, 0x11, 0x11, 0x11,
    0x12, 0x12, 0x12, 0x12, 0x13, 0x13, 0x13, 0x13,
    0x14, 0x14, 0x14, 0x14, 0x15, 0x15, 0x15, 0x15,
    0x16, 0x16, 0x16, 0x16, 0x17, 0x17, 0x17, 0x17,
    0x18, 0x18, 0x19, 0x19, 0x1A, 0x1A, 0x1B, 0x1B,
    0x1C, 0x1C, 0x1D, 0x1D, 0x1E, 0x1E, 0x1F, 0x1F,
    0x20, 0x20, 0x21, 0x21, 0x22, 0x22, 0x23, 0x23,
    0x24, 0x24, 0x25, 0x25, 0x26, 0x26, 0x27, 0x27,
    0x28, 0x28, 0x29, 0x29, 0x2A, 0x2A, 0x2B, 0x2B,
    0x2C, 0x2C, 0x2D, 0x2D, 0x2E, 0x2E, 0x2F, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
])

# identical to stock lzh
D_LEN = bytes([
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
])

def _uint16(x):
    return x & 0xFFFF

class LzHexenState:
    def __init__(self, input_buffer: bytes):
        self._bitbuffer = 0
        self._num_bits_on_buffer = 0
        self._bit_counter = 0
        self._input_buffer = input_buffer
        self._input_offset = 0

        self._frequency_table = [0] * (LZH_T + 1)
        self._parent_nodes = [0] * (LZH_T + LZH_N_CHAR)
        self._child_nodes = [0] * (LZH_T)

        for i in range(LZH_N_CHAR):
            self._frequency_table[i] = _uint16(1)
            self._child_nodes[i] = _uint16(i + LZH_T)
            self._parent_nodes[i + LZH_T] = _uint16(i)

        i = 0
        j = LZH_N_CHAR
        while j <= LZH_R:
            self._frequency_table[j] = _uint16(self._frequency_table[i] + self._frequency_table[i+1])
            self._child_nodes[j] = _uint16(i)
            self._parent_nodes[i] = self._parent_nodes[i + 1] = _uint16(j)
            i += 2
            j += 1
        
        self._frequency_table[LZH_T] = _uint16(0xFFFF)
        self._parent_nodes[LZH_R] = _uint16(0)

    def _read_next_byte(self):
        if self._input_offset >= len(self._input_buffer):
            logger.warning("LZH buffer overrun!")
            return 0
        
        v = self._input_buffer[self._input_offset]
        self._input_offset += 1
        return v

    def read_bit(self):
        if self._num_bits_on_buffer == 0:
            self._bitbuffer = self._read_next_byte()
            self._num_bits_on_buffer = 8

        # bitstream is right-to-left
        bit_out = self._bitbuffer & 1
        self._bitbuffer = (self._bitbuffer >> 1) & 0xFF
        self._num_bits_on_buffer -= 1

        self._bit_counter += 1
        self._bit_counter &= 7

        return bit_out
    
    # when reading multiple bits at a time, the decompressor keeps the rightmost bits
    # but shifts them out in the order the bytes have them in.
    # so even though this stream is now being read right-to-left, the symbols are
    # still in the left-to-right order as in stock LZH
    def read_num_bits(self, num_bits: int):
        byte = 0
        for i in range(num_bits):
            byte |= self.read_bit() << i
        return byte

    def read_byte(self):
        return self.read_num_bits(8)
    
    def read_position(self):
        # identical to original, but i is shifted out from the rightmost bits
        # in left-to-right order
        i = self.read_byte()
        c = D_CODE[i] << 6
        j = D_LEN[i] - 2

        # this behavior is similar to the original in that i needs
        # to be shifted left by j positions, but since the value we need
        # to add to i is left-to-right in the rightmost j bits of the bitstream,
        # we need to read those bits first and THEN add them to the output.
        # reading them bit-by-bit as in the original lzh source won't work. 
        x = self.read_num_bits(j)
        return c | (((i << j) + x) & 0x3F)
    
    # identical to stock lzh
    def _reconstruct(self):

        # collect leaf nodes in the first half of the table
        # and replace frequencies
        j = 0
        for i in range(LZH_T):
            if self._child_nodes[i] >= LZH_T:
                self._frequency_table[j] = _uint16(int((self._frequency_table[i] + 1) / 2))
                self._child_nodes[j] = _uint16(self._child_nodes[i])
                j += 1

        # rebuild child connections
        i = 0
        j = LZH_N_CHAR
        while j < LZH_T:
            k = i + 1
            f = self._frequency_table[j] = _uint16(self._frequency_table[i] + self._frequency_table[k])

            # search for thing
            k = j - 1
            while f < _uint16(self._frequency_table[k]):
                k -= 1
            k += 1

            # original code multiplies by 2 because it does a raw memmove()
            # we don't do this here because we're manually shifting items
            l = (j - k)

            # shift frequencies forward and insert new frequency at the base
            self._frequency_table[k + 1:k + l + 1] = self._frequency_table[k:k+l]
            self._frequency_table[k] = _uint16(f)

            # also shift the child nodes
            self._child_nodes[k + 1:k + l + 1] = self._child_nodes[k:k+l]
            self._child_nodes[k] = _uint16(i)

            i += 2
            j += 1

        # rebuild parent connections
        for i in range(LZH_T):
            k = _uint16(self._child_nodes[i])

            if k >= LZH_T:
                self._parent_nodes[k] = _uint16(i)
            else:
                self._parent_nodes[k] = self._parent_nodes[k+1] = _uint16(i)

    # identical to stock lzh
    def _update(self, c: int):
        if self._frequency_table[LZH_R] == LZH_MAX_FREQ:
            self._reconstruct()

        c = self._parent_nodes[c + LZH_T]
        while True:
            k = _uint16(self._frequency_table[c] + 1)
            self._frequency_table[c] = _uint16(k)

            # swap nodes if something is out of place
            l = c + 1
            if k > _uint16(self._frequency_table[l]):
                l += 1
                while k > _uint16(self._frequency_table[l]):
                    l += 1
                l -= 1
                
                self._frequency_table[c] = _uint16(self._frequency_table[l])
                self._frequency_table[l] = _uint16(k)

                i = _uint16(self._child_nodes[c])
                self._parent_nodes[i] = _uint16(l)
                if (i < LZH_T):
                    self._parent_nodes[i + 1] = _uint16(l)
                
                j = _uint16(self._child_nodes[l])
                self._child_nodes[l] = _uint16(i)

                self._parent_nodes[j] = _uint16(c)
                if j < LZH_T:
                    self._parent_nodes[j + 1] = _uint16(c)
                self._child_nodes[c] = _uint16(j)

                c = l

            # keep looping until root node reached
            c = _uint16(self._parent_nodes[c])
            if c == 0:
                break

    def read_char(self):
        c = _uint16(self._child_nodes[LZH_R])

        # the original code reads up to 3 bytes little endian,
        # and the bitstream itself will be read right-to-left
        while c < LZH_T:
            c += self.read_bit()
            c = _uint16(self._child_nodes[c])
        
        c -= LZH_T

        self._update(c)

        return c

def lzhexen_decompress(input: bytes, output_size: int):
    lzh_state = LzHexenState(input)

    text_buf = bytearray([0x20] * (LZH_N + LZH_F - 1))
    r = LZH_N - LZH_F

    output = bytearray()
    while len(output) < output_size:
        c = lzh_state.read_char()
        if c < 256:
            # copy decoded character straight to output
            output.append(c & 0xFF)
            text_buf[r] = c
            r = (r + 1) & (LZH_N-1)
        else:
            # backseek through the circular text_buf
            i = (r - lzh_state.read_position() - 1) & (LZH_N-1)
            j = c - 255 + LZH_THRESHOLD

            for k in range(j):
                c = text_buf[(i + k) & (LZH_N-1)]
                output.append(c)
                text_buf[r] = c
                r = (r + 1) & (LZH_N-1)
    
    return output
