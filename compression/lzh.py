'''
LZH compression

Based on Haruyasu Yoshizaki's implementation
See also https://github.com/msmiley/lzh/blob/master/src/lzh.c

About the Star Wars - Shadows of the Empire variant...

Zoinkity's notes from https://www.romhacking.net/forum/index.php?topic=40627.0

    SotE uses variants of two--lzhuff and lzss [...]

    They're slightly modified, what you call "ringless ring" types.
    The algo itself is the same, but instead of looking at a dedicated ring buffer
    that is updated every write this reads back through the last 4KB of output.
    A proper ringless type uses an offset back from the current address (cur - 14),
    and a ringless ring uses an actual address (byte 14 of the file).

    Problem is they buggered both up.

    For LZHUFF, the ring is too small.  Pass the size as 0xFC2.
    That's 0x1000 for the correct size, minus lookahead (60),
    minus threshold (2, the minimum dictionary length).

d_code at 80001cc0
d_len at 80001dc0

work vars:
- 80001c84 = output pointer
- 80001c88 = input pointer
- 80001c90 = getbuf, cleared to 0 on state init
- 80001c94 = getlen, cleared to 0 on state init
- 80001cb4 = pointer to freq
- 80001cb8 = pointer to prnt (parent node pointers)
- 80001cbc = pointer to son (child node pointers)

functions:
80000e64 = Decode()
    - text_buf is not used here
800006f4 = StartHuff() (second loop seems modified or unrolled)
80000ce8 = ?

- a LOT of functions are inlined in the mainloop

Compressed payload is copied to 80300000 and decompressed to 80001EC0,
after which 80300000 is wiped and execution starts at 800174b0
'''

import logging

logger = logging.getLogger(__name__)

LZH_N = 4096
LZH_F = 60
LZH_THRESHOLD = 2
LZH_N_CHAR = 256 - LZH_THRESHOLD + LZH_F # should be 314
LZH_T = LZH_N_CHAR * 2 - 1
LZH_R = LZH_T-1
LZH_MAX_FREQ = 0x8000

LZH_SOTE_MAX_BACKSEEK = LZH_N - LZH_F - LZH_THRESHOLD

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

class LzhState:
    '''
    Common LZH state management class for reading inputs/outputs.
    '''
    def __init__(self, input_buffer: bytes):
        self._bitbuffer = 0
        self._num_bits_on_buffer = 0
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

        bit_out = (self._bitbuffer >> 7) & 1
        self._bitbuffer = (self._bitbuffer << 1) & 0xFF
        self._num_bits_on_buffer -= 1

        return bit_out

    def read_byte(self):
        byte = 0
        for _ in range(8):
            byte = (byte << 1) + self.read_bit()
        return byte
    
    def read_position(self):
        i = self.read_byte()
        c = D_CODE[i] << 6
        j = D_LEN[i]

        j -= 2
        while j > 0:
            i = (i << 1) + self.read_bit()
            j -= 1
        
        return c | (i & 0x3F)
    
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

        while c < LZH_T:
            c += self.read_bit()
            c = _uint16(self._child_nodes[c])
        c -= LZH_T

        self._update(c)

        return c

def lzh_decompress(input: bytes, output_size: int):
    '''
    Decompress standard LZH.
    '''
    lzh_state = LzhState(input)

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

def lzhsote_decompress(input: bytes, output_size: int):
    lzh_state = LzhState(input)

    output = bytearray()

    r = LZH_SOTE_MAX_BACKSEEK

    while len(output) < output_size:

        c = lzh_state.read_char()
        if c < 256:
            # write directly to output
            # remember that this LZH variant does NOT use the text buffer
            output.append(c & 0xFF)
        else:
            # backseek to no more than 0xFC2 bytes in the output buffer
            p = lzh_state.read_position()
            j = c - 255 + LZH_THRESHOLD

            i = len(output) - (r - (r - p - 1))
            for _ in range(j):
                output.append(output[i])
                i += 1
    
    return output
