'''
Eurocom's "EuroPak" thing

Based in part (but not entirely) on this incredibly shitty and unreadable code:
https://github.com/aybe/N64UniversalCompressor/blob/master/EDLCompress.cpp

As well as this cleaned up (but not really much cleaner) version of it:
https://github.com/jombo23/N64-Tools/blob/master/GEDecompressor/EDLCompress.cpp

The header is:
- 3 bytes 'EDL'
- 1 byte mode field
- 4 bytes compressed size
- 4 bytes uncompressed size
- ...data follows...

This is a format that is based on RNC but with completely different decompression algorithms.

Similar to RNC, we have several modes:
- Mode 0 is "store" i.e. no compression.
- Mode 1 is a dictionary-based mode with a lot of tables and trees.
- Mode 2 is RLE mode, which is heavily based on RNC mode 2. Not all games
  support it though, and will panic if you try to use it.

Bit 7 of the "mode" field indicates endianness. It should always be 1 (big) for N64 games,
but some games that use this format (Cruis'n World) support little endian mode and can
read little endian values from the header.

Mode 1 compression notes...
- Decompression routine locations:
    - Cruis'n World - 0x80312d40
        - Struct format:
            - +0x00 - ?
            - +0x04 - input pointer
            - +0x08 - compressed size
            - +0x0C - uncompressed size
            - +0x10 - compression mode
            - +0x18 - endianness
            - +0x1C - error code (code will short-circuit upon error case)
    - Mortal Kombat 4 - 0x8000fe48

- The decompression routine reads 32 bit words when reading its bitstream.

'''

import struct

# ------------------------------------------------------------------------------------------------

class EdlState:
    def __init__(self, input_buffer):
        self._input_buffer  = input_buffer
        self._input_pointer = 0

        # bitbuffer is 32 bits
        self._bitbuffer = 0
        self._bits_on_buffer = 0

        # should NEVER be false for a N64 game
        self._is_big_endian = True

        # global variable
        self._n = 0

    def _clone(self):
        cloned = EdlState(self._input_buffer)

        # pylint:disable=protected-access
        cloned._input_pointer  = self._input_pointer
        cloned._bitbuffer      = self._bitbuffer
        cloned._bits_on_buffer = self._bits_on_buffer

        return cloned

    def _read_next_word(self):
        buf = bytearray([])
        for _ in range(4):
            if self._input_pointer >= len(self._input_buffer):
                buf.append(0)
                continue

            buf.append(self._input_buffer[self._input_pointer])
            self._input_pointer += 1

        return struct.unpack(">I" if self._is_big_endian else "<I", buf)

    def read_bits(self, count: int) -> int:
        bits_out = 0
        for _ in range(count):
            if self._bits_on_buffer == 0:
                self._bitbuffer = self._read_next_word()
                self._bits_on_buffer = 32
        
            # the bitstream is read from the rightmost bits.
            # if we read 8 bits, then the result is the lowest
            # 8 bits of the bitbuffer in order
            # (0xDEADBEEF will return 0xEF).
            bits_out = (bits_out << 1) | (self._bits_on_buffer & 1)
            self._bits_on_buffer >>= 1
            
        return bits_out

    def peek_bits(self, count: int) -> int:
        # slow, but easier to read: deep copy the current state
        # and, with the deep copy, read N bits (without affecting this state)
        return self._clone().read_bits(count)
    
    def n(self, new_n: int | None = None):
        if new_n is not None:
            self._n = new_n
        return self._n

# ------------------------------------------------------------------------------------------------
#
# Mode 1: LZW variant, completely different than RNC's Huffman tree encoding
#
# ------------------------------------------------------------------------------------------------

# MK4 @ 80046e9f
EDL_DECOMPRESS_TABLE_1 = [
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x0A, 0x0C, 0x0E,
    0x10, 0x14, 0x18, 0x1C,
    0x20, 0x28, 0x30, 0x38,
    0x40, 0x50, 0x60, 0x70,
    0x80, 0xA0, 0xC0, 0xE0,
    0xFF, 0x00, 0x00, 0x00
]

# MK4 @ 80046ebf (pointed to by 0x80046dbf + 0x100)
EDL_DECOMPRESS_TABLE_2 = [
    0, 0, 0, 0,
    0, 0, 0, 0,
    1, 1, 1, 1,
    2, 2, 2, 2,
    3, 3, 3, 3,
    4, 4, 4, 4,
    5, 5, 5, 5,
    0, 0, 0, 0
]

# MK4 @ 80046ee0, cruisnworld @ 8034b9b0
EDL_DECOMPRESS_TABLE_3 = [
    0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0006,
    0x0008, 0x000C, 0x0010, 0x0018, 0x0020, 0x0030,
    0x0040, 0x0060, 0x0080, 0x00C0, 0x0100, 0x0180,
    0x0200, 0x0300, 0x0400, 0x0600, 0x0800, 0x0C00,
    0x1000, 0x1800, 0x2000, 0x3000, 0x4000, 0x6000
]

# MK4 @ 80046f1c
EDL_DECOMPRESS_TABLE_4 = [
    0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x02, 0x02,
    0x03, 0x03, 0x04, 0x04, 0x05, 0x05, 0x06, 0x06,
    0x07, 0x07, 0x08, 0x08, 0x09, 0x09, 0x0A, 0x0A,
    0x0B, 0x0B, 0x0C, 0x0C, 0x0D, 0x0D, 0x00, 0x00
]

def _rebuild_table(state: EdlState, xsize: int, tsize: int):
    # there's some sort of run-length encoding for the table entries
    base_table = []
    for _ in range(xsize):
        if state.read_bits(1) == 1:
            state.n(state.read_bits(4))
        base_table.append(state.n())

    table = [0] * 0x600
    when = []
    n = [0]

    # build occurence table
    for y in range(1, 16):
        buffer_count = base_table.count(y)
        n.append(buffer_count)

        x = -1
        while True:
            if y not in base_table[x+1:]:
                break
            x = y
            when.append(y)
    
    # count entries and create sample table
    count = sum(n)
    samp = [0] * count

    # now overwrite the base table with the counts we just computed
    i = 0
    for y in range(16):
        x = n[y]
        while x > 0:
            base_table[i] = y
            i += 1
            x -= 1

    # generate bitsample table
    z = base_table[0]
    back = 0
    for x in range(count):
        y = base_table[x]
        if y != z:
            back *= (1 << (y - z))
            z = y
        
        y = (1 << y) | back

        while True:
            samp[x] = ((samp[x] << 1) | (y & 1)) & 0xFFFF
            y >>= 1
            if y == 1:
                break

    # dump temp buffer
    b = [0] * (1 << tsize)
    for x in range(count):
        back = base_table[x]
        if back >= tsize:
            y = (1 << tsize) - 1
            b[samp[x] & y] = x
            continue
        
        y = 1 << back
        z = samp[x]
        while True:
            table[z] = (when[x] << 7) + base_table[x]
            z += y
            if (z >> tsize) != 0:
                break

    # read coded types > size
    z = 0
    x = 0
    while (x >> tsize) == 0:
        y = b[x]
        if y != 0:
            y -= tsize
            if y >= 8:
                # error code 0xFFFFFFF8
                raise RuntimeError("y was not <= 7")
            back = (z << 7) + (y << 4)
            table[x] = back
            z += (1 << y)
    
    if z >= 0x200:
        raise RuntimeError("z exceeded 0x200")

    # build the aliased entries and finalize our wonderful table
    back = 1 << tsize
    for x in range(count):
        if base_table[x] < tsize:
            continue

        z = table[ samp[x] & (back - 1) ]
        y = samp[x] >> tsize

        while True:
            i = y + (z >> 7) + (1 << tsize)
            table[i] = (when[x] << 7) + base_table[x]
            
            y += 1 << (base_table[x] - tsize)

            i = (z >> 4) & 7
            if (y >> i) != 0:
                break
    
    return table

def _auto_rebuild_table(state, list_in, tsize):
    x = state.read_bits(9)
    if x != 0:
        return _rebuild_table(state, x, tsize)
    return list_in

def _decode_reference(state: EdlState, x, num_bits, table, offset):
    m = (x >> 4) & 7
    x >>= 7
    v = state.peek_bits(num_bits + m)
    v >>= num_bits
    return table[x + v + offset]

def _edl_decompress_mode_1(state: EdlState):
    output = bytearray()

    large_list = None
    small_list = None

    while True:
        first_bit = state.read_bits(1)

        # if the first bit we hit is 0, copy n bytes directly to the output
        if first_bit == 0:
            num_bytes = state.read_bits(15)
            for _ in range(num_bytes):
                output.append(state.read_bits(8))

            # stop condition is a 1 bit after reading a chunk.
            # it will be repeated below, but we're short circuiting here
            # to make the code more readable
            if state.read_bits(1) == 1:
                return output
            
            continue

        # otherwise, if we hit a 1 bit, it's time to do a ton of convoluted logic.

        # note in the original code, these two largelist/smalllist repopulations
        # happen in a for loop.
        large_list = _auto_rebuild_table(state, large_list, 10)
        small_list = _auto_rebuild_table(state, small_list, 8)

        x = 0
        while x != 0x100:
            x = large_list[ state.peek_bits(10) ]

            if (x & 0x0F) == 0:
                x = _decode_reference(state, x, 10, large_list, 0x400)

            # advance stream by the number of bits we found
            state.read_bits((x & 0xF))
            
            # recover code. less than 0x100 writes immediate byte,
            # more than 0x100 backseeks
            x >>= 7
            
            if (x == 0x100):
                break
            
            if (x < 0x100):
                output.append(x)
                continue
            
            # the rest of this is the backseek case
            l = 0
            z = EDL_DECOMPRESS_TABLE_2[x - 0x101]
            if z != 0:
                l = state.read_bits(z)

            l += EDL_DECOMPRESS_TABLE_1[x - 0x101]

            x = small_list[ state.peek_bits(8) ]
            if (x & 0x0F) == 0:
                x = _decode_reference(state, x, 8, small_list, 0x100)
            
            # advance stream by the number of bits we found
            state.read_bits(x & 0x0F)

            p = 0
            x >>= 7

            z = EDL_DECOMPRESS_TABLE_4[x]
            if z != 0:
                p = state.read_bits(z)
            
            p += EDL_DECOMPRESS_TABLE_3[x] + 1

            backseek_pointer = len(output) - p
            for _ in l:
                output.append( output[backseek_pointer] )
                backseek_pointer += 1

        # so, after all that, we can finally repeat the EOF check mentioned above
        if state.read_bits(1) == 1:
            return output
        
        # and that's one iteration of the loop folks.

    # in case of premature break
    return output
