'''
EA Madden decompression

There are two versions of this algorithm. Version 1 is used by Madden Football 64 only,
and version 3 is used from Madden 99 onwards.

'''

import struct

from .bitbuffer import BufferBitstreamReader, BitstreamReadOrder

# ----------------------------------------------------------
#
# Madden v1
#
# Super simple RLE algorithm.
#
# Parents, if you wanna get your kids into reverse engineering,
# this is a great one for them to start with. Took no effort to do this.
#
# ----------------------------------------------------------

def madden_v1_decompress(input: bytes):
    if input[0] != 0x01:
        raise RuntimeError("expected 0x01 at the start of the input, but didn't get it")

    input_pointer = 5
    output = bytearray()

    while True:
        first_byte = input[input_pointer]
        input_pointer += 1

        # a totally zero byte is an EOF marker
        if first_byte == 0:
            return output

        if (first_byte & 0x80) != 0:
            for _ in range(first_byte & 0x7F):
                output.append(input[input_pointer])
                input_pointer += 1
            continue

        backseek = struct.unpack("<H", input[input_pointer:input_pointer+2])[0]
        input_pointer += 2

        backseek_offset = len(output) - backseek
        for _ in range(first_byte & 0x7F):
            output.append(output[backseek_offset])
            backseek_offset += 1

# ----------------------------------------------------------
#
# Madden v3
#
# ----------------------------------------------------------

class MaddenV3Bitstream(BufferBitstreamReader):
    def __init__(self,
                 input_buffer: bytes,
                 num_bits: int):
        super().__init__(input_buffer, BitstreamReadOrder.L_TO_R)
        self._num_bits = num_bits

    def keep_reading(self):
        return self._num_bits >= 8

    def read_bit_bool(self):
        self._num_bits -= 1
        return super().read_bit_bool()


# 79c
#
# arguments are:
# $a0       - pointer to start of output buffer
# $a1       - input pointer
# $a2       - output offset
# $a3       - some threshold (hardcoded to 0x010000)
# 0x10($sp) - number of bits to process? (0x1000 * 8)
# 0x14($sp) - output buffer size in bytes (not passed here)
def _v3_decompress_chunk(output_buffer: bytearray,
                      chunk: bytes,
                      output_offset: int,
                      threshold: int,
                      num_bits: int
                      ):

    # bitstream is read 32 bits at a time, left to right.
    # bitstream resets at the start of each 4k chunk
    bitstream = MaddenV3Bitstream(chunk, num_bits)

    # these values reset on every chunk too
    uVar11 = 2
    uVar12 = 1

    # param_3 looks like output offset (NOT output pointer)

    if output_offset == 0:
        if chunk[0] != 0x03:
            raise RuntimeError("expected 0x03, but didn't get it")

        # advance bitstream by five bytes to skip past the header
        for _ in range(5):
            bitstream.read_bits(8)

    while bitstream.keep_reading():
        if output_offset > len(output_buffer):
            return output_offset

        # if first bit is 1, then copy n bytes directly to output
        if bitstream.read_bit() != 0:
            run_length = bitstream.read_bits(7)
            for _ in range(run_length):
                if output_offset >= len(output_buffer):
                    return output_offset
                output_buffer[output_offset] = bitstream.read_bits(8)
                output_offset += 1
            continue

        # otherwise, it's backseek time
        # count zeroes to decode the run length
        num_zero_bits = bitstream.count_zero_bits(8)
        if num_zero_bits == 0:
            run_length = 1
        else:
            run_length = (1 << num_zero_bits) | bitstream.read_bits(num_zero_bits)
        run_length = (run_length + 2) & 0xFF

        # some count thing, uVar12 holds the sum.
        while uVar11 < output_offset:
            if uVar11 < threshold:
                uVar12 += 1
            uVar11 <<= 1

        uVar8 = ( ((1 << (uVar12 & 0x1F)) - 1) - min(output_offset, threshold) ) & 0xFFFFFFFF

        if uVar8 == 0xFFFFFFFF:
            backseek = bitstream.read_bits(uVar12)
        else:
            backseek = bitstream.read_bits(uVar12 - 1)
            if uVar8 <= backseek:
                backseek = (backseek << 1 | bitstream.read_bit()) - uVar8
        
        backseek_offset = output_offset - backseek
        for _ in range(run_length):
            if output_offset >= len(output_buffer):
                return output_offset

            output_buffer[output_offset] = output_buffer[backseek_offset]
            output_offset += 1
            backseek_offset += 1

    return output_offset

# 410
def madden_v3_decompress(input: bytes, output_size: int):
    if output_size == 0:
        return None

    output_buffer = bytearray([0] * output_size)

    output_offset = 0
    input_bytes_left = len(input)
    input_pointer = 0

    while input_bytes_left != 0:

        if input_bytes_left <= 0x1000:
            bits_this_chunk = input_bytes_left * 8
            input_bytes_left = 0
        else:
            bits_this_chunk = 0x1000 * 8
            input_bytes_left -= 0x1000
        
        output_offset = _v3_decompress_chunk(output_buffer,
                             input[input_pointer:],
                             output_offset,
                             0x010000,
                             bits_this_chunk
                             )
        input_pointer += 0x1000

    return output_buffer
