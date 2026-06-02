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
# Currently under construction
#
# ----------------------------------------------------------

# 79c
def _decompress_chunk(chunk: bytes,
                      output_offset: int,
                      stackarg_10,
                      stackarg_14
                      ):

    # param 4 is always 0x010000?
    param_4: int = 0x010000

    # bitstream is read 32 bits at a time, left to right.
    # bitstream resets at the start of each 4k chunk
    bitstream = BufferBitstreamReader(chunk, BitstreamReadOrder.L_TO_R)

    uVar11 = 2
    uVar12 = 1

    output = bytearray()
    
    param_3 = output_offset

    # param_3 looks like output offset (NOT output pointer)

    if param_3 == 0:
        if chunk[0] != 0x03:
            raise RuntimeError("expected 0x03 at start of chunk, but didn't get it")

        # advance bitstream by five bytes
        for _ in range(5):
            bitstream.read_bits(8)

    while True:
        # boundscheck here...

        # if first bit is 1, then copy n bytes directly to output
        if bitstream.read_bit() != 0:
            run_length = bitstream.read_bits(7)
            for _ in range(run_length):
                output.append(bitstream.read_bits(8))
            continue

        # otherwise, it's backseek time
        # count zeroes to decode the run length
        num_zero_bits = bitstream.count_zero_bits(8)
        if num_zero_bits == 0:
            run_length = 1
        else:
            run_length = (1 << num_zero_bits) | bitstream.read_bits(num_zero_bits)
        run_length = (run_length + 2) & 0xFF

        # some count thing, uVar12 holds the sum
        while uVar11 <= param_3:
            uVar11 <<= 1
            if uVar11 < param_4:
                uVar12 += 1

        uVar8 = ( (1 << ((uVar12 & 0x1F) - 1)) - min(param_3, param_4) ) & 0xFFFFFFFF

        if uVar8 == 0xFFFFFFFF:
            uVar2 = bitstream.read_bits(uVar12)
        else:
            uVar2 = bitstream.read_bits(uVar12 - 1)
            if uVar8 <= uVar2:
                pass
        
        backseek = param_3 - uVar2
        
        for _ in range(run_length):
            output.append(output[backseek])
            backseek += 1

    return output

# 410
def madden_decompress(input: bytes,
                      output_size: int):

    if output_size == 0:
        return None

    output_offset = 0
    output_bytes_left = 0

    while output_bytes_left != 0:
        if output_bytes_left <= 0x1000:
            output_bytes_left = 0
        else:
            output_bytes_left -= 0x1000
        


        _decompress_chunk(param_1, param_2 + output_offset, output_offset, 0x010000)
        
        output_offset += 0x1000




    pass