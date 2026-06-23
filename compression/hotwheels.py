'''
Hot Wheels Turbo Racing compression

LZSS-inspired algorithm where the backseek symbol lengths can be specified in the file's header.
The data will start with an uncompressed chunk of data to enable backseeking, and then the actual
bitstream will follow.
'''

import struct

from bitbuffer import BufferBitstreamReader, BitstreamReadOrder

def hotwheels_decompress_chunk(input: bytes, output_so_far: bytearray = bytearray([])):
    output = bytearray(output_so_far)

    uncompressed_size, backseek_num_offset_bits, backseek_num_count_bits = \
        struct.unpack(">IHH", input[:8])

    backseek_symbol_size = (backseek_num_offset_bits + backseek_num_count_bits)
    if backseek_symbol_size > 0x10:
        raise RuntimeError("backseek_symbol_size out of bounds")

    # copy data from the uncompressed chunk to the output before decompressing
    offset = 8
    num_dict_symbols = (1 << backseek_num_offset_bits) + 1
    for _ in range(num_dict_symbols):
        output.append(input[offset])
        offset += 1

    # now time to actually decompress the data
    bitstream = BufferBitstreamReader(input[offset:], BitstreamReadOrder.R_TO_L)
    while len(output) < uncompressed_size:
        # 0 bit = output imm8
        # 1 bit = backseek
        if bitstream.read_bit_bool() is False:
            c = bitstream.read_bits_lifo(8)
            output.append(c)
            continue

        # original code reads these in one shot and splits them up.
        # in that implementation the high bits are the offset and the low bits
        # are the count. but since we're reading right to left here,
        # we have to read these individual symbols in reverse order
        backseek_count  = bitstream.read_bits_lifo(backseek_num_count_bits) + 1
        backseek_offset = bitstream.read_bits_lifo(backseek_num_offset_bits) + 1

        for _ in range(backseek_count):
            output.append(output[len(output) - backseek_offset])

    return output
