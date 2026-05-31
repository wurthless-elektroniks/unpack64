'''
Excitebike 64 compression

The boot executable is stored in a file with this header:

- +0x00 8 bytes ASCII magic "BRSOHYES"
- +0x08 4 bytes section A length, uncompressed
- +0x0C 4 bytes section A length, compressed
- +0x10 4 bytes section B length, uncompressed
- +0x14 4 bytes section B length, compressed
- +0x18 4 bytes section C length, uncompressed
- +0x1C 4 bytes section C length, compressed
- +0x20 4 bytes section D length, uncompressed
- +0x24 4 bytes section D length, compressed

The compressed data follows.
'''

import logging
import struct

logger = logging.getLogger(__name__)

# at 800113f4
MAGIC_TABLE = [
    ( 0x005, 0x001 ),
    ( 0x007, 0x021 ),
    ( 0x009, 0x0A1 ),
    ( 0x00A, 0x2A1 )
]

# 80011564
def _excitebike_decompress_subloop(input,
                        input_pointer,
                        uVar11,
                        v0,
                        v1):
    while True:
        if uVar11 == 1:
            # repopulate bitbuffer if empty
            uVar11 = input[input_pointer] | 0x100
            input_pointer += 1

        # keep shifting bits into v0 until v1 is 0
        at = uVar11 & 1
        v0 <<= 1
        v0 |= at
        v1 -= 1
        uVar11 >>= 1
        if v1 == 0:
            return input_pointer, uVar11, v0, v1

# see 80011414
def _excitebike_decompress_common(input: bytes,
                                  output: bytearray,
                                  output_pointer: int) -> int:
    
    input_pointer = 0    # reg $t0
    # reg $t1 is output pointer
    uVar11 = 1           # reg $t4
    # reg $t5 is always 1

    while True:
        # loop from 8001143c - 80011474
        while True:
            if uVar11 == 1:
                # stop bit hit, repopulate bitbuffer
                uVar11 = input[input_pointer] | 0x100
                input_pointer += 1

            # compiler inlined this logic: 80011440/8001146c are logically identical.
            # read one bit from the bitbuffer, and if it is zero, then copy one byte
            # directly from the input to the output
            t2 = (uVar11 & 1)
            uVar11 >>= 1
            if t2 != 0:
                # goto 80011478
                break

            # jumps to 8001144c
            output[output_pointer] = input[input_pointer]
            input_pointer += 1
            output_pointer += 1


        # 80011478
        while True:
            if uVar11 == 1:
                uVar11 = input[input_pointer] | 0x100
                input_pointer += 1

            t2 = (uVar11 & 1)
            uVar11 >>= 1
            if t2 == 0:
                # goto 800114dc
                break

            input_pointer, uVar11, v0, v1 = \
                _excitebike_decompress_subloop(input,
                                input_pointer,
                                uVar11,
                                0,
                                2)

            t2 = v0 + 0
            if v0 != 0:
                # goto 800114dc
                break

            input_pointer, uVar11, v0, v1 = \
                _excitebike_decompress_subloop(input,
                                input_pointer,
                                uVar11,
                                v0,
                                4)

            t2 = v0 + 3
            if v0 != 0:
                # goto 800114dc
                break

            v0 = input[input_pointer]
            input_pointer += 1

            t2 = v0 + 0x12
            if v0 == 0:
                # end of file reached
                return output_pointer

            # fall through to 800114dc below
            break

        # 800114dc: backseeking about to happen
        t2 += 2

        # find index within magic table
        input_pointer, uVar11, v0, v1 = \
            _excitebike_decompress_subloop(input,
                            input_pointer,
                            uVar11,
                            0,
                            2)
        
        v1,t3 = MAGIC_TABLE[v0]
        
        v0 = 0
        if v1 >= 8:
            v0 = input[input_pointer]
            input_pointer += 1
            v1 -= 8
        
        # backseeking condition
        input_pointer, uVar11, v0, v1 = \
            _excitebike_decompress_subloop(input,
                            input_pointer,
                            uVar11,
                            v0,
                            v1)

        t3 += v0
        backseek_pointer = output_pointer - t3

        if backseek_pointer < 0:
            raise RuntimeError(\
f"""backseek pointer went negative!
input pointer {input_pointer:08x}
output pointer {output_pointer:08x}
t3 = {t3:08x}
t4 = {uVar11:08x}
v0 = {v0:08x}
v1 = {v1:08x}
""")

        while t2 != 0:
            a1 = output[backseek_pointer]
            backseek_pointer += 1
            output[output_pointer] = a1
            output_pointer += 1
            t2 -= 1

        # loop starts over, continue at top

def brs_decompress(input: bytes):
    if input[:8] != b'BRSOHYES':
        return None
    
    compressed_chunks = []
    expected_decompressed_size = []

    decompressed_total_size = 0
    compressed_read_pointer = 0x28
    for i in range(4):
        _i = i * 8
        decompressed_size, compressed_size = struct.unpack(">II", input[8+(i*8):8+((i+1)*8)])
        decompressed_total_size += decompressed_size
        expected_decompressed_size.append(decompressed_size)

        compressed_chunk = input[compressed_read_pointer:compressed_read_pointer+compressed_size]
        compressed_chunks.append(compressed_chunk)
        compressed_read_pointer += compressed_size

    logger.info("BRS decompress: total input chunk size %d bytes, output size %d bytes",
                compressed_read_pointer,
                decompressed_total_size)

    output = bytearray([0] * decompressed_total_size)
    output_pointer = 0
    for i in range(4):
        logger.info("decompress chunk: %d", i)
        output_pointer_before = output_pointer
        output_pointer = _excitebike_decompress_common(compressed_chunks[i],
                                                       output,
                                                       output_pointer)
        
        if (output_pointer-output_pointer_before) != expected_decompressed_size[i]:
            raise RuntimeError(f"decompress error: segment {i} expected size {expected_decompressed_size[i]} actual {output_pointer-output_pointer_before}")

    return output
