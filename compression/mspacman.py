'''
Ms. Pac Man Maze Madness compression

I really don't know what compression algorithm this is, could be custom.
'''

import logging

logger = logging.getLogger(__name__)

# done instruction by instruction, the ghidra decompile had some bug
# that i couldn't find...
def mspacman_decompress_op_by_op(input: bytes, uncompressed_length: int):
    
    output = bytearray([0] * uncompressed_length)
    input_pointer = 0
    
    a3 = 0 # a3 is the output pointer

    a2 = 0
    a1 = 0
    t1 = 0
    t3 = -1
    v1 = uncompressed_length
    t2 = a3 + v1

    # skipping sltu check...
    while True:
        cur_byte = input[input_pointer]
        input_pointer += 1 # delay slot

        if (cur_byte << 24) & 0x80000000 == 0:
            v1 = a1 << 4
            v0 = cur_byte & 0x0F
            a1 = ~(v0 | v1)
            v1 = a2 << 3
            v0 = cur_byte & 0x70
            v0 >>= 4
            v1 += v0
            v1 += t1
            a2 = v1 + 1

            a1 = a1 + a3 # delay slot
            if a2 != t3:
                v1 = -1
                while True:
                    v0 = output[a1]
                    a1 += 1
                    a2 -= 1

                    output[a3] = v0
                    a3 += 1 # delay slot

                    if a2 == v1:
                        break
                a1 = 0
                t1 = 0
                a2 = 0
        else:
            if cur_byte < 0x90:
                v0 = a2 << 4
                v1 = cur_byte & 0x0F
                v0 += v1
                a2 = v0 + 1
                if a2 != 0:
                    t1 = 0
                    while True:
                        v0 = input[input_pointer]
                        input_pointer += 1
                        a2 -= 1
                        
                        output[a3] = v0
                        a3 += 1 # delayslot

                        if a2 == 0:
                            break
                    t1 = 0
            else:
                # at 0x802005ac, done regardless of which path taken below
                t1 += 1
                if cur_byte < 0xA0:
                    v0 = cur_byte & 0x0C
                    a2 = cur_byte & 0x03
                    a1 = v0 >> 2
                elif cur_byte < 0xC0:
                    v1 = a2 << 5
                    v0 = cur_byte & 0x1F
                    a2 = v1 + v0
                else:
                    v1 = a1 << 6
                    v0 = cur_byte & 0x3F
                    a1 = v1 + v0

        # LAB_802005b0 is the end of loop
        if a3 >= t2:
            break

    return output
