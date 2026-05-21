'''
Refpack decompression

Main reference:
https://github.com/GHFear/RW4ArchiveTool/blob/main/RW4ArchiveTool/Archives/Compression/refpack/refpackd.h
'''

import struct

def _copyn(input: bytes,
           input_pointer: int,
           output: bytearray,
           output_pointer: int,
           run_length: int):

    while run_length > 0:
        byte_in = input[input_pointer] if input_pointer < len(input) else 0
        output[output_pointer] = byte_in

        input_pointer += 1
        output_pointer += 1
        run_length -= 1
    
    return output_pointer

def refpack_decompress(input: bytes):
    magic = struct.unpack(">H", input[0:2])[0]
    if (magic & 0x3EFF) != 0x10FB:
        return None
    
    # read compressed size
    # remember, NHL 99 has a 24-bit uncompressed size field
    if (magic & 0x8000) != 0:
        uncompressed_size = struct.unpack(">I", input[2:6])[0]
        input_pointer = 6
    else:
        uncompressed_size = (input[2] << 16) | struct.unpack(">H", input[3:5])[0]
        input_pointer = 5

    output = bytearray([0] * uncompressed_size)
    output_pointer = 0

    first = 0
    second = 0
    third = 0
    fourth = 0

    # HACK: WCW Mayhem game.ovl tries to read past the end of file
    # so abort if that happens
    while input_pointer < len(input):
        backseek_pointer = 0
        run_length = 0 # "run" in original source

        first = input[input_pointer]
        if (first & 0x80) == 0:
            if (input_pointer + 1) >= len(input):
                break
            second = input[input_pointer + 1]
            input_pointer += 2


            run_length = first & 3

            if run_length > 0:
                output_pointer = _copyn(input,
                                        input_pointer,
                                        output,
                                        output_pointer,
                                        run_length)
                input_pointer += run_length

            # backseek
            backseek_pointer = output_pointer - 1 - (((first & 0x60) << 3) + second)
            run_length = ((first & 0x1c) >> 2) + 3

            output_pointer = _copyn(output,
                                    backseek_pointer,
                                    output,
                                    output_pointer,
                                    run_length)

            continue

        if (first & 0x40) == 0:
            second = input[input_pointer + 1]
            third  = input[input_pointer + 2]
            input_pointer += 3

            run_length = second >> 6

            if run_length > 0:
                output_pointer = _copyn(input,
                                        input_pointer,
                                        output,
                                        output_pointer,
                                        run_length)
                input_pointer += run_length

            # backseek
            backseek_pointer = output_pointer - 1 - (((second & 0x3f) << 8) + third)
            run_length = (first & 0x3f) + 4

            output_pointer = _copyn(output,
                                    backseek_pointer,
                                    output,
                                    output_pointer,
                                    run_length)

            continue

        if (first & 0x20) == 0:
            if (input_pointer+4) >= len(input):
                break

            second = input[input_pointer + 1]
            third  = input[input_pointer + 2]
            fourth = input[input_pointer + 3]
            input_pointer += 4

            run_length = first & 3

            if run_length > 0:
                output_pointer = _copyn(input,
                                        input_pointer,
                                        output,
                                        output_pointer,
                                        run_length)
                input_pointer += run_length

            # backseek
            backseek_pointer = output_pointer - 1 -  (((first & 0x10) >> 4 << 16) + (second << 8) + third)
            run_length = ((first & 0x0c) >> 2 << 8) + fourth + 5

            output_pointer = _copyn(output,
                                    backseek_pointer,
                                    output,
                                    output_pointer,
                                    run_length)
            continue
        
        # all other cases: big ol' run length a-comin'
        input_pointer += 1

        run_length = ((first & 0x1f) << 2) + 4
        if run_length <= 112:
            output_pointer = _copyn(input,
                                    input_pointer,
                                    output,
                                    output_pointer,
                                    run_length)
            input_pointer += run_length
            continue

        # if we've reached this point, we're at the end of file.
        # write remaining data and get out
        run_length = first & 3
        if run_length > 0:
            output_pointer = _copyn(input,
                                    input_pointer,
                                    output,
                                    output_pointer,
                                    run_length)
            input_pointer += run_length
        break

    return output
