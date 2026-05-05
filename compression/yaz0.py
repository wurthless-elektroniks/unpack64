'''
Nintendo Yaz0 decompression

Based on http://www.amnoid.de/gc/yaz0.txt

Originally was a Python 3 port of https://github.com/RenolY2/yaz0-decode-encode/blob/master/yaz0.py
but that was way too complex and was giving decompression errors.
'''

import struct

def yaz0_decompress(input: bytes) -> bytes:
    if input[:4] != b'Yaz0':
        return None
    
    uncompressed_size = struct.unpack(">I", input[4:8])[0]
    output = bytearray([0] * uncompressed_size)

    input_pointer = 0x10
    output_pointer = 0
    valid_bit_count = 0

    current_code_byte = None
    while output_pointer < uncompressed_size:
        if valid_bit_count == 0:
            current_code_byte = input[input_pointer]
            input_pointer += 1
            valid_bit_count = 8
        
        if (current_code_byte & 0x80) != 0:
            # copy one byte directly from input to output
            output[output_pointer] = input[input_pointer]
            output_pointer += 1
            input_pointer += 1
        else:
            # RLE
            byte1, byte2 = struct.unpack(">BB", input[input_pointer:input_pointer+2])
            input_pointer += 2

            dist = ((byte1 & 0xF) << 8) | byte2
            copy_source = output_pointer - (dist + 1)
            num_bytes = (byte1 >> 4) & 0xF

            if num_bytes == 0:
                num_bytes = input[input_pointer] + 0x12
                input_pointer += 1
            else:
                num_bytes += 2
            
            for _ in range(num_bytes):
                output[output_pointer] = output[copy_source]
                copy_source += 1
                output_pointer += 1

                if output_pointer >= uncompressed_size:

                    return output

        current_code_byte <<= 1
        valid_bit_count -= 1
    
    return output
