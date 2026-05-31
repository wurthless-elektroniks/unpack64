'''
Mario Tennis compression, actual algorithm unclear
'''

import struct

def _assert_size_limit(output, expected_output_size):
    if len(output) > expected_output_size:
        raise RuntimeError("output exceeded expected size")

def mariotennis_decompress(input: bytes):
    if input[0] == 0:
        # resource not compressed
        expected_output_size = struct.unpack(">I", input[:4])[0] & 0x00FFFFFF
        return input[4:4+expected_output_size]

    input_pointer = 4
    output = bytearray()

    # four-byte header is ignored by the decompressor code.
    # byte 0 = 1 if compressed, 0 otherwise
    # bytes 1-3: size of decompressed payload
    expected_output_size = struct.unpack(">I", input[:4])[0] & 0x00FFFFFF

    while True:
        _assert_size_limit(output, expected_output_size)
        byte_in = input[input_pointer]
        input_pointer += 1
        
        # a zero byte just means "copy eight bytes to output"
        if byte_in == 0:
            for _ in range(8):
                output.append(input[input_pointer])
                input_pointer += 1
            continue

        # "ctrl_word" is a bitbuffer, read left-to-right, to which a
        # stop bit is appended
        ctrl_word = (byte_in << 24) | 0x00800000

        # subloop starting at 80300108
        while True:
            _assert_size_limit(output, expected_output_size)

            # copy up to 8 bytes from input to output
            # looping until 8 bits have been read from the bit buffer,
            # or a 1 bit is encountered
            if (ctrl_word & 0x80000000) == 0:
                # this loop is unrolled in the unpacker
                for _ in range(8):
                    ctrl_word <<= 1
                    output.append(input[input_pointer])
                    input_pointer += 1
                    if (ctrl_word & 0x80000000) != 0:
                        break

                # final left-shift at 0x80300180
                ctrl_word <<= 1
            else:
                # ctrl_word has to be left-shifted after any access
                # code looks ugly and will probably need to be refactored
                ctrl_word <<= 1

            # code execution picks up from 0x80300184
            if (ctrl_word & 0xFFFFFFFF) == 0:
                # if the bitbuffer is totally empty at this point,
                # break from subloop, start from mainloop
                break

            # if there are still bits left in the bitbuffer, then backseek
            v1 = input[input_pointer + 1]
            a1 = input[input_pointer]

            backseek_index = len(output) - v1
            backseek_index -= (a1 & 0xF0) << 4
            a1 &= 0x0F

            # if backseek_index is at output pointer, go to 0x80300260,
            # which finalizes stuff and exits
            if backseek_index == len(output):
                if len(output) != expected_output_size:
                    raise RuntimeError(f"decompression error. expected {expected_output_size} bytes, got {len(output)}")
                # not really the right behavior - can start loop over
                # keeping pointers intact
                return output

            if a1 == 0:
                v0 = input[input_pointer + 2] + 0x11
                input_pointer += 3
            else:
                input_pointer += 2
                if a1 == 1:
                    for _ in range(2):
                        output.append(output[backseek_index])
                        backseek_index += 1

                    # goto 80300108
                    continue

                # else fall through to 8030022c
                v0 = a1 + 1

            # common code path at 80300230
            copy_until_index = len(output) + v0
            output.append(output[backseek_index])
            backseek_index += 1

            while len(output) != copy_until_index:
                _assert_size_limit(output, expected_output_size)
                output.append(output[backseek_index])
                backseek_index += 1
