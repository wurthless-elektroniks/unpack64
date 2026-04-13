'''
Mario Tennis compression, actual algorithm unclear
'''

def mariotennis_decompress(input: bytes):
    input_pointer = 0

    output = bytearray()

    while True:
        byte_in = input[input_pointer]

        # a zero byte just means "copy eight bytes to output"
        if byte_in == 0:
            input_pointer += 1
            for _ in range(8):
                output.append(input[input_pointer])
                input_pointer += 1
            continue

        ctrl_word = (byte_in << 18) | 0x00800000

        # subloop starting at 80300108
        while True:
            if (ctrl_word & 0x80000000) == 0:
                # this loop is unrolled in the unpacker
                for _ in range(8):
                    ctrl_word <<= 1
                    output.append(input[input_pointer])
                    input_pointer += 1
                    if (ctrl_word & 0x80000000) != 0:
                        break
                ctrl_word <<= 1

            if (ctrl_word & 0xFFFFFFFF) == 0:
                break

            a1 = input[input_pointer]
            backseek_index = len(output) - input[input_pointer + 1]
            backseek_index -= (a1 & 0xF0) << 4
            a1 &= 0x0F

            if backseek_index == len(output):
                # not really the right behavior - starts loop over
                # keeping pointers intact
                return output

            if a1 == 0:
                pass
            else:
                input_pointer += 2
                if a1 == t3:
                    output.append(output[backseek_index])
                    output.append(output[backseek_index])
                
                    # goto 80300108
                    continue

                # else fall through to 8030022c
                v0 = a1 + 1

            # common code path at 80300230
            copy_until_index = len(output) + v0
            output.append(output[backseek_index])
            backseek_index += 1

            while len(output) != copy_until_index:
                output.append(output[backseek_index])
                backseek_index += 1

    # read byte
    # if byte is 0:
    #   copy next 8 bytes to output buffer
    #   increment input pointer by 9
    #   continue
    #
    # byte <<= 18
    # byte |= 0x00800000
    # let's call this ctrl_word
    #
    # 80300108:
    #
    # if ctrl_word < 0: goto 80300184
    # delayslot:        ctrl_word <<= 1
    # 
    # read byte at input_ptr+0
    # if ctrl_word < 0: goto 80300200
    # delayslot: store byte at output_ptr+0
    #
    # read byte at input_ptr+1
    # ctrl_word <<= 1
    # if ctrl_word < 0: goto 803001f4
    # delayslot: store byte at output_ptr+1
    #
    # read byte at input_ptr+2
    # ctrl_word <<= 1
    # if ctrl_word < 0: goto 803001e8
    # delayslot: store byte at output_ptr+2
    #
    # read byte at input_ptr+3
    # ctrl_word <<= 1
    # if ctrl_word < 0: goto 803001dc
    # delayslot: store byte at output_ptr+3
    #
    # read byte at input_ptr+4
    # ctrl_word <<= 1
    # if ctrl_word < 0: goto 803001d0
    # delayslot: store byte at output_ptr+4
    #
    # read byte at input_ptr+5
    # ctrl_word <<= 1
    # if ctrl_word < 0: goto 803001c4
    # delayslot: store byte at output_ptr+5
    #
    # read byte at input_ptr+6
    # ctrl_word <<= 1
    # store byte at output_ptr+6
    # increment both pointers by 7
    # fall through to 80300180 below
    #
    # 80300180:
    # ctrl_word <<= 1
    #
    # 80300184:
    # if ctrl_word is 0:
    #   continue loop from start
    #   delayslot is a nop
    #
    # read two bytes from input pointer
    # a1 = byte 0 = ?
    # v1 = byte 1 = index in output pointer (we're looking backwards to repeat data)
    #
    # v1 = output_pointer - v1
    # v0 = (a1 & 0xF0) << 4
    # v1 -= v0
    # 
    # if v1 went zero (basically impossible) goto 80300260
    # delayslot: a1 &= 0x0F
    #
    # if a1 not zero goto 8030020c
    # delayslot: nop
    # 
    # v0 = *(input_pointer + 2) + 0x11
    # input_pointer += 3
    # goto 80300230
    #
    # 803001c4:
    # increment both pointers by 6
    # goto 80300180
    #
    # 803001d0
    # increment both pointers by 5
    # goto 80300180
    #
    # 803001dc
    # increment both pointers by 4
    # goto 80300180
    #
    # 803001e8
    # increment both pointers by 3
    # goto 80300180
    #
    # 803001f4
    # increment both pointers by 2
    # goto 80300180
    #
    # 80300200:
    # increment both pointers by 1
    # goto 80300180
    #
    # 8030020c:
    # if a3 != t3 goto 8030022c
    # delayslot: input_pointer += 2
    # copy two bytes at v1 to output pointer
    # output_pointer += 2
    # goto 80300108 
    #
    # 8030022c:
    # v0 = a1 + 1
    #
    # 80300230:
    # t1 = output_pointer + v0
    # v0 = *((byte*)v1++)
    # a1 = output_pointer + 1
    # store v0 at output_pointer
    #
    # 80300244:
    # v0 = *((byte*)v1 ++)
    # a1 += 1
    # if a1 != t1: continue loop from 80300244
    # delayslot: *((byte*)a1 - 1) = v0
    # 
    # output_pointer = a1
    # goto 80300108 
    #
    # 80300260:
    # if not end of file (not sure how it figures this out)
    # then it seems to hit an error case
    # otherwise, we're done - clear caches and return control to boot stub, which calls entrypoint
    #