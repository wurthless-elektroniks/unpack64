'''
EA custom LZxx compression

Used on World Cup 98, FIFA 99, Knockout Kings 2000
'''


from io import BytesIO


# operation repeated several times in the loop below
def _lzea_common_round(s2, s3, v0, v1) -> tuple[int,int,int,int]:
    '''
    Replicates instruction sequence:
        ```
        addiu      v0,s3,0x2
        andi       s3,v0,0x7
        andi       v1,s2,0x3
        andi       v0,s2,0xff
        ```

    '''
    v0 = s3 + 2
    s3 = v0 & 7
    v1 = s2 & 3
    v0 = s2 & 0xFF
    return s2, s3, v0, v1

def _wc98_common_decompress(input: bytes, output_size: int):
    output = bytearray([0] * output_size)

    # to better match the original
    input_stream = BytesIO(input)
    read_byte = lambda: input_stream.read(1)[0]

    uVar6 = 0          # $s2
    control_byte = 0   # $s3
    uVar3 = 0          # $s5
    output_pointer = 0 # $s6
    
    # $s7 is end of output buffer
    # so logically we treat it the same as output_size

    # offsets below match knockout kings 2000 us.
    # pardon the painful compiler unrolling...
    while output_pointer < output_size:

        v0 = uVar6 + 2 # happens regardless

        if control_byte == 0:
            uVar6 = read_byte()

        # 80000830
        control_byte = v0 & 7
        v1 = uVar6 & 3
        v0 = uVar6 & 0xFF

        s1 = v1 & 0xFF
        uVar6 >>= 2 # assuming uVar6 will always be uint8

        if s1 == 0:
            v0 = read_byte() & 0xFF
            if v0 == 0:
                # keep adding 0xFF until nonzero is hit
                while True:
                    s1 += 0xFF
                    v0 = read_byte()
                    if v0 != 0:
                        break
            
            s1 += v0

            # s1 ++, jump to 800008f4, which does s1 --
            # so here we pretend we fall through to 800008f8
        else:
            # 80000884
            take_jump = (s1 != 3)
            s1 -= 1
            if take_jump is False:
                if control_byte == 0:
                    uVar6 = read_byte()

                v0 = control_byte + 2
                control_byte = v0 & 7
                v1 = uVar6 & 3
                v0 = uVar6 & 0xFF
                s1 = v1 + 3
                s1 -= 1 # delay slot
                if v0 == 6:
                    v0 = control_byte + 2
                    if control_byte == 0:
                        uVar6 = read_byte()
                    
                    control_byte = v0 & 7
                    v1 = uVar6 & 3
                    v0 = uVar6 & 0xFF
                    uVar6 = v0 >> 2
                    s1 = (v1 + 6) - 1

        # 800008f8: FINALLY output a byte.
        # s1 is treated as a signed integer here
        if s1 != -1:
            s0 = v0
            while s1 != s0:
                output[output_pointer] = read_byte()
                output_pointer += 1
                s1 -= 1
            
        # bounds check so we don't go into the subloop below and crash
        if output_pointer >= output_size:
            return output

        # 80000928: start of another subloop
        while True:
            uVar3 = read_byte() & 0xFF
            v1 = uVar3 & 0x60

            # very tangled if statement
            if v1 == 0x40:
                # 0x80000a64
                s4 = uVar3 & 0x1F

                if control_byte == 0:
                    uVar6 = read_byte()

                v0 = control_byte + 2
                control_byte = v0 & 0x07
                v1 = uVar6 & 3
                v0 = uVar6 & 0xFF

                uVar6 = v0 >> 2
                v0 = v1 << 5
                s4 |= v0

                if control_byte == 0:
                    uVar6 = read_byte()

                v0 = control_byte + 2
                control_byte = v0 & 0x07
                v1 = uVar6 & 3
                v0 = uVar6 & 0xFF

                uVar6 = v0 >> 2
                v0 = v1 << 7

                # goto 80000bbc
                pass
            elif v1 < 0x41:
                # 0x80000964
                v0 = 0x60

                # code juggles registers. rom_address = a0
                a0 = uVar3 & 0x78
                if v1 != v0:
                    s4 += 1
                    # goto 80000e54

                # else goto 8000ac0

                if a0 == 0x70:
                    # goto 80000bec
                    pass
                elif a0 < 0x71:
                    # 80000aec -> c60

                    v1 = uVar3 & 0x7E
                    if a0 != v0:
                        s4 += 1
                        # goto 80000e54

                    if v1 == 0x7A:
                        # goto cd8
                        pass
                    elif v1 < 0x7B:
                        # goto c84
                        pass
                    elif v1 == a0:
                        # goto c9c

                        pass
                    else:
                        v0 = 0x7C # set at c70
                        s4 += 1
                        # goto 80000e54
                elif a0 == v1:
                    # goto 80000afc
                else:
                    s1 += 1
                    # goto 80000e54

            elif v1 == 0:
                # 0x80000974
                v0 = 0x20
            
            else:
                # otherwise, increment s4 and go to 80000e54

            # 80000e50: s4 += 1
            # 80000e54: s1 -= 1
            
            # 80000e58
            v1 = output_pointer - s4
            if s1 != -1:
                # e64/e68: copy last byte n times
                a0 = v0
                while s1 != a0:
                    output[output_pointer] = output[v1]
                    v1 += 1
                    output_pointer += 1
                    s1 -= 1

            # else land at e80
            if (uVar3 & 0x80) != 0 and output_pointer < output_size:
                # goto 928 to continue this subloop
                continue
            
            # otherwise goto 810
            break

        # end of mainloop
    
    return output