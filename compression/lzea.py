'''
EA custom LZxx compression
Used on World Cup 98, FIFA 99, Knockout Kings 2000

The decompressor makes one big assumption: the first time through the loop
we won't have anything to backseek through, so the first operation we'll hit
dumps n bytes to the output buffer. After that we are free to backseek.

Thanks to the compiler inlining and unrolling stuff, as well as coding in
conditions that are normally impossible to reach and inane register juggling,
I can say this is the worst decompression code I've had to untangle so far.
'''

from .bitbuffer import BufferBitstreamReader, BitstreamReadOrder

import struct
from io import BytesIO

# block at 80000bbc does common backseek/run length decode
# then execution ends up at 80000e58 via e50/e54
def _lzea_bbc_common(bitstream: BufferBitstreamReader,
                     backseek: int,
                     v0: int):
    
    backseek = (backseek | v0) + 1       # e50 adds 1 to s4
    s1 = bitstream.read_bits_lifo(2) + 4 # +4, but then e54 subtracts 1 from s1
    # jumps to e50
    return backseek, s1

def _match_twobits(unmasked, wanted) -> bool:
    return (unmasked & 0b01100000) == wanted

def _match_fourbits(unmasked, wanted) -> bool:
    return (unmasked & 0b01111000) == wanted

def _match_sixbits(unmasked, wanted) -> bool:
    return (unmasked & 0b01111110) == wanted

def _match_sevenbits(unmasked, wanted) -> bool:
    return (unmasked & 0b01111111) == wanted

def _wc98_common_decompress(input: bytes):

    
    # first 4 bytes of the buffer are the uncompressed size
    output_size = struct.unpack(">I", input[:4])[0]


    output = bytearray([0] * output_size)

    # bitstream is filled 8 bits at a time, and the output takes the lower
    # 2 bits in order (byte &= 3, input_bits >>= 2),
    # so read order is r-to-l and the output bits will be read last-in-first-out
    bitstream = BufferBitstreamReader(input, BitstreamReadOrder.R_TO_L)
    
    input_stream = BytesIO(input)
    read_byte = lambda: input_stream.read(1)[0]

    # s1 ?
    uVar6 = 0          # $s2, looks like an 8-bit bitbuffer
    control_byte = 0   # $s3, uVar11. number of bits on buffer
    backseek = 0       # $s4, uVar4
    uVar3 = 0          # $s5, uVar3
    output_pointer = 0 # $s6
    
    # $s7 is end of output buffer
    # so logically we treat it the same as output_size

    # offsets below match knockout kings 2000 us.
    # pardon the painful compiler unrolling...
    #
    # loop top at 0x80000810
    while output_pointer < output_size:

        # this is duplicated at 81c/82c,
        # but because $s3/control_byte won't change on either code path,
        # it's fine to only perform this operation once
        
        s1 = bitstream.read_bits_lifo(2)

        # decode length of what we're about to read
        # 0b00 -> read byte and keep adding 0xFF to s1 until a nonzero value is hit,
        #         then add the nonzero to s1
        # 0b01 -> s1 = 0 (1 byte)
        # 0b10 -> s1 = 1 (2 bytes)
        # 0b11 -> need to decode more bits
        if s1 == 0:
            # 80000848: keep adding 0xFF until nonzero is hit, then add that to s1
            v0 = bitstream.read_byte()
            while v0 == 0:
                s1 += 0xFF
                v0 = bitstream.read_byte()
            
            s1 += v0

            # s1 ++, jump to 800008f4, which does s1 --, cancelling out the increment.
            # so here we pretend we fall through to 800008f8
        else:
            # 80000884: if we got 0b11, then set the length to 2
            take_jump = (s1 != 3)
            s1 -= 1

            # if s1 = 1, then 0 (1 byte)
            # if s1 = 2, then 1 (2 bytes)
            # if s1 = 3, more length encoding has to be decoded

            # jump to 0x8f8 if this is true (so skip this entire block and fall through)
            if take_jump is False:
                # if s1 was 3, more length encoding has to be decoded

                s1 = bitstream.read_bits_lifo(2) + 2 # +3, but delayslot at jump -1

                # if path not taken, execution falls through to 8f8
                if (s1 + 1) == 6:
                    # if this path is taken, execution continues from 8c8
                    s1 = bitstream.read_bits_lifo(2) + 5 # +6, but then -1 because we end up at 8f4

        # 800008f8: FINALLY output a byte.
        # s1 is treated as a signed integer here.
        while s1 != -1:
            output[output_pointer] = bitstream.read_byte()
            output_pointer += 1
            s1 -= 1
            
        # bounds check so we don't go into the subloop below and crash
        if output_pointer >= output_size:
            return output

        # 80000928: start of another subloop.
        # process backseek blocks and keep looping until (uVar3 & 0x80) is zero
        while True:
            # this byte is very important; it's a packed bitfield
            # that tells us how to decode the backseek
            uVar3 = bitstream.read_byte()

            # START OF THE HORRIBLY LARGE IF STATEMENT
            # which is very tangled if statement thanks to how the bits are packed.
            # we start by matching bits 5/6, then if both are true,
            # we look at bits 3/4, and if both of those ones are true too,
            # we look at bist 1/2.
            if _match_twobits(uVar3, 0x40):
                # a64: backseeking up to 0x1FF bytes
                backseek = (bitstream.read_bits_lifo(2) << 5) | (uVar3 & 0x1F) # in delay slot at a68
                v0 = bitstream.read_bits_lifo(2) << 7
                backseek, s1 = _lzea_bbc_common(bitstream, backseek, v0)

                # execution falls through to 80000e58
            elif _match_twobits(uVar3, 0x20):
                # 9d8
                backseek = (bitstream.read_bits_lifo(2) << 5) | (uVar3 & 0x1F)
                backseek |= bitstream.read_bits_lifo(2) << 7

                v1 = bitstream.read_bits_lifo(2)
                backseek |= (v1 & 1) << 9

                # goto b6c
                s1 = (v1 >> 1) + 2 # +3, but e54 decrements it
                
                # then the usual stuff at e50:
                backseek += 1 # because of e50
                
                # and fall through to 80000e58
            elif _match_twobits(uVar3, 0x00):
                # 974: similar to a64 but with a fixed sizecount
                backseek = (bitstream.read_bits_lifo(2) << 5) | (uVar3 & 0x1F)
                backseek |= bitstream.read_bits_lifo(2) << 7
                
                # code then jumps to 80000e50:
                backseek += 1 # because of e50
                s1 = 1 # set to 2, but e54 decrements it

            elif _match_fourbits(uVar3, 0x60):
                # afc: recovering 14-bit backseek value
                backseek_lobits = (uVar3 & 7)
                backseek_byte = bitstream.read_byte() << 3
                backseek_higher_bits = bitstream.read_bits_lifo(2) << 11

                # the second bit will be used to set length
                last_two_bits = bitstream.read_bits_lifo(2)

                backseek_highest_bit = (last_two_bits & 1) << 13

                backseek = (backseek_highest_bit | backseek_higher_bits | backseek_byte | backseek_lobits)
                
                s1 = (last_two_bits >> 1) + 2 # +3, but e54 decrements it

                # code then jumps to 80000e50:
                backseek += 1 # because of e50

            elif _match_fourbits(uVar3, 0x68):
                # b7c
                backseek_lobits = (uVar3 & 7)
                backseek_byte = bitstream.read_byte() << 3
                backseek_higher_bits = bitstream.read_bits_lifo(2) << 11
            
                # goto bbc path
                pass

            elif _match_fourbits(uVar3, 0x70):
                # bec
                backseek_lobits = (uVar3 & 7)
                backseek_byte = bitstream.read_byte() << 3
                backseek = (backseek_byte | backseek_lobits)

                sizeof_lobits = bitstream.read_bits_lifo(2)
                sizeof_hibits = bitstream.read_bits_lifo(2) << 2

                s1 = (sizeof_hibits | sizeof_lobits) + 8 # +9, but e54 decrements it

                # code then jumps to 80000e50:
                backseek += 1 # because of e50

            elif _match_sixbits(uVar3, 0x78):
                # C9C
                backseek_lobit  = uVar3 & 1
                backseek_byte_1 = bitstream.read_byte() << 1
                byte_2 = bitstream.read_byte()
                backseek_byte_2 = (byte_2 & 0x3F) << 9

                backseek = (backseek_byte_2 | backseek_byte_1 | backseek_lobit)
                s1 = (byte_2 >> 6) + 3 # +4, but e54 decrements it

                # code then jumps to 80000e50:
                backseek += 1 # because of e50
            elif _match_sixbits(uVar3, 0x7A):
                # CD8
                backseek_lobit  = uVar3 & 1
                backseek_byte_1 = bitstream.read_byte() << 1
                byte_2 = bitstream.read_byte()
                backseek_byte_2 = (byte_2 & 0x1F) << 9

                backseek = (backseek_byte_2 | backseek_byte_1 | backseek_lobit) + 0x800

                s1 = (byte_2 >> 5) + 7 # +8, but e54 decrements it

                # code then jumps to 80000e50:
                backseek += 1 # because of e50
            elif _match_sixbits(uVar3, 0x7C):
                # goto D18

                backseek_lobit  = uVar3 & 1
                backseek_byte_1 = bitstream.read_byte() << 1
                byte_2 = bitstream.read_byte()
                backseek_byte_2 = (byte_2 & 0x7) << 9
            
                backseek = (backseek_byte_2 | backseek_byte_1 | backseek_lobit)
                s1 = (byte_2 >> 3) + 0x0F # +0x10, but e54 decrements it

                # code then jumps to 80000e50:
                backseek += 1 # because of e50
            elif _match_sevenbits(uVar3, 0x7E):
                # goto DF8
                pass
            elif _match_sevenbits(uVar3, 0x7F):
                # D60
                pass
            else:
                raise RuntimeError(f"illegal backseek control flag: uVar3 {uVar3:02x} (bits {uVar3:08b})")
            # END OF THE HORRIBLY LARGE IF STATEMENT

            # 80000e50: s4 += 1
            # 80000e54: s1 -= 1
            
            # at this point:
            # s4 is the backseek location

            # 80000e58
            v1 = output_pointer - backseek
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
            
            # otherwise goto 810 (end of backseek operation(s))
            break

        # end of mainloop
    
    return output