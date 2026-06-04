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

import logging
import struct

from .bitbuffer import BufferBitstreamReader, BitstreamReadOrder

logger = logging.getLogger(__name__)


def _match_twobits(unmasked, wanted) -> bool:
    return (unmasked & 0b01100000) == wanted

def _match_fourbits(unmasked, wanted) -> bool:
    return (unmasked & 0b01111000) == wanted

def _match_sixbits(unmasked, wanted) -> bool:
    return (unmasked & 0b01111110) == wanted

def _match_sevenbits(unmasked, wanted) -> bool:
    return (unmasked & 0b01111111) == wanted

def lzea_decompress(input: bytes):
    # first 4 bytes of the buffer are the uncompressed size
    output_size = struct.unpack(">I", input[:4])[0]

    output = bytearray([0] * output_size)

    # bitstream is filled 8 bits at a time, and the output takes the lower
    # 2 bits in order (byte &= 3, input_bits >>= 2),
    # so read order is r-to-l and the output bits will be read last-in-first-out
    bitstream = BufferBitstreamReader(input[4:], BitstreamReadOrder.R_TO_L)
    
    # s1 ?
    # $s2 = 8-bit bitbuffer
    # $s3, uVar11 = number of bits on buffer
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
        s1 = bitstream.read_bits_lifo(2)

        # decode length of what we're about to read
        # 0b00 -> read byte and keep adding 0xFF to s1 until a nonzero value is hit,
        #         then add the nonzero to s1
        # 0b01 -> s1 = 1 byte
        # 0b10 -> s1 = 2 bytes
        # 0b11 -> need to decode more bits
        if s1 == 0:
            # 80000848: keep adding 0xFF until nonzero is hit, then add that to s1
            v0 = bitstream.read_byte()
            while v0 == 0:
                if bitstream.eof():
                    # if execution ends up here it's usually bad news
                    logger.warning("hit bitstream EOF trying to read runlength, aborting!")
                    return output

                s1 += 0xFF
                v0 = bitstream.read_byte()
            
            s1 = (s1 + v0) + 1
        elif s1 == 3:
            # if s1 was 3, more length encoding has to be decoded
            s1 = bitstream.read_bits_lifo(2) + 3

            # if path not taken, execution falls through to 8f8
            if s1 == 6:
                # if this path is taken, execution continues from 8c8
                s1 = bitstream.read_bits_lifo(2) + 6

        # 800008f8: FINALLY output a byte
        for _ in range(s1):
            if output_pointer >= output_size:
                logger.warning("maximum output size hit prematurely, stopping decompression!")
                return output
            output[output_pointer] = bitstream.read_byte()
            output_pointer += 1
            
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
            # we look at bits 1/2.
            if _match_twobits(uVar3, 0x40):
                # a64: backseeking up to 0x1FF bytes
                backseek = (bitstream.read_bits_lifo(2) << 5) | (uVar3 & 0x1F) # in delay slot at a68
                backseek_hibits = bitstream.read_bits_lifo(2) << 7
                backseek = (backseek | backseek_hibits) # in original code e50 adds 1 to s4
                s1 = bitstream.read_bits_lifo(2) + 5

                # execution falls through to 80000e58
            elif _match_twobits(uVar3, 0x20):
                # 9d8
                backseek = (bitstream.read_bits_lifo(2) << 5) | (uVar3 & 0x1F)
                backseek |= bitstream.read_bits_lifo(2) << 7

                v1 = bitstream.read_bits_lifo(2)
                backseek |= (v1 & 1) << 9

                # goto b6c
                s1 = (v1 >> 1) + 3
            elif _match_twobits(uVar3, 0x00):
                # 974: similar to a64 but with a fixed sizecount
                backseek = (bitstream.read_bits_lifo(2) << 5) | (uVar3 & 0x1F)
                backseek |= bitstream.read_bits_lifo(2) << 7
                s1 = 2
            elif _match_fourbits(uVar3, 0x60):
                # afc: recovering 14-bit backseek value
                backseek_lobits = (uVar3 & 7)
                backseek_byte = bitstream.read_byte() << 3
                backseek_higher_bits = bitstream.read_bits_lifo(2) << 11

                # the second bit will be used to set length
                last_two_bits = bitstream.read_bits_lifo(2)

                backseek_highest_bit = (last_two_bits & 1) << 13

                backseek = (backseek_highest_bit | backseek_higher_bits | backseek_byte | backseek_lobits)
                
                s1 = (last_two_bits >> 1) + 3
            elif _match_fourbits(uVar3, 0x68):
                # b7c
                backseek_lobits = (uVar3 & 7)
                backseek_byte = bitstream.read_byte() << 3
                backseek_higher_bits = bitstream.read_bits_lifo(2) << 11
            
                backseek = (backseek_higher_bits | backseek_byte | backseek_lobits) # in original code e50 adds 1 to s4
                s1 = bitstream.read_bits_lifo(2) + 5    # +4, but then e54 subtracts 1 from s1
            elif _match_fourbits(uVar3, 0x70):
                # bec
                backseek_lobits = (uVar3 & 7)
                backseek_byte = bitstream.read_byte() << 3
                backseek = (backseek_byte | backseek_lobits)

                sizeof_lobits = bitstream.read_bits_lifo(2)
                sizeof_hibits = bitstream.read_bits_lifo(2) << 2

                s1 = (sizeof_hibits | sizeof_lobits) + 9
            elif _match_sixbits(uVar3, 0x78):
                # C9C
                backseek_lobit  = uVar3 & 1
                backseek_byte_1 = bitstream.read_byte() << 1
                byte_2 = bitstream.read_byte()
                backseek_byte_2 = (byte_2 & 0x3F) << 9

                backseek = (backseek_byte_2 | backseek_byte_1 | backseek_lobit)
                s1 = (byte_2 >> 6) + 4
            elif _match_sixbits(uVar3, 0x7A):
                # CD8
                backseek_lobit  = uVar3 & 1
                backseek_byte_1 = bitstream.read_byte() << 1
                byte_2 = bitstream.read_byte()
                backseek_byte_2 = (byte_2 & 0x1F) << 9

                backseek = (backseek_byte_2 | backseek_byte_1 | backseek_lobit) + 0x800

                s1 = (byte_2 >> 5) + 8
            elif _match_sixbits(uVar3, 0x7C):
                # goto D18

                backseek_lobit  = uVar3 & 1
                backseek_byte_1 = bitstream.read_byte() << 1
                byte_2 = bitstream.read_byte()
                backseek_byte_2 = (byte_2 & 0x7) << 9
            
                backseek = (backseek_byte_2 | backseek_byte_1 | backseek_lobit)
                s1 = (byte_2 >> 3) + 0x10
            elif _match_sevenbits(uVar3, 0x7E):
                # goto DF8
                backseek = bitstream.read_byte()

                backseek_byte_2 = bitstream.read_byte()
                backseek |= (backseek_byte_2 & 7) << 8

                s1 = backseek_byte_2 >> 3
                s1 |= bitstream.read_bits_lifo(2) << 5

                s1 += 0x19
            elif _match_sevenbits(uVar3, 0x7F):
                # D60
                backseek_byte_1 = bitstream.read_byte()
                backseek_byte_2 = bitstream.read_byte()

                backseek = (backseek_byte_2 << 7) + (backseek_byte_1 & 0x7F)

                length_byte     = bitstream.read_byte()

                # an eighth bit has hit the bitstream, somehow
                if (backseek_byte_1 & 0x80) == 0:
                    # D94
                    length_lobits = bitstream.read_bits_lifo(2) << 8
                    length_hibits = bitstream.read_bits_lifo(2) << 10

                    s1 = (length_hibits | length_lobits | length_byte)
                else:
                    s1 = length_byte

                # code then jumps to 80000e50 - this is the common path
                s1 += 5
                # e50 increments backseek
            else:
                raise RuntimeError(f"illegal backseek control flag: uVar3 {uVar3:02x} (bits {uVar3:08b})")
            # END OF THE HORRIBLY LARGE IF STATEMENT

            # e50 increments backseek (which is done by the backseek + 1 below)
            # e54 decrements s1 because the original code loops while i >= 0

            # 80000e58: apply backseek and output n bytes
            backseek_offset = output_pointer - (backseek + 1)

            for _ in range(s1):
                if output_pointer >= output_size:
                    logger.warning("maximum output size hit prematurely, stopping decompression!")
                    return output

                output[output_pointer] = output[backseek_offset]
                backseek_offset += 1
                output_pointer += 1

            # else land at e80
            if (uVar3 & 0x80) != 0:
                # goto 928 to continue this subloop
                continue
            
            # otherwise goto 810 (end of backseek operation(s))
            break
        # end of mainloop

    return output
