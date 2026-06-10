'''
Hudson's LZSS variant 

Used by:
- Bomberman 64
- Let's Smash / Centre Court Tennis

See also: https://github.com/Bomberhackers/bm64/blob/master/tools/bm64decompress.cpp
'''

LZSS_N = 1024
LZSS_F = 66
THRESHOLD = 2

def lzssbomberman_decompress(buffer: bytes,
                             output_size: int) -> bytes:
    text_buf = bytearray( [0] * (LZSS_N + LZSS_F - 1))
    flags    = 0
    buffer_pos = 0
    c = None
    r = LZSS_N - LZSS_F

    output = bytearray()

    # initial byte buffer values are zero

    while len(output) < output_size:
        # flags are shifted AFTER processing them, not before

        if (flags & 0x0100) == 0:
            if buffer_pos >= len(buffer):
                return output

            c = buffer[buffer_pos]
            buffer_pos += 1

            flags = c | 0xFF00
        
        if (flags & 1) != 0:
            # behaves identically to normal LZSS
            if buffer_pos >= len(buffer):
                return output
            c = buffer[buffer_pos]
            buffer_pos += 1

            output.append(c)
            text_buf[r] = c
            r += 1
            r &= (LZSS_N - 1)
            
        else:
            # read two bytes
            if buffer_pos >= len(buffer):
                return output
            i = buffer[buffer_pos]
            buffer_pos += 1

            if buffer_pos >= len(buffer):
                return output
            j = buffer[buffer_pos]
            buffer_pos += 1

            # flag demunging is different from normal LZSS
            backseek_offset = ((j & 0xC0) << 2) | i
            run_length = (j & 0x3F) + THRESHOLD + 1

            for _ in range(run_length):
                c = text_buf[backseek_offset]
                text_buf[r] = c
                
                output.append(c)

                # these operate independently, it seems
                backseek_offset += 1
                backseek_offset &= (LZSS_N-1)
                r += 1
                r &= (LZSS_N-1)

        # bomberman 64 compiler optimization moves flag shift down here.
        # let's smash puts it at the top of the loop, but since the flags will be 0
        # on the first pass through the loop, it really doesn't matter
        flags >>= 1

    return output
