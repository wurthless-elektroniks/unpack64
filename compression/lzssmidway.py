'''
LZSS variant used by San Francisco Rush
'''

LZSS_N = 4096

def lzssmidway_decompress(buffer: bytes) -> bytes:
    text_buf = bytearray( [0] * (LZSS_N))
    flags    = 0
    buffer_pos = 0
    c = None
    r = 1

    output = bytearray()

    while True:
        flags >>= 1
        if (flags & 0x0100) == 0:
            if buffer_pos >= len(buffer):
                return output

            c = buffer[buffer_pos]
            buffer_pos += 1

            flags = c | 0xFF00
        
        if (flags & 1) != 0:
            if buffer_pos >= len(buffer):
                return output
            c = buffer[buffer_pos]
            buffer_pos += 1

            text_buf[r] = c
            r += 1
            r &= (LZSS_N - 1)

            output.append(c)
        else:
            i = buffer[buffer_pos]
            buffer_pos += 1
            
            offset = (((i & 0xF0) << 4) + buffer[buffer_pos]) & 0xFFF
            buffer_pos += 1

            # end-of-file condition in the midway parser
            if offset == 0 and (i & 0x0F) == 0:
                return output
            
            j = (i & 0x0F) + 1

            for _ in range(j + 1):
                c = text_buf[offset]

                output.append(c)

                offset += 1
                offset &= (LZSS_N-1)

                text_buf[r] = c
                r += 1
                r &= (LZSS_N-1)

