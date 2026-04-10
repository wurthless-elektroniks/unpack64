'''
LZSS as used by Extreme-G
Identical to Haruhiko Okamura's implementation, so we reuse that here.
'''

LZSS_N = 4096
LZSS_F = 18
THRESHOLD = 2

def lzss_decompress(buffer: bytes) -> bytes:
    text_buf = bytearray( [0] * (LZSS_N + LZSS_F - 1))
    flags    = 0
    buffer_pos = 0
    c = None
    r = LZSS_N - LZSS_F

    output = bytearray()

    # initial byte buffer values are zero:
    #
    # 8004b534 24 03 0f ed     li         v1,0xfed
    # 8004b538 27 a4 0f fd     addiu      a0,sp,0xffd
    # 8004b53c 24 42 ff f8     addiu      v0,v0,-0x8
    # 8004b540 00 45 30 21     addu       a2,v0,a1
    #                     LAB_8004b544                                    XREF[1]:     8004b54c(j)  
    # 8004b544 a0 80 00 00     sb         zero,0x0(a0)=>local_33
    # 8004b548 24 63 ff ff     addiu      v1,v1,-0x1
    # 8004b54c 04 61 ff fd     bgez       v1,LAB_8004b544

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

            i |= (j & 0xF0) << 4
            j =  (j & 0x0F) + THRESHOLD

            # for k <= j:
            for k in range(j + 1):
                c = text_buf[(i + k) & (LZSS_N-1)]
                output.append(c)
                text_buf[r] = c
                r += 1
                r &= (LZSS_N-1)
