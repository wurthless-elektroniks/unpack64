'''
MIO0 decompression

Based on https://github.com/queueRAM/sm64tools/blob/master/libmio0.c
'''

import logging
import struct

logger = logging.getLogger(__name__)

class _Mio0Bitstream:
    def __init__(self, data: bytes):
        self._data = data
        self._byte_offset = 0
        self._bitbuffer = 0
        self._bits_on_buffer = 0

    def read_bit(self) -> int:
        if self._bits_on_buffer == 0:
            self._bitbuffer = self._data[self._byte_offset]
            self._bits_on_buffer = 8
            self._byte_offset += 1

        # MIO0 bitstream is left-to-right
        bit_out = 1 if (self._bitbuffer & 0x80) != 0 else 0
        self._bitbuffer = (self._bitbuffer << 1) & 0xFF
        self._bits_on_buffer -= 1

        return bit_out

def mio0_decompress(data: bytes,
                    output_buffer: bytes | None = None,
                    output_offset: int | None = None) -> tuple[bytes, int]:

    if data[0:4] != b'MIO0':
        logger.error("not a MIO0 archive")
        return None

    dest_size, comp_offset, uncomp_offset = struct.unpack(">III", data[4:16])
    output_offset = 0 if output_offset is None else output_offset
    uncomp_index = 0
    comp_index   = 0

    output = output_buffer if output_buffer is not None else bytearray([0] * dest_size)

    bitstream = _Mio0Bitstream(data[16:])

    end_pointer = output_offset + dest_size
    # logger.debug("write to: %08x~%08x", output_offset, end_pointer)
    while output_offset < end_pointer:
        if bitstream.read_bit() == 1:
            output[output_offset] = data[uncomp_offset + uncomp_index]
            output_offset += 1
            uncomp_index += 1
        else:
            word = struct.unpack(">H", data[comp_offset+comp_index:comp_offset+comp_index+2])[0]
            comp_index += 2
            length = (word >> 12) + 3
            backseek_pointer = output_offset - (word & 0xFFF)

            for _ in range(length):
                output[output_offset] = output[backseek_pointer - 1]
                backseek_pointer += 1
                output_offset += 1

    return output, output_offset