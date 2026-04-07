"""
Rob Northen Compression

Used on Turok: Dinosaur Hunter
and a shitton of Amiga/other platform games.

Based in large part on:
- https://github.com/lab313ru/rnc_propack_source/blob/master/main.c
- https://moddingwiki.shikadi.net/wiki/Rob_Northern_Compression (beware, it has typos)
"""

import logging
import struct

logger = logging.getLogger(__name__)

_crc16_table = [
    0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
    0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
    0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
    0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
    0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
    0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
    0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
    0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
    0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
    0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
    0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
    0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
    0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
    0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
    0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
    0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
    0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
    0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
    0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
    0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
    0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
    0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
    0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
    0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
    0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
    0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
    0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
    0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
    0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
    0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
    0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
    0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040
]

def crc16(buffer: bytes, offset: int = 0, size: int | None = None) -> int:
    '''
    Calculate CRC-16 from buffer.
    '''
    if size is None:
        size = len(buffer) - offset
    if size < 0:
        raise RuntimeError("invalid size specified")

    crc = 0
    for i in range(size):
        crc ^= buffer[offset+i]
        crc = (crc >> 8) ^ _crc16_table[crc & 0xFF]
    return crc

# ------------------------------------------------------------------------------------------------

class _RncBitStream():
    def __init__(self, buffer: bytes, offset: int):
        self._buffer = buffer

        self._bits = 0
        self._bits_on_buffer = 0
        self._offset = offset
    
    def offset_in_bytes(self):
        return self._offset

    def bits(self):
        return self._bits
    
    def resync(self):
        # pad message with 0 bits if reads take us out of bounds (prevents crashes with Turok)
        b24 = self._buffer[self._offset + 2] << 16 if (self._offset+2) < len(self._buffer) else 0
        b16 = self._buffer[self._offset + 1] << 8  if (self._offset+1) < len(self._buffer) else 0
        b8 =  self._buffer[self._offset + 0] << 0  if (self._offset+0) < len(self._buffer) else 0
        
        self._bits = ((b24 | b16 | b8) << self._bits_on_buffer) | (self._bits & ((1 << self._bits_on_buffer) - 1))
        self._bits &= 0xFFFFFFFF

    def read_byte(self):
        if self._offset < len(self._buffer):
            self._offset += 1
            return self._buffer[self._offset-1]
        return 0
    
    def read_bits(self, count: int) -> int:
        if count > 16:
            raise RuntimeError(f"too many bits (wanted {count})")

        bits = 0
        prev_bits = 1
        for _ in range(count):
            if self._bits_on_buffer == 0:
                b1 = self.read_byte()
                b2 = self.read_byte()
                b3 = self._buffer[self._offset] if self._offset < len(self._buffer) else 0
                b4 = self._buffer[self._offset+1] if (self._offset+1) < len(self._buffer) else 0
                

                self._bits = (b4 << 24) | (b3 << 16) | (b2 << 8) | b1
                self._bits_on_buffer = 16
            
            if (self._bits & 1) != 0:
                bits |= prev_bits
            
            self._bits >>= 1
            prev_bits <<= 1
            self._bits_on_buffer -= 1
        return bits

class _HuffmanLeaf():
    def __init__(self):
        self._code = 0
        self._code_length = 0
        self._value = 0

    def code(self, new_code: int | None = None) -> int:
        if new_code != None:
            self._code = new_code
        return self._code

    def code_length(self, new_code_length: int | None = None) -> int:
        if new_code_length != None:
            self._code_length = new_code_length
        return self._code_length

    def value(self, new_value: int | None = None) -> int:
        if new_value != None:
            self._value = new_value
        return self._value

def _mirror_bits(value: int, bits: int):
    top = 1 << (bits-1)
    bot = 1
    while top > bot:
        mask = top | bot
        masked = value & mask
        if masked != 0 and masked != mask:
            value ^= mask
        top >>= 1
        bot <<= 1
    return value

def _inverse_bits(value, count):
    i = 0
    while count != 0:
        i <<= 1
        if (value & 1):
            i |= 1
        value >>= 1
        count -= 1
    return i

# the magic "proc 20"
def _proc_20(leaf_node_bit_lengths) -> list:
    val = 0
    div = 0x80000000
    bits_count = 1

    final_leafs = []
    while bits_count <= 16:
        for i,leaf_bit_count in enumerate(leaf_node_bit_lengths):
            if leaf_bit_count == bits_count:
                leaf = _HuffmanLeaf()
                leaf.code(_inverse_bits(int(val / div), bits_count))
                leaf.code_length(bits_count)
                leaf.value(i)
                final_leafs.append(leaf)

                val += div
        bits_count += 1
        div >>= 1
    
    return final_leafs


def _read_huffman_table(bitstream: _RncBitStream) -> list:
    num_leafs = bitstream.read_bits(5)
    if num_leafs == 0:
        # table is empty, somehow
        logger.debug("???? huffman table was empty")
        return None

    # there are never more than 16 leafs, per lab313ru's implementation.
    if num_leafs > 16:
        num_leafs = 16

    leaf_lengths = []
    max_leaf = 0
    for _ in range(num_leafs):
        v = bitstream.read_bits(4)
        leaf_lengths.append(v)
        max_leaf = max(v, max_leaf)

    return _proc_20(leaf_lengths)

def _match_leaf(table: list, bitstream: _RncBitStream) -> _HuffmanLeaf:
    for leaf in table:
        if (bitstream.bits() & (1 << leaf.code_length())-1) == leaf.code():
            return leaf
    return None

def _read_huffman(table: list, bitstream: _RncBitStream) -> int | None:
    for i, leaf in enumerate(table):
        decoded_code = (bitstream.bits() & (1 << leaf.code_length())-1) 
        if (bitstream.bits() & (1 << leaf.code_length())-1) == leaf.code():

            v = leaf.value()
            bitstream.read_bits(leaf.code_length())
            if v < 2:
                return v
            vout = bitstream.read_bits(v-1) | (1 << (v-1))
            return vout
    logger.error("failed to find leaf! bits on buffer were %04x",bitstream.bits())
    return None

# ------------------------------------------------------------------------------------------------

def _unpack_type_1(buffer: bytes) -> bytes | None:
    rnc_header = struct.unpack(">IIIHHH", buffer[0:18])
    magic = rnc_header[0]
    if magic != 0x524E4301:
        return None

    uncompressed_length = rnc_header[1]
    compressed_length   = rnc_header[2]
    uncompressed_crc16  = rnc_header[3]
    compressed_crc16    = rnc_header[4]
    _unused = rnc_header[5]
    
    actual_compressed_crc16 = crc16(buffer, 18, compressed_length)
    if actual_compressed_crc16 != compressed_crc16:
        logging.error("RNC CRC-16 mismatch on compressed data: expected %04x, got %04x", compressed_crc16, actual_compressed_crc16)
        return None

    bitstream = _RncBitStream(buffer, 18)

    # the first two bits are important somehow
    bitstream.read_bits(2)

    out_buffer = bytearray(uncompressed_length)
    out_buffer_pos = 0
    while bitstream.offset_in_bytes() < (18 + compressed_length): # until end of file
        raw_table = _read_huffman_table(bitstream)
        len_table = _read_huffman_table(bitstream)
        pos_table = _read_huffman_table(bitstream)

        if raw_table is None or len_table is None or pos_table is None:
            logger.error("RNC unpack type 1: error initializing huffman tables")
            return None
        
        chunk_count = bitstream.read_bits(16)

        while chunk_count != 0:
            # read length; if not 0, copy bytes directly to the output
            length = _read_huffman(raw_table, bitstream)
            if length is None:
                logger.error("RNC unpack type 1: decode error when reading length of raw data")
                return None

            if length != 0:
                for _ in range(length):
                    out_buffer[out_buffer_pos] = bitstream.read_byte()
                    out_buffer_pos += 1
                
                # bitbuffer must be reset at this point
                bitstream.resync()
            
            chunk_count -= 1
            
            if chunk_count > 0:
                match_offset = _read_huffman(len_table, bitstream)
                if match_offset is None:
                    logger.error("RNC unpack type 1: decode error when reading match offset")
                    return None
                
                match_offset += 1

                match_count  = _read_huffman(pos_table, bitstream)
                if match_count is None:
                    logger.error("RNC unpack type 1: decode error when reading match count")
                    return None
                match_count += 2
                
                for _ in range(match_count):
                    rpos = out_buffer_pos - match_offset
                    if rpos < 0:
                        logger.error("RNC unpack type 1: decode error, match offset went negative")
                        return None
                    out_buffer[out_buffer_pos] = out_buffer[out_buffer_pos - match_offset]
                    out_buffer_pos += 1

    actual_uncompressed_crc16 = crc16(out_buffer, size=uncompressed_length)
    if actual_uncompressed_crc16 != uncompressed_crc16:
        logging.error("RNC decompressed CRC-16 mismatch: expected %04x, got %04x", uncompressed_crc16, actual_uncompressed_crc16)
        return None

    return out_buffer

def rnc_unpack(buffer: bytes) -> bytes | None:
    if buffer[0] == 0x52 and buffer[1] == 0x4E and buffer[2] == 0x43 and buffer[3] == 0x01:
        return _unpack_type_1(buffer)

    return None
