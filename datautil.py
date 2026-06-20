import struct

def unpack_uint24_be(data: bytes):
    hibyte, loword = struct.unpack(">BH", data)
    return (hibyte << 16) + loword
