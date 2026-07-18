import struct


def unpack_uint32_be(data: bytes):
    return struct.unpack(">I", data)[0]


def unpack_uint24_be(data: bytes):
    hibyte, loword = struct.unpack(">BH", data)
    return (hibyte << 16) + loword
