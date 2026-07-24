import struct


def unpack_uint32_be(data: bytes):
    return struct.unpack(">I", data[:4])[0]

def unpack_uint24_be(data: bytes):
    hibyte, loword = struct.unpack(">BH", data[:3])
    return (hibyte << 16) + loword

def unpack_uint16_be(data: bytes):
    return struct.unpack(">H", data[:2])[0]

def unpack_int16_be(data: bytes):
    return struct.unpack(">h", data[:2])[0]
