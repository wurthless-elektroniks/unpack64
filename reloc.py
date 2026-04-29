'''
Common relocation utilty code for stuff that needs it.
'''

from enum import Enum
import struct

# ------------------------------------------------------------------------------------

def _sign_extend_imm16_value(opcode: int) -> int:
    return struct.unpack(">hh", struct.pack(">I", opcode))[1]

def demunge_mips_hilo_offset(hi16_op: bytes, lo16_op: bytes) -> int:
    '''
    Demunges a hi16/lo16 offset from two instructions.
    Assumes lo16 will be an opcode that works on signed integers
    (addiu, lui, etc.).
    '''
    hi16_instruction = struct.unpack(">I", hi16_op)[0]
    lo16_instruction = struct.unpack(">I", lo16_op)[0]

    hi16 = hi16_instruction & 0xFFFF
    lo16_sign_extended = _sign_extend_imm16_value(lo16_instruction)

    return (hi16 << 16) + lo16_sign_extended

def munge_mips_hilo_offset(offset: int) -> tuple[int,int]:
    '''
    Takes an offset and munges it into hi16/lo16 offset pairings.
    Assumes lo16 will be an opcode that works on signed integers
    (addiu, lui, etc.).
    '''
    # we keep the lo16 bits pretty much the same because of the 2's complement
    # nature of what we've just done above.
    # with an address of 8005C6E0:
    #
    # hi16 = 80060000
    # lo16 = FFFFC6E0
    #
    # adding them together produces 8005C6E0.
    if (offset & 0x8000) != 0:
        offset += 0x00010000
    return (offset >> 16), offset & 0xFFFF
