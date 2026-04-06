'''
Minimalist MIPS stuff, massively simplified from the original code because there's no point
implementing a full debugger here...
'''

import logging
import struct


logger = logging.Logger(__name__)

def _to_uint32(data: bytes):
    return struct.unpack(">I", data)[0]

def _to_uint16(data: bytes):
    return struct.unpack(">H", data)[0]

def _to_int16(data: bytes):
    return struct.unpack(">h", data)[0]

def _instruction_template_jtype(op):
    if op > 0b111111:
        raise RuntimeError("opcode too high")
    return bytearray( list([ op << 2, 0, 0, 0]) )


INSTRUCTION_DECODE_BITMASK_UPPER_6       = _to_uint32( bytes([ 0b11111100, 0, 0, 0 ]) )
INSTRUCTION_DECODE_BITMASK_0_AND_LOWER_6 = _to_uint32( bytes([ 0b11111100, 0, 0, 0b00111111 ]) )

INSTRUCTION_ADDI_TEMPLATE  = _to_uint32(_instruction_template_jtype(0b001000))
INSTRUCTION_ADDIU_TEMPLATE = _to_uint32(_instruction_template_jtype(0b001001))
INSTRUCTION_LUI_TEMPLATE   = _to_uint32(_instruction_template_jtype(0b001111))
INSTRUCTION_JAL_TEMPLATE   = _to_uint32(_instruction_template_jtype(0b000011))
INSTRUCTION_JMP_TEMPLATE   = _to_uint32(_instruction_template_jtype(0b000010))
INSTRUCTION_ORI_TEMPLATE   = _to_uint32(_instruction_template_jtype(0b001101))


def disassemble_jump_imm26_target(oporg: int, opbytes: bytes) -> int | None:
    opword = _to_uint32(opbytes)
    masked = (opword & INSTRUCTION_DECODE_BITMASK_UPPER_6)

    if masked in [ INSTRUCTION_JAL_TEMPLATE, INSTRUCTION_JMP_TEMPLATE ]:
        return (oporg & 0xFC000000) + ((opword & 0x03FFFFFF) << 2)

    logger.error("unrecognized opcode, masked result was: %04x", opword)
    return None

def disassemble_imm16_rt_rs_target(oporg: int, opbytes: bytes) -> int | None:
    opword = _to_uint32(opbytes)
    masked = (opword & INSTRUCTION_DECODE_BITMASK_UPPER_6)

    if masked in [ INSTRUCTION_ADDI_TEMPLATE, INSTRUCTION_ADDIU_TEMPLATE ]:
        return _to_int16(opbytes[2:4])

    if masked in [ INSTRUCTION_ORI_TEMPLATE ]:
        return _to_uint16(opbytes[2:4])
    
    if masked == INSTRUCTION_LUI_TEMPLATE:
        return (opword & 0xFFFF) << 16
    
    # unrecognized opcode - give up
    logger.error("unrecognized opcode, masked result was: %04x", opword)
    return None
