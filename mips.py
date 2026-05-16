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

def _instruction_template_rtype(op, func):
    if op > 0b111111:
        raise RuntimeError("opcode too high")
    if func > 0b111111:
        raise RuntimeError("func too high")
    
    return bytearray( list([ op << 2, 0, 0, func]) )

INSTRUCTION_DECODE_BITMASK_UPPER_6       = _to_uint32( bytes([ 0b11111100, 0, 0, 0 ]) )
INSTRUCTION_DECODE_BITMASK_0_AND_LOWER_6 = _to_uint32( bytes([ 0b11111100, 0, 0, 0b00111111 ]) )

INSTRUCTION_ADDI_TEMPLATE  = _to_uint32(_instruction_template_jtype(0b001000))
INSTRUCTION_ADDIU_TEMPLATE = _to_uint32(_instruction_template_jtype(0b001001))
INSTRUCTION_LUI_TEMPLATE   = _to_uint32(_instruction_template_jtype(0b001111))
INSTRUCTION_JAL_TEMPLATE   = _to_uint32(_instruction_template_jtype(0b000011))
INSTRUCTION_JMP_TEMPLATE   = _to_uint32(_instruction_template_jtype(0b000010))
INSTRUCTION_ORI_TEMPLATE   = _to_uint32(_instruction_template_jtype(0b001101))
INSTRUCTION_LW_TEMPLATE  = _to_uint32(_instruction_template_jtype(0b100011))
INSTRUCTION_LHU_TEMPLATE = _to_uint32(_instruction_template_jtype(0b100101))
INSTRUCTION_SW_TEMPLATE = _to_uint32(_instruction_template_jtype(0b101011))

INSTRUCTION_OR_TEMPLATE    = _to_uint32(_instruction_template_rtype(0, 0b100111))
INSTRUCTION_SUBU_TEMPLATE  = _to_uint32(_instruction_template_rtype(0, 0b100011))

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

def disassemble_load_store_imm16(oporg: int, opbytes: bytes) -> int | None:
    opword = _to_uint32(opbytes)
    masked = (opword & INSTRUCTION_DECODE_BITMASK_UPPER_6)

    if masked in [ INSTRUCTION_LW_TEMPLATE,
                   INSTRUCTION_SW_TEMPLATE,
                   INSTRUCTION_LHU_TEMPLATE]:
        return _to_int16(opbytes[2:4])

    # unrecognized opcode - give up
    logger.error("unrecognized opcode, masked result was: %04x", opword)
    return None

def assemble_jal(target_address: int) -> bytes:
    return struct.pack(">I",((target_address & 0x3FFFFFFF) >> 2) | 0x0C000000)

def make_andmask_load_store(mask_dest: bool = False,
                            mask_offs: bool = False,
                            mask_imm16: bool = False):
    base_mask = 0xFFFFFFFF
    if mask_offs:
        base_mask &= 0b11111100_00011111_11111111_11111111
    if mask_dest:
        base_mask &= 0b11111111_11100000_11111111_11111111
    if mask_imm16:
        base_mask &= 0b11111111_11111111_00000000_00000000
    return struct.pack(">I", base_mask)

def make_andmask_reg_opcode(mask_lower6: bool = False,
                            mask_source: bool = False,
                            mask_source2: bool = False,
                            mask_shift: bool = False,
                            mask_dest: bool = False):
    base_mask = 0xFFFFFFFF
    if mask_source:
        base_mask &= 0b11111100_00011111_11111111_11111111
    if mask_source2:
        base_mask &= 0b11111111_11100000_11111111_11111111
    if mask_dest:
        base_mask &= 0b11111111_11111111_00000111_11111111
    if mask_shift:
        base_mask &= 0b11111111_11111111_11111000_00111111
    if mask_lower6:
        base_mask &= 0b11111111_11111111_11111111_11000000

    return struct.pack(">I", base_mask)

def apply_andmask(input_bytes: bytes | int,
                  andmask: bytes) -> bytes:
    
    if isinstance(input_bytes, int):
        input_bytes = struct.pack(">I", input_bytes)

    if len(input_bytes) != len(andmask):
        raise RuntimeError("input_bytes and andmask not equal lengths")
    
    out = bytearray([0] * len(andmask))
    for i, input_byte in enumerate(input_bytes):
        out[i] = input_byte & andmask[i]
    return out


# copypaste from reloc.py, no idea what to do there because we might
# create circular reference problems
def _demunge_mips_hilo_offset(hi16_op: bytes, lo16_op: bytes) -> int:
    '''
    Demunges a hi16/lo16 offset from two instructions.
    Assumes lo16 will be an opcode that works on signed integers
    (addiu, lui, etc.).
    '''
    hi16_instruction = struct.unpack(">I", hi16_op)[0]
    lo16_instruction = struct.unpack(">I", lo16_op)[0]

    hi16 = hi16_instruction & 0xFFFF
    lo16_sign_extended = struct.unpack(">hh", struct.pack(">I", lo16_instruction))[1]

    return (hi16 << 16) + lo16_sign_extended

def extract_range_from_lui_addiu_pairs(bindat: bytes, pattern_offset: int):
    op0, _, \
    op1, _, \
    op2, _, \
    op3, _ = struct.unpack(">HHHHHHHH", bindat[pattern_offset:pattern_offset+0x10])

    if (op0 & 0xFC00) != (op1 & 0xFC00) or \
       (op0 & 0xFC00) != 0x3C00 or \
       (op2 & 0xFC00) != (op3 & 0xFC00) or \
       (op2 & 0xFC00) != 0x2400:
       raise RuntimeError(f"expected format mismatch {op0:04x} {op1:04x} {op2:04x} {op3:04x}")
    
    op0_register = op0 & 0x1F
    op1_register = op1 & 0x1F

    op0_expected_match = (op0_register << 5) | op0_register | 0x2400
    op1_expected_match = (op1_register << 5) | op1_register | 0x2400

    a = None
    b = None

    if op0_expected_match == op2:
        a = _demunge_mips_hilo_offset(bindat[pattern_offset+0x0:pattern_offset+0x4], bindat[pattern_offset+0x8:pattern_offset+0xC])
    elif op0_expected_match == op3:
        a = _demunge_mips_hilo_offset(bindat[pattern_offset+0x0:pattern_offset+0x4], bindat[pattern_offset+0xC:pattern_offset+0x10])

    if op1_expected_match == op2:
        b = _demunge_mips_hilo_offset(bindat[pattern_offset+0x4:pattern_offset+0x8], bindat[pattern_offset+0x8:pattern_offset+0xC])
    elif op1_expected_match == op3:
        b = _demunge_mips_hilo_offset(bindat[pattern_offset+0x4:pattern_offset+0x8], bindat[pattern_offset+0xC:pattern_offset+0x10])

    output = [a, b]
    if None in [ a, b ]:
        raise RuntimeError(f"hurgh {a:08x} {b:08x}")

    output.sort()
    return output