'''
Signature-related stuff I keep repeating in the various game drivers
'''

import struct
from mips import make_andmask_load_store
from signature import Signature, SignatureBuilder, WILDCARD

def pick_pattern(buffer: bytes,
                 patterns: list[Signature],
                 comparing_at_offset: int | None = None) -> tuple[Signature,int]:
    '''
    Given a list of Signatures, tries to find the first one it can in the buffer and,
    if found, returns its position with it.

    Returns None, None if nothing matched.
    '''
    for pattern in patterns:
        if comparing_at_offset is None:
            offset = pattern.find(buffer)
            if offset is None:
                continue
            return pattern, offset
        if pattern.compare(buffer, comparing_at_offset):
            return pattern, comparing_at_offset
        
    return None, None

def find_all_instances(buffer: bytes,
                       pattern: Signature,
                       align32: bool = True):
    
    instances = []
    offset = 0

    while True:
        offset = pattern.find(buffer, offset, align32=align32)
        if offset is None:
            return instances
        
        instances.append(offset)
        offset += pattern.size()
        if align32 and (offset & 3) != 0:
            offset = (offset + 4) & ~3



STACK_MOVE_BACK_PATTERN = SignatureBuilder() \
    .bits(   bytes([0x27, 0xBD, 0x80, 0x00])) \
    .andmask(bytes([0xFF, 0xFF, 0x80, 0x00])) \
    .build()

RETURN_FROM_SUBROUTINE_PATTERN = SignatureBuilder() \
    .pattern([0x03, 0xE0, 0x00, 0x08]) \
    .build()


# N64 games, even ones that use the TLB, prefer to read data from 0x80xxxxxx.
# andmask on 0x24 should also match 0x34 (ori)
LI32_ADDIU_COMBO_PATTERN = SignatureBuilder() \
    .pattern([
        0x3C, WILDCARD, 0x80, WILDCARD,
        0x24, WILDCARD, WILDCARD, WILDCARD
    ]) \
    .modify_andmask(0, [0b11111100]) \
    .modify_andmask(4, [0b11101100]) \
    .build()

# lui rS,0x1234 / li rD,0x5678(rS)
LOAD32_COMBO_PATTERN = SignatureBuilder() \
    .pattern([
        0x3C, WILDCARD, 0x80, WILDCARD,
        0x8C, WILDCARD, WILDCARD, WILDCARD
    ]) \
    .modify_andmask(0, [0b11111100]) \
    .modify_andmask(4, [0b11111100]) \
    .build()

# target is: or ${a0-a2},somereg,$zero / jal fcn
MOV_THEN_CALL_PATTERN = SignatureBuilder() \
    .pattern([
        0x00, WILDCARD, WILDCARD, 0x25,
        0x0C, WILDCARD, WILDCARD, WILDCARD
    ]) \
    .modify_andmask(0, bytes([0b11111100, 0b00000000, 0b00000000, 0b00111111])) \
    .modify_andmask(4, bytes([0b11111100])) \
    .build()

def _detect_mov_then_call_combo(buffer: bytes):
    offset = 0
    while True:
        offset = MOV_THEN_CALL_PATTERN.find(buffer, offset)
        if offset is None:
            return False
        
        # get destination register
        destreg = (struct.unpack(">I", buffer[offset:offset+4])[0] >> (6 + 5)) & 0x1F

        # a0, a1, a2
        if 4 <= destreg <= 6:
            return True
        
        offset += 4


def _detect_li32_combo(buffer: bytes):
    offset = 0
    while True:
        offset = LI32_ADDIU_COMBO_PATTERN.find(buffer, offset)
        if offset is None:
            return False
        
        # get destination register for lui opcode
        reg = buffer[offset+1] & 0x1F

        # get offset register
        offset_reg = ( struct.unpack(">H", buffer[offset+4:offset+6])[0] & 0b000000_11111_00000 ) >> 5
        if reg == offset_reg:
            return True
        
        offset += 4

def _detect_load_imm32_combo(buffer: bytes):
    offset = 0
    while True:
        offset = LOAD32_COMBO_PATTERN.find(buffer, offset)
        if offset is None:
            return False
        
        # get destination register for lui opcode
        reg = buffer[offset+1] & 0x1F

        offset_reg = ( struct.unpack(">H", buffer[offset+4:offset+6])[0] & 0b000000_11111_00000 ) >> 5
        if reg == offset_reg:
            return True
        
        print(f"offset disagreement %d %d", reg, offset_reg)

        offset += 4

def contains_code(buffer: bytes) -> bool:
    return STACK_MOVE_BACK_PATTERN.find(buffer) is not None or \
           RETURN_FROM_SUBROUTINE_PATTERN.find(buffer) is not None or \
           _detect_li32_combo(buffer) or \
           _detect_load_imm32_combo(buffer) or \
           _detect_mov_then_call_combo(buffer)
