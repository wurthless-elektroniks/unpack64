"""
Signature matching and building.

THIS IS LEGACY CODE.
New-style signature/symbol matching is to be done by nusym.
"""

from abc import ABCMeta
import struct
import logging


from mips import disassemble_imm16_rt_rs_target, disassemble_jump_imm26_target

logger = logging.getLogger(__name__)


WILDCARD = -666

XREF_TYPE_ONE_SHOT     = 0
XREF_TYPE_SPLIT_HALVES = 1

META_LIBRARY_NAME     = "libname"
META_LIBULTRA_VERSION = "libultra_version"
META_LIBULTRA_DISTRO  = "libultra_distro"

def _raise_16bit_imm__opcode_error(baseaddr, offset, bytecode):
    raise RuntimeError(f"opcode at 0x{(baseaddr + offset):08x} (+0x{offset:04x}) is not 16-bit rt/rs/imm opcode (got {bytecode})")

def _pattern_to_bits_and_andmask(pattern: list) -> tuple:
    bits    = bytearray(len(pattern))
    andmask = bytearray(len(pattern))
    for i,val in enumerate(pattern):
        if val == WILDCARD:
            bits[i]    = 0x00
            andmask[i] = 0x00
        elif 0 <= val <= 0xFF:
            bits[i]  = val
            andmask[i] = 0xFF
        else:
            raise RuntimeError(f"illegal hex value in pattern: {val:x}")
    return ( bits, andmask )

def _compare_buffer(data: bytearray, offset: int, bits: bytes, andmask: bytes) -> bool:
    data_length = len(data)
    left_finger = 0
    right_finger = len(bits) - 1

    while left_finger <= right_finger:
        # prevent out-of-bounds
        if (offset + left_finger) >= data_length or (offset + right_finger) >= data_length:
            return False

        if (data[offset+left_finger] & andmask[left_finger]) != \
            (bits[left_finger] & andmask[left_finger]):
            return False
        
        if (data[offset+right_finger] & andmask[right_finger]) != \
            (bits[right_finger] & andmask[right_finger]):
            return False
        
        left_finger += 1
        right_finger -= 1
    return True

# -----------------------------------------------------------------------------

class SignatureResolvedSymbol():
    def __init__(self, name: str, symbol_type: int = XREF_TYPE_ONE_SHOT):
        self._name = name
        self._type = symbol_type
        self._imm_value = 0
        self._imm_hi16  = None
        self._imm_lo16  = None
        self._is_weak   = False

    def final(self):
        if self._type == XREF_TYPE_SPLIT_HALVES and (self._imm_hi16 is None or self._imm_lo16 is None):
            raise RuntimeError(f"SignatureXref {self._name} was declared as split hi16/lo16 halves, but only one half was set in the signature.")

    def name(self) -> str:
        return self._name
    
    def is_weak(self) -> bool:
        return self._is_weak

    def set_imm(self, value: int):
        self._imm_value = value

    def set_hi16(self, opcode: bytearray):
        self._imm_hi16 = opcode[2] << 24 | opcode[3] << 16

        if self._imm_hi16 is not None and self._imm_lo16 is not None:
            self.set_imm(self._imm_hi16 + self._imm_lo16)

    def set_lo16(self, imm_lo16: int):
        self._imm_lo16 = imm_lo16
        if self._imm_hi16 is not None and self._imm_lo16 is not None:
            self.set_imm(self._imm_hi16 + self._imm_lo16)
    
    def set_is_weak(self, is_weak: bool):
        self._is_weak = is_weak

class SignatureResolvedXref(SignatureResolvedSymbol):
    def get_address(self) -> int:
        return self._imm_value

class UnresolvedSymbol(metaclass=ABCMeta):
    def __init__(self):
        self._offset = None               # offset within function
        self._target_sym = None           # target symbol name
        self._destptr_offset = 0          # offset to add to target pointer (default 0)
        self._destptr_is_function = False # is this pointing to another function?
        self._destptr_is_weak = False     # are we referencing a weak symbol?

        # is this relative to the current function's base address?
        # (for 26-bit imm jumps within the same function)
        self._is_relative_to_fcn = False

class UnresolvedXref(UnresolvedSymbol):
    def resolve_for(self, baseaddr: int, buffer: bytearray, resolved_xref: SignatureResolvedXref):
        pass

    def create_resolved(self) -> SignatureResolvedXref:
        return SignatureResolvedXref(self._target_sym)

class UnresolvedXrefOp32JImm26(UnresolvedXref):
    def resolve_for(self, baseaddr: int, buffer: bytearray, resolved_xref: SignatureResolvedXref):
        bytecode = buffer[self._offset:self._offset+4]

        dest = disassemble_jump_imm26_target(baseaddr + self._offset, bytecode)
        if dest is None:
            raise RuntimeError(f"opcode at {(baseaddr + self._offset):08x} (+0x{self._offset}) is not 26-bit immediate jump instruction (got {bytecode})")
        resolved_xref.set_imm(dest)
        resolved_xref.set_is_weak(self._destptr_is_weak)

class UnresolvedXrefSplitHalves(UnresolvedXref):
    def create_resolved(self) -> SignatureResolvedXref:
        return SignatureResolvedXref(self._target_sym, XREF_TYPE_SPLIT_HALVES)

class UnresolvedXrefOp32Hi16(UnresolvedXrefSplitHalves):
    def resolve_for(self, baseaddr, buffer, resolved_xref):
        resolved_xref.set_hi16(buffer[self._offset:self._offset+4])

class UnresolvedXrefOp32Lo16(UnresolvedXrefSplitHalves):
    def resolve_for(self, baseaddr, buffer, resolved_xref):
        bytecode = buffer[self._offset:self._offset+4]
        imm16 = disassemble_imm16_rt_rs_target(baseaddr + self._offset, bytecode)
        if imm16 is None:
            _raise_16bit_imm__opcode_error(baseaddr, self._offset, bytecode)
        resolved_xref.set_lo16(imm16)

class UnresolvedXrefImm32(UnresolvedXref):
    def resolve_for(self, baseaddr, buffer, resolved_xref):
        resolved_xref.set_imm(struct.unpack(">I",buffer[self._offset:self._offset+4])[0])

class SignatureResolvedConst(SignatureResolvedSymbol):
    def get_value(self) -> int:
        return self._imm_value

class UnresolvedConst(UnresolvedSymbol):
    '''
    Base class for an unresolved constant.
    '''
    pass


class UnresolvedConstSplitHalves(UnresolvedConst):
    def create_resolved(self) -> SignatureResolvedXref:
        return SignatureResolvedConst(self._target_sym, XREF_TYPE_SPLIT_HALVES)
    
class UnresolvedConstOp32Hi16(UnresolvedConstSplitHalves):
    def resolve_for(self, baseaddr, buffer, resolved_xref):
        resolved_xref.set_hi16(buffer[self._offset:self._offset+4])

class UnresolvedConstOp32Lo16(UnresolvedConstSplitHalves):
    def resolve_for(self, baseaddr, buffer, resolved_xref):
        bytecode = buffer[self._offset:self._offset+4]
        dest = disassemble_imm16_rt_rs_target(baseaddr + self._offset, bytecode)
        if dest is None:
            _raise_16bit_imm__opcode_error(baseaddr, self._offset, bytecode)
        resolved_xref.set_lo16(dest)

class UnresolvedConstOp32Imm16(UnresolvedConst):
    def create_resolved(self) -> SignatureResolvedXref:
        return SignatureResolvedConst(self._target_sym, XREF_TYPE_ONE_SHOT)

    def resolve_for(self, baseaddr, buffer, resolved_xref):
        bytecode = buffer[self._offset:self._offset+4]
        dest = disassemble_imm16_rt_rs_target(baseaddr + self._offset, bytecode)
        if dest is None:
            _raise_16bit_imm__opcode_error(baseaddr, self._offset, bytecode)
        resolved_xref.set_imm(dest)

class UnresolvedConstImm32(UnresolvedConst):
    def create_resolved(self) -> SignatureResolvedXref:
        return SignatureResolvedConst(self._target_sym, XREF_TYPE_ONE_SHOT)
    
    def resolve_for(self, baseaddr, buffer, resolved_xref):
        resolved_xref.set_imm(struct.unpack(">I",buffer[self._offset:self._offset+4])[0])

class Signature():
    '''
    Implements a Signature. Do not instantiate this directly, use the SignatureBuilder.
    '''
    def __init__(self):
        self._name = None
        self._meta = {}
        self._bits = None
        self._andmask = None
        self._tail_bits = None
        self._tail_andmask = None
        self._size = 0
        self._unresolved_xrefs = []
        self._unresolved_consts = []

    def meta(self, key: str) -> str | None:
        '''
        Return specific metadata item by key, or None if no such key exists.
        '''
        if key not in self._meta:
            return None
        return self._meta[key]
    
    def meta_items(self):
        '''
        Return dict_items of internal meta dict.
        '''
        return self._meta.items()

    def libultra_version(self) -> str | None:
        '''
        Returns the earliest known version of libultra this signature applies to.
        '''
        return self.meta(META_LIBULTRA_VERSION)
    
    def libultra_distro(self) -> str | None:
        '''
        Whether the libultra distribution is for "pc" or "sgi".
        '''
        return self.meta(META_LIBULTRA_DISTRO)

    def compare(self, data: bytearray, offset: int = 0) -> bool:
        '''
        Compare signature to given data buffer.
        '''
        pattern_matches = _compare_buffer(data, offset, self._bits, self._andmask)
        if pattern_matches is False or self._tail_bits is None:
            return pattern_matches

        return _compare_buffer(data,
                               offset + (self._size - len(self._tail_bits)),
                               self._tail_bits,
                               self._tail_andmask)
    
    def dump_unresolved_xrefs(self):
        pass

    def xrefs(self, segment_base: int, data: bytearray, offset: int = 0) -> dict:
        '''
        Using this signature, generate dict of xrefs pointing symbol_name -> resolvedxref.
        Returns None if signature didn't match.
        '''
        if self.compare(data, offset) is False:
            return None

        resolutions = {}

        # pass 1: create resolutions
        for unresolved_xref in self._unresolved_xrefs:
            if unresolved_xref._target_sym in resolutions:
                continue
            resolutions[unresolved_xref._target_sym] = unresolved_xref.create_resolved()

        # pass 2: process them
        for unresolved_xref in self._unresolved_xrefs:
            unresolved_xref.resolve_for(segment_base + offset, data[offset:], resolutions[unresolved_xref._target_sym])

        # pass 3: finalize resolutions to list (catching errors)
        for resolution in resolutions.values():
            resolution.final()

        return resolutions
    
    def dump_unresolved_consts(self):
        pass

    def consts(self, segment_base: int, data: bytearray, offset: int = 0) -> dict:
        '''
        Using this signature, generate dict of consts pointing symbol_name -> resolvedconst.
        Returns None if signature didn't match.
        '''
        if self.compare(data, offset) is False:
            return None

        resolutions = {}

        # pass 1: create resolutions
        for unresolved_const in self._unresolved_consts:
            if unresolved_const._target_sym in resolutions:
                continue
            resolutions[unresolved_const._target_sym] = unresolved_const.create_resolved()

        # pass 2: process them
        for unresolved_const in self._unresolved_consts:
            unresolved_const.resolve_for(segment_base + offset, data[offset:], resolutions[unresolved_const._target_sym])

        # pass 3: finalize resolutions to list (catching errors)
        for resolution in resolutions.values():
            resolution.final()

        return resolutions

    def find(self, data: bytearray, offset: int = 0, align32: bool = True) -> None | int:
        '''
        Find match within given data buffer.
        Return offset within the array, or None if not found.
        '''
        step = 4 if align32 is True else 1
        data_len = len(data)
        while offset < data_len:
            if (offset + self._size) >= data_len:
                break
            if self.compare(data, offset) is True:
                return offset
            offset += step
        return None
    
    def bits(self):
        return bytes(self._bits)
    
    def andmask(self):
        return bytes(self._andmask)
    
    def tail_bits(self) -> bytes | None:
        if self._tail_bits is None:
            return None
        return bytes(self._bits)
    
    def tail_andmask(self):
        if self._tail_andmask is None:
            return None
        return bytes(self._andmask)

class SignatureBuilder():
    '''
    Implements a SignatureBuilder.
    '''
    def __init__(self):
        self._bits = None
        self._andmask = None
        self._tail_bits = None
        self._tail_andmask = None
        
        self._name = None
        self._size = None
        self._meta = {}
        self._unresolved_xrefs = []
        self._unresolved_consts = []

    # pylint:disable=protected-access
    def build(self) -> Signature:
        '''
        Build and return a `Signature` object.
        '''
        if self._bits is None or self._andmask is None:
            raise RuntimeError("bits / andmask not specified")

        if len(self._bits) != len(self._andmask):
            raise RuntimeError("bits and andmask must be the same length")

        sig = Signature()
        sig._bits    = self._bits
        sig._andmask = self._andmask

        if (self._tail_andmask is not None and self._tail_bits is not None):
            if len(self._tail_andmask) != len(self._tail_bits):
                raise RuntimeError("tail_bits and tail_andmask must be the same length")

            if self._size is not None and len(self._tail_bits) + len(self._bits) > self._size:
                raise RuntimeError(f"size of bits and tail_bits exceeds total signature size (expected {self._size}, got {len(self._tail_bits) + len(self._bits)})")

            sig._tail_andmask = self._tail_andmask
            sig._tail_bits = self._tail_bits
        elif (self._tail_andmask is not None or self._tail_bits is not None):
            raise RuntimeError("one of tail_bits/tail_andmask not specified (both or neither must be specified)")

        sig._name = self._name
        sig._size = self._size if self._size is not None else len(sig._bits) + (0 if sig._tail_bits is None else len(sig._tail_bits))
        sig._meta = self._meta
        sig._unresolved_xrefs  = self._unresolved_xrefs
        sig._unresolved_consts = self._unresolved_consts
        return sig

    def name(self, name: str):
        self._name = name
        return self
    
    def meta(self, key: str, value: any):
        self._meta[key] = value
        return self

    def libultra_version(self, libultra_version: str):
        return self.meta(META_LIBULTRA_VERSION, libultra_version)
    
    def libultra_distro(self, libultra_distro: str):
        return self.meta(META_LIBULTRA_VERSION, libultra_distro)

    def size(self, sizeof: int):
        '''
        Sets size of the function (NOT the signature itself).
        '''
        self._size = sizeof
        return self
    
    def bits(self, bitpattern: bytes):
        '''
        Set bitpattern.
        '''
        self._bits = bitpattern
        return self
    
    def modify_andmask(self, offset: int, patchedmask: bytes):
        self._andmask[offset:offset+len(patchedmask)] = patchedmask
        return self

    def andmask(self, andmask: bytes):
        '''
        Set AND mask.
        '''
        self._andmask = andmask
        return self
    
    def tail_bits(self, bitpattern: bytes):
        self._tail_bits = bitpattern
        return self
    
    def tail_andmask(self, andmask: bytes):
        self._tail_andmask = andmask
        return self

    def pattern(self, pattern: list):
        '''
        Set pattern.

        This does not control AND masking at the bit level; for that, use `bits()` and `andmask()`.
        '''
        parsed = _pattern_to_bits_and_andmask(pattern)
        return self.bits(parsed[0]).andmask(parsed[1])

    def tail_pattern(self, tail_pattern: list):
        parsed = _pattern_to_bits_and_andmask(tail_pattern)
        return self.tail_bits(parsed[0]).tail_andmask(parsed[1])

    def xref_op32_hi16(self, symbol: str, offset: int, destptr_offset: int = 0, destptr_is_function: bool = False):
        '''
        Create hi16 xref at given offset in signature pointing at symbol.
        '''
        xref = UnresolvedXrefOp32Hi16()
        xref._target_sym = symbol
        xref._offset = offset
        xref._destptr_offset = destptr_offset
        xref._destptr_is_function = destptr_is_function
        self._unresolved_xrefs.append(xref)
        return self
    
    def xref_op32_lo16(self, symbol: str, offset: int, destptr_offset: int = 0, destptr_is_function: bool = False):
        '''
        Create lo16 xref at given offset in signature pointing at symbol.
        '''
        xref = UnresolvedXrefOp32Lo16()
        xref._target_sym = symbol
        xref._offset = offset
        xref._destptr_offset = destptr_offset
        xref._destptr_is_function = destptr_is_function
        self._unresolved_xrefs.append(xref)
        return self

    def xref_j_imm26(self, symbol: str, offset: int, destptr_offset: int = 0, dest_is_weak: bool = False):
        '''
        Create `imm26` at given offset in signature pointing at symbol.

        - dest_is_weak: If true, whatever this points to is a weak symbol. libultra defines default
          implementations of functions (bzero(), cosf(), etc.) that game programmers are free to override.
          This is here so that deep searching/pattern matching code knows that the function at that destination
          might not match a known signature.
        '''
        xref = UnresolvedXrefOp32JImm26()
        xref._target_sym = symbol
        xref._offset = offset
        xref._destptr_offset = destptr_offset
        xref._destptr_is_function = True
        xref._destptr_is_weak = dest_is_weak
        self._unresolved_xrefs.append(xref)
        return self
    
    def xref_j_imm26_relative(self, offset: int, rel_offset_destptr: int = 0):
        '''
        Create `imm26` xref in relative mode.

        The gcc compiler often generates far jumps within a local function,
        leading to situations where we have to apply relocations that point inside
        the same function.

        If the gcc compiler gives us `j 0x0000017c` at offset 0x134 then
        rel_offset_destptr should be 0x17C - 0x134 = 0x48.
        '''

        return self

    def xref_imm32(self, symbol: str, offset: int, destptr_offset: int = 0, dest_is_weak: bool = False):
        '''
        Create `imm32` at given offset in signature pointing at symbol.

        The most common instance of this is in jump tables in .rodata that point to immediate 32-bit addresses
        in .text sections.
        '''
        xref = UnresolvedXref
        xref._target_sym = symbol
        xref._offset = offset
        xref._destptr_offset = destptr_offset
        xref._destptr_is_weak = dest_is_weak
        self._unresolved_xrefs.append(xref)
        return self

    def const_op32_imm16(self, symbol: str, offset: int):
        const = UnresolvedConstOp32Imm16()
        const._target_sym = symbol
        const._offset = offset
        self._unresolved_consts.append(const)
        return self

    def const_op32_hi16(self, symbol: str, offset: int):
        const = UnresolvedConstOp32Hi16()
        const._target_sym = symbol
        const._offset = offset
        self._unresolved_consts.append(const)
        return self

    def const_op32_lo16(self, symbol: str, offset: int):
        const = UnresolvedConstOp32Lo16()
        const._target_sym = symbol
        const._offset = offset
        self._unresolved_consts.append(const)
        return self

    def const_imm32(self, symbol: str, offset: int):
        const = UnresolvedConstImm32()
        const._target_sym = symbol
        const._offset = offset
        self._unresolved_consts.append(const)
        return self
