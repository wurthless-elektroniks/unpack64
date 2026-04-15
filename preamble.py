"""
Preamble identification.
 
The "preamble" is the first game code to execute prior to the C runtime startup.
It clears BSS, sets up the stack pointer, then jumps to (or calls) the CRT entry point.

The two most common preambles are:
- libultra-type: Used on most games, starts with 0x3C 0x08 (i.e., `lui $t0,...`)
- nustd-type: Alternative standard boot stub, starts with 0x3C 0x1D

Nonstandard preambles are ones where the game deviates from the normal N64 game
startup pattern. This may be because the boot exe has been packed/compressed.

Some games use completely nonstandard preambles:
- Army Men - Sarge's Heroes and Sarge's Heroes 2: See sarge.py.
- ECW Hardcore Revolution / WWF Attitude / WWF War Zone: See ecwwwf.py.

Other interesting/frustrating finds:
- Excitebike 64 puts a completely useless `li $t0,0xBEEFDEAD` at its entry point.
  The code afterwards is a typical nustd-type preamble.

- Re-Volt looks like it's nustd, but it then sets up the TLB and then jumps
  to the CRT entry point in kuseg.

Note that a standard preamble doesn't mean the boot exe is unpacked or fully loaded
in RAM at startup. As an example, Rareware games use a standard preamble and even
call `osInitialize()`, but then they load more code segments before starting the idle thread.
"""

import logging
from signature import Signature,WILDCARD,SignatureBuilder
from bffi import BffiBuilder

logger = logging.getLogger(__name__)

class Preamble():
    '''
    Contains Preamble information.
    '''
    def __init__(self,
                 preamble_type,
                 initial_stack_pointer,
                 crt_entry_point,
                 size,
                 deep_trace_required = False):
        self._type = preamble_type
        self._initial_stack_pointer = initial_stack_pointer
        self._crt_entry_point       = crt_entry_point
        self._bss_sections          = []
        self._size = size
        self._deep_trace_required   = deep_trace_required

    def size(self):
        return self._size

    def type(self):
        '''
        Name of preamble type.
        '''
        return self._type
    
    def bss_sections(self):
        '''
        Return .bss sections. Each will be a tuple of `(start_addr,end_addr)`.

        It is possible for this to return an empty list, especially if the preamble
        will be followed by code that unpacks the boot executable somewhere.
        '''
        return self._bss_sections

    def add_bss(self, start_addr: int, end_addr: int):
        '''
        Add new .bss section.
        '''
        self._bss_sections.append( (start_addr,end_addr) )

    def initial_stack_pointer(self):
        '''
        Return initial value for `$sp` register.
        '''
        return self._initial_stack_pointer

    def crt_entry_point(self):
        '''
        Get address of CRT entry point.
        '''
        return self._crt_entry_point

    def deep_trace_required(self):
        '''
        Flag that indicates that a deep code inspection must be performed.
        Typically encountered when we find a packed bootexe.
        '''
        return self._deep_trace_required

def _try_ident_preamble(ident_fcns, bootexe, ipc) -> Preamble | None:
    for fcn in ident_fcns:
        pre = fcn(bootexe, ipc)
        if pre is not None:
            return pre
    return None

# ------------------------------------------------------------------------------------------
#
# Standard libultra prologue
#
# ------------------------------------------------------------------------------------------

# Standard libultra preamble, usually loaded at 0x80000400
LIBULTRA_BSS_PREAMBLE_TYPE_1 = SignatureBuilder() \
    .pattern([
    0x3C, 0x08, 0x80,     WILDCARD,   # +$00 lui t0,0x80..
    0x25, 0x08, WILDCARD, WILDCARD,   # +$04 addiu t0,t0,#### = li t0,bss_start_address
    0x3C, 0x09, WILDCARD, WILDCARD,   # +$08 lui t1,####
    0x25, 0x29, WILDCARD, WILDCARD,   # +$0C addiu t1,t1,#### = li t1,bss_size_in_bytes
    0xAD, 0x00, 0x00, 0x00,           # +$10 sw zero,0(t0)
    0xAD, 0x00, 0x00, 0x04,           # +$14 sw zero,4(t0)
    0x21, 0x08, 0x00, 0x08,           # +$18 addiu t0,t0,0x08
    0x21, 0x29, 0xFF, 0xF8,           # +$1C addiu t1,t1,-0x08
    0x15, 0x20, 0xFF, 0xFB,           # +$20 loop while t1 not zero
    0x00, 0x00, 0x00, 0x00,           # +$24 nop
    0x3C, 0x0A, WILDCARD, WILDCARD,   # +$28 lui t2,XXXX
    0x25, 0x4A, WILDCARD, WILDCARD,   # +$2C addiu t2,t2,0x450
    0x3C, 0x1D, WILDCARD, WILDCARD,   # +$30 lui sp,XXXX
    0x01, 0x40, 0x00, 0x08,           # +$34 jr t2 --> CRT startup
    0x27, 0xBD, WILDCARD, WILDCARD,   # +$38 _addiu sp,sp,XXXX
    ]) \
    .modify_andmask(0x04, [0xEF]) \
    .modify_andmask(0x0C, [0xEF]) \
    .modify_andmask(0x20, [0xF7]) \
    .modify_andmask(0x38, [0xEF]) \
    .xref_op32_hi16("bss_start_address", 0x00) \
    .xref_op32_lo16("bss_start_address", 0x04) \
    .const_op32_hi16("bss_size_in_bytes", 0x08) \
    .const_op32_lo16("bss_size_in_bytes", 0x0C) \
    .xref_op32_hi16("crt_startup", 0x28) \
    .xref_op32_lo16("crt_startup", 0x2C) \
    .xref_op32_hi16("initial_sp", 0x30) \
    .xref_op32_lo16("initial_sp", 0x38) \
    .size(0x3C) \
    .build()

def _ident_libultra_type1(bootexe: bytearray, ipc: int) -> Preamble | None:
    if LIBULTRA_BSS_PREAMBLE_TYPE_1.compare(bootexe) is False:
        return None

    xrefs  = LIBULTRA_BSS_PREAMBLE_TYPE_1.xrefs(ipc, bootexe)
    consts = LIBULTRA_BSS_PREAMBLE_TYPE_1.consts(ipc, bootexe)
    bss_start_address      = xrefs["bss_start_address"].get_address()
    crt_entry_point        = xrefs["crt_startup"].get_address()
    initial_stack_pointer  = xrefs["initial_sp"].get_address()
    bss_size_in_bytes      = consts["bss_size_in_bytes"].get_value()
    bss_end_address = bss_start_address + bss_size_in_bytes

    preamble = Preamble("libultra standard, type 1",
                    initial_stack_pointer,
                    crt_entry_point,
                    0x3C)
    preamble.add_bss(bss_start_address, bss_end_address)
    return preamble

# "type 2" has a small .bss space.
# this came from Banjo-Kazooie, which loads and decompresses its main
# code segments.
LIBULTRA_BSS_PREAMBLE_TYPE_2 = SignatureBuilder() \
    .pattern([
        0x3C, 0x08, 0x80,     WILDCARD,   # +$00 lui t0,0x80..
        0x25, 0x08, WILDCARD, WILDCARD,   # +$04 addiu t0,t0,#### = li t0,bss_start_address
        0x24, 0x09, WILDCARD, WILDCARD,   # +$08 li t1,####
        0x21, 0x29, 0xFF, 0xF8,           # +$0C addiu t1,t1,-0x08
        0xAD, 0x00, 0x00, 0x00,           # +$10 sw zero,0(t0)
        0xAD, 0x00, 0x00, 0x04,           # +$14 sw zero,4(t0)
        0x15, 0x20, 0xFF, 0xFC,           # +$18 loop while t1 not zero
        0x21, 0x08, 0x00, 0x08,           # +$1C addiu t0,t0,0x08
        0x3C, 0x0A, WILDCARD, WILDCARD,   # +$20 lui t2,XXXX
        0x3C, 0x1D, WILDCARD, WILDCARD,   # +$24 lui sp,XXXX
        0x25, 0x4A, WILDCARD, WILDCARD,   # +$28 addiu t2,t2,XX
        0x01, 0x40, 0x00, 0x08,           # +$2C jr t2 --> CRT startup
        0x27, 0xBD, WILDCARD, WILDCARD,   # +$30 _addiu sp,sp,XXXX
    ]) \
    .modify_andmask(0x18, [0xF7]) \
    .xref_op32_hi16("bss_start_address", 0x00) \
    .xref_op32_lo16("bss_start_address", 0x04) \
    .xref_op32_hi16("crt_startup", 0x20) \
    .xref_op32_lo16("crt_startup", 0x28) \
    .xref_op32_hi16("initial_sp", 0x24) \
    .xref_op32_lo16("initial_sp", 0x30) \
    .const_op32_imm16("bss_size_in_bytes", 0x08) \
    .size(0x34) \
    .build()

def _ident_libultra_type2(bootexe: bytearray, ipc: int) -> Preamble | None:
    if LIBULTRA_BSS_PREAMBLE_TYPE_2.compare(bootexe) is False:
        return None

    xrefs  = LIBULTRA_BSS_PREAMBLE_TYPE_2.xrefs(ipc, bootexe)
    consts = LIBULTRA_BSS_PREAMBLE_TYPE_2.consts(ipc, bootexe)
    bss_start_address     = xrefs["bss_start_address"].get_address()
    bss_size_in_bytes     = consts["bss_size_in_bytes"].get_value()
    crt_entry_point       = xrefs["crt_startup"].get_address()
    initial_stack_pointer  = xrefs["initial_sp"].get_address()
    bss_end_address = bss_start_address + bss_size_in_bytes

    preamble = Preamble("libultra standard, type 2",
                        initial_stack_pointer,
                        crt_entry_point,
                        0x34)
    preamble.add_bss(bss_start_address, bss_end_address)
    return preamble

# "type 3", used on earlier games
LIBULTRA_BSS_PREAMBLE_TYPE_3 = SignatureBuilder() \
    .pattern([
        0x3C, 0x08, 0x80,     WILDCARD,   # +$00 lui t0,0x80..
        0x3C, 0x09, WILDCARD, WILDCARD,   # +$04 li t1,####
        0x25, 0x08, WILDCARD, WILDCARD,   # +$08 addiu t0,t0,#### = li t0,bss_start_address
        0x35, 0x29, WILDCARD, WILDCARD,   # +$0C ori t1,t1,#### 
        0x21, 0x29, 0xFF, 0xF8,           # +$10 addi t1,t1,-0x08
        0xAD, 0x00, 0x00, 0x00,           # +$14 sw zero,0(t0)
        0xAD, 0x00, 0x00, 0x04,           # +$18 sw zero,4(t0)
        0x15, 0x20, 0xFF, 0xFC,           # +$1C loop while t1 not zero
        0x21, 0x08, 0x00, 0x08,           # +$20 addiu t0,t0,0x08
        0x3C, 0x0A, WILDCARD, WILDCARD,   # +$24 lui t2,XXXX
        0x3C, 0x1D, WILDCARD, WILDCARD,   # +$28 lui sp,XXXX
        0x25, 0x4A, WILDCARD, WILDCARD,   # +$2C addiu t2,t2,XX
        0x01, 0x40, 0x00, 0x08,           # +$30 jr t2 --> CRT startup
        0x27, 0xBD, WILDCARD, WILDCARD,   # +$34 _addiu sp,sp,XXXX
    ]) \
    .modify_andmask(0x08, [0xEF]) \
    .modify_andmask(0x0C, [0xEF]) \
    .modify_andmask(0x1C, [0xF7]) \
    .size(0x38) \
    .xref_op32_hi16("bss_start_address", 0x00) \
    .xref_op32_lo16("bss_start_address", 0x08) \
    .const_op32_hi16("bss_size_in_bytes", 0x04) \
    .const_op32_lo16("bss_size_in_bytes", 0x0C) \
    .xref_op32_hi16("crt_startup", 0x24) \
    .xref_op32_lo16("crt_startup", 0x2C) \
    .xref_op32_hi16("initial_sp", 0x28) \
    .xref_op32_lo16("initial_sp", 0x34) \
    .build()

def _ident_libultra_type3(bootexe: bytearray, ipc: int) -> Preamble | None:
    if LIBULTRA_BSS_PREAMBLE_TYPE_3.compare(bootexe) is False:
        return None

    xrefs  = LIBULTRA_BSS_PREAMBLE_TYPE_3.xrefs(ipc, bootexe)
    consts = LIBULTRA_BSS_PREAMBLE_TYPE_3.consts(ipc, bootexe)
    bss_start_address     = xrefs["bss_start_address"].get_address()
    bss_size_in_bytes     = consts["bss_size_in_bytes"].get_value()
    crt_entry_point       = xrefs["crt_startup"].get_address()
    initial_stack_pointer = xrefs["initial_sp"].get_address()
    bss_end_address = bss_start_address + bss_size_in_bytes

    preamble = Preamble("libultra standard, type 3",
                    initial_stack_pointer,
                    crt_entry_point,
                    0x38)
    preamble.add_bss(bss_start_address, bss_end_address)
    return preamble

# "type 4", with very small .bss segment, seen on 1080 Snowboarding (PAL)
LIBULTRA_BSS_PREAMBLE_TYPE_4 = SignatureBuilder() \
    .pattern([
        0x3c, 0x08, 0x80, WILDCARD,
        0x25, 0x08, WILDCARD, WILDCARD,
        0x34, 0x09, WILDCARD, WILDCARD,
        0x21, 0x29, 0xff, 0xf8,
        0xad, 0x00, 0x00, 0x00,
        0xad, 0x00, 0x00, 0x04,
        0x15, 0x20, 0xff, 0xfc,
        0x21, 0x08, 0x00, 0x08,
        0x3c, 0x0a, 0x80, WILDCARD,
        0x3c, 0x1d, 0x80, WILDCARD,
        0x25, 0x4a, WILDCARD, WILDCARD,
        0x01, 0x40, 0x00, 0x08,
        0x27, 0xbd, WILDCARD, WILDCARD
    ]) \
    .size(0x34) \
    .xref_op32_hi16("bss_start_address", 0x00) \
    .xref_op32_lo16("bss_start_address", 0x04) \
    .const_op32_imm16("bss_size_in_bytes", 0x08) \
    .xref_op32_hi16("crt_startup", 0x20) \
    .xref_op32_lo16("crt_startup", 0x28) \
    .xref_op32_hi16("initial_sp", 0x24) \
    .xref_op32_lo16("initial_sp", 0x30) \
    .build()

def _ident_libultra_type4(bootexe: bytearray, ipc: int) -> Preamble | None:
    if LIBULTRA_BSS_PREAMBLE_TYPE_4.compare(bootexe) is False:
        return None

    xrefs  = LIBULTRA_BSS_PREAMBLE_TYPE_4.xrefs(ipc, bootexe)
    consts = LIBULTRA_BSS_PREAMBLE_TYPE_4.consts(ipc, bootexe)
    bss_start_address     = xrefs["bss_start_address"].get_address()
    bss_size_in_bytes     = consts["bss_size_in_bytes"].get_value()
    crt_entry_point       = xrefs["crt_startup"].get_address()
    initial_stack_pointer = xrefs["initial_sp"].get_address()
    bss_end_address = bss_start_address + bss_size_in_bytes

    preamble = Preamble("libultra standard, type 4",
                    initial_stack_pointer,
                    crt_entry_point,
                    0x34)
    preamble.add_bss(bss_start_address, bss_end_address)
    return preamble

# "type 5". does not abuse the delayslot to set up $sp for some reason.
# seen on 64 Hanafuda (J).
# Tsumi to Batsu (J) uses bgtz in the bss clear loop.
LIBULTRA_BSS_PREAMBLE_TYPE_5 = SignatureBuilder() \
    .pattern([
    0x3C, 0x08, 0x80,     WILDCARD,   # +$00 lui t0,0x80..
    0x25, 0x08, WILDCARD, WILDCARD,   # +$04 addiu t0,t0,#### = li t0,bss_start_address
    0x3C, 0x09, WILDCARD, WILDCARD,   # +$08 lui t1,####
    0x25, 0x29, WILDCARD, WILDCARD,   # +$0C addiu t1,t1,#### = li t1,bss_size_in_bytes
    0xAD, 0x00, 0x00, 0x00,           # +$10 sw zero,0(t0)
    0xAD, 0x00, 0x00, 0x04,           # +$14 sw zero,4(t0)
    0x21, 0x08, 0x00, 0x08,           # +$18 addiu t0,t0,0x08
    0x21, 0x29, 0xFF, 0xF8,           # +$1C addiu t1,t1,-0x08
    0x15, 0x20, 0xFF, 0xFB,           # +$20 loop while t1 not zero
    0x00, 0x00, 0x00, 0x00,           # +$24 nop
    0x3C, 0x0A, WILDCARD, WILDCARD,   # +$28 lui t2,XXXX
    0x25, 0x4A, WILDCARD, WILDCARD,   # +$2C addiu t2,t2,0x450
    0x3C, 0x1D, WILDCARD, WILDCARD,   # +$30 lui sp,XXXX
    0x27, 0xBD, WILDCARD, WILDCARD,   # +$34 _addiu sp,sp,XXXX
    0x01, 0x40, 0x00, 0x08,           # +$38 jr t2 --> CRT startup
    0x00, 0x00, 0x00, 0x00,           # +$3C nop
    ]) \
    .modify_andmask(0x04, [0xEF]) \
    .modify_andmask(0x0C, [0xEF]) \
    .modify_andmask(0x20, [0xF7]) \
    .xref_op32_hi16("bss_start_address", 0x00) \
    .xref_op32_lo16("bss_start_address", 0x04) \
    .const_op32_hi16("bss_size_in_bytes", 0x08) \
    .const_op32_lo16("bss_size_in_bytes", 0x0C) \
    .xref_op32_hi16("crt_startup", 0x28) \
    .xref_op32_lo16("crt_startup", 0x2C) \
    .xref_op32_hi16("initial_sp", 0x30) \
    .xref_op32_lo16("initial_sp", 0x34) \
    .size(0x40) \
    .build()

def _ident_libultra_type5(bootexe: bytearray, ipc: int) -> Preamble | None:
    if LIBULTRA_BSS_PREAMBLE_TYPE_5.compare(bootexe) is False:
        return None

    xrefs  = LIBULTRA_BSS_PREAMBLE_TYPE_5.xrefs(ipc, bootexe)
    consts = LIBULTRA_BSS_PREAMBLE_TYPE_5.consts(ipc, bootexe)
    bss_start_address      = xrefs["bss_start_address"].get_address()
    crt_entry_point        = xrefs["crt_startup"].get_address()
    initial_stack_pointer  = xrefs["initial_sp"].get_address()
    bss_size_in_bytes      = consts["bss_size_in_bytes"].get_value()
    bss_end_address = bss_start_address + bss_size_in_bytes

    preamble = Preamble("libultra standard, type 5",
                    initial_stack_pointer,
                    crt_entry_point,
                    0x40)
    preamble.add_bss(bss_start_address, bss_end_address)
    return preamble

# "type 6". inexplicably reorders instructions. found on Paper Mario (US)
LIBULTRA_BSS_PREAMBLE_TYPE_6 = SignatureBuilder() \
    .pattern([
    0x3C, 0x08, 0x80,     WILDCARD,   # +$00 lui t0,0x80..
    0x25, 0x08, WILDCARD, WILDCARD,   # +$04 addiu t0,t0,#### = li t0,bss_start_address
    0x3C, 0x09, WILDCARD, WILDCARD,   # +$08 lui t1,####
    0x25, 0x29, WILDCARD, WILDCARD,   # +$0C addiu t1,t1,#### = li t1,bss_size_in_bytes
    0xAD, 0x00, 0x00, 0x00,           # +$10 sw zero,0(t0)
    0xAD, 0x00, 0x00, 0x04,           # +$14 sw zero,4(t0)
    0x21, 0x08, 0x00, 0x08,           # +$18 addiu t0,t0,0x08
    0x21, 0x29, 0xFF, 0xF8,           # +$1C addiu t1,t1,-0x08
    0x15, 0x20, 0xFF, 0xFB,           # +$20 loop while t1 not zero
    0x00, 0x00, 0x00, 0x00,           # +$24 nop
    0x3C, 0x1D, WILDCARD, WILDCARD,   # +$28 lui sp,XXXX
    0x27, 0xBD, WILDCARD, WILDCARD,   # +$2C _addiu sp,sp,XXXX
    0x3C, 0x0A, WILDCARD, WILDCARD,   # +$30 lui t2,XXXX
    0x25, 0x4A, WILDCARD, WILDCARD,   # +$34 addiu t2,t2,0x450
    0x01, 0x40, 0x00, 0x08,           # +$38 jr t2 --> CRT startup
    0x00, 0x00, 0x00, 0x00,           # +$3C nop
    ]) \
    .modify_andmask(0x04, [0xEF]) \
    .modify_andmask(0x0C, [0xEF]) \
    .modify_andmask(0x20, [0xF7]) \
    .xref_op32_hi16("bss_start_address", 0x00) \
    .xref_op32_lo16("bss_start_address", 0x04) \
    .const_op32_hi16("bss_size_in_bytes", 0x08) \
    .const_op32_lo16("bss_size_in_bytes", 0x0C) \
    .xref_op32_hi16("initial_sp", 0x28) \
    .xref_op32_lo16("initial_sp", 0x2C) \
    .xref_op32_hi16("crt_startup", 0x30) \
    .xref_op32_lo16("crt_startup", 0x34) \
    .size(0x40) \
    .build()

def _ident_libultra_type6(bootexe: bytearray, ipc: int) -> Preamble | None:
    if LIBULTRA_BSS_PREAMBLE_TYPE_6.compare(bootexe) is False:
        return None

    xrefs  = LIBULTRA_BSS_PREAMBLE_TYPE_6.xrefs(ipc, bootexe)
    consts = LIBULTRA_BSS_PREAMBLE_TYPE_6.consts(ipc, bootexe)
    bss_start_address      = xrefs["bss_start_address"].get_address()
    crt_entry_point        = xrefs["crt_startup"].get_address()
    initial_stack_pointer  = xrefs["initial_sp"].get_address()
    bss_size_in_bytes      = consts["bss_size_in_bytes"].get_value()
    bss_end_address = bss_start_address + bss_size_in_bytes

    preamble = Preamble("libultra standard, type 6",
                    initial_stack_pointer,
                    crt_entry_point,
                    0x40)
    preamble.add_bss(bss_start_address, bss_end_address)
    return preamble

# "type 7": variant on type3, seen on Daikatana
LIBULTRA_BSS_PREAMBLE_TYPE_7 = SignatureBuilder() \
    .pattern([
        0x3C, 0x08, 0x80,     WILDCARD,   # +$00 lui t0,0x80..
        0x3C, 0x09, WILDCARD, WILDCARD,   # +$04 li t1,####
        0x25, 0x08, WILDCARD, WILDCARD,   # +$08 addiu t0,t0,#### = li t0,bss_start_address
        0x35, 0x29, WILDCARD, WILDCARD,   # +$0C ori t1,t1,####
        0xAD, 0x00, 0x00, 0x00,           # +$10 sw zero,0(t0)
        0xAD, 0x00, 0x00, 0x04,           # +$14 sw zero,4(t0)
        0x21, 0x08, 0x00, 0x08,           # +$18 addiu t0,t0,0x08
        0x21, 0x29, 0xFF, 0xF8,           # +$1C addi t1,t1,-0x08
        0x15, 0x20, 0xFF, 0xFB,           # +$20 loop while t1 not zero
        0x00, 0x00, 0x00, 0x00,           # +$24 nop
        0x3C, 0x0A, WILDCARD, WILDCARD,   # +$28 lui t2,XXXX
        0x3C, 0x1D, WILDCARD, WILDCARD,   # +$2C lui sp,XXXX
        0x25, 0x4A, WILDCARD, WILDCARD,   # +$30 addiu t2,t2,XX
        0x27, 0xBD, WILDCARD, WILDCARD,   # +$34 _addiu sp,sp,XXXX
        0x01, 0x40, 0x00, 0x08,           # +$38 jr t2 --> CRT startup
        0x00, 0x00, 0x00, 0x00,           # +$3C nop
    ]) \
    .modify_andmask(0x08, [0xEF]) \
    .modify_andmask(0x0C, [0xEF]) \
    .modify_andmask(0x20, [0xF7]) \
    .size(0x40) \
    .xref_op32_hi16("bss_start_address", 0x00) \
    .xref_op32_lo16("bss_start_address", 0x08) \
    .const_op32_hi16("bss_size_in_bytes", 0x04) \
    .const_op32_lo16("bss_size_in_bytes", 0x0C) \
    .xref_op32_hi16("crt_startup", 0x28) \
    .xref_op32_lo16("crt_startup", 0x30) \
    .xref_op32_hi16("initial_sp", 0x2C) \
    .xref_op32_lo16("initial_sp", 0x34) \
    .build()

def _ident_libultra_type7(bootexe: bytearray, ipc: int) -> Preamble | None:
    if LIBULTRA_BSS_PREAMBLE_TYPE_7.compare(bootexe) is False:
        return None

    xrefs  = LIBULTRA_BSS_PREAMBLE_TYPE_7.xrefs(ipc, bootexe)
    consts = LIBULTRA_BSS_PREAMBLE_TYPE_7.consts(ipc, bootexe)
    bss_start_address     = xrefs["bss_start_address"].get_address()
    bss_size_in_bytes     = consts["bss_size_in_bytes"].get_value()
    crt_entry_point       = xrefs["crt_startup"].get_address()
    initial_stack_pointer = xrefs["initial_sp"].get_address()
    bss_end_address = bss_start_address + bss_size_in_bytes

    preamble = Preamble("libultra standard, type 7",
                    initial_stack_pointer,
                    crt_entry_point,
                    0x40)
    preamble.add_bss(bss_start_address, bss_end_address)
    return preamble

def _ident_libultra(bootexe: bytearray, ipc: int) -> Preamble | None:
    return _try_ident_preamble([
        _ident_libultra_type1,
        _ident_libultra_type2,
        _ident_libultra_type3,
        _ident_libultra_type4,
        _ident_libultra_type5,
        _ident_libultra_type6,
        _ident_libultra_type7,
    ], bootexe, ipc)

# ------------------------------------------------------------------------------------------
#
# Alternate libultra prologue (probably generated by libnustd)
#
# ------------------------------------------------------------------------------------------

# type 1 
# Seen on Toy Story 2, Rocket - Robot on Wheels, probably others
ALT_LIBULTRA_PREAMBLE_TYPE_1 = SignatureBuilder() \
    .bits(bytearray([
        0x3C, 0x1D, 0x80, 0x00, # +$00 lui sp,0x80xx    - set initial stack pointer, typically to 0x803FFFF0 at end of RDRAM
        0x27, 0xBD, 0x00, 0x00, # +$04 ori sp,sp,#### (Battletanx and others use addiu $sp,$sp,...)
        0x3C, 0x08, 0x80, 0x00, # +$08 lui t0,0x80xx
        0x25, 0x08, 0x00, 0x00, # +$0C addiu t0,t0,#### - BSS start position
        0x3C, 0x09, 0x80, 0x00, # +$10 lui t1,0x80xx
        0x25, 0x29, 0x00, 0x00, # +$14 addiu t0,t0,#### - BSS end position
        0x11, 0x09, 0x00, 0x05, # +$18 beq t0,t1,... - do not initialize BSS if start/end pos are the same (why? they never should be...)
        0x00, 0x00, 0x00, 0x00, # +$1C nop
        0x25, 0x08, 0x00, 0x04, # +$20 addiu t0,t0,4
        0x01, 0x09, 0x08, 0x2b, # +$24 sltu at,t0,t1
        0x14, 0x20, 0xff, 0xfd, # +$28 bne at,zero,...  - clear bss 4 bytes at a time
        0xAD, 0x00, 0xFF, 0xFC, # +$2C sw zero,-0x04(t0)
        0x08, 0x00, 0x00, 0x00, # +$30 jal crt_entry (0x08 catches jal and j opcodes)
        0x00, 0x00, 0x00, 0x00, # +$34 nop
    ])) \
    .andmask(bytearray([
        0xFF, 0xFF, 0xFF, 0x00, # +$00
        0xEF, 0xFF, 0x00, 0x00, # +$04
        0xFF, 0xFF, 0xFF, 0x00, # +$08
        0xFF, 0xFF, 0x00, 0x00, # +$0C
        0xFF, 0xFF, 0xFF, 0x00, # +$10
        0xFF, 0xFF, 0x00, 0x00, # +$14
        0xFF, 0xFF, 0xFF, 0xFF, # +$18
        0xFF, 0xFF, 0xFF, 0xFF, # +$1C
        0xFF, 0xFF, 0xFF, 0xFF, # +$20
        0xFC, 0x00, 0x00, 0x3F, # +$24 - catch all sltu ops
        0xFC, 0x0F, 0xFF, 0xFF, # +$28 - catch all register possibilities
        0xFF, 0xFF, 0xFF, 0xFF, # +$2C
        0xFB, 0x00, 0x00, 0x00, # +$30 - catches jal and j opcodes
        0xFF, 0xFF, 0xFF, 0xFF, # +$34
    ])) \
    .size(0x38) \
    .xref_op32_hi16("initial_sp", 0x00) \
    .xref_op32_lo16("initial_sp", 0x04) \
    .xref_op32_hi16("bss_start_address", 0x08) \
    .xref_op32_lo16("bss_start_address", 0x0C) \
    .xref_op32_hi16("bss_end_address", 0x10) \
    .xref_op32_lo16("bss_end_address", 0x14) \
    .xref_j_imm26("crt_entry", 0x30) \
    .build()

def _ident_alt_libultra_type_1(bootexe: bytearray, ipc: int) -> Preamble | None:
    if ALT_LIBULTRA_PREAMBLE_TYPE_1.compare(bootexe) is False:
        return None

    xrefs = ALT_LIBULTRA_PREAMBLE_TYPE_1.xrefs(ipc, bootexe)

    crt_entry_point        = xrefs["crt_entry"].get_address()
    initial_stack_pointer  = xrefs["initial_sp"].get_address()

    preamble = Preamble("libultra alt. (nustd?), type 1",
                    initial_stack_pointer,
                    crt_entry_point,
                    0x38)

    preamble.add_bss(xrefs["bss_start_address"].get_address(), xrefs["bss_end_address"].get_address())
    return preamble

# This seems to be a nustd-ish bootstub with multiple BSS sections, or something like it.
# Found this one on South Park Racing (U)
# Gotchas:
# - Extreme-G uses same preamble but does NOT initialize its .bss sections here.
ALT_LIBULTRA_PREAMBLE_TYPE_2 = SignatureBuilder() \
    .bits(bytearray([
        0x3C, 0x1D, 0x80, 0x00, # +$00 lui sp,0x80xx    - set initial stack pointer, typically to 0x803FFFF0 at end of RDRAM
        0x27, 0xBD, 0x00, 0x00, # +$04 ori sp,sp,#### / addiu sp,sp,####
        0x3C, 0x08, 0x80, 0x00, # +$08 lui t0,0x80xx
        0x25, 0x08, 0x00, 0x00, # +$0C addiu t0,t0,#### - BSS start position
        0x3C, 0x09, 0x80, 0x00, # +$10 lui t1,0x80xx
        0x25, 0x29, 0x00, 0x00, # +$14 addiu t0,t0,#### - BSS end position
        0x11, 0x09, 0x00, 0x05, # +$18 beq t0,t1,... - do not initialize BSS if start/end pos are the same (why? they never should be...)
        0x00, 0x00, 0x00, 0x00, # +$1C nop
        0x25, 0x08, 0x00, 0x04, # +$20 addiu t0,t0,4
        0x01, 0x09, 0x08, 0x2b, # +$24 sltu at,t0,t1
        0x14, 0x20, 0xff, 0xfd, # +$28 bne at,zero,...  - clear bss 4 bytes at a time
        0xAD, 0x00, 0xFF, 0xFC, # +$2C sw zero,-0x04(t0)

        0x3C, 0x08, 0x80, 0x00, # +$30 lui $t0,0x80xx
        0x25, 0x08, 0x00, 0x00, # +$34 addiu $t0,$t0,#### - ??
        0x3C, 0x09, 0x80, 0x00, # +$38 lui t1,0x80xx
        0x25, 0x29, 0x00, 0x00, # +$3C addiu t0,t0,#### - ??????
        0x11, 0x09, 0x00, 0x05, # +$40 beq t0,t1,... - do not initialize BSS if start/end pos are the same (why? they never should be...)
        0x00, 0x00, 0x00, 0x00, # +$44 nop
        0x25, 0x08, 0x00, 0x04, # +$48 addiu t0,t0,4
        0x01, 0x09, 0x08, 0x2b, # +$4C sltu at,t0,t1
        0x14, 0x20, 0xff, 0xfd, # +$50 bne at,zero,...  - clear bss 4 bytes at a time
        0xAD, 0x00, 0xFF, 0xFC, # +$54 sw zero,-0x04(t0)
        0x08, 0x00, 0x00, 0x00, # +$58 jal crt_entry (also catches j opcodes)
        0x00, 0x00, 0x00, 0x00, # +$5C nop
    ])) \
    .andmask(bytearray([
        0xFF, 0xFF, 0xFF, 0x00, # +$00
        0xEF, 0xFF, 0x00, 0x00, # +$04
        0xFF, 0xFF, 0xFF, 0x00, # +$08
        0xFF, 0xFF, 0x00, 0x00, # +$0C
        0xFF, 0xFF, 0xFF, 0x00, # +$10
        0xFF, 0xFF, 0x00, 0x00, # +$14
        0xFF, 0xFF, 0xFF, 0xFF, # +$18
        0xFF, 0xFF, 0xFF, 0xFF, # +$1C
        0xFF, 0xFF, 0xFF, 0xFF, # +$20
        0xFF, 0xFF, 0xFF, 0xFF, # +$24
        0xFF, 0xFF, 0xFF, 0xFF, # +$28
        0xFF, 0xFF, 0xFF, 0xFF, # +$2C

        0xFF, 0xFF, 0xFF, 0x00, # +$30
        0xFF, 0xFF, 0x00, 0x00, # +$34
        0xFF, 0xFF, 0xFF, 0x00, # +$38
        0xFF, 0xFF, 0x00, 0x00, # +$3C
        0xFF, 0xFF, 0xFF, 0xFF, # +$40
        0xFF, 0xFF, 0xFF, 0xFF, # +$44
        0xFF, 0xFF, 0xFF, 0xFF, # +$48
        0xFF, 0xFF, 0xFF, 0xFF, # +$4C
        0xFF, 0xFF, 0xFF, 0xFF, # +$50
        0xFF, 0xFF, 0xFF, 0xFF, # +$54
        0xFB, 0x00, 0x00, 0x00, # +$58
        0xFF, 0xFF, 0xFF, 0xFF, # +$5C
    ])) \
    .size(0x60) \
    .xref_op32_hi16("initial_sp", 0x00) \
    .xref_op32_lo16("initial_sp", 0x04) \
    .xref_op32_hi16("bss_start_address", 0x08) \
    .xref_op32_lo16("bss_start_address", 0x0C) \
    .xref_op32_hi16("bss_end_address", 0x10) \
    .xref_op32_lo16("bss_end_address", 0x14) \
    .xref_op32_hi16("bss2_start_address", 0x30) \
    .xref_op32_lo16("bss2_start_address", 0x34) \
    .xref_op32_hi16("bss2_end_address", 0x38) \
    .xref_op32_lo16("bss2_end_address", 0x3C) \
    .xref_j_imm26("crt_entry", 0x58) \
    .build()

def _ident_alt_libultra_type_2(bootexe: bytearray, ipc: int) -> Preamble | None:
    if ALT_LIBULTRA_PREAMBLE_TYPE_2.compare(bootexe) is False:
        return None

    xrefs = ALT_LIBULTRA_PREAMBLE_TYPE_2.xrefs(ipc, bootexe)

    crt_entry_point        = xrefs["crt_entry"].get_address()
    initial_stack_pointer  = xrefs["initial_sp"].get_address()

    preamble = Preamble("libultra alt. (nustd?), type 2",
                    initial_stack_pointer,
                    crt_entry_point,
                    0x68)

    preamble.add_bss(xrefs["bss_start_address"].get_address(), xrefs["bss_end_address"].get_address())
    preamble.add_bss(xrefs["bss2_end_address"].get_address(),  xrefs["bss2_end_address"].get_address())
    return preamble

# Much more minimalist one, this one from Vigilante 8 (U)
ALT_LIBULTRA_PREAMBLE_TYPE_3 = SignatureBuilder() \
    .bits([
        0x3C, 0x1D, 0x80, 0x00, # +$00 lui sp,0x80xx    - set initial stack pointer, typically to 0x803FFFF0 at end of RDRAM
        0x27, 0xBD, 0x00, 0x00, # +$04 ori sp,sp,#### / addiu sp,sp,####
        0x3c, 0x02, 0x80, 0x00, # +$08 lui $v0,0x80xx
        0x24, 0x42, 0x00, 0x00, # +$0C addiu $v0,$v0,#### - BSS start address
        0x3c, 0x03, 0x80, 0x00, # +$10 lui $v1,0x80xx
        0x24, 0x63, 0x00, 0x00, # +$14 addiu $v1,$v1,#### - BSS end address
        0xAC, 0x40, 0x00, 0x00, # +$18 sw $zero,0($v0) - clear bytes
        0x00, 0x43, 0x08, 0x2B, # +$1C stlu $at,$v0,$v1
        0x14, 0x20, 0xFF, 0xFD, # +$20 bne $at,$zero,... - loop while v0 < v1
        0x24, 0x42, 0x00, 0x04, # +$24 addiu $v0,$v0,4
        0x08, 0x00, 0x00, 0x00, # +$28 j crt_entry
        0x00, 0x00, 0x00, 0x00  # +$2C nop
    ]) \
    .andmask([
        0xFF, 0xFF, 0xFF, 0x00, # +$00
        0xEF, 0xFF, 0x00, 0x00, # +$04
        0xFF, 0xFF, 0xFF, 0x00, # +$08
        0xFF, 0xFF, 0x00, 0x00, # +$0C
        0xFF, 0xFF, 0xFF, 0x00, # +$10
        0xFF, 0xFF, 0x00, 0x00, # +$14
        0xFF, 0xFF, 0xFF, 0xFF, # +$18
        0xFF, 0xFF, 0xFF, 0xFF, # +$1C
        0xFF, 0xFF, 0xFF, 0xFF, # +$20
        0xFF, 0xFF, 0xFF, 0xFF, # +$24
        0xFB, 0x00, 0x00, 0x00, # +$28
        0xFF, 0xFF, 0xFF, 0xFF  # +$2C
    ]) \
    .size(0x30) \
    .xref_op32_hi16("initial_sp", 0x00) \
    .xref_op32_lo16("initial_sp", 0x04) \
    .xref_op32_hi16("bss_start_address", 0x08) \
    .xref_op32_lo16("bss_start_address", 0x0C) \
    .xref_op32_hi16("bss_end_address", 0x10) \
    .xref_op32_lo16("bss_end_address", 0x14) \
    .xref_j_imm26("crt_entry", 0x28) \
    .build()

def _ident_alt_libultra_type_3(bootexe: bytearray, ipc: int) -> Preamble | None:
    if ALT_LIBULTRA_PREAMBLE_TYPE_3.compare(bootexe) is False:
        return None

    xrefs = ALT_LIBULTRA_PREAMBLE_TYPE_3.xrefs(ipc, bootexe)

    bss_start_address      = xrefs["bss_start_address"].get_address()
    bss_end_address        = xrefs["bss_end_address"].get_address()
    crt_entry_point        = xrefs["crt_entry"].get_address()
    initial_stack_pointer  = xrefs["initial_sp"].get_address()

    preamble = Preamble("libultra alt. (nustd?), type 3",
                    initial_stack_pointer,
                    crt_entry_point,
                    0x30)
    preamble.add_bss(bss_start_address, bss_end_address)
    return preamble

# same as type2, but initializes $gp to 0
# (Aidyn Chronicles does this)
ALT_LIBULTRA_PREAMBLE_TYPE_4 = SignatureBuilder() \
    .bits(bytearray([
        0x3C, 0x1D, 0x80, 0x00, # +$00 lui sp,0x80xx    - set initial stack pointer, typically to 0x803FFFF0 at end of RDRAM
        0x27, 0xBD, 0x00, 0x00, # +$04 ori sp,sp,#### / addiu sp,sp,####
        0x3C, 0x08, 0x80, 0x00, # +$08 lui t0,0x80xx
        0x25, 0x08, 0x00, 0x00, # +$0C addiu t0,t0,#### - BSS start position
        0x3C, 0x09, 0x80, 0x00, # +$10 lui t1,0x80xx
        0x25, 0x29, 0x00, 0x00, # +$14 addiu t0,t0,#### - BSS end position
        0x11, 0x09, 0x00, 0x05, # +$18 beq t0,t1,... - do not initialize BSS if start/end pos are the same (why? they never should be...)
        0x00, 0x00, 0x00, 0x00, # +$1C nop
        0x25, 0x08, 0x00, 0x04, # +$20 addiu t0,t0,4
        0x01, 0x09, 0x08, 0x2b, # +$24 sltu at,t0,t1
        0x14, 0x20, 0xff, 0xfd, # +$28 bne at,zero,...  - clear bss 4 bytes at a time
        0xAD, 0x00, 0xFF, 0xFC, # +$2C sw zero,-0x04(t0)

        0x3C, 0x08, 0x80, 0x00, # +$30 lui $t0,0x80xx
        0x25, 0x08, 0x00, 0x00, # +$34 addiu $t0,$t0,#### - ??
        0x3C, 0x09, 0x80, 0x00, # +$38 lui t1,0x80xx
        0x25, 0x29, 0x00, 0x00, # +$3C addiu t0,t0,#### - ??????
        0x11, 0x09, 0x00, 0x05, # +$40 beq t0,t1,... - do not initialize BSS if start/end pos are the same (why? they never should be...)
        0x00, 0x00, 0x00, 0x00, # +$44 nop
        0x25, 0x08, 0x00, 0x04, # +$48 addiu t0,t0,4
        0x01, 0x09, 0x08, 0x2b, # +$4C sltu at,t0,t1
        0x14, 0x20, 0xff, 0xfd, # +$50 bne at,zero,...  - clear bss 4 bytes at a time
        0xAD, 0x00, 0xFF, 0xFC, # +$54 sw zero,-0x04(t0)
        0x3C, 0x1C, 0x00, 0x00, # +$58 lui $gp,0x80xx
        0x27, 0x9C, 0x00, 0x00, # +$5C addiu $gp,$gp,#### - points somewhere within bss, probably some compiler enabled this optimization

        0x08, 0x00, 0x00, 0x00, # +$60 jal crt_entry (also catches j opcodes)
        0x00, 0x00, 0x00, 0x00, # +$64 nop
    ])) \
    .andmask(bytearray([
        0xFF, 0xFF, 0xFF, 0x00, # +$00
        0xEF, 0xFF, 0x00, 0x00, # +$04
        0xFF, 0xFF, 0xFF, 0x00, # +$08
        0xFF, 0xFF, 0x00, 0x00, # +$0C
        0xFF, 0xFF, 0xFF, 0x00, # +$10
        0xFF, 0xFF, 0x00, 0x00, # +$14
        0xFF, 0xFF, 0xFF, 0xFF, # +$18
        0xFF, 0xFF, 0xFF, 0xFF, # +$1C
        0xFF, 0xFF, 0xFF, 0xFF, # +$20
        0xFF, 0xFF, 0xFF, 0xFF, # +$24
        0xFF, 0xFF, 0xFF, 0xFF, # +$28
        0xFF, 0xFF, 0xFF, 0xFF, # +$2C

        0xFF, 0xFF, 0xFF, 0x00, # +$30
        0xFF, 0xFF, 0x00, 0x00, # +$34
        0xFF, 0xFF, 0xFF, 0x00, # +$38
        0xFF, 0xFF, 0x00, 0x00, # +$3C
        0xFF, 0xFF, 0xFF, 0xFF, # +$40
        0xFF, 0xFF, 0xFF, 0xFF, # +$44
        0xFF, 0xFF, 0xFF, 0xFF, # +$48
        0xFF, 0xFF, 0xFF, 0xFF, # +$4C
        0xFF, 0xFF, 0xFF, 0xFF, # +$50
        0xFF, 0xFF, 0xFF, 0xFF, # +$54
        0xFF, 0xFF, 0x00, 0x00, # +$58
        0xFF, 0xFF, 0x00, 0x00, # +$5C
        0xFB, 0x00, 0x00, 0x00, # +$60
        0xFF, 0xFF, 0xFF, 0xFF, # +$64
    ])) \
    .size(0x68) \
    .xref_op32_hi16("initial_sp", 0x00) \
    .xref_op32_lo16("initial_sp", 0x04) \
    .xref_op32_hi16("bss_start_address", 0x08) \
    .xref_op32_lo16("bss_start_address", 0x0C) \
    .xref_op32_hi16("bss_end_address", 0x10) \
    .xref_op32_lo16("bss_end_address", 0x14) \
    .xref_op32_hi16("bss2_start_address", 0x30) \
    .xref_op32_lo16("bss2_start_address", 0x34) \
    .xref_op32_hi16("bss2_end_address", 0x38) \
    .xref_op32_lo16("bss2_end_address", 0x3C) \
    .xref_op32_hi16("gp_address", 0x58) \
    .xref_op32_lo16("gp_address", 0x5C) \
    .xref_j_imm26("crt_entry", 0x60) \
    .build()

def _ident_alt_libultra_type_4(bootexe: bytearray, ipc: int) -> Preamble | None:
    if ALT_LIBULTRA_PREAMBLE_TYPE_4.compare(bootexe) is False:
        return None

    xrefs = ALT_LIBULTRA_PREAMBLE_TYPE_4.xrefs(ipc, bootexe)

    crt_entry_point        = xrefs["crt_entry"].get_address()
    initial_stack_pointer  = xrefs["initial_sp"].get_address()

    preamble = Preamble("libultra alt. (nustd?), type 4",
                    initial_stack_pointer,
                    crt_entry_point,
                    0x68)

    preamble.add_bss(xrefs["bss_start_address"].get_address(), xrefs["bss_end_address"].get_address())
    preamble.add_bss(xrefs["bss2_end_address"].get_address(),  xrefs["bss2_end_address"].get_address())
    return preamble

def _ident_nustd(bootexe: bytearray, ipc: int) -> Preamble | None:
    return _try_ident_preamble([
        _ident_alt_libultra_type_1,
        _ident_alt_libultra_type_2,
        _ident_alt_libultra_type_3,
        _ident_alt_libultra_type_4
    ], bootexe, ipc)

# ------------------------------------------------------------------------------------------
#
# Non-standard preambles
# Any of these mean bad news
#
# ------------------------------------------------------------------------------------------

# packed boot executables are easily identified by this signature.
# actual packer implementation varies between games.
#
# this is actually a variant on the standard libultra preamble but with no .bss section.
#
# found on:
# Star Wars - Shadows of the Empire
# Turok - Dinosaur Hunter
PACKED_BOOTEXE_PREAMBLE = SignatureBuilder() \
    .pattern([
        0x3c, 0x0a, 0x80, WILDCARD,
        0x3c, 0x1d, 0x80, WILDCARD,
        0x25, 0x4a, WILDCARD, WILDCARD,
        0x01, 0x40, 0x00, 0x08,
        0x27, 0xbd, WILDCARD, WILDCARD,
    ]) \
    .size(0x14) \
    .xref_op32_hi16("initial_sp", 0x04) \
    .xref_op32_lo16("initial_sp", 0x10) \
    .xref_op32_hi16("crt_entry", 0x00) \
    .xref_op32_lo16("crt_entry", 0x08) \
    .build()

def _identify_packed_bootexe(bootexe: bytearray, ipc: int) -> Preamble:
    if PACKED_BOOTEXE_PREAMBLE.compare(bootexe) is False:
        return None

    xrefs = PACKED_BOOTEXE_PREAMBLE.xrefs(ipc, bootexe)
    crt_entry_point        = xrefs["crt_entry"].get_address()
    initial_stack_pointer  = xrefs["initial_sp"].get_address()

    preamble = Preamble("libultra with no .bss, probably packed",
                    initial_stack_pointer,
                    crt_entry_point,
                    0x14,
                    deep_trace_required=True)
    return preamble

# nustd-style preamble with no .bss, indicates packed boot .exe
# seen on All-Star Baseball '99 and others
NUSTD_STYLE_PACKED_BOOTEXE_PREAMBLE = SignatureBuilder() \
    .bits(bytearray([
        0x3C, 0x1D, 0x80, 0x00,
        0x27, 0xBD, 0x00, 0x00, # same ori/addiu possibility as nustd type 1
        0x08, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ])) \
    .andmask(bytearray([
        0xFF, 0xFF, 0xFF, 0x00,
        0xEF, 0xFF, 0x00, 0x00,
        0xFB, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF
    ])) \
    .size(0x10) \
    .xref_op32_hi16("initial_sp", 0x00) \
    .xref_op32_lo16("initial_sp", 0x04) \
    .xref_j_imm26("crt_entry", 0x08) \
    .build()

def _identify_nustd_packed_bootexe(bootexe: bytearray, ipc: int) -> Preamble:
    if NUSTD_STYLE_PACKED_BOOTEXE_PREAMBLE.compare(bootexe) is False:
        return None

    xrefs = NUSTD_STYLE_PACKED_BOOTEXE_PREAMBLE.xrefs(ipc, bootexe)
    crt_entry_point        = xrefs["crt_entry"].get_address()
    initial_stack_pointer  = xrefs["initial_sp"].get_address()

    preamble = Preamble("nustd with no .bss, probably packed",
                    initial_stack_pointer,
                    crt_entry_point,
                    0x10,
                    deep_trace_required=True)
    return preamble

def _identify_nonstandard_preamble(bootexe: bytearray, ipc: int) -> Preamble:
    preamble = _try_ident_preamble([
        _identify_packed_bootexe,
        _identify_nustd_packed_bootexe
    ], bootexe, ipc)
    return preamble

# ------------------------------------------------------------------------------------------

def identify_preamble(bootexe: bytearray, ipc: int) -> Preamble | None:
    '''
    Identifies preamble. Return a Preamble on success, None if couldn't be identified.
    '''
    
    # Excitebike 64 tries to be cute with its first two opcodes,
    # so we detect this in advance and skip past it
    if bootexe[0:8] == bytes([0x3C, 0x08, 0xBE, 0xEF, 0x35, 0x08, 0xDE, 0xAD]):
        logger.debug("excitebike 64 programmers tried to be funny, skipping past useless instructions")
        return identify_preamble(bootexe[8:],ipc+8)

    if bootexe[0] == 0x3C and bootexe[1] == 0x08:
        logger.debug("preamble seems to be libultra-type")
        preamble = _ident_libultra(bootexe, ipc)
        if preamble is not None:
            return preamble

    if bootexe[0] == 0x3C and bootexe[1] == 0x1D:
        logger.debug("preamble seems to be nustd-type")
        preamble =  _ident_nustd(bootexe, ipc)
        if preamble is not None:
            return preamble

    return _identify_nonstandard_preamble(bootexe, ipc)


def preamble_extract_bss_sections_to_bffi(preamble: Preamble, bffibuilder: BffiBuilder):
    '''
    Extracts BSS sections to a BffiBuilder and returns a tuple
    containing earliest BSS segment address and total BSS segments size.
    '''

    bss_total_size = 0

    # stupid "let's assume the game uses the expansion pak" assumption
    # but .bss sections usually live in the first 4 mbytes of RDRAM
    # so that the game can start without an expansionpak
    earliest_bss_address = 0x80800000

    for bss_start_address,bss_end_address in preamble.bss_sections():
        logger.info("bss section: 0x%08x~0x%08x (%d bytes)", bss_start_address, bss_end_address, bss_end_address-bss_start_address)
        bss_this_size = bss_end_address-bss_start_address
        
        if bss_this_size == 0:
            continue

        if bffibuilder is not None:
            bffibuilder.bss(bss_start_address, bss_this_size)

        bss_total_size += bss_this_size

        if bss_start_address < earliest_bss_address:
            earliest_bss_address = bss_start_address

    return earliest_bss_address, bss_total_size