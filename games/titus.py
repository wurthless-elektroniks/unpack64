'''
Titus detritus

Games that should be in here:
- Automobili Lamborghini / Super Speed Race 64
- Roadsters Trophy
- Superman
- Virtual Chess 64

'''

import logging
import struct

from bffi import Bffi, BffiBuilder
from n64rom import N64Rom
from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi
from reloc import demunge_mips_hilo_offset
from signature import SignatureBuilder, WILDCARD

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------
#
# Superman
#
# read_cart routine at 0x80000fc0
# $a0=ROM address, $a1=RAM address, $a2=sizeof
#
# Rough ROM map (US version):
# - 0x0e15f0 - overlay
# - 0x0f4440 - French locale
# - 0x0f6bc0 - English locale
# - 0x0f91e0 - Spanish locale
# - 0x0fba30 - Dutch locale
# - 0x0fe250 - Italian locale
# - 0x100bb0 - German locale
# - 0x1c6c00 - overlay
# 
# This unpacker scans for all calls to read_cart that pass hardcoded
# addresses. Only a couple of them are overlays, as you can see above.
# You can change the code if you want to dump out all the other resources.
#
# ----------------------------------------------------------------

SUPERMAN_READ_CART_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xb8,          # addiu      sp,sp,-0x48
        0xaf, 0xbf, 0x00, 0x24,          # sw         ra,local_24(sp)
        0xaf, 0xa4, 0x00, 0x48,          # sw         a0,local_res0(sp)
        0xaf, 0xa5, 0x00, 0x4c,          # sw         a1,local_res4(sp)
        0xaf, 0xa6, 0x00, 0x50,          # sw         a2,local_res8(sp)
        0x8f, 0xae, 0x00, 0x50,          # lw         t6,local_res8(sp)
        0x34, 0x01, 0xf0, 0x00,          # ori        at,zero,0xf000
        0x01, 0xc1, 0x08, 0x2b,          # sltu       at,t6,at
        0x14, 0x20, 0x00, 0x05,          # bne        at,zero,LAB_80000ff8
        0x00, 0x00, 0x00, 0x00,          # _nop
        0x3c, 0x0f, 0x80, WILDCARD,      # lui        t7,0x800d
        0x85, 0xef, WILDCARD, WILDCARD,  # lh         t7,offset DAT_800d60d0(t7)
        0x15, 0xe0, 0x00, 0x18,          # bne        t7,zero,LAB_80001054
    ]) \
    .build()

# "addiu $sp,$sp,-xxx" on a 32-bit-aligned address is a good indication
# that a given resource contains code
STACK_MOVE_BACK_PATTERN = SignatureBuilder() \
    .bits(   bytes([0x27, 0xBD, 0x80, 0x00])) \
    .andmask(bytes([0xFF, 0xFF, 0x80, 0x00])) \
    .build()

def _superman_build_readcart_call_pattern(readcart_address):
    return SignatureBuilder() \
        .bits(bytes([
            0x3c, 0x00, 0x00, 0x00,     # +0x00 lui        tX,0x4a
            0x3c, 0x00, 0x00, 0x00,     # +0x04 lui        tY,0x4b
            0x24, 0x00, 0x00, 0x00,     # +0x08 addiu      tX,tX,0x73a0
            0x24, 0x00, 0x00, 0x00,     # +0x0C addiu      tY,tY,0x45c0
            0x3c, 0x05, 0x80, 0x00,     # +0x10 lui        a1,0x8033
            0x24, 0xa5, 0x00, 0x00,     # +0x14 addiu      a1,a1,0x1540
            0x01, 0x40, 0x20, 0x25,     # +0x18 or         a0,tY,zero
        ]) +
        struct.pack(">I",((readcart_address & 0x3FFFFFFF) >> 2) | 0x0C000000) +
        bytes([
            0x00, 0x00, 0x30, 0x23,     # +0x20 _subu      a2,tY,tX
        ])) \
        .andmask(bytes([
            0b11111100, 0, 0, 0, # +0x00
            0b11111100, 0, 0, 0, # +0x04
            0b11111100, 0, 0, 0, # +0x08
            0b11111100, 0, 0, 0, # +0x0C
            0xFF, 0xFF, 0xFF, 0, # +0x10
            0xFF, 0xFF, 0, 0,    # +0x14
            0b11111100, 0b00011111, 0xFF, 0xFF, # +0x18
            0xFF, 0xFF, 0xFF, 0xFF, # +0x1C,
            0b11111100, 0, 0xFF, 0xFF, #+0x20
        ])) \
        .const_op32_hi16("ram_load_address", 0x10) \
        .const_op32_lo16("ram_load_address", 0x14) \
        .build()

def _superman_extract_rom_range(bindat: bytes, pattern_offset: int):
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
        a = demunge_mips_hilo_offset(bindat[pattern_offset+0x0:pattern_offset+0x4], bindat[pattern_offset+0x8:pattern_offset+0xC])
    elif op0_expected_match == op3:
        a = demunge_mips_hilo_offset(bindat[pattern_offset+0x0:pattern_offset+0x4], bindat[pattern_offset+0xC:pattern_offset+0x10])

    if op1_expected_match == op2:
        b = demunge_mips_hilo_offset(bindat[pattern_offset+0x4:pattern_offset+0x8], bindat[pattern_offset+0x8:pattern_offset+0xC])
    elif op1_expected_match == op3:
        b = demunge_mips_hilo_offset(bindat[pattern_offset+0x4:pattern_offset+0x8], bindat[pattern_offset+0xC:pattern_offset+0x10])

    output = [a, b]
    if None in [ a, b ]:
        raise RuntimeError(f"hurgh {a:08x} {b:08x}")

    output.sort()
    return output

def superman_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None

    builder = BffiBuilder()
    earliest_bss_section, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    bootexe = rom.boot_exe()[:earliest_bss_section-ipc]

    builder.fix(ipc, bootexe)
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())

    read_cart_offset = SUPERMAN_READ_CART_PATTERN.find(bootexe)
    if read_cart_offset is None:
        return None
    
    read_cart_address = read_cart_offset + ipc
    logger.info("found Titus Superman readcart routine at 0x%08x", read_cart_address)

    logger.info("searching for potential overlay loads...")

    offset = 0
    readcart_call_pattern = _superman_build_readcart_call_pattern(read_cart_address)

    while True:
        offset = readcart_call_pattern.find(bootexe, offset)
        if offset is None:
            break

        rom_range = _superman_extract_rom_range(bootexe, offset)
        if rom_range is None:
            continue

        rom_start = rom_range[0]
        rom_end = rom_range[1]
        consts = readcart_call_pattern.consts(ipc, bootexe, offset)
        ram_load_address = consts["ram_load_address"].get_value()
        offset += readcart_call_pattern.size()

        resource = rom.read_bytes(rom_start, rom_end-rom_start)
        if STACK_MOVE_BACK_PATTERN.find(resource) is None:
            continue

        logger.info("found code overlay: ROM 0x%08x-0x%08x -> RAM 0x%08x",
                    rom_start,
                    rom_end,
                    ram_load_address)
        builder.seg(ram_load_address, resource)

    return builder.build()
