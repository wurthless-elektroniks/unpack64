
'''
Locomotive Corporation games

'''

import logging
import struct

from bffi import BffiBuilder, Bffi
from mips import apply_andmask, make_andmask_load_store, make_andmask_reg_opcode, \
                 assemble_jal, INSTRUCTION_ADDIU_TEMPLATE, INSTRUCTION_LUI_TEMPLATE, \
                 INSTRUCTION_SW_TEMPLATE, INSTRUCTION_OR_TEMPLATE, INSTRUCTION_SUBU_TEMPLATE, \
                 extract_range_from_lui_addiu_pairs
from n64rom import N64Rom
from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi
from signature import SignatureBuilder, WILDCARD
from sigutil import find_all_instances
from strutil import extract_cstring

logger = logging.getLogger(__name__)

# ----------------------------------------------------------
#
# Penny Racers
#
# Most modules helpfully loaded in printf()/read_cart() patterns.
#
# ----------------------------------------------------------

PENNYRACERS_MODULE_LOAD_PRINTF_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x11, 0x00, WILDCARD,          # +0x00 lui        s1,0x3         <-- ROM end
        0x26, 0x31, WILDCARD, WILDCARD,      # +0x04 addiu      s1,s1,-0x65c0
        0x3c, 0x10, 0x00, WILDCARD,          # +0x08 lui        s0,0x2         <-- ROM start
        0x26, 0x10, WILDCARD, WILDCARD,      # +0x0C addiu      s0,s0,0x5ea0
        0x02, 0x30, 0x88, 0x23,              # +0x10 subu       s1,s1,s0
        0x3c, 0x04, 0x80, WILDCARD,          # +0x14 lui        a0,0x8005      <-- printf() format
        0x24, 0x84, WILDCARD, WILDCARD,      # +0x18 addiu      a0,a0,-0x6790
        0x02, 0x00, 0x28, 0x21,              # +0x1C move       a1,s0
        0x3c, 0x06, 0x80, WILDCARD,          # +0x20 lui        a2,0x800e      <-- load address
        0x24, 0xc6, WILDCARD, WILDCARD,      # +0x24 addiu      a2,a2,-0x1d20
        0x0c, WILDCARD, WILDCARD, WILDCARD,  # +0x28 jal        printf_stubbedout
        0x02, 0x20, 0x38, 0x21,              # +0x2C  _move      a3,s1
    ]) \
    .const_op32_hi16("rom_end_address", 0x00) \
    .const_op32_lo16("rom_end_address", 0x04) \
    .const_op32_hi16("rom_start_address", 0x08) \
    .const_op32_lo16("rom_start_address", 0x0C) \
    .const_op32_hi16("printfstr_address", 0x14) \
    .const_op32_lo16("printfstr_address", 0x18) \
    .const_op32_hi16("ram_address", 0x20) \
    .const_op32_lo16("ram_address", 0x24) \
    .build()

def pennyracers_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    builder = BffiBuilder()
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    bootexe = rom.boot_exe()[:earliest_bss-ipc]

    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.fix(ipc, bootexe)

    printf_instances = find_all_instances(bootexe, PENNYRACERS_MODULE_LOAD_PRINTF_PATTERN)
    if not printf_instances:
        return None
    
    logger.info("found Penny Racers printf()/readcart() module load combo")

    for offset in printf_instances:
        consts = PENNYRACERS_MODULE_LOAD_PRINTF_PATTERN.consts(ipc, bootexe, offset)

        rom_end_address = consts["rom_end_address"].get_value()
        rom_start_address = consts["rom_start_address"].get_value()
        printfstr_address = consts["printfstr_address"].get_value()
        ram_address = consts["ram_address"].get_value()

        # let's print the original debugstrings, just to be cute.
        # debug strings are formatted "objdriver trans   %x -> %x (%7d bytes)"
        printfstr = extract_cstring(bootexe[printfstr_address-ipc:]).strip()
        logger.info(printfstr, rom_start_address, ram_address, rom_end_address-rom_start_address)

        seg = rom.read_bytes(rom_start_address, rom_end_address-rom_start_address)
        builder.seg(ram_address, seg)
    
    return builder.build()

# ----------------------------------------------------------
#
# Transformers - Beast Wars Transmetal
#
# Lots of code overlays swapped in on mainthread start and later during execution.
#
# Uses "S1" and "B1" archive thingies.
#
# readcart routine at 800cfca0, takes parameters:
# $a0 = ROM address, $a1 = RAM address, $a2 = sizeof
# This one reads in 16k chunks at a time.
#
# ----------------------------------------------------------

TRANSFORMERS_READCART_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0x90,                # addiu      sp,sp,-0x70
        0xaf, 0xb7, 0x00, 0x30,                # sw         s7,local_40(sp)
        0xaf, 0xb6, 0x00, 0x2c,                # sw         s6,local_44(sp)
        0xaf, 0xb3, 0x00, 0x20,                # sw         s3,local_50(sp)
        0xaf, 0xb2, 0x00, 0x1c,                # sw         s2,local_54(sp)
        0xaf, 0xb1, 0x00, 0x18,                # sw         s1,local_58(sp)
        0x00, 0xc0, 0x88, 0x25,                # or         s1,a2,zero
        0x00, 0xa0, 0x90, 0x25,                # or         s2,a1,zero
        0x00, 0x80, 0x98, 0x25,                # or         s3,a0,zero
        0x27, 0xb6, 0x00, 0x40,                # addiu      s6,sp,0x40
        0x27, 0xb7, 0x00, 0x3c,                # addiu      s7,sp,0x3c
        0xaf, 0xbf, 0x00, 0x34,                # sw         ra,local_3c(sp)
        0xaf, 0xb5, 0x00, 0x28,                # sw         s5,local_48(sp)
        0xaf, 0xb4, 0x00, 0x24,                # sw         s4,local_4c(sp)
        0xaf, 0xb0, 0x00, 0x14,                # sw         s0,local_5c(sp)
        0x02, 0xe0, 0x28, 0x25,                # or         a1,s7,zero
        0x02, 0xc0, 0x20, 0x25,                # or         a0,s6,zero
        0x0c, WILDCARD, WILDCARD, WILDCARD,    # jal        FUN_800e05b0
        0x24, 0x06, 0x00, 0x01,                # _li        a2,0x1
    ]) \
    .build()

# you'll have to excuse this somewhat shitty code,
# i'm trying to do something a bit more universal and
# this is the best idea i have at the moment.
# the pattern is the same, but register usage is juggled a LOT
# and i don't really want a repeat of what i did for superman...
def _transformers_build_readcart_call_pattern(readcart_address: int):
    return SignatureBuilder() \
    .bits(
        # +0x00 3c 0c 00 11 lui   t4,0x11
        apply_andmask(INSTRUCTION_LUI_TEMPLATE,
                      make_andmask_load_store(mask_dest=True,
                                              mask_offs=True,
                                              mask_imm16=True)) +
        # +0x04 3c 0d 00 0e lui   t5,0xe
        apply_andmask(INSTRUCTION_LUI_TEMPLATE,
                      make_andmask_load_store(mask_dest=True,
                                              mask_offs=True,
                                              mask_imm16=True)) +
        # +0x08 25 ad 53 e0 addiu t5,t5,0x53e0
        bytes([0x24, 0, 0, 0]) +

        # +0x0C 25 8c 8c 10 addiu t4,t4,-0x73f0
        bytes([0x24, 0, 0, 0]) +

        # +0x10 3c 0f 80 20 lui   t7,0x8020
        apply_andmask(INSTRUCTION_LUI_TEMPLATE, make_andmask_load_store(mask_dest=True,
                                              mask_offs=True,
                                              mask_imm16=True)) +

        # +0x14 25 ef 80 00 addiu t7,t7,-0x8000
        bytes([0x24, 0, 0, 0]) +

        # +0x18 01 8d 70 23 subu  t6,t4,t5
        apply_andmask(0x018d7023, make_andmask_reg_opcode(mask_source=True,mask_source2=True,mask_shift=True,mask_dest=True)) +

        # +0x1C af ae 00 28 sw    t6,local_10(sp)
        apply_andmask(INSTRUCTION_SW_TEMPLATE, make_andmask_load_store(mask_dest=True,
                                              mask_offs=True,
                                              mask_imm16=True)) +

        # +0x20 01 c0 30 25 or    a2,t6,zero
        apply_andmask(0x01c03025, make_andmask_reg_opcode(mask_source=True,
                                                          mask_source2=False,
                                                          mask_dest=False)) +
        
        # +0x24 af af 00 24 sw    t7,local_14(sp)
        apply_andmask(INSTRUCTION_SW_TEMPLATE, make_andmask_load_store(mask_dest=True,
                                              mask_offs=True,
                                              mask_imm16=True)) +

        # +0x28 01 e0 28 25 or    a1,t7,zero
        apply_andmask(0x01e02825, make_andmask_reg_opcode(mask_source=True,
                                                          mask_source2=False,
                                                          mask_dest=False)) +

        # +0x2C 0c xx xx xx jal   readcart
        assemble_jal(readcart_address) +

        # +0x30 01 a0 20 25 _or   a0,t5,zero
        apply_andmask(0x01a02025, make_andmask_reg_opcode(mask_source=True,
                                                          mask_source2=False,
                                                          mask_dest=False))
    ) \
    .andmask(
        # +0x00 3c 0c 00 11 lui   t4,0x11
        make_andmask_load_store(mask_dest=True,mask_offs=True,mask_imm16=True) +

        # +0x04 3c 0d 00 0e lui   t5,0xe
        make_andmask_load_store(mask_dest=True,mask_offs=True,mask_imm16=True) +

        # +0x08 25 ad 53 e0 addiu t5,t5,0x53e0
        bytes([0xFC, 0, 0, 0]) +

        # +0x0C 25 8c 8c 10 addiu t4,t4,-0x73f0
        bytes([0xFC, 0, 0, 0]) +

        # +0x10 3c 0f 80 20 lui   t7,0x8020
        make_andmask_load_store(mask_dest=True,mask_offs=True,mask_imm16=True) +

        # +0x14 25 ef 80 00 addiu t7,t7,-0x8000
        bytes([0xFC, 0, 0, 0]) +

        # +0x18 01 8d 70 23 subu  t6,t4,t5
        make_andmask_reg_opcode(mask_source=True,mask_source2=True,mask_shift=True,mask_dest=True) +

        # +0x1C af ae 00 28 sw    t6,local_10(sp)
        make_andmask_load_store(mask_dest=True,mask_offs=True,mask_imm16=True) +

        # +0x20 01 c0 30 25 or    a2,t6,zero
        make_andmask_reg_opcode(mask_source=True,mask_source2=False,mask_dest=False) +
        
        # +0x24 af af 00 24 sw    t7,local_14(sp)
        make_andmask_load_store(mask_dest=True,mask_offs=True,mask_imm16=True) +

        # +0x28 01 e0 28 25 or    a1,t7,zero
        make_andmask_reg_opcode(mask_source=True,mask_source2=False,mask_dest=False) +

        # +0x2C 0c xx xx xx jal   readcart
        bytes([0xFF,0xFF,0xFF,0xFF]) +

        # +0x30 01 a0 20 25 _or   a0,t5,zero
        make_andmask_reg_opcode(mask_source=True,mask_source2=False,mask_dest=False)
    ) \
    .const_imm32("romaddr_hi16_op_0", 0x00) \
    .const_imm32("romaddr_hi16_op_1", 0x04) \
    .const_imm32("romaddr_lo16_op_0", 0x08) \
    .const_imm32("romaddr_lo16_op_1", 0x0C) \
    .const_op32_hi16("ram_address", 0x10) \
    .const_op32_lo16("ram_address", 0x14) \
    .build()

STACK_MOVE_BACK_PATTERN = SignatureBuilder() \
    .bits(   bytes([0x27, 0xBD, 0x80, 0x00])) \
    .andmask(bytes([0xFF, 0xFF, 0x80, 0x00])) \
    .build()

def transformers_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None
    
    builder = BffiBuilder()
    earliest_bss, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    bootexe = rom.boot_exe()[:earliest_bss-ipc]

    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.fix(ipc, bootexe)

    readcart_offset = TRANSFORMERS_READCART_PATTERN.find(bootexe)
    if readcart_offset is None:
        return None
    
    readcart_address = readcart_offset + ipc
    
    logger.info("found Locomotive Corporation Transformers readcart routine at 0x%08x", readcart_address)

    pattern = _transformers_build_readcart_call_pattern(readcart_address)

    logger.info("searching for all calls to readcart...")

    offset = 0
    while True:
        offset = pattern.find(bootexe, offset)
        if offset is None:
            break

        consts = pattern.consts(ipc, bootexe, offset)
        ram_address = consts["ram_address"].get_value()
        rom_range = extract_range_from_lui_addiu_pairs(bootexe, offset)

        offset += pattern.size()

        rom_start = rom_range[0]
        rom_end   = rom_range[1]

        resource = rom.read_bytes(rom_start, rom_end-rom_start)
        if STACK_MOVE_BACK_PATTERN.find(resource) is None:
            continue

        logger.info("found resource with code in it: ROM 0x%08x-0x%08x -> RAM 0x%08x",
                    rom_start,
                    rom_end,
                    ram_address)

        builder.seg(ram_address, resource)

    return builder.build()

# ----------------------------------------------------------
#
# Choro Q II
#
# Appears to be single load.
# I have my doubts about this one, but there's nothing obvious here...
#
# read_cart routine at 0x800cc580 takes args
# $a0 = rom address, $a1 = ram address, $a2 = sizeof
#
# Aerogauge might also be single-load, have to confirm
# 
# ----------------------------------------------------------
