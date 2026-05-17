'''
Traveller's Tales

Toy Story 2 and A Bug's Life both use the same engine and infrastructure.
They also use a filesystem, but it isn't dumped here, because no code loads from it (I think).

Overlay loading is a god damned mess. One huge switch table is used for the
overlay loader jump statement, and whereever the jump lands will have the
overlay load code in place. The function we're looking for (at 0x800859a4 in TS2 US)
takes $a0 = ROM address, $a1 = RAM address, $a2 = sizeof,
and those registers are set between other logic. It's really bad and impossible
to dump accurately with simple signature matching.

The good news is we can still grab the jump table, use a simple code tracer to
decode the arguments and then break at the first jal or j instruction we hit.
If we have $a0/$a1/$a2 set, then all is well.

Overlays should always be dropped at 0x80000400, but there are some that don't.

One other thing: the function we scan for is just a raw readcart routine.
There is a completely different one for reading files from the filesystem,
but as none of them contain code, I'm leaving them out of this driver.
'''

import logging
import struct

from bffi import BffiBuilder, Bffi
from mips import disassemble_jump_imm26_target
from n64rom import N64Rom
from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi
from signature import SignatureBuilder, WILDCARD
from sigutil import pick_pattern

logger = logging.getLogger(__name__)

# ----------------------------------------------------

TS2_READCART_RAW_PATTERN = SignatureBuilder() \
    .pattern([
        0x27, 0xbd, 0xff, 0xa8,     # addiu      sp,sp,-0x58
        0xaf, 0xb4, 0x00, 0x48,     # sw         s4,local_10(sp)
        0x00, 0x80, 0xa0, 0x21,     # move       s4,a0
        0xaf, 0xb5, 0x00, 0x4c,     # sw         s5,local_c(sp)
        0x00, 0xa0, 0xa8, 0x21,     # move       s5,a1
        0xaf, 0xb2, 0x00, 0x40,     # sw         s2,local_18(sp)
        0x00, 0xc0, 0x90, 0x21,     # move       s2,a2
        0xaf, 0xbf, 0x00, 0x50,     # sw         ra,local_8(sp)
        0xaf, 0xb3, 0x00, 0x44,     # sw         s3,local_14(sp)
        0xaf, 0xb1, 0x00, 0x3c,     # sw         s1,local_1c(sp)
        0x0c, WILDCARD, WILDCARD, WILDCARD,     # jal        FUN_80091de0
        0xaf, 0xb0, 0x00, 0x38,     # _sw        s0,local_20(sp)
        0x3c, 0x04, 0x80, 0x00,     # lui        a0,0x8000
        0x0c, WILDCARD, WILDCARD, WILDCARD,     # jal        FUN_80099720
        0x3c, 0x05, 0x00, 0x40,     # _lui       a1,0x40
        0x24, 0x10, 0x10, 0x00,     # li         s0,0x1000
        0x00, 0x00, 0x88, 0x21,     # clear      s1
    ]) \
    .build()

TS2_OVERLAY_SWITCH_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x01, 0x80, WILDCARD,      # +0x00 lui        at,0x800a
        0xe4, 0x20, WILDCARD, WILDCARD,  # +0x04 swc1       f0,offset DAT_800a2928(at)
        0x3c, 0x01, 0x80, WILDCARD,      # +0x08 lui        at,0x800a
        0xe4, 0x20, WILDCARD, WILDCARD,  # +0x0C swc1       f0,offset DAT_800a2934(at)
        0x3c, 0x01, 0x80, WILDCARD,      # +0x10 lui        at,0x800a
        0xe4, 0x22, WILDCARD, WILDCARD,  # +0x10 swc1       f2,offset DAT_800a2924(at)
        0x3c, 0x01, 0x80, WILDCARD,      # +0x10 lui        at,0x800a
        0xe4, 0x24, WILDCARD, WILDCARD,  # +0x10 swc1       f4,offset DAT_800a2930(at)
        0x3c, 0x01, 0x80, WILDCARD,      # +0x20 lui        at,0x800a
        0xe4, 0x26, WILDCARD, WILDCARD,  # +0x24 swc1       f6,offset DAT_800a292c(at)
        0x3c, 0x01, 0x80, WILDCARD,      # +0x28 lui        at,0x800a
        0xe4, 0x20, WILDCARD, WILDCARD,  # +0x2C swc1       f0,offset DAT_800a2934(at)
        0x3c, 0x01, 0x80, WILDCARD,      # +0x30 lui        at,0x800a
        0xe4, 0x22, WILDCARD, WILDCARD,  # +0x34 swc1       f2,offset DAT_800a2938(at)
        0x10, 0x40, 0x00, WILDCARD,      # +0x38 beq        v0,zero,LAB_8000b864
        0x00, 0x05, 0x10, 0x80,          # +0x3C _sll       v0,a1,0x2
        0x3c, 0x01, 0x80, WILDCARD,      # +0x40 lui        at,0x800a
        0x00, 0x22, 0x08, 0x21,          # +0x44 addu       at,at,v0
        0x8c, 0x22, WILDCARD, WILDCARD,  # +0x48 lw         v0,offset PTR_LAB_800a0920(at)
        0x00, 0x40, 0x00, 0x08,          # +0x4C jr         v0
        0x00, 0x00, 0x00, 0x00,          # +0x50 nop
    ]) \
    .const_op32_hi16("jump_table_address", 0x40) \
    .const_op32_lo16("jump_table_address", 0x48) \
    .build()

# a bugs life is on the same engine but has a different overlay switch case
# because of obvious code differences
BUGSLIFE_OVERLAY_SWITCH_PATTERN = SignatureBuilder() \
    .pattern([
        0x24, 0x02, 0x06, 0x40,         # +0x00 li         v0,0x640
        0x3c, 0x01, 0x80, WILDCARD,     # +0x04 lui        at,0x801c
        0xac, 0x22, WILDCARD, WILDCARD, # +0x08 sw         v0,offset DAT_801c5298(at)
        0x24, 0x02, WILDCARD, WILDCARD, # +0x0C li         v0,0x1f40
        0x3c, 0x01, 0x80, WILDCARD,     # +0x10 lui        at,0x800a
        0xac, 0x22, WILDCARD, WILDCARD, # +0x14 sw         v0,-0x491c(at)=>DAT_8009b6e4
        0x24, 0x02, 0x01, 0x90,         # +0x18 li         v0,0x190
        0x3c, 0x01, 0x80, WILDCARD,     # +0x1C lui        at,0x801c
        0xac, 0x22, WILDCARD, WILDCARD, # +0x20 sw         v0,offset DAT_801c4a80(at)
        0x2c, 0xa2, 0x00, 0x64,         # +0x24 sltiu      v0,a1,0x64
        0xaf, 0xbf, 0x00, 0x10,         # +0x28 sw         ra,local_8(sp)
        0x3c, 0x01, 0x80, WILDCARD,     # +0x2C lui        at,0x801f
        0xac, 0x20, WILDCARD, WILDCARD, # +0x30 sw         zero,-0x5a6c(at)=>DAT_801ea594
        0x10, 0x40, 0x00, WILDCARD,     # +0x34 beq        v0,zero,switchD_8000a72c::caseD_12
        0x00, 0x05, 0x10, 0x80,         # +0x38 _sll       v0,a1,0x2
        0x3c, 0x01, 0x80, WILDCARD,     # +0x3C lui        at,0x8008
        0x00, 0x22, 0x08, 0x21,         # +0x40 addu       at,at,v0
        0x8c, 0x22, WILDCARD, WILDCARD, # +0x44 lw         v0,0x2620(at)
        0x00, 0x40, 0x00, 0x08,         # +0x48 jr         v0
        0x00, 0x00, 0x00, 0x00,         # +0x4C _nop
    ]) \
    .const_op32_hi16("jump_table_address", 0x3C) \
    .const_op32_lo16("jump_table_address", 0x44) \
    .build()

def _ts2_trace_switch_case(bootexe: bytes,
                           offset: int,
                           readcart_address: int):
    a0_pairs = [ None, None ]
    a1_pairs = [ None, None ]
    a2_pairs = [ None, None ]

    call_address = None
    about_to_break = False

    while True:
        op = bootexe[offset:offset+4]
        offset += 4

        operation = op[0] & 0xFC

        upper16 = struct.unpack(">H",op[:2])[0]

        # handle delay slot nonsense first
        if op[0] & 0xFC == 0x08:
            # if we hit ANY jump, stop
            about_to_break = True
            continue
        if op[1] & 0xFC == 0x0C:
            # jal pending
            call_address = disassemble_jump_imm26_target(0x80000000, op)
            continue

        # only listen for lui/addiu/ori opcodes affecting a0/a1/a2
        if operation == 0x3C:
            # lui
            target_reg = upper16 & 0x1F
            if target_reg == 4:
                a0_pairs[0] = struct.unpack(">H",op[2:])[0] << 16
            elif target_reg == 5:
                a1_pairs[0] = struct.unpack(">H",op[2:])[0] << 16
            elif target_reg == 6:
                a2_pairs[0] = struct.unpack(">H",op[2:])[0] << 16
        elif operation == 0x34:
            # ori
            reg_a = upper16 & 0x1F
            reg_b = (upper16 >> 5) & 0x1F
            if reg_a == reg_b:
                if reg_a == 4:
                    a0_pairs[1] = struct.unpack(">H",op[2:])[0]
                elif reg_a == 5:
                    a1_pairs[1] = struct.unpack(">H",op[2:])[0]
                elif reg_a == 6:
                    a2_pairs[1] = struct.unpack(">H",op[2:])[0]
        elif operation == 0x24:
            # addiu
            reg_a = upper16 & 0x1F
            reg_b = (upper16 >> 5) & 0x1F
            if reg_a == reg_b:
                if reg_a == 4:
                    a0_pairs[1] = struct.unpack(">h",op[2:])[0]
                elif reg_a == 5:
                    a1_pairs[1] = struct.unpack(">h",op[2:])[0]
                elif reg_a == 6:
                    a2_pairs[1] = struct.unpack(">h",op[2:])[0]
        elif upper16 == 0x03E0:
            break

        if call_address is not None:
            # if we hit a jal to a function that is NOT readcart, throw the results out
            if call_address != readcart_address:
                a0_pairs = [ None, None ]
                a1_pairs = [ None, None ]
                a2_pairs = [ None, None ]
            else:
                # logger.debug("hit call to readcart, stopping trace")
                break
            call_address = None

        if about_to_break is True:
            # logger.debug("hit unconditional jump, stopping trace")
            break

    if None in a0_pairs or None in a1_pairs or None in a2_pairs:
        return None
    
    # success if a0/a1/a2 pairs are identified
    return [
        a0_pairs[0] + a0_pairs[1],
        a1_pairs[0] + a1_pairs[1],
        a2_pairs[0] + a2_pairs[1]
    ]

def ts2_unpack(rom: N64Rom, ipc: int) -> Bffi:
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        return None

    builder = BffiBuilder()
    earliest_bss_section, _ = preamble_extract_bss_sections_to_bffi(preamble, builder)
    bootexe = rom.boot_exe()[:earliest_bss_section-ipc]

    readcart_offset = TS2_READCART_RAW_PATTERN.find(bootexe)
    if readcart_offset is None:
        return None
    readcart_address = ipc + readcart_offset
    logger.info("found Traveller's Tales readcart routine at 0x%08x", readcart_address)

    builder.fix(ipc, bootexe)
    builder.initial_stack_pointer(preamble.initial_stack_pointer())
    builder.initial_program_counter(preamble.crt_entry_point())

    overlay_switch_pattern, overlay_switch_offset = pick_pattern(bootexe,
                                                                 [ BUGSLIFE_OVERLAY_SWITCH_PATTERN, TS2_OVERLAY_SWITCH_PATTERN])
    
    if overlay_switch_pattern is None:
        logger.error("cannot find overlay load switch statement")
        return None
    
    consts = overlay_switch_pattern.consts(ipc, bootexe, overlay_switch_offset)
    jump_table_address = consts["jump_table_address"].get_value()
    logger.info("overlay load jump table is at 0x%08x", jump_table_address)

    jump_table_offset = jump_table_address-ipc

    jump_addresses_traced = []
    while True:
        jump_address = struct.unpack(">I", bootexe[jump_table_offset:jump_table_offset+4])[0]
        jump_table_offset += 4

        if (jump_address & 0xFF000000) != 0x80000000:
            break

        if jump_address in jump_addresses_traced:
            continue

        jump_addresses_traced.append(jump_address)

        logger.info("attempt trace of code path 0x%08x...", jump_address)

        results = _ts2_trace_switch_case(bootexe, jump_address-ipc, readcart_address)
        if results is not None:
            rom_address = results[0]
            if (rom_address & 0xFF000000) != 0xB0000000:
                continue

            rom_address &= 0x03FFFFFF
            ram_address = results[1]
            sizeof = results[2]

            logger.info("found overlay load: ROM 0x%08x -> RAM 0x%08x, sizeof %d bytes",
                        rom_address,
                        ram_address,
                        sizeof
                        )
            
            seg = rom.read_bytes(rom_address, sizeof)
            builder.seg(ram_address, seg)
        
    
    return builder.build()
