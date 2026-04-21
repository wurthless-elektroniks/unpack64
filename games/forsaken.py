'''
Forsaken 64 from Acclaim

Standard nustd-style preamble, but someone had the bright idea to
write 0xFACEFACE to the start of BSS. Bootexe is otherwise unpacked.

The rest of the game uses RNC/RNX compression, but they've made this a chore
because compression and resource loading happens on its own thread. As a result,
RNC decompression is done in 16kbyte (0x4000) chunks, which is inefficient,
so they have other commands in the decompression loop to compensate.

For Forsaken 64 (US):

The game sets up multiple resource tables at 0x80002c8c.
Each resource table has entries that are 12 bytes each:
- 4 bytes location relative to start of resource block
- 4 bytes compressed size
- 4 bytes uncompressed size

When reading decompiler stuff in Ghidra, it looks like this:
    DAT_80040130 = 0xb002a910;
    DAT_80040134 = 0x38;
    DAT_80040128 = 0xb03e6450;
    DAT_8004012c = 0x1a;
    DAT_80040110 = 0xb0423bc8;
    DAT_80040114 = 0x1e;
    DAT_80040198 = 0xb063f580;
    DAT_8004019c = 0x1e;
    DAT_80040170 = 0xb06c49d8;
    DAT_80040174 = 2;
    DAT_80040180 = 0xb0050bd0;
    DAT_80040184 = 0x156;
    DAT_80040140 = 0xb03a0528;
    DAT_80040144 = 0x1e;
    DAT_80040188 = 0xb03db9f0;
    DAT_8004018c = 0x26;

This should be fairly obvious: table address in raw PI space, number of entries in that table.
0xb06c49d8 is for the code overlays; decompression starts in a function at 0x80002dc8.

Code overlay segments are dropped at 0x800b82b0.
'''

import logging
import struct


from compression.rnc import rnc_unpack
from bffi import Bffi, BffiBuilder
from n64rom import N64Rom
from signature import SignatureBuilder, WILDCARD

logger = logging.getLogger(__name__)

FORSAKEN_PREAMBLE_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x1d, 0x80, WILDCARD,         # +0x00 lui   sp,0x8004
        0x27, 0xbd, WILDCARD, WILDCARD,     # +0x04 addiu sp,sp,-0x6300

        0x3c, 0x08, 0x80, WILDCARD,         # +0x08 lui   t0,0x8003
        0x25, 0x08, WILDCARD, WILDCARD,     # +0x0C addiu t0,t0,-0x62f0
        0x3c, 0x09, 0x80, WILDCARD,         # +0x10 lui   t1,0x800c
        0x25, 0x29, WILDCARD, WILDCARD,     # +0x14 addiu t1,t1,-0x7d50
        0x11, 0x09, 0x00, 0x05,             # +0x18 beq   t0,t1,LAB_80000430
        0x00, 0x00, 0x00, 0x00,             # +0x1C _nop

        0x25, 0x08, 0x00, 0x04,             # +0x20 addiu t0,t0,0x4
        0x01, 0x09, 0x08, 0x2b,             # +0x24 sltu  at,t0,t1
        0x14, 0x20, 0xff, 0xfd,             # +0x28 bne   at,zero,LAB_80000420
        0xad, 0x00, 0xff, 0xfc,             # +0x2C _sw   zero,-0x4(t0)

        # fuck whoever put this here
        0x3c, 0x08, 0x80, WILDCARD,         # +0x30 lui   t0,0x8003
        0x25, 0x08, WILDCARD, WILDCARD,     # +0x34 addiu t0,t0,-0x62f0
        0x3c, 0x01, 0xfa, 0xce,             # +0x38 lui   at,0xface
        0x34, 0x21, 0xfa, 0xce,             # +0x3C ori   at,at,0xface
        0x00, 0x01, 0x48, 0x21,             # +0x40 move  t1,at
        0xad, 0x09, 0x00, 0x00,             # +0x44 sw    t1,0x0(t0)
        
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x48 jal   FUN_80001bc0
        0x00, 0x00, 0x00, 0x00,             # +0x4C _nop
    ]) \
    .const_op32_hi16("initial_sp", 0x00) \
    .const_op32_lo16("initial_sp", 0x04) \
    .const_op32_hi16("bss_start", 0x08) \
    .const_op32_lo16("bss_start", 0x0C) \
    .const_op32_hi16("bss_end", 0x10) \
    .const_op32_lo16("bss_end", 0x14) \
    .xref_j_imm26("entry_point", 0x48) \
    .build()

FORSAKEN_RESOURCE_INIT_TABLES_A_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x02, 0xb0, WILDCARD,     # lui        v0,0xb026
        0x24, 0x44, WILDCARD, WILDCARD, # addiu      a0,v0,-0x10f0
        0x3c, 0x02, 0xb0, WILDCARD,     # lui        v0,0xb003
        0x24, 0x43, WILDCARD, WILDCARD, # addiu      v1,v0,-0x56f0
        0x30, 0x82, 0x00, 0x07,         # andi       v0,a0,0x7
        0x14, 0x40, 0x00, 0x03,         # bne        v0,zero,LAB_80002cb0
        0x30, 0x62, 0x00, 0x07,         # _andi      v0,v1,0x7
        0x10, 0x40, 0x00, 0x03,         # beq        v0,zero,LAB_80002cb8
        0x00, 0x83, 0x58, 0x23,         # _subu      t3,a0,v1
        0x00, 0x01, 0x00, 0x4d,         # break      0x401
        0x00, 0x83, 0x58, 0x23,         # subu       t3,a0,v1
    ]) \
    .const_op32_hi16("some_rom_address_end", 0x00) \
    .const_op32_lo16("some_rom_address_end", 0x04) \
    .const_op32_hi16("some_rom_address_start", 0x08) \
    .const_op32_lo16("some_rom_address_start", 0x0C) \
    .build()

FORSAKEN_RESOURCE_INIT_TABLES_B_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x08, 0xb0, WILDCARD,     # lui        t0,0xb090
        0x25, 0x08, WILDCARD, WILDCARD, # addiu      t0,t0,-0x7028
        0x01, 0x0b, 0x40, 0x23,         # subu       t0,t0,t3
    ]) \
    .const_op32_hi16("munged_codetable_offset", 0) \
    .const_op32_lo16("munged_codetable_offset", 4) \
    .build()

FORSAKEN_RESOURCE_INIT_TABLES_C_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x02, 0x80, WILDCARD,     # lui        v0,0x8004
        0xac, 0x48, WILDCARD, WILDCARD, # sw         t0,offset DAT_80040170(v0)
        0x24, 0x42, WILDCARD, WILDCARD, # addiu      v0,v0,0x170
        0x24, 0x03, 0x00, 0x02,         # li         v1,0x2
    ]) \
    .const_op32_hi16("codetable_ptr_address", 0x00) \
    .const_op32_lo16("codetable_ptr_address", 0x08) \
    .build()

FORSAKEN_UPK_FILE_CALL_PATTERN = SignatureBuilder() \
    .pattern([
        0x3c, 0x02, 0x80, WILDCARD,         # +0x00 lui        v0,0x8002
        0x3c, 0x06, 0x80, WILDCARD,         # +0x04 lui        a2,0x8004
        0x3c, 0x07, 0x80, WILDCARD,         # +0x08 lui        a3,0x8009
        0x24, 0xc6, WILDCARD, WILDCARD,     # +0x0C addiu      a2,a2,0x170    <-- pointer to pointer to code table in ROM
        0x8c, 0x45, WILDCARD, WILDCARD,     # +0x10 lw         a1,offset PTR_DAT_8002207c(v0) <-- pointer to load address
        0x0c, WILDCARD, WILDCARD, WILDCARD, # +0x14 jal        UPK_File
        0x24, 0xe7, WILDCARD, WILDCARD,     # +0x18 _addiu     a3=,a3,-0x6030
    ]) \
    .const_op32_hi16("code_load_ptr_address", 0x00) \
    .const_op32_lo16("code_load_ptr_address", 0x10) \
    .const_op32_hi16("codetable_ptr_address", 0x04) \
    .const_op32_lo16("codetable_ptr_address", 0x0C) \
    .build()


def _find_code_table_addresses(bootexe: bytes, ipc: int):
    pattern_a_offset = FORSAKEN_RESOURCE_INIT_TABLES_A_PATTERN.find(bootexe)
    if pattern_a_offset is None:
        logger.error("cannot find resource table init function")
        return None, None

    # bit of leeway in case of minor code differences
    func = bootexe[pattern_a_offset:pattern_a_offset+0x150]

    pattern_b_offset = FORSAKEN_RESOURCE_INIT_TABLES_B_PATTERN.find(func)
    if pattern_b_offset is None:
        logger.error("cannot find resource table init pattern B")
        return None, None

    pattern_c_offset = FORSAKEN_RESOURCE_INIT_TABLES_C_PATTERN.find(func, pattern_b_offset)
    if pattern_c_offset is None:
        logger.error("cannot find resource table init pattern C")
        return None, None
    
    pattern_a_consts = FORSAKEN_RESOURCE_INIT_TABLES_A_PATTERN.consts(ipc + pattern_a_offset,
                                                                      func)
    
    pattern_b_consts = FORSAKEN_RESOURCE_INIT_TABLES_B_PATTERN.consts(ipc + pattern_a_offset,
                                                                      func,
                                                                      pattern_b_offset)

    pattern_c_consts = FORSAKEN_RESOURCE_INIT_TABLES_C_PATTERN.consts(ipc + pattern_a_offset,
                                                                      func,
                                                                      pattern_c_offset)

    some_rom_address_start = pattern_a_consts["some_rom_address_start"].get_value()
    some_rom_address_end   = pattern_a_consts["some_rom_address_end"].get_value()

    munged_codetable_offset = pattern_b_consts["munged_codetable_offset"].get_value()

    logger.info("munged_codetable_offset %08x", munged_codetable_offset)
    logger.info("some_rom_address_end %08x", some_rom_address_end)
    logger.info("some_rom_address_start %08x", some_rom_address_start)

    codetable_pi_address = munged_codetable_offset - (some_rom_address_end-some_rom_address_start)
    
    codetable_ptr_address = pattern_c_consts["codetable_ptr_address"].get_value()

    return codetable_pi_address, codetable_ptr_address

def _find_code_load_address(bootexe: bytes, ipc: int, codetable_ptr_address: int):
    upkfile_call_offset = FORSAKEN_UPK_FILE_CALL_PATTERN.find(bootexe)
    if upkfile_call_offset is None:
        logger.error("cannot find call to UPK_File")
        return None

    consts = FORSAKEN_UPK_FILE_CALL_PATTERN.consts(ipc, bootexe, upkfile_call_offset)

    if codetable_ptr_address != consts["codetable_ptr_address"].get_value():
        logger.error("codetable_ptr_address mismatch")
        return None

    code_load_ptr_address = consts["code_load_ptr_address"].get_value()
    code_load_ptr_offset = code_load_ptr_address - ipc

    code_load_address = struct.unpack(">I", bootexe[code_load_ptr_offset:code_load_ptr_offset+4])[0]
    return code_load_address

def _extract_resource_from_table(rom: N64Rom, table_base_address: int, resource_id: int):
    table_base_address &= 0x7FFFFF

    rel_address, compressed_size, _ = \
        struct.unpack(">III",
                  rom.read_bytes(table_base_address + (resource_id * 12), 12))

    compressed_resource = rom.read_bytes( table_base_address + rel_address, compressed_size )

    offset = 0
    output = bytearray()

    # loop until we hit a word that says "END!"
    while compressed_resource[offset:offset+4] != bytes([0x45, 0x4E, 0x44, 0x21]):

        magic = struct.unpack(">I", compressed_resource[offset:offset+4])[0]
    
        # this loop treats RNX the same as RNC, so substitute RNC whenever we see one
        if compressed_resource[offset:offset+4] == b"RNX\1":
            compressed_resource = compressed_resource[:offset+2]+b'C'+compressed_resource[offset+3:]
    
        if compressed_resource[offset:offset+4] == b"RNC\1":
            uncompressed_resource = rnc_unpack(compressed_resource[offset:])
            
            compressed_chunk_size = struct.unpack(">I", compressed_resource[offset+8:offset+12])[0]
            offset += compressed_chunk_size + 18
            if (offset & 3) != 0:
                offset = (offset + 4) & 0xFFFFFFFC

            output += uncompressed_resource
        
        elif compressed_resource[offset:offset+4] == b'FILL':
            fill_length, fill_char, _ = struct.unpack(">HBB", compressed_resource[offset+4:offset+8])
            if fill_length < 0x4000:
                raise RuntimeError(f"UPK_FillMem: Chunk size error ({fill_length:04x})")

            output += bytes( [fill_char] * fill_length )
            offset += 8
        elif compressed_resource[offset:offset+4] == b'\0\0\0\0':
            offset += 4
        else:
            raise RuntimeError(f"hit something else: offset {table_base_address + rel_address + offset:08x}, {magic:08x}")

    return output


def forsaken_unpack(rom: N64Rom, ipc: int) -> Bffi:
    if FORSAKEN_PREAMBLE_PATTERN.compare(rom.boot_exe()) is False:
        return None
    
    logger.info("found Forsaken 64 preamble")

    xrefs = FORSAKEN_PREAMBLE_PATTERN.xrefs(ipc, rom.boot_exe())
    consts = FORSAKEN_PREAMBLE_PATTERN.consts(ipc, rom.boot_exe())
    initial_sp = consts["initial_sp"].get_value()
    bss_start  = consts["bss_start"].get_value()
    bss_end    = consts["bss_end"].get_value()
    entry_point = xrefs["entry_point"].get_address()

    codetable_pi_address, codetable_ptr_address = _find_code_table_addresses(rom.boot_exe(), ipc)

    if None in [ codetable_pi_address, codetable_ptr_address ]:
        logger.error("cannot determine code table location")
        return None

    logger.info("code table in PI space at 0x%08x", codetable_pi_address)
    logger.info("game stores code table pointer at 0x%08x", codetable_ptr_address)

    code_load_address = _find_code_load_address(rom.boot_exe(), ipc, codetable_ptr_address)
    if code_load_address is None:
        logger.error("cannot find code load address")
        return None

    logger.info("code segments will load to 0x%08x", code_load_address)

    builder = BffiBuilder()
    builder.initial_stack_pointer(initial_sp)
    builder.bss(bss_start, bss_end-bss_start)
    builder.fix(ipc, rom.boot_exe()[:bss_start-ipc])

    # TODO: copy FACEFACE word to the right address
    # this might be a critical stack guard

    for i in range(2):
        logger.info("extract code resource %d", i)
        res = _extract_resource_from_table(rom, codetable_pi_address, i)
        builder.seg(code_load_address, res)

    builder.initial_program_counter(entry_point)

    return builder.build()
