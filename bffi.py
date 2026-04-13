'''
Binary Format for Fucking Idiots

This is a headered file to be used by other tools that contains, at the very least,
the boot executable. It should also contain other sections like the initial TLB settings
and code overlay segments, if necessary.
'''

import logging
import struct
import zlib
from enum import Enum

logger = logging.getLogger(__name__)

class BffiCompressionMode(Enum):
    UNCOMPRESSED = 0x00

    ZLIB_DEFLATE = 0x01

class BffiSectionType(Enum):
    # ------------------------------
    # 0x00-0x07: data fields
    # ------------------------------

    EOF = 0x00
    '''
    Explicit end-of-file marker.

    bffiboot expects IPC to be the end-of-file marker, as it will take that address,
    clear caches, and jump to it to start the program. If it encounters EOF, it will
    enter an infinite loop and not start the program. The EOF marker therefore exists
    for use by toolchains only.
    '''

    BSS = 0x01
    '''
    BSS or other similar initialize-to-given-word section.
    '''

    FIX = 0x02
    '''
    Fixed (always-loaded) section of code.
    '''

    SEG = 0x03
    '''
    Code overlay segments, not always loaded; to be loaded later while the game is running.
    '''

    COPY = 0x04
    '''
    Explicit memory copy operation. Copies data from a source to destination address.
    Sarge's Heroes does this to copy `osMemSize` at 0x80000318 to a higher address; in practice
    this value is ignored, but the BFFI keeps it for completeness' sake.

    Important note about how this is to be built and parsed:

    bffiboot will execute this operation immediately when encountered, but this script
    does not preserve this order-of-operations when a BFFI is parsed. The serializer
    will queue copy operations **after** BSS and code segments have been handled.

    The order-of-operations is not preserved here because it isn't expected that we'll be moving
    memory much during initialization. The BSS and code segment loaders should have taken
    care of memory initialization for us.
    '''

    IGP = 0x05
    '''
    Initial Global Pointer value. Not used by most games.
    '''

    ISP = 0x06
    '''
    Initial Stack Pointer value.
    '''

    IPC = 0x07
    '''
    Initial Program Counter i.e. entry point.
    This is to be treated as an end-of-file marker.
    '''

    # ------------------------------
    # 0x08-0x0F: TLB initialization
    # ------------------------------

    TLB_IDX = 0x08
    '''
    Set TLB cop0 Index register to this value. The value will be latched
    for subsequent operations.
    '''

    TLB_RND = 0x09
    '''
    Set TLB cop0 Random register to this value.
    '''

    TLB_UNMAP_RANGE = 0x0D
    '''
    Unmaps range of TLB entries from the current index,
    incrementing Index as we go.
    
    Values will be set as follows:
    - EntryHi  = 0x80000000
    - EntryLo0 = 0x00000000
    - EntryLo1 = 0x00000000

    PageMask will not be updated.
    '''

    TLB_SET = 0x0E
    '''
    Set TLB entry at the current Index to the values given, then increment Index value.

    Takes four u32 parameters: EntryHi, EntryLo0, EntryLo1, PageMask.

    Please read the extensive MIPS documentation about how these cop0 registers work,
    and the values expected to be written to them.
    '''

    TLB_UNMAP = 0x0F
    '''
    Unmap single TLB entry at the current Index, then increment Index value.
    See also TLB_UNMAP_RANGE.
    '''

    # ------------------------------
    # 0x10-0x1F: metadata
    # ------------------------------
    DYN = 0x10
    '''
    Dynamically-used memory pool section. Patchers or other utilities can use this to
    know where not to put patches, or similar.
    '''

    SHA = 0x11
    '''
    SHA-256 digest of the ROM the BFFI file was generated from.
    '''

    ORIGIN = 0x12
    '''
    Where a code segment originally sat in ROM.

    segment_type,segment_id,rom_start_address,rom_end_address
    '''

PAGE_SIZE_LUT = {
    (0x0000 << 13): 4 * 1024,
    (0x0003 << 13): 16 * 1024,
    (0x000F << 13): 64 * 1024,
    (0x003F << 13): 256 * 1024,
    (0x00FF << 13): 1024 * 1024,
    (0x03FF << 13): 4 * 1024 * 1024,
    (0x0FFF << 13): 16 * 1024 * 1024
}

def _serialize_section_marker(section_id: int,
                              section_type: BffiSectionType,
                              unused_1: int = 0,
                              unused_2: int = 0):
    return struct.pack(">BBBB", section_type.value, unused_1, section_id, unused_2)

def _serialize_section_type_with_single_u32(section_type: BffiSectionType, value: int) -> bytes:
    return _serialize_section_marker(0, section_type) + struct.pack(">I", value)

def _serialize_section_type_only(section_type: BffiSectionType) -> bytes:
    return _serialize_section_marker(0, section_type)

def _serialize_bss(section_id: int, virtual_load_address: int, load_size: int, initial_word: int):
    return _serialize_section_marker(section_id, BffiSectionType.BSS) + struct.pack(">III", virtual_load_address, load_size, initial_word)

def _serialize_fix_or_seg(section_type: BffiSectionType,
                          section_id,
                          source_offset,
                          load_address,
                          uncompressed_size,
                          compressed_size,
                          payload_crc,
                          compression_mode) -> bytes:
    
    unused_1, unused_2, unused_3 = (0,0,0)

    return _serialize_section_marker(section_id, section_type) + \
        struct.pack(">IIIIIBBBB",source_offset, load_address, uncompressed_size, compressed_size,
                    payload_crc, compression_mode, unused_1, unused_2, unused_3)


class Finalizable():
    '''
    Base object that provides a "finalized" state (not to be confused with Python's
    concept of finalization).
    '''
    def __init__(self):
        self._finalized = False

    def _finalize(self):
        self._finalized = True
    
    def _assert_not_final(self):
        if self._finalized:
            raise RuntimeError("Item is finalized")

class BffiCopyEntry(Finalizable):
    def __init__(self):
        super().__init__()
        self._source_address = 0
        self._target_address = 0
        self._copy_length = 0

    def source_address(self, new_source_address: int | None = None):
        if new_source_address is not None:
            self._assert_not_final()
            self._source_address = new_source_address 
        return self._source_address

    def target_address(self, new_target_address: int | None = None):
        if new_target_address is not None:
            self._assert_not_final()
            self._target_address = new_target_address
        return self._target_address

    def copy_length(self, new_copy_length: int | None = None):
        if new_copy_length is not None:
            self._assert_not_final()
            self._copy_length = new_copy_length
        return self._copy_length

def _entrylo_valid(entrylo):
    return (entrylo & 2) != 0

class BffiTlbEntry(Finalizable):
    def __init__(self):
        super().__init__()
        self._entryhi  = 0
        self._entrylo0 = 0
        self._entrylo1 = 0
        self._pagemask = 0

    def entryhi(self, new_entryhi: int | None = None):
        if new_entryhi is not None:
            self._assert_not_final()
            self._entryhi = new_entryhi
        return self._entryhi
        
    def entrylo0(self, new_entrylo0: int | None = None):
        if new_entrylo0 is not None:
            self._assert_not_final()
            self._entrylo0 = new_entrylo0
        return self._entrylo0

    def entrylo1(self, new_entrylo1: int | None = None):
        if new_entrylo1 is not None:
            self._assert_not_final()
            self._entrylo1 = new_entrylo1
        return self._entrylo1

    def pagemask(self, new_pagemask: int | None = None):
        if new_pagemask is not None:
            self._assert_not_final()
            self._pagemask = new_pagemask
        return self._pagemask
    
    def is_valid(self):
        return _entrylo_valid(self._entrylo0) or _entrylo_valid(self._entrylo1)
    
    def page_number(self):
        return self._entryhi >> 13
    
    def asid(self):
        return self._entryhi & 0xFF
    
    def is_global(self):
        return (self._entrylo0 & 1) != 0 and (self._entrylo1 & 1) != 0
    

class BffiTlb(object):
    def __init__(self):
        self._random_reg = 0
        self._entries: list[BffiTlbEntry] = [ None ] * 0x20
        self._final = False

    def _assert_not_final(self):
        if self._final:
            raise RuntimeError("TLB is finalized")

    def random(self, new_random: int | None = None):
        if new_random is not None:
            self._assert_not_final()
            self._random_reg = new_random
        return self._random_reg
    
    def entry(self, index: int, new_entry: BffiTlbEntry | None = None) -> BffiTlbEntry | None:
        if new_entry is not None:
            self._assert_not_final()
            self._entries[index] = new_entry
        return self._entries[index]

    def serialize(self):
        # since the TLB "sections" are actually commands that we will
        # be sending to the TLB registers in cop0, they all have to go in
        # the right order or the TLB won't be initialized correctly.
        
        # first though, **ALL** TLB entries must be configured.
        # any uninitialized entries result in undefined behavior on the console.
        if None in self._entries:
            raise RuntimeError("uninitialized TLB entry exists")

        # On the N64 side, you can assume the following will be true:
        # - All MIPS cop0 registers and TLB entries will be in an undefined state at load time.
        # - The loader keeps track of the Index value in a MIPS register and increments it
        #   after a page entry is written.
        # - The Index value will default to 0.
        # - The EntryHi value, which selects the ASID, will be undefined, but will be preserved
        #   after an entry is written.
        # - The cop0 Index register will be set to the current Index value before a page entry is written.

        for i in range(0x20):
            entry = self._entries[i]
            
            if entry.entryhi() == 0x80000000 and \
               entry.entrylo0() == 0x00000000 and \
               entry.entrylo1() == 0x00000000:
                # entry is unmapped
                pass
            
            # otherwise, the entry is mapped

            pass


        pass

    def _tlb_lookup_entry_for_address(self, address: int, entryhi_value: int = 0) -> BffiTlbEntry | None:
        '''
        Attempt TLB lookup for given virtual address. Returns the entry and the matching
        EntryLoX value.

        entryhi_value is used to select the current ASID. N64 games typically
        don't use the ASID field, so it can be left zero.
        '''
        # paraphrased from the VR4300 manual:
        #
        # the virtual 32-bit address reserves bits 31/30/29 for page permissions
        # (user/supervisor/kernel). on n64 games execution should always be in kernel
        # mode but we'll have to keep in mind games frequently destroy any assumption
        # i make.
        #
        # with 4k pages bits 28~12 will be the virtual page number, and the low 11 bits
        # are the offset added to the physical page.

        current_asid = entryhi_value & 0xFF

        for i,tlb_entry in enumerate(self._entries):
            if tlb_entry is None:
                raise RuntimeError(f"uninitialized TLB entry at index {i:02x}")

            if tlb_entry.is_valid() is False:
                continue

            logger.debug("TLB entry 0x%02x valid, checking it", i)
            
            if tlb_entry.is_global() is False and \
                tlb_entry.asid() != current_asid:
                logger.debug("- not global and ASID didn't match")
                continue

            mask = tlb_entry.pagemask()
            if mask not in PAGE_SIZE_LUT:
                raise RuntimeError(f"illegal cop0 PageMask: {mask:08x}")
            
            # using https://en64.shoutwiki.com/wiki/N64_TLB as a reference here...
            page_size           = (mask >> 1) | 0x0FFF
            mask                = mask | 0x1FFF
            virtual_page_number = tlb_entry.entryhi() & ~mask

            logger.debug("page size %08x, mask %08x, vpn %08x", page_size, mask, virtual_page_number)
            if (address & virtual_page_number) != virtual_page_number:
                logger.debug("...miss")
                continue

            even_odd_pagemask = PAGE_SIZE_LUT[tlb_entry.pagemask()]
            
            entrylo = tlb_entry.entrylo0() if (address & even_odd_pagemask) == 0 else tlb_entry.entrylo1()
            logger.debug("entrylo was: %08x", entrylo)
            if _entrylo_valid(entrylo) is False:
                logger.debug("...ended up in an unmapped page.")
                continue

            return (self._entries[i], entrylo)

        return None

    def _address_is_kseg0_or_kseg1(self, address: int):
        return 0x80000000 <= address < 0xA0000000 or 0xA0000000 <= address < 0xC0000000

    def virtual_to_physical(self, address: int, entryhi_value: int = 0) -> int | None:
        '''
        Convert virtual to physical address.
        Return address if successful, None if address not mapped.

        This function implements some protection against pagefaults including null pointer dereference.
        It's still up to the MMU as to if the kseg0/kseg1 access is valid.
        '''
        if self._address_is_kseg0_or_kseg1(address):
            return address & 0x1FFFFFFF
        
        tlb_entry_tuple = self._tlb_lookup_entry_for_address(address, entryhi_value=entryhi_value)
        if tlb_entry_tuple is None:
            return None
        
        entrylo     = tlb_entry_tuple[1]
        page_mask   = (tlb_entry_tuple[0].pagemask() >> 1) | 0x0FFF

        physical_page_number = (entrylo >> 6) & 0xFFFFFF
        return (address & page_mask) | (physical_page_number * PAGE_SIZE_LUT[tlb_entry_tuple[0].pagemask()])

    def print_info(self):
        pass


class Bffi(object):
    def __init__(self):
        self._rom_hash = None
        
        self._ipc = 0
        self._initial_sp = 0
        self._initial_gp = None
        
        self._tlb: BffiTlb = None
        self._bss_sections: dict[int,BffiBssSegment] = {}
        self._seg_sections: dict[int,BffiCodeSegment] = {}
        self._fix_sections: dict[int,BffiCodeSegment] = {}

        self._required_memory_size = 0

    def rom_hash(self) -> bytes:
        return self._rom_hash

    def serialize(self) -> bytes:
        buffer = bytearray()

        # magic word goes first
        buffer += b'BFFI'

        # version field
        buffer.append(0)

        # memory size required (0 = works for both 4mb and 8mb systems)
        buffer.append(self._required_memory_size)

        # unused/reserved, leave zero
        buffer.append(0)
        buffer.append(0)

        # --- metadata ---

        if self._rom_hash is not None and self._rom_hash != bytes([0] * 32):
            buffer += _serialize_section_type_only(BffiSectionType.SHA)
            buffer += self._rom_hash

        # --- end of metadata, start of stuff actually needed by the loader ---

        # TLB must be setup before bss and fix segments get loaded
        if self._tlb is not None:
            buffer += self._tlb.serialize()

        # BSS sections next
        for section_id, bss in self._bss_sections.items():
            buffer += _serialize_bss(section_id, bss.virtual_load_address(), bss.section_size(), bss.initial_word())

        # section data lives somewhere else in the file
        # so we have to queue things for serialization instead of doing that right away.
        # the file structure is seg/fix stuff
        queued_headers = []

        # then isp followed by ipc
        # ipc MUST be the last in the file
        if self._initial_sp != 0:
            queued_headers.append(_serialize_section_type_with_single_u32(BffiSectionType.ISP, self._initial_sp))
        else:
            logger.warning("UH OH: BFFI serialized without initial stackpointer value!")
        
        if self._ipc != 0:
            queued_headers.append(_serialize_section_type_with_single_u32(BffiSectionType.IPC, self._ipc))
        else:
            logger.warning("BIG PROBLEM: BFFI serialized without entry point!")

        if self._initial_gp is not None:
            queued_headers.append(_serialize_section_type_with_single_u32(BffiSectionType.IGP, self._initial_gp))

        # queue explicit EOF too for tools that need it
        queued_headers.append(_serialize_section_type_only(BffiSectionType.EOF))

        # now we can know the size of all headers to be flushed to the file.
        # calc size of fix/seg headers
        total_headers_size = len(buffer) + (len(self._fix_sections) * 28) +  (len(self._seg_sections) * 28)
        for queued_header in queued_headers:
            total_headers_size += len(queued_header)
        
        logger.info("section data will be at file offset: 0x%08x", total_headers_size)

        queued_section_data = []
        queued_section_data_size = 0

        queued_section_headers = []

        for segment_id, segment in self._fix_sections.items():
            # no compression for the time being
            contents = segment.contents()
            uncompressed_size = len(contents)
            crc = zlib.crc32(contents)
            queued_section_data.append( segment.contents() )

            queued_section_headers.append(_serialize_fix_or_seg(BffiSectionType.FIX,
                                                    segment_id,
                                                    total_headers_size + queued_section_data_size,
                                                    segment.virtual_load_address(),
                                                    uncompressed_size,
                                                    uncompressed_size,
                                                    crc,
                                                    0))

            queued_section_data_size += len(segment.contents())
        
        for segment_id, segment in self._seg_sections.items():
            # no compression for the time being
            contents = segment.contents()
            uncompressed_size = len(contents)
            crc = zlib.crc32(contents)
            queued_section_data.append( segment.contents() )

            queued_section_headers.append(_serialize_fix_or_seg(BffiSectionType.SEG,
                                                    segment_id,
                                                    total_headers_size + queued_section_data_size,
                                                    segment.virtual_load_address(),
                                                    uncompressed_size,
                                                    uncompressed_size,
                                                    crc,
                                                    0))

            queued_section_data_size += len(segment.contents())

        # now flush everything queued for serialization to the file
        for h in queued_section_headers + queued_headers:
            buffer += h

        if len(buffer) != total_headers_size:
            raise RuntimeError(f"estimated header size was wrong. expected {total_headers_size}, got {len(buffer)}")

        for s in queued_section_data:
            buffer += s

        return buffer

class BffiBssSegment():
    '''
    Init-to-zero (or some other word) segment.
    '''
    def __init__(self):
        self._virtual_load_address = 0x00000000
        self._section_size = 0
        self._initial_word = 0x00000000

    def virtual_load_address(self, new_virtual_load_address: int | None = None):
        if new_virtual_load_address is not None:
            self._virtual_load_address = new_virtual_load_address
        return self._virtual_load_address

    def section_size(self, new_section_size: int | None = None):
        if new_section_size is not None:
            self._section_size = new_section_size
        return self._section_size

    def initial_word(self, new_initial_word: int | None = None):
        if new_initial_word is not None:
            self._initial_word = new_initial_word
        return self._initial_word

class BffiCodeSegment():
    '''
    Code segment, loaded statically (`fix`) or dynamically (`seg`).
    '''

    def __init__(self):
        self._segment_type = BffiSectionType.FIX
        self._id = 0
        self._virtual_load_address = 0
        self._contents = bytes([])

    def segment_type(self, new_segment_type: BffiSectionType | None = None):
        if new_segment_type is not None:
            self._segment_type = new_segment_type
        return self._segment_type

    def id(self, new_id: int | None = None):
        if new_id is not None:
            self._id = new_id
        return self._id

    def virtual_load_address(self, new_virtual_load_address: int | None = None):
        if new_virtual_load_address is not None:
            self._virtual_load_address = new_virtual_load_address
        return self._virtual_load_address

    def contents(self, new_contents: bytes | None = None):
        if new_contents is not None:
            self._contents = bytes(new_contents)
        return self._contents

class BffiBuilder(object):
    def __init__(self):
        self._ipc = 0
        self._initial_sp = 0
        self._initial_gp = None
        self._rom_hash = bytes([0] * 32)

        # loaded once
        self._fix_segments = {}
        self._current_fix_segment_id = 0

        # segments swapped in/out during runtime (code overlays/dlls)
        self._seg_segments = {}
        self._current_seg_segment_id = 0

        # dynamic memory areas (metadata only; not actually used to load anything)
        self._dyn_segments = []

        self._bss_segments = {}
        self._current_bss_segment_id = 0

        # memory copy operations
        self._copy_ops = []

        # required memory size
        # 0 = works on both 4 mb and 8 mb systems
        # 4 = 4 mb systems only
        # 8 = 8 mb systems only
        #
        # reason for this is in case games build completely different code for 4mb/8mb systems,
        # and for games that require the expansion pak
        self._required_memory_size = 0

    def rom_hash(self, romhash: bytes):
        if isinstance(romhash, str):
            romhash = bytes.fromhex(romhash)
        if len(romhash) != 32:
            raise RuntimeError(f"romhash should be 32 bytes (or padded), instead got {len(romhash)} byte(s)")
        self._rom_hash = romhash
        return self

    def initial_tlb(self, tlb):
        pass

    def bss(self,
            virtual_start_address: int,
            sizeof: int,
            init_word: int = 0x00000000):
        
        if sizeof == 0:
            logger.warning("tried to add BSS segment of size zero, silently ignoring it")
            return self

        segment = BffiBssSegment()
        segment.virtual_load_address(virtual_start_address)
        segment.section_size(sizeof)
        segment.initial_word(init_word)

        self._bss_segments[self._current_bss_segment_id] = segment
        self._current_bss_segment_id += 1

        return self

    def dyn(self,
            virtual_start_address: int,
            sizeof: int):
        pass


    def fix(self,
            virtual_load_address: int,
            contents: bytes,
            segment_id: int | None = None):
        
        segment = BffiCodeSegment()
        segment.segment_type(BffiSectionType.FIX)
        segment.virtual_load_address(virtual_load_address)
        segment.contents(contents)

        actual_segment_id = 0
        if segment_id is None:
            actual_segment_id = self._current_fix_segment_id
            self._current_fix_segment_id += 1
        else:
            actual_segment_id = segment_id

        self._fix_segments[actual_segment_id] = segment

        return self

    def seg(self,
            virtual_load_address: int,
            contents: bytes,
            segment_id: int | None = None):
        segment = BffiCodeSegment()
        segment.segment_type(BffiSectionType.SEG)
        segment.virtual_load_address(virtual_load_address)
        segment.contents(contents)

        actual_segment_id = 0
        if segment_id is None:
            actual_segment_id = self._current_seg_segment_id
            self._current_seg_segment_id += 1
        else:
            actual_segment_id = segment_id

        self._seg_segments[actual_segment_id] = segment

        return self
    
    def copy(self,
             source_address: int,
             target_address: int,
             length: int):
        
        copy_op = BffiCopyEntry()
        copy_op.source_address(source_address)
        copy_op.target_address(target_address)
        copy_op.copy_length(length)
        copy_op._finalize()

        self._copy_ops.append(copy_op)

    def required_memory_size(self, megabytes: int):
        self._required_memory_size = megabytes

    def initial_program_counter(self, virtual_address: int):
        self._ipc = virtual_address
        return self

    def initial_global_pointer(self, virtual_address: int):
        self._initial_gp = virtual_address
        return self

    def initial_stack_pointer(self, virtual_address: int):
        self._initial_sp = virtual_address
        return self

    def build(self) -> Bffi:
        bffi = Bffi()

        bffi._initial_sp = self._initial_sp
        bffi._ipc = self._ipc
        bffi._initial_gp = self._initial_gp
        bffi._rom_hash = self._rom_hash

        bffi._fix_sections = self._fix_segments
        bffi._seg_sections = self._seg_segments
        bffi._bss_sections = self._bss_segments
        bffi._required_memory_size = self._required_memory_size

        return bffi

# --------------------------------------------------------------------------------

def _deserialize_section_marker(buffer: bytes, offset: int) -> tuple[BffiSectionType,int,int,int]:
    '''
    Parse section type. Return tuple `(section_type, section_id, unused_1, unused_2)`.
    '''
    unused_1, section_id, unused_2, section_type_ordinal = \
        struct.unpack(">BBBB",buffer[offset:offset+4])

    return BffiSectionType(section_type_ordinal), section_id, unused_1, unused_2

def _parse_copy(buffer: bytes, offset: int) -> tuple[int,int,int,int,int]:
    _, source_address, target_address, length = struct.unpack(">IIII", buffer[offset:offset+16])
    return offset+16, source_address, target_address, length

def _parse_bss(buffer: bytes, offset: int) -> tuple:
    _, load_address, load_size_in_u32s, initial_word = struct.unpack(">IIII", buffer[offset:offset+16])
    return offset+16, load_address, load_size_in_u32s, initial_word

def _parse_fix_and_seg(buffer: bytes, offset: int, segment_fetch_cb) -> tuple:
    _, source_offset, load_address, uncompressed_size, compressed_size, \
        payload_crc, compression_mode, unused_1, unused_2, unused_3 = \
            struct.unpack(">IIIIIIBBBB", buffer[offset:offset+28])


    segment_size = compressed_size if compression_mode != 0 else uncompressed_size
    payload = segment_fetch_cb(source_offset, segment_size)

    if compression_mode == 1:
        # zlib deflate
        payload = zlib.decompress(payload)

    if payload_crc != zlib.crc32(payload):
        raise RuntimeError("payload CRC32 check FAILED.")

    return offset, load_address, payload

def _parse_sha(buffer: bytes, offset: int) -> tuple[int,bytes]:
    return (offset+4+32), buffer[4:4+32]

def _parse_dyn(buffer: bytes, offset: int):
    _, start_address, length = struct.unpack(">III", buffer[offset:offset+12])
    return offset+12, start_address, length

def _parse_origin(buffer: bytes, offset: int):
    _, __, segment_type_value, ___, segment_id, origin_rom_address, origin_size = struct.unpack(">IBBBBII", buffer[offset:offset+16])
    segment_type = BffiSectionType(segment_type_value)

    if segment_type not in [BffiSectionType.FIX, BffiSectionType.SEG]:
        raise RuntimeError(f"illegal section type in origin: {segment_type}")

    return offset+16, segment_type, segment_id, origin_rom_address, origin_size

def _handle_tlb_set(buffer: bytes, offset: int, current_tlb_idx: int, tlb: BffiTlb) -> tuple[int,int]:
    _, pagehi, pagelo0, pagelo1, pagemask = struct.unpack(">IIIII", buffer[offset:offset+20])

    entry = BffiTlbEntry()
    entry.entryhi(pagehi)
    entry.entrylo0(pagelo0)
    entry.entrylo1(pagelo1)
    entry.pagemask(pagemask)

    tlb.entry(current_tlb_idx, entry)

    return offset+20, current_tlb_idx+1

def _handle_tlb_unmap(buffer: bytes, offset: int, current_tlb_idx: int, tlb: BffiTlb) -> tuple[int,int]:
    entry = tlb.entry(current_tlb_idx)
    
    entry = BffiTlbEntry()
    entry.entryhi(0x80000000)
    entry.entrylo0(0)
    entry.entrylo1(0)
    entry.pagemask(0)
    tlb.entry(current_tlb_idx, entry)

    return offset+4, current_tlb_idx+1

def _handle_tlb_unmap_range(buffer: bytes, offset: int, current_tlb_idx: int, tlb: BffiTlb) -> tuple[int,int]:
    _, count = struct.unpack(">II", buffer[offset:offset+8])

    for _ in range(count):
        entry = BffiTlbEntry()
        entry.entryhi(0x80000000)
        entry.entrylo0(0)
        entry.entrylo1(0)
        entry.pagemask(0)
        tlb.entry(current_tlb_idx, entry)

        current_tlb_idx += 1

    return offset+8, current_tlb_idx

def _parse_generic_u32(buffer: bytes, offset: int) -> tuple[int,int]:
    return offset+4, struct.unpack(">I",buffer[offset:offset+4])[0]


def bffi_parse_from_binary(data: bytes, segment_fetch_cb) -> Bffi | None:
    if data[0:4] != bytes(['B','F','F','I']):
        logger.error("not a BFFI: magic word didn't match")
        return None
    
    if (data[4] >> 4) != 0:
        logger.error("version is not 0")
        return None

    offset = 8
    tlb : BffiTlb = None
    current_tlb_idx = 0

    keep_reading = True

    builder = BffiBuilder()

    while keep_reading:
        section_type, _, __, ___ = _deserialize_section_marker(data, offset)

        match section_type:
            case BffiSectionType.EOF:
                keep_reading = False
                break

            case BffiSectionType.BSS:
                offset, load_address, load_size_in_u32s, initial_word = _parse_bss(data, offset)

                builder.bss(load_address, load_size_in_u32s, init_word=initial_word)

            case BffiSectionType.FIX:
                offset, load_address, data = _parse_fix_and_seg(data, offset, segment_fetch_cb)
                builder.fix(load_address, data)

            case BffiSectionType.SEG:
                offset, load_address, data = _parse_fix_and_seg(data, offset, segment_fetch_cb)
                builder.seg(load_address, data)

            case BffiSectionType.COPY:
                offset, source_address, target_address, length = _parse_copy(data, offset)
                builder.copy(source_address, target_address, length)

            case BffiSectionType.ISP:
                offset, isp = _parse_generic_u32(data, offset)
                builder.initial_stack_pointer(isp)

            case BffiSectionType.IPC:
                offset, ipc = _parse_generic_u32(data, offset)
                builder.initial_program_counter(ipc)
                keep_reading = False
                break

            case BffiSectionType.TLB_IDX:
                if tlb is None:
                    tlb = BffiTlb()

                offset, tlb_index = _parse_generic_u32(data, offset)
                current_tlb_idx = tlb_index

            case BffiSectionType.TLB_RND:
                if tlb is None:
                    tlb = BffiTlb()

                offset, tlb_random = _parse_generic_u32(data, offset)
                tlb.random(tlb_random)

            case BffiSectionType.TLB_UNMAP_RANGE:
                if tlb is None:
                    tlb = BffiTlb()

                offset, current_tlb_idx = _handle_tlb_unmap_range(data, offset, current_tlb_idx, tlb)

            case BffiSectionType.TLB_SET:
                if tlb is None:
                    tlb = BffiTlb()

                offset, current_tlb_idx = _handle_tlb_set(data, offset, current_tlb_idx, tlb)

            case BffiSectionType.TLB_UNMAP:
                if tlb is None:
                    tlb = BffiTlb()

                offset, current_tlb_idx = _handle_tlb_unmap(data, offset, current_tlb_idx, tlb)

            case BffiSectionType.SHA:
                offset, sha = _parse_sha(data, offset)
                builder.rom_hash(sha)

            case BffiSectionType.DYN:
                offset, start_address, length = _parse_dyn(data, offset)
                builder.dyn(start_address, length)

            case BffiSectionType.ORIGIN:
                offset, segment_type, segment_id, origin_rom_address, origin_rom_length = _parse_origin(data, offset)
                pass

            case _:
                raise RuntimeError("unrecognized section type")



    if tlb is not None:
        builder.initial_tlb(tlb)

    return builder.build()

