from bffi import BffiTlb, BffiTlbEntry


def _generate_default_unwired_entry():
    entry = BffiTlbEntry()
    entry.pagemask(0)
    entry.entryhi(0x80000000)
    entry.entrylo0(1)
    entry.entrylo1(1)
    return entry

def tlbutil_generate_bffi_tlb(pages: dict[int,BffiTlbEntry]) -> BffiTlb:
    '''
    Generates a BffiTlb from a page configuration.

    Inputs:
    - pages: dict pointing page_id -> BffiTlbEntry. page_id must be between 0x00-0x1F
      inclusive; anything else will be ignored. Any page id that isn't wired here
      will use a default unwired entry, so if you only pass a dict with one TLB entry
      assigned to page 0, then pages 0x01-0x1F will be set to the default unwired entry.
    '''

    tlb = BffiTlb()
    for i in range(0x20):
        if i in pages:
            tlb.entry(i, pages[i])
        else:
            tlb.entry(i, _generate_default_unwired_entry())

    return tlb


def tlbutil_pack_entrylo( page_physical_address, flags ) -> int:
    pfn = (page_physical_address >> 6) & 0xFFFFFFC0
    flags &= 0x1F
    return pfn | flags