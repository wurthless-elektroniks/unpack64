'''
Ubisoft games on the Rayman 2 engine, which are decidedly not single-load games.

Rayman 2 (US) has a function at 0x800026D8 which we'll call ReadCart.
It clears caches, kicks off a DMA transfer through osPiStartDma(), then optionally
blocks until the transfer completes (using osRecvMesg()).

It takes the parameters:
    void ReadCart(a0 = rom_start_address,
                  a1 = rom_end_address,
                  a2 = rdram_address,
                  a3 = dma_is_async)

Tonic Trouble and Donald Duck - Goin' Quackers are built off the same engine so
they'll probably boot the same way.
'''

from preamble import identify_preamble
from n64rom import N64Rom
from bffi import Bffi,BffiBuilder,BffiSectionType

#
# Rayman 2 (US)
#
# Code overlays are as follows:
# - seg0: 0x1DCC0~0xC5BF0 --> 80025C50: seems like the main engine code
#   bonus french swearing debugmessage "C'est quoi ce bordel !?!??!"" ("what the fuck is this?")
# - seg1: 0xC5BF0~0xD0A20 --> 800F64A0: Controller Pak menuing, loaded from 0x80000B20
#
# TODO: make this reusable instead of doing all games ad hoc, if possible.

def ray2us_unpack(rom: N64Rom, ipc: int) -> Bffi:
    # standard preamble. nothing exciting here
    preamble = identify_preamble(rom.boot_exe(), ipc)

    builder = BffiBuilder()
    builder.rom_hash(rom.sha256())

    for start_addr,end_addr in preamble.bss_sections():
        builder.bss(start_addr,end_addr-start_addr)

    # TODO: remove hardcoding, if possible
    builder.fix(0x80000400, rom.boot_exe()[:0x1CCC0])
    builder.seg(0x80025C50, rom.read_bytes(0x1DCC0,0xC5BF0-0x1DCC0), segment_id=0)
    builder.seg(0x800F64A0, rom.read_bytes(0xC5BF0,0xD0A20-0xC5BF0), segment_id=1)
    
    builder.initial_program_counter(preamble.crt_entry_point())
    builder.initial_stack_pointer(preamble.initial_stack_pointer())

    return builder.build()
