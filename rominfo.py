
from argparse import ArgumentParser, RawTextHelpFormatter
import sys
import logging


from tlb import tlb_try_detect_preamble
from preamble import identify_preamble, preamble_extract_bss_sections_to_bffi
from n64rom import load_rom, load_rom_from_zip
from n64cic import get_cic
logger = logging.getLogger(__name__)

def _init_argparser():
    argparser = ArgumentParser(formatter_class=RawTextHelpFormatter,
                               prog='unpack64')

    argparser.add_argument("--directory",
                           default=False,
                           action='store_true',
                           help="Treat input path as a directory")

    argparser.add_argument("input",
                           nargs='?',
                           help="Input N64 ROM (.z64, .v64, .zip)")
  
    return argparser


def rominfo_main():
    argparser = _init_argparser()
    args = argparser.parse_args()

    if args.input is None:
        logger.error("must specify input")
        return

    inputrom = args.input
    rom = None
    if inputrom.endswith(".z64") or inputrom.endswith(".v64") or inputrom.endswith(".n64"):
        rom = load_rom(inputrom)
    elif inputrom.endswith(".zip"):
        rom = load_rom_from_zip(inputrom)
    else:
        logger.error("file doesn't have a valid extension, must be one of: .z64, .v64, .n64, .zip")
        exit(1)

    if rom is None:
        logger.error("unable to load ROM: %s",inputrom)
        exit(1)

    romhead = rom.header()
    cic = get_cic(rom)
    ipc = cic.entry_point(rom)

    print( \
f"""
{inputrom}
        game code: {romhead.game_id()}
        game name: {romhead.game_name()}
        CIC type:  {cic.name()}
        SHA-256:   {rom.sha256()}
        CRC32:     {rom.crc32():08x}
        load address/ipc:  {ipc:08x}""")
    
    preamble = identify_preamble(rom.boot_exe(), ipc)
    if preamble is None:
        _, preamble = tlb_try_detect_preamble(rom, ipc)
        if preamble is None:
            print(\
f"""
        preamble unrecognized - further analysis impossible.
        first two bytes of preamble: {rom.boot_exe()[0]:02x} {rom.boot_exe()[1]:02x}""")
            return
    
    print( \
f"""
        preamble type:   {preamble.type()}
        initial $sp:     {preamble.initial_stack_pointer():08x}
        crt entry point: {preamble.crt_entry_point():08x}""")
    
    earliest_bss_loc, bss_total_size = preamble_extract_bss_sections_to_bffi(preamble, None)

    if len(preamble.bss_sections()) == 0 or bss_total_size == 0:
        print( \
"""
        no .bss sections detected - custom packer likely used
""")
    else:
        for bss in preamble.bss_sections():
            print( \
f"        bss: {bss[0]:08x} ~ {bss[1]:08x} ({bss[1]-bss[0]} bytes)")
        print( \
f"        code: {ipc:08x} ~ {earliest_bss_loc:08x} ({earliest_bss_loc-ipc} bytes)")

if __name__ == "__main__":
    rominfo_main()
