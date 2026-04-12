import sys
import logging
from argparse import ArgumentParser,RawTextHelpFormatter

from bffi import BffiBuilder, Bffi
from n64rom import load_rom, load_rom_from_zip, N64Rom
from n64cic import get_cic
from games import GAME_SPECIFIC_UNPACKERS

from preamble import identify_preamble, Preamble, preamble_extract_bss_sections_to_bffi


logger = logging.getLogger(__name__)

def _init_argparser():
    argparser = ArgumentParser(formatter_class=RawTextHelpFormatter,
                               prog='unpack64')
    
    argparser.add_argument("n64rom_in",
                           nargs='?',
                           help="Input N64 ROM (.z64, .v64, .zip)")
  
    argparser.add_argument("bffi_out",
                           nargs='?',
                           help="Output .bffi file")
    
    argparser.add_argument("--ident-only",
                           default=False,
                           action='store_true',
                           help="Only try identifying preamble type; do not try unpacking")
  
    return argparser

def auto_unpack(rom: N64Rom) -> Bffi:
    cic = get_cic(rom)

    bootexe_entry_point = cic.entry_point(rom)
    logger.info("bootexe entry point: 0x%08x", bootexe_entry_point)
    preamble = identify_preamble(rom.boot_exe(), bootexe_entry_point)
    
    if preamble is None:
        logger.error("preamble can't be identified, unable to unpack rom...")
        return None

    logger.info("preamble identified as: %s", preamble.type())
    
    if preamble.deep_trace_required():
        logger.error("preamble requires deep trace (bootexe uses custom packer), stopping auto-unpack.")
        return None
    
    bffibuilder = BffiBuilder()

    crt_entry_point        = preamble.crt_entry_point()
    initial_stack_pointer  = preamble.initial_stack_pointer()

    bffibuilder.initial_program_counter(crt_entry_point)
    logger.info("crt entry point: 0x%08x", crt_entry_point)

    bffibuilder.initial_stack_pointer(initial_stack_pointer)
    logger.info("initial stack pointer: 0x%08x", initial_stack_pointer)

    earliest_bss_address, bss_total_size = preamble_extract_bss_sections_to_bffi(preamble, bffibuilder)
    
    if bss_total_size < 0x1000:
        logger.error("total BSS section size is below acceptable threshold (total size %d byte(s)), custom packer likely used. stopping.",bss_total_size)
        return None
    
    # create fix segment for all code between start of bootexe to first BSS section.
    # this is often enough to accurately capture the boot executable.
    # again, if there are problems, that's what the game-specific drivers are for...

    code = None
    if (bootexe_entry_point <= earliest_bss_address < (bootexe_entry_point + 0x00100000)) is False:
        logger.warning("earliest BSS segment starts outside of the bootexe; entire bootexe will be included in fix segment")
        code = rom.boot_exe()
    else:
        code = rom.boot_exe()[:earliest_bss_address-bootexe_entry_point]
    
    # rareware games are decidely not single-load games and will decompress their code.
    # banjo-kazooie is 20k, blast corps is 16k, etc.
    # this attempts to catch that situation, as it's expected the main libultra functions
    # plus the game's common logic will be way more than 32k in size.
    if len(code) < 32*1024:
        logger.error("fix segment is below acceptable threshold (total size %d byte(s)), way too small for a typical N64 game. custom packer likely used. stopping.", len(code))
        return None

    logger.info("fix segment is %d byte(s)", len(code))
    bffibuilder.fix(bootexe_entry_point, code)

    return bffibuilder.build()

def unpack_rom(rom: N64Rom) -> Bffi | None:
    # first, hash the ROM and try to find a game-specific unpacker for it,
    # as that's how we'll know how to find all the various code overlays
    rom_hash = rom.sha256()

    bffi = None

    if rom_hash in GAME_SPECIFIC_UNPACKERS:
        cic = get_cic(rom)
        bootexe_entry_point = cic.entry_point(rom)

        logger.info("game-specific unpacker found, jumping to it...")
        unpack_fcn = GAME_SPECIFIC_UNPACKERS[rom_hash]

        return unpack_fcn(rom, bootexe_entry_point)

    logger.warning("no game specific unpacker found for this ROM, running in automatic mode (can produce invalid results). rom sha256 hash was: %s", rom_hash)
    return auto_unpack(rom)

def main():
    argparser = _init_argparser()
    args = argparser.parse_args()

    if args.n64rom_in is None or args.bffi_out is None:
        logger.error("must specify input and output files")
        return
    
    rom = None
    if args.n64rom_in.endswith(".z64") or args.n64rom_in.endswith(".v64") or args.n64rom_in.endswith(".n64"):
        rom = load_rom(args.n64rom_in)
    elif args.n64rom_in.endswith(".zip"):
        rom = load_rom_from_zip(args.n64rom_in)
    else:
        logger.error("file doesn't have a valid extension, must be one of: .z64, .v64, .n64, .zip")
        return

    if rom is None:
        logger.error("unable to load ROM, stopping.")
        return
    
    if args.ident_only:
        romhash = rom.sha256()
        if romhash in GAME_SPECIFIC_UNPACKERS:
            logger.info("%s: ROM is in the game-specific unpacker dict (sha256 = %s), no point identifying...", args.n64rom_in, romhash)
            return
        
        cic = get_cic(rom)
        bootexe_entry_point = cic.entry_point(rom)
        logger.info("bootexe entry point: 0x%08x", bootexe_entry_point)
        preamble = identify_preamble(rom.boot_exe(), bootexe_entry_point)
        if preamble is None:
            logger.error("%s: unable to identify preamble", args.n64rom_in)
            return

        logger.info("%s: preamble type is: %s", args.n64rom_in, preamble.type())

        return

    bffi = unpack_rom(rom)

    if bffi is None:
        logger.error("unpack failed!")
        return None
    
    # serialize BFFI and write it to a file
    logger.info("serializing BFFI...")
    serialized = bffi.serialize()
    
    if serialized is None:
        logger.error("serialize failed!")
        return None
    
    logger.info("attempt write to: %s", args.bffi_out)
    with open(args.bffi_out, "wb") as f:
        f.write(serialized)
    

if __name__ == "__main__":
    logging.basicConfig(filename='/dev/null', level=logging.DEBUG)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    logging.getLogger().addHandler(handler)
    main()
