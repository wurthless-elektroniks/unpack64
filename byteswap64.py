'''
Everyone ought to have a ROM byteswap utility in their toolchain.
'''

import sys
import logging
from argparse import ArgumentParser,RawTextHelpFormatter
from n64rom import load_rom, load_rom_from_zip, ROMENDIANNESS_BIG

logger = logging.getLogger(__name__)

def _init_argparser():
    argparser = ArgumentParser(formatter_class=RawTextHelpFormatter,
                               prog='byteswap64')
    
    argparser.add_argument("n64rom_in",
                           nargs='?',
                           help="Input N64 ROM (.z64, .v64, .zip)")
  
    argparser.add_argument("z64_out",
                           nargs='?',
                           help="Output .z64 big-endian byteswapped ROM")
    
    return argparser

def main():
    argparser = _init_argparser()
    args = argparser.parse_args()

    if args.n64rom_in is None or args.z64_out is None:
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
    
    if rom.endianness() == ROMENDIANNESS_BIG:
        logger.error("ROM is already big-endian")
        return
    
    with open(args.z64_out, "wb") as f:
        f.write(rom.read_bytes_until_end(0))
    
    logger.info("wrote byteswapped ROM ok!")

if __name__ == "__main__":
    logging.basicConfig(filename='/dev/null', level=logging.DEBUG)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    logging.getLogger().addHandler(handler)
    main()
