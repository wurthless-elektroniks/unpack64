# unpack64: Nintendo 64 executable unpacker

This is a tool that dumps boot executables (and associated code) out of Nintendo 64 ROMs
for use with other tools. It outputs the binary data in a custom format ([BFFI](docs/bffi.md)) which
was specifically designed for this task.

Nintendo 64 games do not use a common boot executable format. Instead, the IPL3 bootloader will
copy the first megabyte of the cartridge to RDRAM and jump to it. For the most part, programmers
fell back on the standard Nintendo/SGI boot stub to clear .bss segments before jumping to the C
runtime entry point, which calls `osInitialize()` to setup basic system parameters, then creates
and starts the idle process thread (the first call to `osStartThread()` never returns).

unpack64 is part of a wider project called fakepfs, which aims to patch N64 games to use save devices
other than the Controller Pak. It was mothballed for being way too complex, so this repo is part of
an attempt to bring that project out of cold storage. (Whether or not it'll actually ever be complete
is another matter...)

To use it:

`python3 unpack64.py rom_in.z64 binary_out.bffi`

For most games, it should be enough to dump only the boot executable for your romhacking adventures,
as the bootexe will contain most commonly used libultra functions, which will in turn be used by the
various code overlays.

The majority of N64 games will work fine with automatic mode, but any game using a packed boot executable
or the TLB will have problems, and will need game-specific unpackers.

## License

Public domain
