# unpack64: Nintendo 64 executable unpacker

This is a tool that dumps boot executables (and associated code) out of Nintendo 64 ROMs
for use with other tools. It outputs the binary data in a custom format ([BFFI](docs/bffi.md)) which
was specifically designed for this task.

unpack64 is part of a wider project called fakepfs, which aims to patch N64 games to use save devices
other than the Controller Pak. It was mothballed for being way too complex, so this repo is part of
an attempt to bring that project out of cold storage. (Whether or not it'll actually ever be complete
is another matter...)

## Usage

To use it:

`python3 unpack64.py rom_in.z64 binary_out.bffi`

For most games, it should be enough to dump only the boot executable for your romhacking adventures,
as the bootexe will contain most commonly used libultra functions, which will in turn be used by the
various code overlays.

The majority of N64 games will work fine with automatic mode, but any game using a packed boot executable
or the TLB will have problems, and will need game-specific unpackers.

If you want to display information about a ROM (or ROMs):

`python3 rominfo.py rom.z64`

which should tell you basic stuff about the ROM so you can tell which games still need proper support:

```
        game code: NT2E
        game name: Turok 2: Seeds of Ev
        CIC type:  6102
        SHA-256:   a182ff273697bd337c17be427041a1dee6dec0f90d7d62407843c5eabb7e6ef0
        CRC32:     ff5e7636
        load address/ipc:  80000400

        preamble type:   nustd with no .bss, probably packed + TLB: unmap 0x00-0x1E/map 0x1F
        initial $sp:     803fffc0
        crt entry point: 0028d380

        no .bss sections detected - custom packer likely used
```

## So how do these games boot, anyway?

Nintendo 64 games do not use a common boot executable format. Instead, the IPL3 bootloader will
copy the first megabyte of the cartridge to RDRAM and jump to it. For the most part, programmers
fell back on the standard Nintendo/SGI boot stub to clear .bss segments before jumping to the C
runtime entry point, which calls `osInitialize()` to setup basic system parameters, then creates
and starts the idle process thread (the first call to `osStartThread()` never returns).

The simplest way a game can boot is... uh... how do I put this politely... just as I described it.
When IPL3 reads in that 1 MB of cartridge, all the code is there and there's no need to load any
more executable data.

Most games, though, do not do this, because it's inefficient. You'd have the entire game
code loaded in RDRAM, of which there's only 4 MB (8 with the Expansion Pak), meaning that if
one specific boss in the game calls a routine that makes it shit itself before it dies, that
routine - and the rest of the boss code - remains loaded the entire time and thus wastes space.
Even worse is that all that code has chewed up space in ROM, and if it's the 1990s, developers
would frown at this because the cost of a 64 megabit (8 megabyte) mask ROM would be stupid expensive.

So, to save ROM and RAM space, programmers used some combination of the following:

- Compression: The obvious one, just zip up the code and unzip it at run time.
  Rare liked to use zlib and gzip for this task, while Acclaim's various studios,
  particularly Iguana Entertainment, preferred variants on the more oldschool Rob
  Northen Compression suite. Sometimes, though, you'll run into completely custom
  decompressors that will make you hate your life (Mario Tennis does this).

- Statically-linked code overlays: Instead of loading all the code in memory at once,
  the game swaps out different segments as it is running. Each overlay will load to the
  same address every time, so there's no need to implement a whole ELF-like loader; just
  swap in the segment, clear caches, and keep on going.

- Dynamically-linked code overlays: This one's for the programmers who are masochistic
  enough to implement an executable loader and linker on a console with limited memory
  resources. The advantage is that you can load the code you want, when you want, where
  you want, allowing them to be mixed in with a normal memory heap, but the problem is
  you need to keep track of what module calls what and where they are all located, so
  any memory efficiency you gain could be cancelled out by the dynamic linker.
  Nintendo experimented with this for 1080 Snowboarding and the Zelda games.

And we can't forget to mention the games that insist on using virtual memory! Games
will use virtual memory to fake there being more space for code than there actually is.
The typical implementation swaps 4kbyte pages to a cache in memory, then sets the TLB
to point at those pages, relying on the TLB miss exception to swap pages in as appropriate.
Acclaim were the worst offenders with virtual memory, but Factor 5 and Rareware also used the TLB.

Even someone who can't understand all of that technobabble can guess that this all makes
disassembling N64 games a real pain, to the point where half of the N64 romhacking
and code analysis tools out there tell their users to just make a savestate or memory
dump from an emulator instead of implementing all of these unpackers themselves.
Nobody is that much of an insane idiot to do that, anyways. Except for me, of course.

### I am a boring nerd and that shit sounds interesting. Which are the most interesting games?

Dynamically loaded and relocatable code segments:

- 1080 Snowboarding (uses full DLL implementation with imports and exports)
- Beetle Adventure Racing!
- Dobutsu no Mori / Animal Forest (uses the Zelda framework)
- Duck Dodgers Starring Daffy Duck
- Indy Racing 2000
- F-1 World Grand Prix
- F-1 World Grand Prix II
- Zelda: Ocarina of Time
- Zelda: Majora's Mask

Games using virtual memory:

- All-Star Baseball 2000
- All-Star Baseball 2001
- Armorines: Project S.W.A.R.M.
- GoldenEye 007
- Indiana Jones and the Infernal Machine
- Jeremy McGrath Supercross 2000
- NBA Jam 2000
- NFL Quarterback Club 99
- NFL Quarterback Club 2000
- NFL Quarterback Club 2001
- Perfect Dark
- Re-Volt
- Star Wars Episode 1: Battle for Naboo
- South Park
- South Park: Chef's Luv Shack
- Turok 2: Seeds of Evil
- Turok 3: Shadow of Oblivion

Serious boot executable abuse:

- Excitebike 64: Boot executable displays the "N64 SPORTS" logo while it loads
  the main code (its own boot executable), then runs it. The "N64 SPORTS" logo
  code is completely unloaded afterwards.

Expansion Pak games that don't officially support the Expansion Pak:

- 1080 Snowboarding: Allocates extra heap space when extra memory is present.
  Presumably allows for more resources to be loaded into memory so that they
  don't have to be swapped out later.

- South Park: Chef's Luv Shack: Uses Acclaim's contemporary framework and one-shot
  loads overlays if the Expansion Pak is present. 

## What does all of this mean for decomp projects?

Probably not much. Most decomp projects are already far enough along so this project won't
add much value to them. For decomp projects just starting out, maybe it'll be of some use,
but many of the unpackers are still a work in progress, and others might never be completed.

## Will this thing ever be able to unpack game resources (not just code)?

Not sure, it'd take a hell of a refactor to support that, and it would also mean supporting
a lot more compression algorithms. I just want to patch games, not do total conversions...

## License

Public domain
