# HEAVILY UNDER CONSTRUCTION

Code in bffi.py is to be considered "correct" until further notice...

# Binary Format for Fucking Idiots (BFFI)

BFFI (yes, it's pronounced "biffy") is a super basic format that represents a Nintendo 64 boot executable,
its sections, TLB initialization instructions, and other such data.

The first thing that any programmer is probably asking is "why not use ELF instead?"

- Unable to accurately represent N64 code as it is loaded in memory
- Can't be used to configure TLB
- Much more complex to parse, especially when you want to keep the binary loader code to as small a size as possible

## Basic file structure

First header:
- 4 bytes magic word ASCII `BFFI`
- 1 byte, two nibbles. Upper 4 BFFI file format version (leave 0), lower 4 BFFI type: 0 = file, 1 = as embedded in ROM (see "Source offset handling" below) 
- 3 bytes unused, leave 0

## Source offset handling

BFFI headers come in two varieties: the ones in a standalone .bffi file, and the ones that can be embedded
into an N64 ROM.

- **Type 0**: In .bffi files, the source offset points to an offset within the file itself.
- **Type 1**: When the .bffi is embedded in an N64 ROM, the source offset points to a PI address, allowing
  all the different sections to be scattered throughout the ROM instead of in one continuous blob.

## Section headers and how they are parsed

Each section begins with a 32-bit value identifying the section uniquely, as well as its type,
in the form `00 ii 00 tt`, where `ii` is the section unique identifier and `tt` is the type.

`0x00` through `0x07` inclusive are data fields:

- `0x00`: `eof` - explicit end-of-file marker (NOT guaranteed to be supported by all tools!!)
- `0x01`: `fix` - Fixed (always-loaded) sections of code
- `0x02`: `seg` - Overlay/DLL segments, not always loaded
- `0x03`: `bss` - BSS or other similar initialize-to-given-word section (special case, see below)
- `0x04`: `dyn` - Dynamically used memory pool section (so patchers or similar know not to put any patches there)
- `0x06`: `isp` - Initial stack pointer value
- `0x07`: `ipc` - Initial Program Counter value (entry point); **acts as end-of-file**

`0x08` through `0x0F` inclusive are TLB initialization commands:
- `0x10`: `tlbidx` - set TLB Index register
- `0x11`: `tlbrnd` - set TLB Random register
- `0x13`: `tlbset` - Write TLB entry at current Index, then increment Index value
- `0x14`: `tlbnull` - Write zero to TLB entry at current Index, then increment Index value

`0x08` through `0x0F` inclusive are metadata fields (NOT guaranteed to be supported by all tools!!):

- `0x08`: `dyn` - Dynamically used memory pool section (so patchers or similar know not to put any patches there)
- `0x0F`: `hash` - SHA-256 of the ROM this BFFI was generated from

### TLB initialziation

A handful of N64 games initialize the TLB before CRT startup, so the BFFI format provides a simple state machine to setup the TLB.

**The TLB MUST be initialized before the BSS and fix segments are loaded,** otherwise the CPU
will write to unmapped memory and crash. Consequently **all TLB instructions MUST be placed in the
file before all other section types (metadata excluded).**

On the N64 side, you can assume the following will be true:
- All MIPS cop0 registers and TLB entries will be in an undefined state at load time.
- The loader keeps track of the Index value in a MIPS register and increments it after a page entry is written.
- The Index value will default to 0.
- The cop0 Index register will be set to the current Index value before a page entry is written.

Using Re-Volt as an example:
```
    00 00 00 xx - clear entries 0x00-0x1E
    00 00 00 1F

    00 00 00 xx - set TLB entry 0x1F
    00 00 00 00   EntryHi  = 0x00000000
    00 00 00 01   EntryLo0 = 0x00000001
    00 00 00 1F   EntryLo1 = 0x0000001F
    00 1F E0 00   PageMask = 0x001FE000
                  index register will wrap to 0

    note: Random register is not used
```

### `fix`/`seg`: Loadable binary sections

- 4 bytes section/type identifier field
- 4 bytes source offset (see "Source offset handling")
- 4 bytes destination load address (MIPS virtual address, e.g., `0x80000400`)
- 4 bytes uncompressed/raw size
- 4 bytes compressed size if compression enabled, 0 otherwise
- 4 bytes payload CRC-32
- 1 byte compression mode (0 = uncompressed, 1 = zlib deflate, all others illegal)
- 1 byte when this segment is to be loaded (0 = before CRT startup, 1 = before idle thread creation)
- 2 bytes unused, leave 0

`fix` segments are loaded immediately on startup, while `seg` segments are dynamically-loaded code overlays
that are loaded whenever the game feels like it.

If you need to load a code stub into memory that'll get jettisoned later, like a dynamic patching routine,
you should use `fix`.


## `bss*`: BSS/similar sections

Handles `.bss` initialization and similar edge cases.

If any section starting with `bss` is encountered:
- 4 bytes section ID, set to `bss0`, `bss1`, etc.
- 4 bytes destination load address (MIPS virtual address, e.g., `0x80000400`)
- 4 bytes number of 32-bit words to write
- 4 bytes initial 32-bit word to fill memory with (for `.bss` sections, this will be `0x00000000`)

Cases in which something other than 0 is written:
- Army Men - Sarge's Heroes (and its sequel) insists on filling several segments with a non-zero value (`0x55555555`) at startup.

As with fix/overlay segments, **the section ID does not need to be printable.**

## `sha`: Hash of parent ROM

Hash of the ROM this BFFI file applies to. Used only for metadata in toolchains; **MUST NOT** be present when
encoded into a patched ROM.

- 4 bytes section ID, set to `sha\x00`
- 32 bytes SHA-256 hash of parent ROM

## `reg`: Initial GPR register value

- 4 bytes `reg` followed by GPR register value to set (0-31)
- 4 bytes absolute value of that GPR

Example: `reg`, 0x1F, 0x803FFFF0 sets register 31 (stack pointer) to 0x803FFFF0

## `ipc`: Initial Program Counter (entry point)

- 4 bytes section ID, set to `ipc\x00`
- 4 bytes absolute virtual MIPS address of the entry point

The `ipc` header **MUST** be the last entry in the BFFI header so that any N64 code running the parser
knows it's hit the end-of-file state. For the BFFI IPL (bffiboot), this will be a signal that everything that should
be loaded is loaded and it's time to jump to the entry point.

## `eof`: Explicit end-of-file marker

- 4 bytes `eof\x00`

This is for tools that will actually check for an end-of-file marker. As mentioned, the IPL will treat `ipc`
as the end-of-file marker.

