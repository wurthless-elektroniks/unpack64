'''
Paper Mario / Mario Story

This is another annoying game, mostly because Intelligent Systems decided to obfuscate
the boot process as a copy protection measure.

Copy protection consists of the following:

- IPL3 checks: base ROM addresses and other seeds are obfuscated using values relative
  to words scattered in the IPL3 program. Any mismatch (caused by filthy pirates swapping
  the IPL3 program) will cause the game to run off into the weeds.

- Integrity checks on loaded segments: Various game segments are checksummed, and then the
  checksums calculated are used in different ways, such as to calculate addresses for function
  calls.

A full decomp exists (https://github.com/pmret/papermario) but this needs to be supported for completeness...
'''
