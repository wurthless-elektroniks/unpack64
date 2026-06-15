'''
Rareware games using the TLB

Games that go here:
- Conker's Bad Fur Day
- GoldenEye 007
- Perfect Dark

These games have been picked apart by the community and are therefore low priority.

Perfect Dark uses virtual memory on 4 MB systems. When the Expansion Pak
is present, it will load the swap segment to RAM in one shot.
'''

# ---------------------------------------------------------------
#
# Conker's Bad Fur Day
# 
# A very rude game with a very rude surprise: it's a TLB game.
# Even ruder is that the game is encrypted.
#
# Upon boot the game immediately maps all of RDRAM to 0x10000000, then
# jumps to the real entrypoint in RDRAM-mapped space.
#
# 0x42450 is a resource blob starting with a four-byte filesize and an
# encrypted table of contents. The game will immediately seek past this
# to a zlibbed blob at 0x188328, which contains the main code segment (I think).
#
# The resource table has a simple XOR encryption applied to it. Each resource
# address is XORed with 0x8039CCCA (applies to both US and European versions).
# Once decoded you'll have all the offsets you'll need to dump files out of the
# resource blob, each of course being zlibbed.
#
# ---------------------------------------------------------------
