'''
Zed Two
'''

# ------------------------------------------------
#
# Wetrix
# Very likely a single load game
#
# Readcart routine at 0x80032df0, $a0=ROM address, $a1=RAM address, $a2=sizeof
#
# The game will load resources by allocating memory for them through
# 80039504 ($a0=sizeof, $a1=resource name), then loading them straight from ROM.
# It doesn't look like any code is loaded from ROM besides the bootexe.
#
# ------------------------------------------------
