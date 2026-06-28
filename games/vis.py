'''
VIS "Entertainment"

Games that go here:
- Earthworm Jim 3D
- Powerpuff Girls: Chemical X-Traction
- Tom and Jerry in Fists of Furry

These games all run on the same engine (the text "Jim textures and geometries" appears in all three).

Based on how Tom and Jerry acts, it seems these games are all single load.
There is no single readcart routine; osPiStartDma() is called across multiple functions, often
after the game allocates space on the heap for whatever resource is to be loaded.

The only time osInvalICache() is used is in a function that, in Tom and Jerry (U), is at 0x80082ccc.
This seems to be a debugging function that patches code, replacing whatever instructions with 0x0000040D
which represents the instruction `break 0x10`.

If it turns out these games do have overlays, then they will be revisited later...
'''
