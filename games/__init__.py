'''
Game-specific unpacker drivers.
'''

from .ecwwwf import ecwwf_unpack
from .sarge  import sarge_unpack
from .iguana import turok_unpack

# points hash -> unpacker function.
# unpacker function accepts (rom: N64Rom, ipc: int) and returns a BFFI.
# ROM filenames are from an ancient goodn64 set, except where noted
GAME_SPECIFIC_UNPACKERS = {

    # ------------------------------------------------------
    # ECW / WWF games using the ECW variant of Acclaim's RNC packer
    # ------------------------------------------------------

    # ECW Hardcore Revolution (U) [!]
    "c12c0f6579d9e49762658c73a58bf5b9a82fab154e29952039b7f8d231869d13": ecwwf_unpack,

    # ------------------------------------------------------
    # Most variants of the Iguana/Turok/Acclaim RNC unpacker
    # ------------------------------------------------------

    # Turok - Dinosaur Hunter (U) (V1.0) [!]
    "4111045ae8e05da883037906dc9f693d8e6f55ad6b3a0c43a9472c632486e082": turok_unpack,

    # Turok - Dinosaur Hunter (U) (V1.1) [!]
    "876dc5e9962962b3fdf6248b7611c62b0df117a855d987b39cf8ee1fb3257f96": turok_unpack,

    # Turok - Dinosaur Hunter (U) (V1.2) [!]
    "3f46508afd36173886f8a6ea65066663c431be9e1edb8d299356569d87e48bab": turok_unpack,

    # Turok - Dinosaur Hunter (E) (V1.0) [!]
    "9c9ea5dffe062ebc5038827a5b1d16100752561de6d904eec4186620bc351a0a": turok_unpack,

    # Turok - Dinosaur Hunter (E) (V1.1) [!]
    "0b55834cd737391353c2359f225253e6a2e9bf2121080d376aef7f9a36871d44": turok_unpack,

    # Turok - Dinosaur Hunter (E) (V1.2) [!]
    "4c12397d7a85896e488df15f1329f7fe66502323fcec589b7e0c726a1c93c969": turok_unpack,

    # Turok - Dinosaur Hunter (G) [!]
    "5bf631a7a35a44ce8f5f29e30c6882bb533a7ec09074549e21d32f8163d1ecf0": turok_unpack,

    # Tokisora Senshi Turok (J) [!] (actual name Jikuu Senshi Turok i.e. Turok 1 Japanese)
    "78cd7b8174f1e54bae8a77b1c1314a0a147752635b2c95668e34464fedcf4d2d": turok_unpack,

    # ------------------------------------------------------
    # 3DO / Sarge's Heroes games using a custom preamble
    # ------------------------------------------------------

    # Army Men - Sarge's Heroes (U) [!].z64
    "b1992d8069cb7c14d5be4c351578058631cae9e1b2f29656ae7fb9d5ecc1dc22": sarge_unpack,   
    # Army Men - Sarge's Heroes (E) (M3) [!].z64
    "25d3091b4d0713099006933349c4b6e01e79e1f108596abbc5342a4d7d647066": sarge_unpack,
    # Army Men - Sarge's Heroes 2 (U) [!].z64
    "ee8568e107b6d33128a5384d7614acac530cc834417e2c8e3d65e7ed9b82d546": sarge_unpack,

    # ------------------------------------------------------
}
