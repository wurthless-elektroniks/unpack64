'''
Game-specific unpacker drivers.
'''

from .ecwwwf import ecwwf_unpack
from .extremeg import extremeg_unpack
from .sarge  import sarge_unpack
from .iguana import turok_unpack, allstar99_unpack
from .ubisoft import ray2us_unpack
from .tlb import tlb_try_detect_singleton

# points hash -> unpacker function.
# unpacker function accepts (rom: N64Rom, ipc: int) and returns a BFFI.
# ROM filenames are from an ancient goodn64 set, except where noted
GAME_SPECIFIC_UNPACKERS = {

    # ------------------------------------------------------
    # ECW / WWF games using the ECW variant of Acclaim's RNC packer
    # ------------------------------------------------------

    # ECW Hardcore Revolution (U) [!]
    "c12c0f6579d9e49762658c73a58bf5b9a82fab154e29952039b7f8d231869d13": ecwwf_unpack,

    # ECW Hardcore Revolution (E) [!]
    "4902bdb739cea1eb5722a120bf046776eb2bb11bbd9a455f181555f9ea528e48": ecwwf_unpack,

    # WWF - War Zone (U) [!]
    "ee4f5a036423b78449475fa09471de6148ff6972d0510098943bc83092f990b5": ecwwf_unpack,

    # WWF - War Zone (E) [!]
    "75539b5fa0bcb196d7dae076d9317ac21864f953b63dcb78c85e7f4fb4144501": ecwwf_unpack,

    # WWF Attitude (U) [!]
    "a6702c3a7a535b785ad4bd75cdca2e1f15fca59556824b7c54bdae56ecae34d3": ecwwf_unpack,

    # WWF Attitude (E) [!]
    "403189fe4c003396404f12589e29ec9d6342d908ef87d9d3fc315aa3fa555c06": ecwwf_unpack,

    # WWF Attitude (G) [!]
    "97b7d1fa75de75181f9a4785ea9d7efc109a8cdcf26627fc3194aacdc3ebf268": ecwwf_unpack,

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


    # All-Star Baseball '99 (U) [!]
    "018f19f4174f4efd2c2bb7aabf92a9218436bdbbf2fd65085801d6c86a0a9516": allstar99_unpack,

    # All-Star Baseball '99 (E) [!]
    "94c4b3f6964109fe237e158ba5a659d5c05b14361f35f6c36a3e6583434782ef": allstar99_unpack,

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
    # Rayman 2 and other Ubisoft games using the same engine
    # ------------------------------------------------------
    "e9a71380b43e25b998f638480b309e300ad9b8a0439ff36e0a8b5fc4ac132e8a": ray2us_unpack,

    #
    # Extreme-G LZSS packer
    #
    "9e67bc574e40ef273759d587972655003d5213e625bfa68d3071dc9782d2071c": extremeg_unpack,

    # ------------------------------------------------------
    # Games using standard TLB but nothing else that's fancy
    # ------------------------------------------------------

    # Re-Volt (U) [!]
    #"826fd84fb778f6ddaa8bc14cbf116fb25bf1bf6ed4b833d7e30501be6f144823": tlb_try_detect_singleton,
    
    # Turok 2 (testing only)
    #"a182ff273697bd337c17be427041a1dee6dec0f90d7d62407843c5eabb7e6ef0": tlb_try_detect_singleton,

    # ------------------------------------------------------
}
