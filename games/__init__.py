'''
Game-specific unpacker drivers.
'''

from .acclaim import armorines_unpack, southpark_unpack
from .bam import bam99_unpack
from .bottomup import sumo_unpack, alice_unpack, onegai_unpack
from .dma import sssv_unpack, bodyharvest_unpack
from .dualheroes import dualheroes_unpack
from .ea import nhl99_unpack, nbalive2k_unpack
from .ecwwwf import ecwwf_unpack
from .edgeofreality import erz_unpack
from .excitebike import excitebike_unpack
from .extremeg import extremeg_unpack, xg2_unpack
from .factor5 import rogue_us_unpack, rogue_jp_unpack, indy_unpack
from .forsaken import forsaken_unpack
from .gauntlet import gauntlet_unpack
from .hal import kirby64_unpack, smash64_unpack
from .konami import deadlyarts_unpack, castlevania_unpack
from .mariotennis import mariotennis_unpack
from .midway import sfrush_unpack, rush2_unpack, calispeed_unpack, \
                    cruisnusa_unpack, cruisnexotica_unpack
from .mspacman import mspacman_unpack
from .nintendo import sm64_unpack, drmario_unpack
from .paradigm import aerofighters_unpack, beetle_unpack
from .rare import bk_unpack, blastcorps_unpack, dk64us_unpack, dk64jp_unpack
from .sarge  import sarge_unpack
from .slugfest import slugfest_unpack
from .iguana import turok_unpack, allstar99_unpack, allstar2k_unpack, nbajam2k_unpack, \
                    chef_unpack
from .worms import worms_unpack, worms_eu_unpack
from .ubisoft import ray2_unpack
from .uso import uso_unpack
from .zelda import dobutsu_unpack


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

    # NBA Jam 2000 (U) [!]
    "c41d5622e96280fb00d8c2f17a80fc5cf9520b4b209788a6240e152a1c88c540": nbajam2k_unpack,

    # NBA Jam 2000 (E) [!]
    "76778e298da9b3929c1659c2374d19df1d542fb2db89ff5be7d53c7dfa267fca": nbajam2k_unpack,

    # All-Star Baseball 2000 (U) [!]
    "f354489d79d6ca69a43f3bf95e0e112a6d3a20acdbf96ae847c4180aa0154791": allstar2k_unpack,

    # All-Star Baseball 2000 (E) [!]
    "2e30b758271c441eab2ed35dcf3a542fd46782522607c2fd6b1663771b756e07": allstar2k_unpack,

    # All-Star Baseball 2001 (U) [!]
    "35313f399fd98072bd7dd22d98814bb2b5e49aadcc654b51d558b639c438f144": allstar2k_unpack,

    # South Park - Chef's Luv Shack (U) [!]
    "71219cf4aaab9884b7d026d1676bfbc00eaae2f0e05d1c0a09836b42473ea575": chef_unpack,

    # South Park - Chef's Luv Shack (E) [!]
    "808c16c10a8c60998b743f7ed96ec82363172dfeccc1035d2cbd527bdc9df6d0": chef_unpack,

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
    # Rayman 2 and other Ubisoft games using the Openspace engine
    # ------------------------------------------------------

    # Rayman 2 - The Great Escape (U) (M5) [!]
    "e9a71380b43e25b998f638480b309e300ad9b8a0439ff36e0a8b5fc4ac132e8a": ray2_unpack,

    # Rayman 2 - The Great Escape (E) (M5) [!]
    "c80b063de6afe80bb47281efe76406654070e942d5a733fee2668c8e11a2581b": ray2_unpack,

    # Disney's Donald Duck - Goin' Quackers (U) [!]
    "eccdbe42168f6b5efcaadcedda1cc811181d9b3ffdbd8ce8a8e6558a711a4368": ray2_unpack,

    # Donald Duck - Quack Attack (E) (M5) [!]
    "89ddd46cf3f360359d40aebf7068714ca5f6eb5b436a93150f307c0969954c0c": ray2_unpack,

    # ------------------------------------------------------
    # Extreme-G LZSS packer
    # ------------------------------------------------------

    # Extreme-G (U) [!]
    "9e67bc574e40ef273759d587972655003d5213e625bfa68d3071dc9782d2071c": extremeg_unpack,

    # Extreme-G (J) [!]
    "a4784b478525cef90be5576a1acfde1ca23bac254535952811f22385d5e03601": extremeg_unpack,

    # Extreme-G (E) (M5) [!]
    "45cfbf079b7c5777ee47f3b86c643eeeb406acb2a84c95ec4ab2b5e2d754107b": extremeg_unpack,

    # Extreme-G XG2 (U) [!]
    "0b5d9904cf45a92396396308506da0ae258afe44a902c96e50d0ff4969c67500": xg2_unpack,

    # Extreme-G XG2 (J) [!]
    "5004c79552feb976b72aec4fa3e3eba2e19f7e7b6233be58acee9f7b7fb75cbe": xg2_unpack,

    # Extreme-G XG2 (E) (M5) [!]
    "de1deae125b6f17048cb240132dbfe918b8fec61fe2ed1fe8e5a2e03995211b3": xg2_unpack,

    # ------------------------------------------------------
    # Rareware DEFLATE-based unpacker (zlib or gzip)
    # ------------------------------------------------------

    # Banjo-Kazooie (U) (v1.0) [!]
    "59875835b9a5128bb0054315a7f929e2071c2001e528d70bf543e1d6680e6eff": bk_unpack,

    # Banjo to Kazooie no Daibouken (J) [!]
    "f766bdb553dd38bf1ce1b9395647aa44abb85503ef08592c8c1a94b15eb6dbfb": bk_unpack,

    # Banjo-Kazooie (E) (M3) [!]
    "d4e7534d8bcdc329386bf28dcb86e35136e793622f3e6913342500d17e89a931": bk_unpack,

    # Blast Corps (U) (V1.0) [!]
    "902769f9d27d888a35d8bdbec88ae9f4f3f33583323475678e99b6456eeaa6f5": blastcorps_unpack,

    # Blast Corps (U) (V1.1) [!]
    "42e4d8cde3c106637a25bbfa62d74cc2e5c1eed1d64de5bbb0b1c4896b185927": blastcorps_unpack,

    # Blast Corps (E) (M2) [!]
    "9a9246c1128ae4e1cfc6b9b0137894a9575202ce9cd62bf4b9405fb0cdfbd506": blastcorps_unpack,

    # Blast Dozer (J) [!]
    "88b8ab9ea99dd0d226c3699d1386c7e4b3253ce0b4ab1d298855a4c82bd28229": blastcorps_unpack,

    # Donkey Kong 64 (U) [!]
    "b6347d9f1f75d38a88d829b4f80b1acf0d93344170a5fbe9546c484dae416ce3": dk64us_unpack,

    # Donkey Kong 64 (J) [!]
    "8a6a5b48b0a4d5d31fa59608e65bafe787b8664fbc9dbaecbcce16e41e8934cd": dk64jp_unpack,

    # Donkey Kong 64 (E) [!]
    "f704ddc06dda5bee065dd89adcf86aa58bd817684e190094cd0776c0cabba9df": dk64jp_unpack,


    # ------------------------------------------------------
    # Bust-A-Move '99 with .bss-less preamble, that instead initializes .bss
    # in CRT startup function
    # ------------------------------------------------------

    # Bust-A-Move '99 (U) [!]
    "2932dae8bcce7cb86bbc15c5f1cca96ba5838c486398d445b248276f1203b501": bam99_unpack,

    # Bust-A-Move 3 DX (E) [!]
    "b8847b703aff8ff887d58b482067fc8dece91856503685b20249c25066c4657c": bam99_unpack,

    # Puzzle Bobble 64 (J) [!]
    "754ffac52da6d7ccd024c61aaef9305ddd6991130c678783122ac69a0a25c717": bam99_unpack,

    # ------------------------------------------------------
    #
    # Factor 5 games
    #
    # ------------------------------------------------------

    # Star Wars - Rogue Squadron (U) (M3) [!].z64
    "9c32d0087fa2b83c5ee6f19ee86683907653ed8f30e7d4680a0adac334559dd7": rogue_us_unpack,

    # Star Wars - Shutsugeki! Rogue Chuutai (J) [!]
    "6c13a4b27820ab17f8e9d67775cf68f6df757c62babc6347542e5d456770878c": rogue_jp_unpack,

    # Star Wars - Rogue Squadron (E) (M3) (V1.0) [!]
    "a33b6b738116c36e78a0d078ceb9ff7ddaa7b36244689421fa7d85d70ccc2273": rogue_us_unpack,

    # Star Wars - Rogue Squadron (E) (M3) (V1.1) [!]
    "592b37eed2730ae25232b163dea6632cf6b9ed21dd3be35c0500a939b897627b": rogue_jp_unpack,

    # Indiana Jones and the Infernal Machine (U) [!]
    "6e127e592f098a28c92d2032d71c56af1412e5dd189fe792d9238b12a0928c59": indy_unpack,

    # Star Wars Episode I - Battle for Naboo (U) [!]
    "515b2302fefe1741c09103f70708690a058ba77a7ab8acd086c48b972b22d33e": indy_unpack,

    # Star Wars Episode I - Battle for Naboo (E) [!]
    "b5bdfe343a2b24cad636b66cac0af54ac04aefbfa26a817957227cc24ced4846": indy_unpack,    

    # ------------------------------------------------------
    #
    # Mario Tennis
    #
    # ------------------------------------------------------

    # Mario Tennis (U) [!]
    "6341ec31c937eddf6fab5c848470c9b7c27f43a42a494a7a1aae943eb91d90fb": mariotennis_unpack,

    # Mario Tennis (E) [!]
    "1d9add31b3cf320657ada5295954de12061070cede84dfa6dd1245e9c6548838": mariotennis_unpack,

    # Mario Tennis 64 (J) [!]
    "b8d053a22ea2764904f32ed19daa60552e1bca28e1f1c074f4e4c59c91b9fe47": mariotennis_unpack,

    # ------------------------------------------------------
    #
    # Gauntlet Legends
    # TLB + zlib bootloader + filesystem combo!!
    #
    # ------------------------------------------------------

    # Gauntlet Legends (U) [!]
    "1cc9cb70686b4785c46fff337ded30a2e1f83f2d63768ad8041e978ad0379ec9": gauntlet_unpack,

    # Gauntlet Legends (J) [!]
    "4e27d82c476bfaa48172aa6230b2d5beb66a7f326d915b1e2e4ad0ccf7736d24": gauntlet_unpack,

    # Gauntlet Legends (E) [!]
    "344a04c993618acdbf01f8bc7283874d77ebcc78c534a49f3ac2e38ca61e38a9": gauntlet_unpack,

    # ------------------------------------------------------
    #
    # Forsaken 64
    # Semi-custom preamble and RNC-based overlay loader
    #
    # ------------------------------------------------------

    # Forsaken 64 (U) [!]
    "e323fa5e482244ac7b520fd09393c59ddfca6be0666fbb1325554324a945abe0": forsaken_unpack,

    # Forsaken 64 (E) (M4) [!]
    "a94eb83c9e68906d1cfb320bb3d07c74b74f6fa1ac9c57d291e5801cc15e9289": forsaken_unpack,

    # Forsaken 64 (G) [!]
    "bbe52d306ec9382629e3cc8c6cc14dcf7c9052c89ce3c0ad6172c8975d77795f": forsaken_unpack,

    # ------------------------------------------------------
    # Edge of Reality games using the ERZ (custom RNC) unpacker
    # ------------------------------------------------------

    # Monster Truck Madness 64 (U) [!]
    "52501f827a677df01ba3861b1f4616c7e6bb47dc000e174267c8fbed9e4ae3dd": erz_unpack,

    # Monster Truck Madness 64 (E) [!]
    "eb84ef801d3723c3709fc62b5551c5cc83887015d4831392039e99f236eb0c76": erz_unpack,

    # Spider-Man (U) [!]
    "feff90ed1201c91ff167d66958048e61c192c9d6a756ddb98f799017ac9cd25c": erz_unpack,

    # Tony Hawk's Pro Skater (U) (V1.0) [!]
    "f96e1688a360214844421a230a782a0c0215dddfab81f1bfedade0364648ee52": erz_unpack,

    # Tony Hawk's Pro Skater (E) [!]
    "10eb3aa1501d8172a711c4bc939fec65afd1f2d79f51e11c59235ca4c29f3585": erz_unpack,

    # Tony Hawk's Pro Skater 2 (U) [!]
    "6ac38612aaae84f8bba22a33a165c17fba3072b16999edcc9a86ab726008d726": erz_unpack,

    # Tony Hawk's Pro Skater 2 (E) [!]
    "1f675f4a3c73d4e985fb72764a80a6a2b28fd888152d438efcfe629d0d80180c": erz_unpack,

    # Tony Hawk's Pro Skater 3 (U)
    "93c8a1be89390ef27e5f2da709ca16c9a24936538766c6774640cf534c9d2aee": erz_unpack,

    # ------------------------------------------------------
    # "USO" dynamic loader that 1080 Snowboarding uses
    # ------------------------------------------------------

    # 1080 Snowboarding (JU) (M2) [!]
    "5e9d7168e5786ba1bd4b643431ba7100ff3d7a09e558acae15438d426c0f34df": uso_unpack,

    # 1080 Snowboarding (E) (M4) [!]
    "a5d47b9b21bc2c234a0e5c8a1f7eb0e893a914e17a0755318b48c5ad15b7d13c": uso_unpack,

    # ------------------------------------------------------
    # Bottom Up games
    # ------------------------------------------------------
    
    # 64 Oozumo (J) [!]
    "661420aa5a7b5c0f86aad0dad813a0c876b99267d9d92fed0f4507e8e2a37240": sumo_unpack,

    # 64 Trump Collection - Alice no Wakuwaku Trump World (J) [!]
    "afc2eedcd4e7cfe6fd0e56259a45d58ed5647f7ce64fad6d2199312ea564de6f": alice_unpack,

    # 64 Oozumou 2 (J) [!]
    "3ff701b4735c84b17f8d80a996db59801caa766ee7da4d3e5a3b88eb34d99a17": alice_unpack,

    # Onegai Monsters (J) [b1]
    # TODO: get newer N64 romset with a good dump for this
    "057c1596dee9c18a912a39263011cf8b65036c9535b301d9455ab8a08b66c60a": onegai_unpack,

    # ------------------------------------------------------
    # Angel Studios's Griffey games
    # ------------------------------------------------------

    # Ken Griffey Jr.'s Slugfest (U) [!]
    "85bea38c90d9f6e023afea3053207b46ed8397a55e682fad2727c744e645b6e5": slugfest_unpack,
    
    # Major League Baseball Featuring Ken Griffey Jr. (U) [!]
    "c489d247f13d0ac6ba71b3bbc6052100a8d582576df8e2a80988ee20b1dcb821": slugfest_unpack,

    # Major League Baseball Featuring Ken Griffey Jr. (E) [!]
    "5e2c3a938d237b81b0c2c446c264c9f72832ddb667af4dfd9582fd6a206680a4": slugfest_unpack,

    # ------------------------------------------------------
    # HAL games
    # ------------------------------------------------------

    # Kirby 64 - The Crystal Shards (U) [!]
    "2f579751d7ad2824dfd8a6141570306bfaeda1cff40139ba231c30b8591d681c": kirby64_unpack,

    # Hoshi no Kirby 64 (J) (V1.0) [!]
    "c01a3223483e7dad87db8e4b9a4b0860983585278b7295c92544849dab5258cb": kirby64_unpack,

    # Kirby 64 - The Crystal Shards (E) [!]
    "391a33a74dedffb870aad78c19d1d8c443f4b6963c582066ee77b14b343ba520": kirby64_unpack,

    # Super Smash Bros. (U) [!]
    "15592e79d3c5295cef4371d4992f0bd25bec2102fc29644c93e682f7ea99ef3d": smash64_unpack,

    # Nintendo All-Star! Dairantou Smash Brothers (J) [!]
    "527bdd5a36d6f1b90988523ac8d44276e32b44cf93f609ef6d76f399c9733f25": smash64_unpack,

    # Super Smash Bros. (E) (M3) [!]
    "ddc65284e78c301f764d2f5e1e01de9a017225867a0b9326b73057fb8bdb1daf": smash64_unpack,

    # Super Smash Bros. (A) [!]
    "ae6bc07dec084e10bf8ed6364964425d29cd2dacf427c9f06e35fb33290f78bf": smash64_unpack,

    # Shigesato Itoi's No. 1 Bass Fishing! Definitive Edition (J) [b1]
    "c1b4179d25a583efd494117ec754adad43606572bf328049e4cc209a32fa2041": smash64_unpack,

    # Pokemon Snap (U) [!]
    "a1d5d816db7f8557ee04c35a011326d058b2c1fbca76b57b352b1d705a1ec1cc": smash64_unpack,

    # Pocket Monsters Snap (J) [!]
    "f13e6bf81048af5618ddc35f0fbe6c9a4e3345cc53d7360355c5bb87b0b9afa4": smash64_unpack,

    # Pokemon Snap (E) [!]
    "5fe996f65900f83376ff96cb54fcad2da40010700fe4e36cb006a59737f969f1": smash64_unpack,

    # Pokemon Snap (F) [!]
    "ddafdca5aeaef7f00aa3a844baf4e950d212c0ccb213664c8ae1a2266b3612ae": smash64_unpack,

    # Pokemon Snap (G) [!]
    "f4866ef4187c2357cc921624e8f8d35ad5a2832281dfe91a70ec04628d47ef5a": smash64_unpack,

    # Pokemon Snap (I) [!]
    "5ad74c877ae900acd927e71cc3841d9f4e522f83b453688061266ef2eab154c4": smash64_unpack,

    # Pokemon Snap (S) [!]
    "3bf1549b5443cdb3e6e7c74617646f6ad881394b70df01e43cbe8025a10efd97": smash64_unpack,

    # Pokemon Snap (A) [!]
    "9e0974fc8a43b93493f057e0c62bfd955ec2e70f65d578a89c5eae6cf7742b4a": smash64_unpack,

    # Pokemon Snap Station (U) [!]
    "95bea63075551b8fa171b104f5d4d51fa405bb38d61bd57f6a31c038b6213ca0": smash64_unpack,

    # ------------------------------------------------------
    # Paradigm Entertainment
    # ------------------------------------------------------

    # Pilotwings 64 (U) [!]
    "32e3056e854bda2e1d79ce5d050548ffcdef51003aacb0a0fd0328c70eff31b2": aerofighters_unpack,

    # Pilotwings 64 (J) [!]
    "69bb7ca8e2a320ecd6f1851ef4f0caeece67457fa5475408e2dc0bec0e364b8f": aerofighters_unpack,    

    # Pilotwings 64 (E) (M3) [!]
    "afe1c8ea27446b6dcf98d8eed92338db0031edf95419bccf4c95be292166fd84": aerofighters_unpack,

    # AeroFighters Assault (U) [!]
    "5abd27f2be286d6814d64c76a521a80b2b07d03802a71bc03e61e80a16b27931": aerofighters_unpack,

    # AeroFighters Assault (E) (M3) [!]
    "be4a5d9c32e79334ddbe1611136b6a7c31c1e41a2a1024bbc32eec6632855c4d": aerofighters_unpack,

    # Sonic Wings Assault (J) [!]
    "febf0934f6d2b792b9668df33fab18fc7d51d64a2ef8b88fe4ffbe43ee12c512": aerofighters_unpack,

    # F-1 World Grand Prix (U) [!]
    "b5470d259dfebcdf7910257479ff47792bcc83e82f6c70131d4363d7ecb6e7a0": beetle_unpack,

    # F-1 World Grand Prix (J) [!]
    "756bfcd4f823a5306520ad48d14d43b94392e5a8c922653328165b109f1be147": beetle_unpack,

    # F-1 World Grand Prix (E) [!]
    "94c0cfff085a9e1768d840d9b48f226d6a6c12692e629bf0bb0b1b5f7d955b27": beetle_unpack,

    # F-1 World Grand Prix (F) [!]
    "673a8da8fc0dadf665d54f2cfcf319f8f876941dc0f691d956c6e7afebb4e346": beetle_unpack,

    # F-1 World Grand Prix (G) [!]
    "b64f5b9a3c4afc1907aa71f81edd7df91222a961bd346e0ef57bba6d25900fb4": beetle_unpack,

    # Beetle Adventure Racing! (U) (M3) [!]
    # FIXME: one module fails to load
    "6addd60de277c83351eff83099e4dab25ac45279b6401728cfda9eea2f1380df": beetle_unpack,

    # Beetle Adventure Racing! (E) (M3) [!]
    # FIXME: one module fails to load
    "ef0c7bfa39712b841cc0d5b87ab6f8faf15a6877e587168a48ddff0c9c3bef87": beetle_unpack,

    # HSV Adventure Racing (A)
    # FIXME: one module fails to load
    "c1ab44c36d2442d8f3e2123bd976a2c2768a0940ebe4ac14408db924241e5a6d": beetle_unpack,

    # F-1 World Grand Prix II (E) (M4) [!]
    # FIXME: one module referenced by the boot segment doesn't load and the unpack fails
    # "84ad927e250a746b24ab6a9c35264a008d7c27c216da37e5ec1dd46c4c5f699f": beetle_unpack,

    # Duck Dodgers Starring Daffy Duck (U) (M3) [!]
    "2bbfe0cfc6aff7b623ae53673b8f91e9008cc5749fe07920712e0d0f9abe3fc5": beetle_unpack,

    # Looney Tunes - Duck Dodgers (E) (M6) [!]
    "296938fb1192d721944e2036b988262af9c556cf432ff9353623495f7e297bb9": beetle_unpack,

    # Indy Racing 2000 (U) [!].z64
    "1a4672323200183efef8df6e9f4ec6bab230f76731407386a72dbebf6d984d08": beetle_unpack,

    # ------------------------------------------------------
    # Ms. Pacman and its unusual unpacker
    # ------------------------------------------------------

    "e11a9f47257696d29b62c831c1a577b262437cdbed953f9c08fbaf022397efbe": mspacman_unpack,

    # ------------------------------------------------------
    # Various Midway games
    # ------------------------------------------------------

    # San Francisco Rush - Extreme Racing (U) (M3) [!]
    "493960054c6749048d9a1f9f01df5f99a8a5983f19e033606ae4b85beffb3841": sfrush_unpack,

    # San Francisco Rush - Extreme Racing (E) (M3) [!]
    "344a58277fd5f833b7c5dbae8c6f947fba391c2fd74e56c9604640fd68dc553b": sfrush_unpack,

    # Rush 2 - Extreme Racing USA (U) [!]
    "a59e65822d46775ca91d98b1220bcdea9acb54e48e56a7b5c026a3a877c08eb5": rush2_unpack,

    # Rush 2 - Extreme Racing USA (E) (M6) [!]
    "fbc02c5a58f42f88de3ae595ddce3ebbfd6d866f1c39ea346addcedca997cd2a": rush2_unpack,

    # San Francisco Rush 2049 (U) [!]
    "83c4964d513718e99cd3569bc33108308cee983eb24bf057c25b366a9160f92c": rush2_unpack,

    # San Francisco Rush 2049 (E) (M6) [!]
    "40bd50dfe6bc41f38323000927b37f2c0a02d8d0090b1db4882576c39eabf2e4": rush2_unpack,

    # California Speed (U) [!]
    "32d083c6570a92614f7ed8221b136ca45eb3d06ca98d8a8342e0a366563ba791": calispeed_unpack,

    # NFL Blitz (U) [!]
    "1c37ed9d1d88122dd174b6258fa72b23b404b4c64a259592504392fa7e21e41e": calispeed_unpack,

    # NFL Blitz 2000 (U) [!]
    "81fd09077c4be225eea90539b0fddc56339b5d1afd7e313b5d08e0c795aeefeb": calispeed_unpack,

    # NFL Blitz 2001 (U) [!]
    "c2e8d6f62dc75dcb6f7fda50311b010385ec85d61c88280f1e6e973d0bb5228d": calispeed_unpack,

    # NFL Blitz - Special Edition (U) [!]
    "8e861e75e7f16a9baefe2d82525240b68dfb79e01933571537dc5967dd482cc0": calispeed_unpack,

    # Cruis'n USA (U) (V1.0) [!]
    "2eee547273101e02bb96d0ef3db5e400f0506fba77397719d33b1072617c0558": cruisnusa_unpack,

    # Cruis'n USA (U) (V1.1) [!]
    "9c7cf76974a0219575ff0fc007f9fb2ccd9c1971b7571e3c6269a946f095df5b": cruisnusa_unpack,

    # Cruis'n USA (U) (V1.2) [!]
    "86db95f334c54fd900db7dce9a2f5880e933cc3650e4e4ebfc2def0f4bcd59c6": cruisnusa_unpack,

    # Cruis'n USA (E) [!]
    "25fd3ca587edc8316080f28814b7a22fddce2338ef22ac23ed61dbc87b4d8473": cruisnusa_unpack,

    # Cruis'n Exotica (U) [!]
    "d26ecb1b3a3dc965acc1063cc243ab573bf5ffca310e96aff2f6d2265a49f0b1": cruisnexotica_unpack,

    # Cruis'n World appears to be a single-load game...

    # ------------------------------------------------------
    # Worms Armageddon
    # ------------------------------------------------------

    # Worms - Armageddon (U) (M3) [!]
    "42f408c8d3448233c7f452188270057875164cf763c9194a1bb8e8c8014a9468": worms_unpack,

    # Worms - Armageddon (E) (M6) [!]
    "d79ebabeef2d0a913c910497e73bf7d188c012fd578ec66a855d7bdbaa6d5bdc": worms_eu_unpack,

    # ------------------------------------------------------
    # Konami
    # ------------------------------------------------------

    # Deadly Arts (U) [!]
    "80ba81827277bc1f171a00c4669406a3ef51d419f3aa0d510b9b567b43531a2c": deadlyarts_unpack,

    # G.A.S.P!! Fighter's NEXTream (J) [!]
    "77f06356547f3da2d2631d7d4ee9a9c193bb2f2052cac5a9f93a2f0dc3ece84f": deadlyarts_unpack,

    # G.A.S.P!! Fighter's NEXTream (E) [!]
    "dcb4b7c2c53b1505e12db2136af1dea4877ba1be446d4524c2bca18dbe65acd3": deadlyarts_unpack,

    # Castlevania (U) (V1.0) [!]
    "0237b439a3adcc2e6c1b24b4ff1b24d2f0d8f04a2d0cc29b8b67cb075f1903c5": castlevania_unpack,

    # Castlevania (U) (V1.2) [!]
    "0f53f12e85bcf5799c8c8e9e71957e20c434f8f5823ab95bd1f54c33c16e7b1c": castlevania_unpack,

    # Akumajou Dracula Mokushiroku - Real Action Adventure (J) [!]
    "f5b8a1bd8dd4d03b5fe291428b284ca30d9afd300fe25f60317aa1e4590db638": castlevania_unpack,

    # Castlevania (E) (M3) [!]
    "902f060c7787ffdf83f547203eb1182c737714a2bec5f42c409f05b26ecdb9dc": castlevania_unpack,

    # Castlevania - Legacy of Darkness (U) [!]
    "89e15df6042defddc48c61f7408f99d06fffdb845e2422cf8b5ba8e73d4d70fb": castlevania_unpack,

    # Akumajou Dracula Mokushiroku Gaiden - Legend of Cornell (J) [!]
    "51a0443883f3f94b20b6fb9a8688631c51bc7feafb143c51e48dc7198adfd1ca": castlevania_unpack,

    # Castlevania - Legacy of Darkness (E) (M3) [!]
    "e78c172c1d554d1c94865969cec9b87a2149c92ec69ebc52b73a46648b5b2395": castlevania_unpack,

    # Dance Dance Revolution - Disney Dancing Museum (J) [o1]
    "6faae1c2878a411a5cb1a3fcfef5456a3aa010b448a25b476d759365247ecd77": castlevania_unpack,

    # NBA In the Zone '98 (U) [!]
    "0422b2364cf1f7822dbdf4a64e297ea36155a99a6497368d4e844e51692957a2": castlevania_unpack,

    # NBA In the Zone '98 (J) [!]
    "8ac071ecf2786a3e3b14b7b10f2ef060c7c1bfb17a7a5621c4f3bc6e5bca35fe": castlevania_unpack,

    # NBA Pro 98 (E) [!]
    "90ed10e89d507758551d40e549520228acba39eccd495a4c3088b0e73f6c63c9": castlevania_unpack,

    # NBA In the Zone '99 (U) [!]
    "4189751eb5fc07932c7a440c7b448f8929ef8eba104aa1425f430737f284d609": castlevania_unpack,

    # NBA In the Zone 2 (J) [!]
    "74f80f1aa04eb5103bdf014d327b3aa707da45ba77e9f005d970764209d3c09e": castlevania_unpack,

    # NBA Pro 99 (E) [!]
    "765bb9b7b8f7a5660ac27459b92ef111e58ff710a88ff70599622492f0b2b96e": castlevania_unpack,

    # NHL Blades of Steel '99 (U) [!]
    "779fa692d07c6a322e189ec80183cb5fa700bbae1c8d5476a78d4ace3cfa4434": castlevania_unpack, 

    # Susume! Taisen Puzzle Dama Toukon! Marumata Chou (J) [!]
    "bf07279640b1c64287f02413794c8200769a74570d3cb0e5e5d22df4c1dda66e": castlevania_unpack,

    # ------------------------------------------------------
    # Super low priority Nintendo games
    # ------------------------------------------------------

    # Super Mario 64 (U) [!]
    "17ce077343c6133f8c9f2d6d6d9a4ab62c8cd2aa57c40aea1f490b4c8bb21d91": sm64_unpack,

    # Super Mario 64 (J) [!]
    "9cf7a80db321b07a8d461fe536c02c87b7412433953891cdec9191bfad2db317": sm64_unpack,

    # Super Mario 64 (E) (M3) [!]
    "c792e5ebcba34c8d98c0c44cf29747c8ee67e7b907fcc77887f9ff2523f80572": sm64_unpack,

    # Super Mario 64 - Shindou Edition (J) [!]
    "f8807b5e28f1b1a31c5d3675d23ece73f949ccb553dcbb07972666a1e76adfa2": sm64_unpack,

    # Dr. Mario 64 (U) [!]
    "bb2c0dec0a8287ad256929563d0509801c2f239df883c1cf52cab05b23bd77b6": drmario_unpack,

    # ------------------------------------------------------
    # DMA Design
    # ------------------------------------------------------

    # Space Station Silicon Valley (U) [!]
    "b125bf0d761547ba878e44ef83f9e1ec3f400da7c46cf9a404b6caee6f9ba473": sssv_unpack,

    # Space Station Silicon Valley (E) (M7) [!]
    "0b13e3a0d4c7eaeda6556fdcad9bf0e6aefad2696c827a820786bb123e9387b0": sssv_unpack,

    # Body Harvest (U) [!]
    "d4b2654d6d903e43454bffdf025eeb4a954d8fafefab64dc5f8cf0e6dd392a74": bodyharvest_unpack,

    # Body Harvest (E) (M3) [!]
    "e0340a9656384420eab6c92ac6e2d0b6eba38cb527cf1ec26e4b2057964984a4": bodyharvest_unpack,

    # ------------------------------------------------------
    # Excitebike 64
    # ------------------------------------------------------

    # Excitebike 64 (U) [!]
    "2909229be3cdaac1b5ead544648b970a23e8ea83c2c3a7f891ce121fefe918cc": excitebike_unpack,

    # Excitebike 64 (J) [!]
    "a2227d626690256f6d1242d5fe7c9bbbf8fa5aec2d803a0a138e1e09dd26b635": excitebike_unpack,

    # Excitebike 64 (E) [!]
    "a28143f7dc16e905ca4da25665875a2b0d5489bcc7310ce4465637537ab096d0": excitebike_unpack,

    # Excitebike 64 (U) (Kiosk Demo) [!]
    "cd056cc339b30b77d9a7afa99bc7f9203d655ba9e34ee4048cc0b36982458263": excitebike_unpack,
    
    # ------------------------------------------------------
    # Dual Heroes
    # ------------------------------------------------------

    # Dual Heroes (U) [!]
    "5715846bd3bf7da5c296e10384b7ff4ff6e94ee315856c4ad275d5c2ed9bd712": dualheroes_unpack,

    # Dual Heroes (J) [!]
    "2d390313b93fbc838ddda8225901f994d5953191853ed3f7549f48720767930c": dualheroes_unpack,

    # Dual Heroes (E) [!]
    "292ffc02db47118a4b94a5581394c2edf41d16f0f1d42e9cbfae73dad78f0b2f": dualheroes_unpack,


    # ------------------------------------------------------
    # Zelda games and other Nintendo junk using the same framework
    # ------------------------------------------------------

    # Doubutsu no Mori (J) [!]
    "d9417be056534fcc0bdff2e6cd5f1135511be7c0a4dace04a96a2649596ce908": dobutsu_unpack,

    # ------------------------------------------------------
    # EA games
    # ------------------------------------------------------
    
    # NHL 99 (U) [!]
    "bfab38dda9ff0fd465a2ce0eac9f604ca7806369bb02c711f625b9e111885c04": nhl99_unpack,

    # NHL 99 (E) [!]
    "1660afff428682d1b4852239bc4fab2e35b2fd14d6c2d9d339269430702df731": nhl99_unpack,

    # NBA Live 2000 (U) (M4) [!]
    "3f36da957e6e578f029adbe183d76a2c94352d90dd9ef75ddb3e151ea367eca7": nbalive2k_unpack,

    # NBA Live 2000 (E) (M4) [!]
    "d0c85a3035687673be6b4c38cfba3728a6c50cf7beee36fc3a8572f4013a512b": nbalive2k_unpack,

    # NBA Live 99 (U) (M5) [!]
    "1c37eb542195ca5a85eb0e2e67a92c34ff6700b0f7442e04a73b0fe79098381b": nbalive2k_unpack,

    # NBA Live 99 (E) (M5) [!]
    "f21ddf33f8e597a0b49e1dde2b0d9cf55d2b8fd007cf20a92996a0783f7de411": nbalive2k_unpack,

    # ------------------------------------------------------
    # Acclaim games using TLB but no packing
    #
    # n.b.: Turok 2 kiosk demo does NOT use the TLB at all
    # ------------------------------------------------------

    # Armorines - Project S.W.A.R.M. (U) [!]
    "6c999d00089e384a1d85bec52c3474d789f905a49726fc1d901cdc367ebf7524": armorines_unpack,

    # Armorines - Project S.W.A.R.M. (E) [!]
    "558588b3649c7313cc694610ce81344dfe9a829d63e315c7c108d1a27d7d987b": armorines_unpack,

    # Armorines - Project S.W.A.R.M. (G) [!]
    "aebd316ab12bae8bf84f2cab21023a3cb08ae1bec04f6bc574cad415dfb3c090": armorines_unpack,

    # Turok 2 - Seeds of Evil (U) (V1.0) [!]
    "a182ff273697bd337c17be427041a1dee6dec0f90d7d62407843c5eabb7e6ef0": armorines_unpack,

    # Turok 2 - Seeds of Evil (E) [!]
    "6c8ec2083adeb6eb7bc0aad865384f77a8f89a98ff21b74a630dd85e8256ebf8": armorines_unpack,

    # Turok 2 - Seeds of Evil (G) [!]
    "7545e13528bad67c540668777322ed82e69d7d76efdcd46e6bf46a48a1289f5d": armorines_unpack,

    # Violence Killer - Turok New Generation (J) [b1]
    "78eada162ac94ffef6ab1fcd0aefeef01c69151d1b5c1abf6ebe74e56aa96077": armorines_unpack,

    # South Park (U) [!]
    "68e87dbae05414026a126cb6e0c632e7660668a0003e1e1c975df8296e2a36a6": southpark_unpack,

    # South Park (E) (M3) [!]
    "e0cdb6f2c756febffc10266a5bf93ee853a0393de2f18353174e569303d3252c": southpark_unpack,

    # South Park (G) [!]
    "346ddcf6d1259bd31389267009d2caac74ddf79f608dfd826705e7c9fbfdad9e": southpark_unpack,    

    # ------------------------------------------------------
    # Games using standard TLB but nothing else that's fancy
    # ------------------------------------------------------

    # Re-Volt (U) [!]
    #"826fd84fb778f6ddaa8bc14cbf116fb25bf1bf6ed4b833d7e30501be6f144823": tlb_try_detect_singleton,
    
    # Turok 2 (testing only)
    #"a182ff273697bd337c17be427041a1dee6dec0f90d7d62407843c5eabb7e6ef0": tlb_try_detect_singleton,

    # ------------------------------------------------------
    # Confirmed single-load games
    #
    # Any game that does not need to be unpacked should be blacklisted
    # by setting its unpacker to None
    # ------------------------------------------------------

    # Jinsei Game 64 (J) [!] - appears to be single-load
    # "bfa3cbe991967318eecabac89883427ec29cf071373e97751dccc99cd7efe70d": None,

}
