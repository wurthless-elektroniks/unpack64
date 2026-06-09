'''
Game-specific unpacker drivers.
'''

from .acclaim import armorines_unpack, southpark_unpack, turok3_unpack, revolt_unpack, \
                     shadowman_unpack
from .bam import bam99_unpack
from .bottomup import sumo_unpack, alice_unpack, onegai_unpack
from .buckbumble import buckbumble_unpack
from .daikatana import daikatana_unpack
from .dma import sssv_unpack, bodyharvest_unpack
from .dualheroes import dualheroes_unpack
from .ea import nhl99_unpack, nbalive2k_unpack, wcw_unpack, kok2k_unpack, \
                fifa64_unpack
from .ecwwwf import ecwwf_unpack
from .edgeofreality import erz_unpack
from .excitebike import excitebike_unpack
from .eurocom import mk4_unpack
from .extremeg import extremeg_unpack, xg2_unpack
from .factor5 import rogue_unpack, indy_unpack
from .forsaken import forsaken_unpack
from .gauntlet import gauntlet_unpack
from .hal import kirby64_unpack, smash64_unpack
from .hudson import marioparty_unpack, bomberman64_unpack, bomberman2_unpack
from .human import airboarders_unpack
from .iguana import turok_unpack, allstar99_unpack, nflqbc98_unpack
from .iguanatlb import allstar2k_unpack, nbajam2k_unpack, chef_unpack, nflqbc99_unpack
from .imagineer import simcity_unpack, yakyuuking_unpack, mrc_unpack, fightersdestiny_unpack
from .locomotive import pennyracers_unpack, transformers_unpack
from .konami import deadlyarts_unpack, castlevania_unpack
from .madden import madden64_unpack, madden99_unpack, madden2k2_unpack
from .mariotennis import mariotennis_unpack
from .midway import sfrush_unpack, rush2_unpack, calispeed_unpack, \
                    cruisnusa_unpack, cruisnexotica_unpack
from .mspacman import mspacman_unpack
from .nintendo import sm64_unpack, drmario_unpack
from .paradigm import aerofighters_unpack, beetle_unpack
from .pm64 import pm64_unpack
from .rare import bk_unpack, blastcorps_unpack, dk64_unpack, kig_unpack
from .re2 import re2_unpack
from .sarge  import sarge_unpack
from .seta import shshogi_unpack
from .shiren import shiren_unpack
from .slugfest import slugfest_unpack
from .sote import sote_unpack
from .sparkrally import sparkrally_unpack
from .sw1racer import sw1racer_unpack
from .titus import superman_unpack, roadsters_unpack
from .tt import ts2_unpack
from .worms import worms_unpack, worms_eu_unpack
from .ubisoft import ray2_unpack
from .uso import uso_unpack
from .zelda import dobutsu_unpack

# points hash -> unpacker function.
# unpacker function accepts (rom: N64Rom, ipc: int) and returns a BFFI.
# ROM filenames are from an ancient goodn64 set, except where noted.
#
# Any game that does not need to be unpacked (i.e., is a single-load game)
# should be blacklisted by setting its unpacker to None
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

    # NFL Quarterback Club 98 (U) [!]
    "937c256ee962095dc57aff47e5196004f02b5e70bbc7fb430bad0ad4d8385a95": nflqbc98_unpack,

    # NFL Quarterback Club 98 (E) [!]
    "493a19ce012a9f37dc2a35671e8d4b8d4e60d66963777de3ef4fc7ce30a3b6fb": nflqbc98_unpack,

    # NBA Jam 99 (U) [!]
    "062d9d741a324055d0799bc9f46e152fd427fdcc957328f3434cfa99d148eea7": allstar99_unpack,

    # NBA Jam 99 (E) [!]
    "f37cf583be0b9b5b94c7b7725ba219b09c90a1e33dc80f77b139fe2ca121c71e": allstar99_unpack,

    # ------------------------------------------------------
    # Iguana/Acclaim's Expansion Pak-friendly RNC unpacker and TLB swapper framework
    # ------------------------------------------------------

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

    # Jeremy McGrath Supercross 2000 (U) [!]
    "bf5d67ce97052ee1b50928647d766eca388dbcfc69b1d7f4adeba7e8610f04e7": chef_unpack,

    # Jeremy McGrath Supercross 2000 (E) [!]
    "0aae47e4a9ae696f7bbd6446fc3b620cb1add70ea9d79a2d26f9693c5df0dd88": chef_unpack,

    # NFL Quarterback Club 99 (U) [!]
    "ddb39ce144e3aa308eae87763670aa8ae6546ca24fec5fde3e5c982c79409649": nflqbc99_unpack,

    # NFL Quarterback Club 99 (E) [!]
    "c8150c8b97af3871373e19fa9e2f43a266de6a500d55c96a1f9e9a3112565354": nflqbc99_unpack,

    # NFL Quarterback Club 2000 (U) [!]
    "35ac6193499247596bd0cce20cfe33fb69049e2b107d7ec6000896f52ed14d31": nflqbc99_unpack,

    # NFL Quarterback Club 2000 (U) [!]
    "a89fab662762377041fec54f2610b01fc06aaea417d3e03c38695bec428ed6b3": nflqbc99_unpack,

    # NFL Quarterback Club 2001 (U) [!]
    "39f24f4fafbf486684bfd9e79ebab44069cf94dcc51391a3886e5da502c27356": nflqbc99_unpack,

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
    "b6347d9f1f75d38a88d829b4f80b1acf0d93344170a5fbe9546c484dae416ce3": dk64_unpack,

    # Donkey Kong 64 (J) [!]
    "8a6a5b48b0a4d5d31fa59608e65bafe787b8664fbc9dbaecbcce16e41e8934cd": dk64_unpack,

    # Donkey Kong 64 (E) [!]
    "f704ddc06dda5bee065dd89adcf86aa58bd817684e190094cd0776c0cabba9df": dk64_unpack,

    # Killer Instinct Gold (U) (V1.0) [!]
    "660bc99b0023b731348535d160d894700fa4bab5b750dff70bd3ce79596f5793": kig_unpack,

    # Killer Instinct Gold (U) (V1.1) [!]
    "6cb27a5e1be6e65a8959a1b35dcd92f6203b45a1aaf5bcf573452d027943266c": kig_unpack,

    # Killer Instinct Gold (U) (V1.2) [!]
    "f80cae340efadf5725cd0f75441addb9186be9860267595be2b4a2d317b05f8a": kig_unpack,

    # Killer Instinct Gold (E) [!]
    "a77af932a359c4cd9f17f38e22ebccb3e11ae3dfd58da2780fbdec780809a4c0": kig_unpack,

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
    "9c32d0087fa2b83c5ee6f19ee86683907653ed8f30e7d4680a0adac334559dd7": rogue_unpack,

    # Star Wars - Shutsugeki! Rogue Chuutai (J) [!]
    "6c13a4b27820ab17f8e9d67775cf68f6df757c62babc6347542e5d456770878c": rogue_unpack,

    # Star Wars - Rogue Squadron (E) (M3) (V1.0) [!]
    "a33b6b738116c36e78a0d078ceb9ff7ddaa7b36244689421fa7d85d70ccc2273": rogue_unpack,

    # Star Wars - Rogue Squadron (E) (M3) (V1.1) [!]
    "592b37eed2730ae25232b163dea6632cf6b9ed21dd3be35c0500a939b897627b": rogue_unpack,

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

    # NHL Pro 99 (E) [!]
    "800dcc787de9fcdb1210b88bc8c23045a4770e7f692222fde039c306c26e5f12": castlevania_unpack,

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

    # Supercross 2000 (U) [!]
    # (not to be confused with Jeremy McGrath Supercross 2000)
    "2659be83dc4d8795d01d4838383579ad9aecf1a06ef0ea6aebc9588184fb9080": nhl99_unpack,

    # Supercross 2000 (E) (M3) [!]
    "92db4d0ba456d921c077d5bd524c913c297ea888bc78d5018ced70faa6203a59": nhl99_unpack,

    # NBA Live 2000 (U) (M4) [!]
    "3f36da957e6e578f029adbe183d76a2c94352d90dd9ef75ddb3e151ea367eca7": nbalive2k_unpack,

    # NBA Live 2000 (E) (M4) [!]
    "d0c85a3035687673be6b4c38cfba3728a6c50cf7beee36fc3a8572f4013a512b": nbalive2k_unpack,

    # NBA Live 99 (U) (M5) [!]
    "1c37eb542195ca5a85eb0e2e67a92c34ff6700b0f7442e04a73b0fe79098381b": nbalive2k_unpack,

    # NBA Live 99 (E) (M5) [!]
    "f21ddf33f8e597a0b49e1dde2b0d9cf55d2b8fd007cf20a92996a0783f7de411": nbalive2k_unpack,

    # WCW Mayhem (U) [!]
    "45acaf7b9d36436d73aef1ddc130b48ad115e5c8a3a4efafedf621afaddc2edf": wcw_unpack,

    # WCW Mayhem (E) [!]
    "d8c97d05f5050636a5756ddac73d1983ab636544f996a6a5d3dd5d15a14339b2": wcw_unpack,

    # WCW Backstage Assault (U) [!]
    "cf4169a5489d25711fb94e6c716ab5bf00b9aaf742556f5142998e20bffce7e7": wcw_unpack,

    # World Cup 98 (U) (M8) [!]
    "45f7895bbf19f4f0c0b41e6a32f847236aef08b85d49b8475357ea846c717daa": kok2k_unpack,

    # World Cup 98 (E) (M8) [!]
    "8f99290db186f35b4dd96562edc12138146157df5f48ca4b389a8cef1afe7a49": kok2k_unpack,

    # FIFA 99 (U) [!]
    "1299c143c9310cb03aa7424635fb2e148a00173cf21f9baebbd992c03fb90d43": kok2k_unpack,

    # FIFA 99 (E) (M8) [!]
    "9598ee62390f249f02bd595c8610e5f81a21f71b7d1162f7d1014012ce799db0": kok2k_unpack,

    # Knockout Kings 2000 (U) [!]
    "e34165bdcfcf6dff6322ec6faf23f59ce38d43417573e6eb41233ebf7309e293": kok2k_unpack,

    # Knockout Kings 2000 (E) [!]
    "9b01ba8aae55151d3445bab551150c884959af7a4897566946b43f7bd6ae394f": kok2k_unpack,

    # FIFA Soccer 64 (U) (M3) [!]
    "4721c09d2f5e33c278dd7bf7b13037d95c54cc357d1c9f71ccde91006f7780a4": fifa64_unpack,

    # FIFA Soccer 64 (E) (M3) [!]
    "f00e3398a860839631b1e06ad26454029bf0d35b3fa27703fdbe58dc1e89051f": fifa64_unpack,

    # J.League Live 64 (J) [!]
    "8472aae0167eceac08923de4b1f21d7a1302883cc0489ba03fe7d4d5e0db370d": fifa64_unpack,

    # FIFA - Road to World Cup 98 (U) (M7) [!]
    "aa6f85b86a40b9388d99324e7ff58c3df67ce666f2dbc5cf01a31357b4f7ccc2": fifa64_unpack,

    # FIFA - Road to World Cup 98 (E) (M7) [!]
    "baee4f4a6b528eab242f09885c518af282fb02175c622812ecb82d58c79d8849": fifa64_unpack,

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

    # Turok - Rage Wars (U) [!]
    "0433043aaba2649bdd1fe717c4020550ac663c0362527aa082490f5977a3e46b": armorines_unpack,

    # Turok - Rage Wars (E) [!]
    "d763cbbe485a5f9e1b7be97d5ac16735087e23d0bb62c05dc844e01b7e1156d1": armorines_unpack,

    # Turok - Legenden des Verlorenen Landes (G) [!]
    "9dc401252bacb2ad7412ef003f97f28cb225d76b3cc76f430fbc27fa05067ca8": armorines_unpack,

    # South Park (U) [!]
    "68e87dbae05414026a126cb6e0c632e7660668a0003e1e1c975df8296e2a36a6": southpark_unpack,

    # South Park (E) (M3) [!]
    "e0cdb6f2c756febffc10266a5bf93ee853a0393de2f18353174e569303d3252c": southpark_unpack,

    # South Park (G) [!]
    "346ddcf6d1259bd31389267009d2caac74ddf79f608dfd826705e7c9fbfdad9e": southpark_unpack,    

    # Turok 3 - Shadow of Oblivion (U) [!]
    "9ac5a8049d6c0dce16fd0ac2898fb42fec42455ca8497d3244de215df1e6e096": turok3_unpack,

    # Turok 3 - Shadow of Oblivion (E) [!]
    "26520b99cbadf6a2f095ec94d898907901a9541703c34976f5f8c926bc90b706": turok3_unpack,

    # Re-Volt (U) [!]
    "826fd84fb778f6ddaa8bc14cbf116fb25bf1bf6ed4b833d7e30501be6f144823": revolt_unpack,

    # Re-Volt (E) (M4) [!]
    "ce619ae064bc608d9a139f95e6bbc9f17fe3898d242943bc92fd0d6fc74915b0": revolt_unpack,

    # Shadow Man (U) [!]
    "da1a8af84f16ff385271704ca31673b0aa2343f40bc9cd95eac0bdf20676ca27": shadowman_unpack,

    # Shadow Man (E) (M3) [!]
    "322603e871ebf8556c565f291bb3642d42fbd27bcda03e7c0ecf4d2aec86a5a7": shadowman_unpack,

    # Shadow Man (F) [!]
    "4b38312c467b825ee0472746fe572a13d5520e8db3638299ae33c98110bc72e0": shadowman_unpack,

    # Shadow Man (G) [!]
    "6efd99af685a32105ddbc0b0193af38a0ce8d262c4921e0ddeec68e49b6921ce": shadowman_unpack,


    # ------------------------------------------------------
    # Seta
    # ------------------------------------------------------

    # Saikyou Habu Shougi (J) [!]
    "1d81949eda06331501f807296aaa3b775ccf4fea12a57b1575641579a7b299ab": shshogi_unpack,

    # ------------------------------------------------------
    # Titus
    # ------------------------------------------------------

    # Superman (U) (M3) [!]
    "37df2542bf24951e259990c4d76c13f96dd52cba867f492b3a99391d0978b178": superman_unpack,

    # Superman (E) (M6) [!]
    "ae0cb81d7fff296f4a079e3ec08255ea9d65979230bb41ab4ae492bf830d56a0": superman_unpack,

    # Roadsters Trophy (U) (M3) [!]
    "49c4494ce6acca523c7066b0bdf598ff466a9b5a91cb2ff85730a7079c1911fd": roadsters_unpack,    

    # Roadsters Trophy (E) (M6) [!]
    "ba3307883fe81ddeb81ed6a51cb1d4cd9d3353c73ca9007c02212c777b572e2e": roadsters_unpack,    

    # Automobili Lamborghini (U) [!]
    "cab2467684a58bc19c787423d704a961aa497629763367d9fe691172de58591c": superman_unpack,

    # Automobili Lamborghini (E) [!]
    "740a878157b15c0cd65e2623dea3ab9c90b6984ad709d8543b7e50f33e88fc62": superman_unpack,

    # Super Speed Race 64 (J) [o1]
    "06c9c992014da5982e747117c690c1590a011c0c6756b0522df126366bf8b9a1": superman_unpack,

    # Virtual Chess 64 might be single-load

    # ------------------------------------------------------
    # Human Entertainment
    # ------------------------------------------------------

    # Airboarder 64 (J) [!]
    "e3fa6d6f13671237e703f32d01f48aff62071114a7a92086c9e3229d1b943ecc": airboarders_unpack,

    # Airboarder 64 (E) [!]
    "adc68241f2472aa5b4cd71f189f0b04f44d99e4d29776e831feb0ef86e6ceb79": airboarders_unpack,

    # ------------------------------------------------------
    # Locomotive Corporation
    # ------------------------------------------------------

    # Penny Racers (U) [!]
    "f8f58b65f6d50fdd42a478573e39371faec03c448e39c4f99af9a0860d6bd6a1": pennyracers_unpack,

    # Choro Q 64 (J) [!]
    "e54dd88e65c6a14b7d591118c18d1c69551de334dbebba43d70a96162d63ba32": pennyracers_unpack,

    # Penny Racers (E) [!]
    "c2f4887ee2c9129ac9d550b0e8877fcf9066f56474a82967362df4b561f72487": pennyracers_unpack,

    # Choro Q 64 II: might be single-load (can't find code outside bootexe)

    # AeroGauge: same, can't find code outside bootexe

    # Transformers - Beast Wars Transmetal (U) [!]
    "aae1c838d88a4ff7eac6b515452265416141f22bc5dea760c66d0f1eb811165b": transformers_unpack,

    # Transformers - Beast Wars Metals 64 (J) [!]
    "8f9aea4cdf8cbf85a62efab04bc39b43fee7b73bac489bd38af62ff0955cd462": transformers_unpack,

    # ------------------------------------------------------
    # Traveller's Tales
    # ------------------------------------------------------

    # Toy Story 2 (U) [!]
    "b8b0db1259ca80b4397c3c58ef63d38100a69d436ed3f097079eb81d07e764c9": ts2_unpack,

    # Toy Story 2 (E) [!]
    "ae77d1d9b5aa207ea2ec5daa0a0d6bd680425041bacb9dfdc984dd0ec8f39fa1": ts2_unpack,

    # Toy Story 2 (F) [!]
    "5ff7efb853a66959e1a8a96d94942d96ea97d5409769edcb4952db41b0c82a04": ts2_unpack,

    # Toy Story 2 (G) [!]
    "04392e31d7be9b6b138e3030a08d256326071a0dbe16398d2ea7b1836427249b": ts2_unpack,

    # Bug's Life, A (U) [!]
    "a9a3ad10d2660e0fa8c1c23c6a75f900ee2882569917abab6e258f3bd333a3e4": ts2_unpack,

    # Bug's Life, A (E) [!]
    "2c67a977be8c159298d3e1e93e1f2d390994037d73ac786705943ee3dcd9ee53": ts2_unpack,

    # Bug's Life, A (F) [!]
    "ca95b985145db27f39d08166829df792a08fb83192368aa4acf9174efa53b12d": ts2_unpack,

    # Bug's Life, A (G) [!]
    "296969309890de4f1b0b62ca6f8b0ad29742a26817794e33d6ee4846676b137b": ts2_unpack,

    # ------------------------------------------------------
    # Buck Bumble
    # ------------------------------------------------------

    # Buck Bumble (U) [!]
    "d21e3d1c2ec4d7f025cfaa119553be9a5fa87a9fd6625ef1ef44dc1d4b0aa54b": buckbumble_unpack,

    # Buck Bumble (J) [!]
    "9b4be33fe5adbc911e69546bcb0149c380f00f02c669539411a8cf1d78714ff4": buckbumble_unpack,

    # Buck Bumble (E) (M5) [!]
    "3ac266d98a84f01174ad7ffbb532f3e3bc041a57ebc8874c0b45bb062899a6db": buckbumble_unpack,

    # ------------------------------------------------------
    # Imagineer/Genki games
    # ------------------------------------------------------

    # Sim City 2000 (J) [!]
    "858bfc0a47afb73452b59966095fc1a96d3fb701da274d4ea7acea5f74451f8d": simcity_unpack,

    # Chou Kuukan Night Pro Yakyuu King (J) [!]
    "a8267610ebf5832a222de6689a8364ce60b981bc327fbe83bf3871f9e6275255": yakyuuking_unpack,

    # MRC - Multi Racing Championship (U) [!]
    "5729e822337b7dfac5ae81210f1c2e3bfa739b90dfc8182d9e573a4990dd14d9": mrc_unpack,

    # MRC - Multi Racing Championship (J) [!]
    "5e26351f7b09cfbc64c6e89381eec3e45e27527e8bb83ae8d8aadaf01c113b0c": mrc_unpack,

    # MRC - Multi Racing Championship (E) (M3) [!]
    "7d9e4554abd1c360f9af32ff72c6be47d8f67ce3f08e1c8ffef0ea8aa70ad622": mrc_unpack,

    # Rally Challenge 2000 (U) [!]
    "60681b4ff96742f6e4d77043cf37f8f22d73bdc257c2605be41283de96c88db3": simcity_unpack,

    # Rally '99 (J) [!]
    "f2d510d7ebda2abe25221137a0170a9fd98fb60892fb84ef6ef33f3e7c217dee": simcity_unpack,

    # Fighter's Destiny (U) [!]
    "0e6dae67a6e002eb14b4c890fbce18491560c87430e11711f31c0264f6843175": fightersdestiny_unpack,

    # Fighting Cup (J) [!]
    "b52c505767ae8ffb9dc1168b7f45efb1e440f83adbc1c76a2c937cfc4a24742a": fightersdestiny_unpack,        

    # Fighter's Destiny (E) [!]
    "45ca5db19ca02452a2b381135f4c866f1a4201e16766f705a3dfd952c04001c4": fightersdestiny_unpack,

    # Fighter's Destiny (F) [!]
    "4e46e50062480bf4cbca6936dd46e6e16e714da21a21e2e4250ede73d528c3f0": fightersdestiny_unpack,

    # Fighter's Destiny (G) [!]
    "604cf4dc2f8bbf24091e1a3a9ae431d7a98ed10735de7e2f999fb68ce99a088f": fightersdestiny_unpack,

    # Fighter Destiny 2 (U) [!]
    "f38166f6d8ef4f04fc698cd8c4885b84622e4eb58f0aefca47b95af1eb7c3c6d": simcity_unpack,

    # Kakutou Denshou - F-Cup Maniax (J) [!]
    "aa4b4f7528a8f465ef0152652f86888790b6ab0ec0fdced22e349885afcdff64": simcity_unpack,

    # ------------------------------------------------------
    # Shiren the Wanderer 2
    # ------------------------------------------------------

    # Fushigi no Dungeon - Fuurai no Shiren 2 - Oni Shuurai! Shiren Jou! (J) [!]
    "4073a9f6516ef5d15cdd8b259a952a7d07633a2815f2a738fb5d98415d30a458": shiren_unpack,

    # ------------------------------------------------------
    # Star Wars - Shadows of the Empire (long overdue)
    # ------------------------------------------------------

    # Star Wars - Shadows of the Empire (U) (V1.0) [!]
    "f916ff87a7ad3217ca26697607dc48d30f187edb797dc1535e1095edffdb0ff6": sote_unpack,

    # Star Wars - Shadows of the Empire (U) (V1.1) [!]
    "895d3dbbdc4945b690ef80f6dff8e5c95b5e3ab9fb3d9b62b5a8e9c61110a0e9": sote_unpack,

    # Star Wars - Shadows of the Empire (U) (V1.2) [!]
    "e7085e013123537f34e0edec8801318016da4dbac424172d6dc5f3b67d98642c": sote_unpack,

    # Star Wars - Teikoku no Kage (J) [!]
    "ed01f66646360a645f8c283d9d887504f662dc741758cbe3a865c8dc85c8d52f": sote_unpack,

    # Star Wars - Shadows of the Empire (E) [!]
    "e9a7566a699e2c885d3cf86eb366f9fcd36e06a68f1ca0419700bbec44e3eacb": sote_unpack,

    # ------------------------------------------------------
    # Resident Evil 2
    # ------------------------------------------------------

    # Resident Evil 2 (U) (V1.1) [!]
    "71f3f779613bf1f0e2050bfa600425385d2c257a647d2e40f63be1a7986e9aac": re2_unpack,

    # Biohazard 2 (J) [!]
    "f64a3c4a3873cf145e577ee710366fd638bb8d03f6f01549f81e04df738fd425": re2_unpack,

    # Resident Evil 2 (E) (M2) [!]
    "52093e994c89848b17c8e6f26546d66374cf47c9b471ec15da7f322b7ee17ab8": re2_unpack,

    # ------------------------------------------------------
    # Star Wars Episode 1: Racer
    # ------------------------------------------------------

    # Star Wars Episode I - Racer (U) [!]
    "8d6f85683b630e25385619af37197d48279366f6609bb6edc1201ff24c08b757": sw1racer_unpack,

    # Star Wars Episode I - Racer (J) [b1]
    "c32a78a9b16b48c139bf9dced1358aac411d122aa937d86613abfcd281de027c": sw1racer_unpack,

    # Star Wars Episode I - Racer (E) (M3) [!]
    "326b810b24cef38b04b74084bfd487fb6d40ea955dc2a54849de942bde076edc": sw1racer_unpack,

    # ------------------------------------------------------
    # South Park Rally
    # ------------------------------------------------------

    # South Park Rally (U) [!]
    "0e5168c8864f65781f50b83267528350d7f8ee4ffa9d4d3555533edccd656d87": sparkrally_unpack,

    # South Park Rally (E) [!]
    "20192eac2b4ae2eac5a5eb0f516463a789e6e5a2860411ea7f91f5f46fb9fe0a": sparkrally_unpack,

    # ------------------------------------------------------
    # Daikatana
    # ------------------------------------------------------
    
    # John Romero's Daikatana (U) [!]
    "b7a2db013ff1e0628fec4dd87399eb01ede4a3f185be2e7653ff2e072bf42f6c": daikatana_unpack,

    # John Romero's Daikatana (E) (M3) [!]
    "3bbf87a2fb2479996cd544758b38ac09861b77235fb8f35b31150e481966653b": daikatana_unpack,

    # John Romero's Daikatana (J) [!]
    "d733debf3a38c643127d58e84b086f44948bd630bf6449030db8cea1ca51abf8": daikatana_unpack,

    # ------------------------------------------------------

    # Premier Manager 64 (E) [!]
    "a3c0a0b8c41c2d8215b253aa330517b91329986d2cc6b2882d638de06e72a4c9": pm64_unpack,

    # ------------------------------------------------------
    # Eurocom
    # ------------------------------------------------------

    # Mortal Kombat 4 (U) [!]
    "ea908a1f790340dc34f1056c4799f7d0984048d90344607f2910d96abf036478": mk4_unpack,

    # Mortal Kombat 4 (E) [!]
    "9bf17deaf7a7beabccb285ccf6e0394cbeb2cc88dcc390efdc2a79ef20e79f34": mk4_unpack,

    # ------------------------------------------------------
    # EA's Madden NFL games
    # ------------------------------------------------------

    # Madden Football 64 (U) [!]
    "39f25dad3af4782a909bf58d7127acae700ea7c6f17c48d39ab76fe331735d6f": madden64_unpack,
    
    # Madden Football 64 (E) [!]
    "7eaef372a0e0f00a8e0150150686d1c72a87c5232a9ea3b374424275efdad059": madden64_unpack,

    # Madden NFL 99 (U) [!]
    "e1bc1ce2fe40c4ec803e6eb0bc762bcd0d9d9fb501e9c3c71fb249369506d454": madden99_unpack,

    # Madden NFL 99 (E) [!]
    "0614ccd5bbe6fa5b40f899ca000505390bf49eb6a13f6c1b053ba827c84309b6": madden99_unpack,

    # Madden NFL 2000 (U) [!]
    "a5584fd350722f0f1c9792820b9de528665954142ebcee6c236782db8c895822": madden99_unpack,

    # Madden NFL 2001 (U) [!]
    "f9dc0e73a76ac936b176475bdbb0bc260054223112a32b30ed2f8ee32b4c7a49": madden2k2_unpack,

    # Madden NFL 2002 (U) [!]
    "1ffc43042b9d374ee121d5c784fb78f6fc2092c5d66344ed0c356b1e091a7b16": madden2k2_unpack,

    # ------------------------------------------------------
    # Player 1
    # All are assumed to be single-load until proven otherwise
    # ------------------------------------------------------

    # Blues Brothers 2000 (U) [!]
    # Can't find code outside bootexe, game is likely single-load
    "3ca0ac99c1611125783d474825b9d912b7b2e491d17468b0db6fb29b941fc985": None,

    # Blues Brothers 2000 (E) (M6) [!]
    # Can't find code outside bootexe, game is likely single-load
    "2a7540a8cb2d0f2eec24bc99e8c9af505a17f32e3aa2e43394a4ac94867dc2c8": None,

    # Hercules - The Legendary Journeys (U) [!]
    # Can't find code outside bootexe, game is likely single-load
    "8c7d23b9d9a349561f922c90aa128d85abf5ccafc696a2bcd36a434738bf72bc": None,

    # Hercules - The Legendary Journeys (E) (M6) [!]
    # Can't find code outside bootexe, game is likely single-load
    "655bf0ba5eb75d4a21ddaaaf96d308ff11480eca9124140eb010048033bcf62a": None,

    # Robotron 64 (U) [!]
    # Likely a single-load game
    "91d85baeca4b9517e93b3637b52909cee942b09e2fe44a37df9ded17687faddd": None,

    # Robotron 64 (E) [!]
    # Likely a single-load game
    "18e582cfc79c8659d06664459bee45d5892291a9264ffda0652cb36c0d548aa6": None,

    # Milo's Astro Lanes (U) [o1]
    # Likely a single-load game
    "2399cfc9142891a262579f6018b3269137dba52fa333c64e8d7edbd3a6a204c6": None,

    # Milo's Astro Lanes (E) [o1]
    # Likely a single-load game
    "71384a0e942c4fb5d8b138fff47880372af68a4ab88cae8e5249ab968edfb8cb": None,

    # ------------------------------------------------------
    # Hudson Soft
    # ------------------------------------------------------

    # Mario Party (U) [!]
    "ca4fb9605fff4884e9ba4319dfa23d96b7347ce88ffb8d04e6c25a3a9ff9ed6a": marioparty_unpack,

    # Mario Party (J) [!]
    "2fed99bec5458b07900bbc58cbacf0bbec46b3250ac35de00100310d7265c09d": marioparty_unpack,

    # Mario Party (E) (M3) [!]
    "48e6cbb83735ec4e4662866fa99cd6895da97a3b90814f5078bfabd132cbfb9a": marioparty_unpack,

    # Mario Party 2 (U) [!]
    "0b7b2ec3bd2ac8713b4c43f74a634285a720779964ee2658f7ad2dfa97b33576": marioparty_unpack,

    # Mario Party 2 (J) [!]
    "bae1720d257791b58fc29189241553d64dece6ce241a6c2af275bf77d25bb96f": marioparty_unpack,

    # Mario Party 2 (E) (M5) [!]
    "4fe18c71dba3520dab2a0618fdd949cf0869579325ea2ecfd2040337daff3863": marioparty_unpack,

    # Mario Party 3 (U) [!]
    "a08cbd6a4f40d15cbd8bcdee644f80cdfb843e06d569d1334bcd49f23262855a": marioparty_unpack,

    # Mario Party 3 (J) [!]
    "bdf532f2f9c927a4398a1657b5e9ecfb34d416db68e791c743929ef5d0628f69": marioparty_unpack,

    # Mario Party 3 (E) (M4) [!]
    "23a33bd5ec1ef62f6888e0d7b68f56ffb36da83025be789ca1170da43266242f": marioparty_unpack,

    # Bomberman 64 (U) [!]
    "e6da7c26127788cd894b88b71cc055ff9dec0d0f4f8e10d9b15b40153af2b52a": bomberman64_unpack,

    # Baku Bomberman (J) [!]
    "7a36567a0a26dfdcb6f24eb454be9f9cd815cf96d6660867845e8a55434084cf": bomberman64_unpack,

    # Bomberman 64 (E) [!]
    "412112a3a7dbd712c9d7420028144b47691768aa6a26846c897abae8c9a69157": bomberman64_unpack,

    # Bomberman 64 - The Second Attack! (U) [!]
    "96f641120471a1d5dab848dffdeeeeb7c4002333a06763ae20e14af72126efd8": bomberman2_unpack,

    # Baku Bomberman 2 (J) [!]
    "45c622c2e6d65ceb255c531b499c78d0e1880c32e9e9d7b804c617549f3da7cb": bomberman2_unpack,

    # ------------------------------------------------------
    # Confirmed single-load games
    #
    # Any game that does not need to be unpacked should be blacklisted
    # by setting its unpacker to None
    # ------------------------------------------------------

    # Jinsei Game 64 (J) [!] - appears to be single-load
    # "bfa3cbe991967318eecabac89883427ec29cf071373e97751dccc99cd7efe70d": None,
}
