local nmap = require "nmap"
local shortport = require "shortport"
local sslcert = require "sslcert"
local stdnse = require "stdnse"
local string = require "string"
local math = require "math"
local table = require "table"
local tls = require "tls"
local vulns = require "vulns"
local have_ssl, openssl = pcall(require, "openssl")

description = [[
Weak ephemeral Diffie-Hellman parameter detection for SSL/TLS services.

This script simulates SSL/TLS handshakes using ciphersuites that have ephemeral
Diffie-Hellman as the key exchange algorithm.

Diffie-Hellman MODP group parameters are extracted and analyzed for vulnerability
to Logjam (CVE 2015-4000) and other weaknesses.

Opportunistic STARTTLS sessions are established on services that support them.
]]

---
-- @usage
-- nmap --script ssl-dh-params <target>
--
-- @output
-- Host script results:
-- | ssl-dh-params:
-- |   VULNERABLE:
-- |   Transport Layer Security (TLS) Protocol DHE_EXPORT Ciphers Downgrade MitM (Logjam)
-- |     State: VULNERABLE
-- |     IDs:  OSVDB:122331  CVE:CVE-2015-4000
-- |       The Transport Layer Security (TLS) protocol contains a flaw that is triggered
-- |       when handling Diffie-Hellman key exchanges defined with the DHE_EXPORT cipher.
-- |       This may allow a man-in-the-middle attacker to downgrade the security of a TLS
-- |       session to 512-bit export-grade cryptography, which is significantly weaker,
-- |       allowing the attacker to more easily break the encryption and monitor or tamper
-- |       with the encrypted stream.
-- |     Disclosure date: 2015-5-19
-- |     Check results:
-- |       EXPORT-GRADE DH GROUP 1
-- |         Ciphersuite: TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
-- |         Modulus Type: Non-safe prime
-- |         Modulus Source: sun.security.provider/512-bit DSA group with 160-bit prime order subgroup
-- |         Modulus Length: 512 bits
-- |         Generator Length: 512 bits
-- |         Public Key Length: 512 bits
-- |     References:
-- |       https://weakdh.org
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-4000
-- |       http://osvdb.org/122331
-- |
-- |   Diffie-Hellman Key Exchange Insufficient Diffie-Hellman Group Strength
-- |     State: VULNERABLE
-- |       Transport Layer Security (TLS) services that use Diffie-Hellman groups of
-- |       insuffficient strength, especially those using one of a few commonly shared
-- |       groups, may be susceptible to passive eavesdropping attacks.
-- |     Check results:
-- |       WEAK DH GROUP 1
-- |         Ciphersuite: TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
-- |         Modulus Type: Safe prime
-- |         Modulus Source: Unknown/Custom-generated
-- |         Modulus Length: 512 bits
-- |         Generator Length: 8 bits
-- |         Public Key Length: 512 bits
-- |     References:
-- |       https://weakdh.org
-- |
-- |   Diffie-Hellman Key Exchange Potentially Unsafe Group Parameters
-- |     State: VULNERABLE
-- |       This TLS service appears to be using a modulus that is not a safe prime and does
-- |       not correspond to any well-known DSA group for Diffie-Hellman key exchange.
-- |       These parameters MAY be secure if:
-- |       - They were generated according to the procedure described in FIPS 186-4 for
-- |         DSA Domain Parameter Generation, or
-- |       - The generator g generates a subgroup of large prime order
-- |       Additional testing may be required to verify the security of these parameters.
-- |     Check results:
-- |       NON-SAFE DH GROUP 1
-- |         Cipher Suite: TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
-- |         Modulus Type: Non-safe prime
-- |         Modulus Source: Unknown/Custom-generated
-- |         Modulus Length: 1024 bits
-- |         Generator Length: 1024 bits
-- |         Public Key Length: 1024 bits
-- |     References:
-- |       https://weakdh.org
-- |_      http://www2.esentire.com/TLSUnjammedWP

author = "Jacob Gajek"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}


-- Anonymous Diffie-Hellman key exchange variants
local DH_anon_ALGORITHMS = {
  ["DH_anon_EXPORT"] = 1,
  ["DH_anon"] = 1
}

-- Full-strength ephemeral Diffie-Hellman key exchange variants
local DHE_ALGORITHMS = {
  ["DHE_RSA"] = 1,
  ["DHE_DSS"] = 1,
  ["DHE_PSK"] = 1
}

-- Export-grade ephemeral Diffie-Hellman key exchange variants
local DHE_ALGORITHMS_EXPORT = {
  ["DHE_RSA_EXPORT"] = 1,
  ["DHE_DSS_EXPORT"] = 1,
  ["DHE_DSS_EXPORT1024"] = 1
}

local fromhex = stdnse.fromhex

-- Common Diffie-Hellman groups
--
-- The primes from weakdh.org were harvested by:
--    1) Scanning the IPv4 space
--    2) Scanning Alexa Top 1 million (seen >100 times)
--
-- The list from weakdh.org overlaps the original script source code, therefore those were removed.
-- The primes were not searchable on Google (hope for source code match) - they may belong to closed
-- source software. If someone happens to find/match it, send a pull request.
local DHE_PRIMES = {
  [fromhex([[
    D4BCD524 06F69B35 994B88DE 5DB89682 C8157F62 D8F33633 EE5772F1 1F05AB22
    D6B5145B 9F241E5A CC31FF09 0A4BC711 48976F76 795094E7 1E790352 9F5A824B
  ]])] = "mod_ssl 2.0.x/512-bit MODP group with safe prime modulus",

  [fromhex([[
    E6969D3D 495BE32C 7CF180C3 BDD4798E 91B78182 51BB055E 2A206490 4A79A770
    FA15A259 CBD523A6 A6EF09C4 3048D5A2 2F971F3C 20129B48 000E6EDD 061CBC05
    3E371D79 4E5327DF 611EBBBE 1BAC9B5C 6044CF02 3D76E05E EA9BAD99 1B13A63C
    974E9EF1 839EB5DB 125136F7 262E56A8 871538DF D823C650 5085E21F 0DD5C86B
  ]])] = "mod_ssl 2.0.x/1024-bit MODP group with safe prime modulus",

  [fromhex([[
    9FDB8B8A 004544F0 045F1737 D0BA2E0B 274CDF1A 9F588218 FB435316 A16E3741
    71FD19D8 D8F37C39 BF863FD6 0E3E3006 80A3030C 6E4C3757 D08F70E6 AA871033
  ]])] = "mod_ssl 2.2.x/512-bit MODP group with safe prime modulus",

  [fromhex([[
    D67DE440 CBBBDC19 36D693D3 4AFD0AD5 0C84D239 A45F520B B88174CB 98BCE951
    849F912E 639C72FB 13B4B4D7 177E16D5 5AC179BA 420B2A29 FE324A46 7A635E81
    FF590137 7BEDDCFD 33168A46 1AAD3B72 DAE88600 78045B07 A7DBCA78 74087D15
    10EA9FCC 9DDD3305 07DD62DB 88AEAA74 7DE0F4D6 E2BD68B0 E7393E0F 24218EB3
  ]])] = "mod_ssl 2.2.x/1024-bit MODP group with safe prime modulus",

  [fromhex([[
    BBBC2DCA D8467490 7C43FCF5 80E9CFDB D958A3F5 68B42D4B 08EED4EB 0FB3504C
    6C030276 E710800C 5CCBBAA8 922614C5 BEECA565 A5FDF1D2 87A2BC04 9BE67780
    60E91A92 A757E304 8F68B076 F7D36CC8 F29BA5DF 81DC2CA7 25ECE662 70CC9A50
    35D8CECE EF9EA027 4A63AB1E 58FAFD49 88D0F65D 146757DA 071DF045 CFE16B9B
  ]])] = "nginx/1024-bit MODP group with safe prime modulus",

  [fromhex([[
    FCA682CE 8E12CABA 26EFCCF7 110E526D B078B05E DECBCD1E B4A208F3 AE1617AE
    01F35B91 A47E6DF6 3413C5E1 2ED0899B CD132ACD 50D99151 BDC43EE7 37592E17
  ]])] = "sun.security.provider/512-bit DSA group with 160-bit prime order subgroup",

  [fromhex([[
    E9E64259 9D355F37 C97FFD35 67120B8E 25C9CD43 E927B3A9 670FBEC5 D8901419
    22D2C3B3 AD248009 3799869D 1E846AAB 49FAB0AD 26D2CE6A 22219D47 0BCE7D77
    7D4A21FB E9C270B5 7F607002 F3CEF839 3694CF45 EE3688C1 1A8C56AB 127A3DAF
  ]])] = "sun.security.provider/768-bit DSA group with 160-bit prime order subgroup",

  [fromhex([[
    FD7F5381 1D751229 52DF4A9C 2EECE4E7 F611B752 3CEF4400 C31E3F80 B6512669
    455D4022 51FB593D 8D58FABF C5F5BA30 F6CB9B55 6CD7813B 801D346F F26660B7
    6B9950A5 A49F9FE8 047B1022 C24FBBA9 D7FEB7C6 1BF83B57 E7C6A8A6 150F04FB
    83F6D3C5 1EC30235 54135A16 9132F675 F3AE2B61 D72AEFF2 2203199D D14801C7
  ]])] = "sun.security.provider/1024-bit DSA group with 160-bit prime order subgroup",

  [fromhex([[
    DA583C16 D9852289 D0E4AF75 6F4CCA92 DD4BE533 B804FB0F ED94EF9C 8A4403ED
    574650D3 6999DB29 D776276B A2D3D412 E218F4DD 1E084CF6 D8003E7C 4774E833
  ]])] = "openssl/512-bit MODP group with safe prime modulus",

  [fromhex([[
    97F64261 CAB505DD 2828E13F 1D68B6D3 DBD0F313 047F40E8 56DA58CB 13B8A1BF
    2B783A4C 6D59D5F9 2AFC6CFF 3D693F78 B23D4F31 60A9502E 3EFAF7AB 5E1AD5A6
    5E554313 828DA83B 9FF2D941 DEE95689 FADAEA09 36ADDF19 71FE635B 20AF4703
    64603C2D E059F54B 650AD8FA 0CF70121 C74799D7 587132BE 9B999BB9 B787E8AB
  ]])] = "openssl/1024-bit MODP group with safe prime modulus",

  [fromhex([[
    ED928935 824555CB 3BFBA276 5A690461 BF21F3AB 53D2CD21 DAFF7819 1152F10E
    C1E255BD 686F6800 53B9226A 2FE49A34 1F65CC59 328ABDB1 DB49EDDF A71266C3
    FD210470 18F07FD6 F7585119 72827B22 A934181D 2FCB21CF 6D92AE43 B6A829C7
    27A3CB00 C5F2E5FB 0AA45985 A2BDAD45 F0B3ADF9 E08135EE D983B3CC AEEAEB66
    E6A95766 B9F128A5 3F2280D7 0BA6F671 939B810E F85A90E6 CCCA6F66 5F7AC010
    1A1EF0FC 2DB6080C 6228B0EC DB8928EE 0CA83D65 94691669 533C5360 13B02BA7
    D48287AD 1C729E41 35FCC27C E951DE61 85FC199B 76600F33 F86BB3CA 520E29C3
    07E89016 CCCC0019 B6ADC3A4 308B33A1 AFD88C8D 9D01DBA4 C4DD7F0B BD6F38C3
  ]])] = "openssl/2048-bit MODP group with safe prime modulus",

  [fromhex([[
    AED037C3 BDF33FA2 EEDC4390 B70A2089 7B770175 E9B92EB2 0F8061CC D4B5A591
    723C7934 FDA9F9F3 274490F8 50647283 5BE05927 1C4F2C03 5A4EE756 A36613F1
    382DBD47 4DE8A4A0 322122E8 C730A83C 3E4800EE BD6F8548 A5181711 BA545231
    C843FAC4 175FFAF8 49C440DB 446D8462 C1C3451B 49EFA829 F5C48A4C 7BAC7F64
    7EE00015 1AA9ED81 101B36AB 5C39AAFF EC54A3F8 F97C1B7B F406DCB4 2DC092A5
    BAA06259 EFEB3FAB 12B42698 2E8F3EF4 B3F7B4C3 302A24C8 AA4213D8 45035CE4
    A8ADD31F 816616F1 9E21A5C9 5080597F 8980AD6B 814E3585 5B79E684 4491527D
    552B72B7 C78D8D6B 993A736F 8486B305 88B8F1B8 7E89668A 8BD3F13D DC517D4B
  ]])] = "openssl/2048-bit MODP group with safe prime modulus",

  [fromhex([[
    FEEAD19D BEAF90F6 1CFCA106 5D69DB08 839A2A2B 6AEF2488 ABD7531F BB3E462E
    7DCECEFB CEDCBBBD F56549EE 95153056 8188C3D9 7294166B 6AABA0AA 5CC8555F
    9125503A 180E9032 4C7F39C6 A3452F31 42EE72AB 7DFFC74C 528DB6DA 76D9C644
    F55D083E 9CDE74F7 E742413B 69476617 D2670F2B F6D59FFC D7C3BDDE ED41E2BD
    2CCDD9E6 12F1056C AB88C441 D7F9BA74 651ED1A8 4D407A27 D71895F7 77AB6C77
    63CC00E6 F1C30B2F E7944692 7E74BC73 B8431B53 011AF5AD 1515E63D C1DE83CC
    802ECE7D FC71FBDF 179F8E41 D7F1B43E BA75D5A9 C3B11D4F 1B0B5A09 88A9AACB
    CCC10512 26DC8410 E41693EC 8591E31E E2F5AFDF AEDE122D 1277FC27 0BE4D25C
    1137A58B E961EAC9 F27D4C71 E2391904 DD6AB27B ECE5BD6C 64C79B14 6C2D208C
    D63A4B74 F8DAE638 DBE2C880 6BA10773 8A8DF5CF E214A4B7 3D03C912 75FBA572
    8146CE5F EC01775B 74481ADF 86F4854D 65F5DA4B B67F882A 60CE0BCA 0ACD157A
    A377F10B 091AD0B5 68893039 ECA33CDC B61BA8C9 E32A87A2 F5D8B7FD 26734D2F
    09679235 2D70ADE9 F4A51D84 88BC57D3 2A638E0B 14D6693F 6776FFFB 355FEDF6
    52201FA7 0CB8DB34 FB549490 951A701E 04AD49D6 71B74D08 9CAA8C0E 5E833A21
    291D6978 F918F25D 5C769BDB E4BB72A8 4A1AFE6A 0BBAD18D 3EACC7B4 54AF408D
    4F1CCB23 B9AE576F DAE2D1A6 8F43D275 741DB19E EDC3B81B 5E56964F 5F8C3363
  ]])] = "openssl/4096-bit MODP group with safe prime modulus",

  [fromhex([[
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74
    020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B 302B0A6D F25F1437
    4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9 A63A3620 FFFFFFFF FFFFFFFF
  ]])] = "RFC2409/Oakley Group 1",

  [fromhex([[
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74
    020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B 302B0A6D F25F1437
    4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381 FFFFFFFF FFFFFFFF
  ]])] = "RFC2409/Oakley Group 2",

  [fromhex([[
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74
    020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B 302B0A6D F25F1437
    4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D C2007CB8 A163BF05
    98DA4836 1C55D39A 69163FA8 FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB
    9ED52907 7096966D 670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF
  ]])] = "RFC3526/Oakley Group 5",

  [fromhex([[
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74
    020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B 302B0A6D F25F1437
    4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D C2007CB8 A163BF05
    98DA4836 1C55D39A 69163FA8 FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB
    9ED52907 7096966D 670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
    E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718
    3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
  ]])] = "RFC3526/Oakley Group 14",

  [fromhex([[
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74
    020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B 302B0A6D F25F1437
    4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D C2007CB8 A163BF05
    98DA4836 1C55D39A 69163FA8 FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB
    9ED52907 7096966D 670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
    E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718
    3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D 04507A33
    A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
    ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B F12FFA06 D98A0864
    D8760273 3EC86A64 521F2B18 177B200C BBE11757 7A615D6C 770988C0 BAD946E2
    08E24FA0 74E5AB31 43DB5BFC E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF
  ]])] = "RFC3526/Oakley Group 15",

  [fromhex([[
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74
    020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B 302B0A6D F25F1437
    4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D C2007CB8 A163BF05
    98DA4836 1C55D39A 69163FA8 FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB
    9ED52907 7096966D 670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
    E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718
    3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D 04507A33
    A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
    ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B F12FFA06 D98A0864
    D8760273 3EC86A64 521F2B18 177B200C BBE11757 7A615D6C 770988C0 BAD946E2
    08E24FA0 74E5AB31 43DB5BFC E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7
    88719A10 BDBA5B26 99C32718 6AF4E23C 1A946834 B6150BDA 2583E9CA 2AD44CE8
    DBBBC2DB 04DE8EF9 2E8EFC14 1FBECAA6 287C5947 4E6BC05D 99B2964F A090C3A2
    233BA186 515BE7ED 1F612970 CEE2D7AF B81BDD76 2170481C D0069127 D5B05AA9
    93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34063199 FFFFFFFF FFFFFFFF
  ]])] = "RFC3526/Oakley Group 16",

  [fromhex([[
    B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6 9A6A9DCA 52D23B61
    6073E286 75A23D18 9838EF1E 2EE652C0 13ECB4AE A9061123 24975C3C D49B83BF
    ACCBDD7D 90C4BD70 98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0
    A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708 DF1FB2BC 2E4A4371
  ]])] = "RFC5114/1024-bit DSA group with 160-bit prime order subgroup",

  [fromhex([[
    AD107E1E 9123A9D0 D660FAA7 9559C51F A20D64E5 683B9FD1 B54B1597 B61D0A75
    E6FA141D F95A56DB AF9A3C40 7BA1DF15 EB3D688A 309C180E 1DE6B85A 1274A0A6
    6D3F8152 AD6AC212 9037C9ED EFDA4DF8 D91E8FEF 55B7394B 7AD5B7D0 B6C12207
    C9F98D11 ED34DBF6 C6BA0B2C 8BBC27BE 6A00E0A0 B9C49708 B3BF8A31 70918836
    81286130 BC8985DB 1602E714 415D9330 278273C7 DE31EFDC 7310F712 1FD5A074
    15987D9A DC0A486D CDF93ACC 44328387 315D75E1 98C641A4 80CD86A1 B9E587E8
    BE60E69C C928B2B9 C52172E4 13042E9B 23F10B0E 16E79763 C9B53DCF 4BA80A29
    E3FB73C1 6B8E75B9 7EF363E2 FFA31F71 CF9DE538 4E71B81C 0AC4DFFE 0C10E64F
  ]])] = "RFC5114/2048-bit DSA group with 224-bit prime order subgroup",

  [fromhex([[
    87A8E61D B4B6663C FFBBD19C 65195999 8CEEF608 660DD0F2 5D2CEED4 435E3B00
    E00DF8F1 D61957D4 FAF7DF45 61B2AA30 16C3D911 34096FAA 3BF4296D 830E9A7C
    209E0C64 97517ABD 5A8A9D30 6BCF67ED 91F9E672 5B4758C0 22E0B1EF 4275BF7B
    6C5BFC11 D45F9088 B941F54E B1E59BB8 BC39A0BF 12307F5C 4FDB70C5 81B23F76
    B63ACAE1 CAA6B790 2D525267 35488A0E F13C6D9A 51BFA4AB 3AD83477 96524D8E
    F6A167B5 A41825D9 67E144E5 14056425 1CCACB83 E6B486F6 B3CA3F79 71506026
    C0B857F6 89962856 DED4010A BD0BE621 C3A3960A 54E710C3 75F26375 D7014103
    A4B54330 C198AF12 6116D227 6E11715F 693877FA D7EF09CA DB094AE9 1E1A1597
  ]])] = "RFC5114/2048-bit DSA group with 256-bit prime order subgroup",

  [fromhex([[
    D6C094AD 57F5374F 68D58C7B 096872D9 45CEE1F8 2664E059 4421E1D5 E3C8E98B
    C3F0A6AF 8F92F19E 3FEF9337 B99B9C93 A055D55A 96E42573 4005A68E D47040FD
    F00A5593 6EBA4B93 F64CBA1A 004E4513 611C9B21 7438A703 A2060C20 38D0CFAA
    FFBBA48F B9DAC4B2 450DC58C B0320A03 17E2A31B 44A02787 C657FB0C 0CBEC11D
  ]])] = "weakdh.org/1024-bit MODP group with non-safe prime modulus",

  [fromhex([[
    C9BBF5F7 74A8297B 0F97CDDA 3A3468C7 117B6BF7 99A13D9F 1F5DAC48 7B2241FE
    95EFB13C 2855DFD2 F898B3F9 9188E24E DF326DD6 8C76CC85 53728351 2D46F195
    3129C693 364D8C71 202EABB3 EBC85C1D F53907FB D0B7EB49 0AD0BC99 28968680
    0C46AB04 BF7CDD9A D425E6FB 25592EB6 258A0655 D75E93B2 671746AE 349E721B
  ]])] = "weakdh.org/1024-bit MODP group with safe prime modulus",

  [fromhex([[
    829FEBFC E3EE0434 862D3364 A62BDE7B 65F0C74A 3A53B555 291414FC AE5E86D7
    34B16DBD CC952B1C 5EB443B1 54B3B466 62E811E1 1D8BC731 34018A5E A7B5B6A9
    720D84BC 28B74822 C5AF24C9 04E5BB5A DABF8FF2 A5ED7B45 6688D6CA B82F8AF0
    188A456C 3ED62D2F EACF6BD3 FD47337D 884DFA09 F0A3D696 75E35806 E3AE9593
  ]])] = "weakdh.org/1024-bit MODP group with safe prime modulus",

  [fromhex([[
    92402435 C3A12E44 D3730D8E 78CADFA7 8E2F5B51 A956BFF4 DB8E5652 3E9695E6
    3E32506C FEB912F2 A77D22E7 1BB54C86 80893B82 AD1BCF33 7F7F7796 D3FB9681
    81D9BA1F 7034ABFB 1F97B310 4CF3203F 663E8199 0B7E090F 6C4C5EE1 A0E57EC1
    74D3E84A D9E72E6A C7DA6AEA 12DF297C 131854FB F21AC4E8 79C23BBC 60B4F753
  ]])] = "weakdh.org/1024-bit MODP group with safe prime modulus",

  [fromhex([[
    A9A34811 446C7B69 A29FF999 7C2181EC FAAAD139 CCDE2455 755D42F4 2E700AFD
    86779D54 8A7C07CA 5DE42332 61117D0A 5773F245 9C331AF1 A1B08EF8 360A14DE
    4046F274 62DA36AA 47D9FDE2 92B8815D 598C3A9C 546E7ED3 95D22EC3 9119F5B9
    22CC41B3 0AF220FF 47BDE1B8 8334AD29 81DDC5ED 923F11C3 DDD3B22C 949DC41B
  ]])] = "weakdh.org/1024-bit MODP group with safe prime modulus",

  [fromhex([[
    CA6B8564 6DC21765 7605DACF E801FAD7 59845383 4AF126C8 CC765E0F 81014F24
    93546AB7 DDE5C677 C32D5B06 05B1BBFA 4C5DBFA3 253ADB33 205B7D8C 67DF98C4
    BCE81C78 13F9FC26 15F1C332 F953AB39 CE8B7FE7 E3951FB7 3131407F 4D5489B6
    B17C6875 9A2EAF8B 195A8DE8 0A165E4E B7520774 B167A00F A5629FDC 5A9A25F3
  ]])] = "weakdh.org/1024-bit MODP group with safe prime modulus",

  [fromhex([[
    EB373E94 AB618DF8 20D233ED 93E3EBCB 319BDAC2 0994C1DF 003986A7 9FAFFF76
    54151CC9 E0641314 92698B47 496F5FDC FAF12892 679D8BC3 1580D7D4 1CD83F81
    529C7951 3D58EC67 2E0E87FC D008C137 E3E5861A B2D3A02F 4D372CEE 4F220FEB
    2C9039AC 997664A7 EBB75444 6AA69EB3 E0EF3C60 F91C2639 2B54EC35 A970A7BB
  ]])] = "weakdh.org/1024-bit MODP group with safe prime modulus",

  [fromhex([[
    80A68ADC 5327E05C AAD07C44 64B8ADEA 908432AF 9651B237 F47A7A8B F84D568F
    DFDAFAB0 6621C0C4 28450F1C 55F7D4A8 ECE383F2 7D6055AD DF60C4B8 37DCC1E3
    B8374E37 99517929 39FDC3BB B4285112 C8B4A9F6 FCE4DD53 AA23F99E 2647C394
    CE4D8BB8 2E773F41 EB786CE8 4CD0C3DD 4C31D755 D1CF9E9B 70C45EE2 8ECDABAB
  ]])] = "weakdh.org/1024-bit MODP group with safe prime modulus",

  [fromhex([[
    C0EB5F3A 4CB30A9F FE3786E8 4C038141 69B52030 5AD49F54 EFD8CAAC 31A69B29
    73CC9F57 B4B8F80D 2C5FB68B 3913B617 2042D2E5 BD53381A 5E597696 C9E97BD6
    488DB339 5581320D DD4AF9CD E4A4EBE2 9118C688 28E5B392 89C26728 0B4FDC25
    10C288B2 174D77EE 0AAD9C1E 17EA5ED3 7CF971B6 B19A8711 8E529826 591CA14B
  ]])] = "weakdh.org/1024-bit MODP group with safe prime modulus",

  [fromhex([[
    8FC0E1E2 0574D6AB 3C76DDEA 64524C20 76446B67 98E5B6BD 2614F966 9A5061D6
    99034DB4 819780EC 8EE28A4E 66B5C4E0 A634E47B F9C981A5 EC4908EE 1B83A410
    813165AC 0AB6BDCF D3257188 AC49399D 541C16F2 960F9D64 B9C51EC0 85AD0BB4
    FE389013 18F0CD61 65D4B1B3 1C723953 B83217F8 B3EBF870 8160E82D 7911754B
  ]])] = "weakdh.org/1024-bit MODP group with safe prime modulus",

  -- haproxy, postfix, and IronPort params courtesy Frank Bergmann
  [fromhex([[
    EC86F870 A03316EC 051A7359 CD1F8BF8 29E4D2CF 52DDC224 8DB5389A FB5CA4E4
    B2DACE66 5074A685 4D4B1D30 B82BF310 E9A72D05 71E781DF 8B59523B 5F430B68
    F1DB07BE 086B1B23 EE4DCC9E 0E43A01E DF438CEC BEBE90B4 5154B92F 7B64764E
    5DD42EAE C29EAE51 4359C777 9C503C0E ED73045F F14C762A D8F8CFFC 3440D1B4
    42618466 423904F8 68B262D7 55ED1B74 7591E0C5 69C1315C DB7B442E CE84580D
    1E660CC8 449EFD40 08675DFB A7768F00 1187E993 F97DC4BC 745520D4 4A412F43
    421AC1F2 97174927 376B2F88 7E1CA0A1 899227D9 565A71C1 56377E3A 9D05E7EE
    5D8F8217 BCE9C293 3082F9F4 C9AE49DB D054B4D9 754DFA06 B8D63841 B71F77F3
  ]])] = "haproxy 1.5 builtin",

  [fromhex([[
    B0FEB4CF D45507E7 CC88590D 1726C50C A54A9223 8178DA88 AA4C1306 BF5D2F9E
    BC96B851 009D0C0D 75ADFD3B B17E714F 3F915414 44B83025 1CEBDF72 9C4CF189
    0D683F94 8EA4FB76 8918B291 16900199 668C5381 4E273D99 E75A7AAF D5ECE27E
    FAED0118 C2782559 065C39F6 CD4954AF C1B1EA4A F953D0DF 6DAFD493 E7BAAE9B
  ]])] = "postfix builtin",

  [fromhex([[
    F8D5CCE8 7A3961B5 F5CBC834 40C51856 E0E6FA6D 5AB28310 78C86762 1CA46CA8
    7D7FA3B1 AF75B834 3C699374 D36920F2 E39A653D E8F0725A A6E2D297 7537558C
    E27E784F 4B549BEF B558927B A30C8BD8 1DACDCAE 93027B5D CE1BC176 70AF7DEC
    E81149AB D7D632D9 B80A6397 CEBCC7A9 619CCF38 288EA3D5 23287743 B04E6FB3
  ]])] = "IronPort SMTPD builtin",
}


-- DSA parameters
local DSA_PARAMS = {
  -- sun.security.provider/512-bit DSA group with 160-bit prime order subgroup
  [fromhex([[
    FCA682CE 8E12CABA 26EFCCF7 110E526D B078B05E DECBCD1E B4A208F3 AE1617AE
    01F35B91 A47E6DF6 3413C5E1 2ED0899B CD132ACD 50D99151 BDC43EE7 37592E17
  ]])] =

         fromhex([[
           678471B2 7A9CF44E E91A49C5 147DB1A9 AAF244F0 5A434D64 86931D2D 14271B9E
           35030B71 FD73DA17 9069B32E 2935630E 1C206235 4D0DA20A 6C416E50 BE794CA4
         ]]),

  -- sun.security.provider/768-bit DSA group with 160-bit prime order subgroup
  [fromhex([[
    E9E64259 9D355F37 C97FFD35 67120B8E 25C9CD43 E927B3A9 670FBEC5 D8901419
    22D2C3B3 AD248009 3799869D 1E846AAB 49FAB0AD 26D2CE6A 22219D47 0BCE7D77
    7D4A21FB E9C270B5 7F607002 F3CEF839 3694CF45 EE3688C1 1A8C56AB 127A3DAF
  ]])] =

         fromhex([[
           30470AD5 A005FB14 CE2D9DCD 87E38BC7 D1B1C5FA CBAECBE9 5F190AA7 A31D23C4
           DBBCBE06 17454440 1A5B2C02 0965D8C2 BD2171D3 66844577 1F74BA08 4D2029D8
           3C1C1585 47F3A9F1 A2715BE2 3D51AE4D 3E5A1F6A 7064F316 933A346D 3F529252
         ]]),

  -- sun.security.provider/1024-bit DSA group with 160-bit prime order subgroup
  [fromhex([[
    FD7F5381 1D751229 52DF4A9C 2EECE4E7 F611B752 3CEF4400 C31E3F80 B6512669
    455D4022 51FB593D 8D58FABF C5F5BA30 F6CB9B55 6CD7813B 801D346F F26660B7
    6B9950A5 A49F9FE8 047B1022 C24FBBA9 D7FEB7C6 1BF83B57 E7C6A8A6 150F04FB
    83F6D3C5 1EC30235 54135A16 9132F675 F3AE2B61 D72AEFF2 2203199D D14801C7
  ]])] =

         fromhex([[
           F7E1A085 D69B3DDE CBBCAB5C 36B857B9 7994AFBB FA3AEA82 F9574C0B 3D078267
           5159578E BAD4594F E6710710 8180B449 167123E8 4C281613 B7CF0932 8CC8A6E1
           3C167A8B 547C8D28 E0A3AE1E 2BB3A675 916EA37F 0BFA2135 62F1FB62 7A01243B
           CCA4F1BE A8519089 A883DFE1 5AE59F06 928B665E 807B5525 64014C3B FECF492A
         ]]),

  -- RFC5114/1024-bit DSA group with 160-bit prime order subgroup
  [fromhex([[
    B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6 9A6A9DCA 52D23B61
    6073E286 75A23D18 9838EF1E 2EE652C0 13ECB4AE A9061123 24975C3C D49B83BF
    ACCBDD7D 90C4BD70 98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0
    A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708 DF1FB2BC 2E4A4371
  ]])] =

         fromhex([[
           A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F D6406CFF 14266D31
           266FEA1E 5C41564B 777E690F 5504F213 160217B4 B01B886A 5E91547F 9E2749F4
           D7FBD7D3 B9A92EE1 909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A
           D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24 855E6EEB 22B3B2E5
         ]]),

  -- RFC5114/2048-bit DSA group with 224-bit prime order subgroup
  [fromhex([[
    AD107E1E 9123A9D0 D660FAA7 9559C51F A20D64E5 683B9FD1 B54B1597 B61D0A75
    E6FA141D F95A56DB AF9A3C40 7BA1DF15 EB3D688A 309C180E 1DE6B85A 1274A0A6
    6D3F8152 AD6AC212 9037C9ED EFDA4DF8 D91E8FEF 55B7394B 7AD5B7D0 B6C12207
    C9F98D11 ED34DBF6 C6BA0B2C 8BBC27BE 6A00E0A0 B9C49708 B3BF8A31 70918836
    81286130 BC8985DB 1602E714 415D9330 278273C7 DE31EFDC 7310F712 1FD5A074
    15987D9A DC0A486D CDF93ACC 44328387 315D75E1 98C641A4 80CD86A1 B9E587E8
    BE60E69C C928B2B9 C52172E4 13042E9B 23F10B0E 16E79763 C9B53DCF 4BA80A29
    E3FB73C1 6B8E75B9 7EF363E2 FFA31F71 CF9DE538 4E71B81C 0AC4DFFE 0C10E64F
  ]])] =

         fromhex([[
           AC4032EF 4F2D9AE3 9DF30B5C 8FFDAC50 6CDEBE7B 89998CAF 74866A08 CFE4FFE3
           A6824A4E 10B9A6F0 DD921F01 A70C4AFA AB739D77 00C29F52 C57DB17C 620A8652
           BE5E9001 A8D66AD7 C1766910 1999024A F4D02727 5AC1348B B8A762D0 521BC98A
           E2471504 22EA1ED4 09939D54 DA7460CD B5F6C6B2 50717CBE F180EB34 118E98D1
           19529A45 D6F83456 6E3025E3 16A330EF BB77A86F 0C1AB15B 051AE3D4 28C8F8AC
           B70A8137 150B8EEB 10E183ED D19963DD D9E263E4 770589EF 6AA21E7F 5F2FF381
           B539CCE3 409D13CD 566AFBB4 8D6C0191 81E1BCFE 94B30269 EDFE72FE 9B6AA4BD
           7B5A0F1C 71CFFF4C 19C418E1 F6EC0179 81BC087F 2A7065B3 84B890D3 191F2BFA
         ]]),

  -- RFC5114/2048-bit DSA group with 256-bit prime order subgroup
  [fromhex([[
    87A8E61D B4B6663C FFBBD19C 65195999 8CEEF608 660DD0F2 5D2CEED4 435E3B00
    E00DF8F1 D61957D4 FAF7DF45 61B2AA30 16C3D911 34096FAA 3BF4296D 830E9A7C
    209E0C64 97517ABD 5A8A9D30 6BCF67ED 91F9E672 5B4758C0 22E0B1EF 4275BF7B
    6C5BFC11 D45F9088 B941F54E B1E59BB8 BC39A0BF 12307F5C 4FDB70C5 81B23F76
    B63ACAE1 CAA6B790 2D525267 35488A0E F13C6D9A 51BFA4AB 3AD83477 96524D8E
    F6A167B5 A41825D9 67E144E5 14056425 1CCACB83 E6B486F6 B3CA3F79 71506026
    C0B857F6 89962856 DED4010A BD0BE621 C3A3960A 54E710C3 75F26375 D7014103
    A4B54330 C198AF12 6116D227 6E11715F 693877FA D7EF09CA DB094AE9 1E1A1597
  ]])] =

         fromhex([[
           3FB32C9B 73134D0B 2E775066 60EDBD48 4CA7B18F 21EF2054 07F4793A 1A0BA125
           10DBC150 77BE463F FF4FED4A AC0BB555 BE3A6C1B 0C6B47B1 BC3773BF 7E8C6F62
           901228F8 C28CBB18 A55AE313 41000A65 0196F931 C77A57F2 DDF463E5 E9EC144B
           777DE62A AAB8A862 8AC376D2 82D6ED38 64E67982 428EBC83 1D14348F 6F2F9193
           B5045AF2 767164E1 DFC967C1 FB3F2E55 A4BD1BFF E83B9C80 D052B985 D182EA0A
           DB2A3B73 13D3FE14 C8484B1E 052588B9 B7D2BBD2 DF016199 ECD06E15 57CD0915
           B3353BBB 64E0EC37 7FD02837 0DF92B52 C7891428 CDC67EB6 184B523D 1DB246C3
           2F630784 90F00EF8 D647D148 D4795451 5E2327CF EF98C582 664B4C0F 6CC41659
         ]])
}


-- Add additional context (protocol) to debug output
local function ctx_log(level, protocol, fmt, ...)
  return stdnse.debug(level, "(%s) " .. fmt, protocol, ...)
end


-- returns a function that yields a new tls record each time it is called
local function get_record_iter(sock)
  local buffer = ""
  local i = 1
  local fragment
  return function ()
    local record
    i, record = tls.record_read(buffer, i, fragment)
    if record == nil then
      local status, err
      status, buffer, err = tls.record_buffer(sock, buffer, i)
      if not status then
        return nil, err
      end
      i, record = tls.record_read(buffer, i, fragment)
      if record == nil then
        return nil, "done"
      end
    end
    fragment = record.fragment
    return record
  end
end


local function get_server_response(host, port, t)
  local timeout = stdnse.get_timeout(host, 10000, 5000)

  -- Create socket.
  local status, sock, err
  local starttls = sslcert.getPrepareTLSWithoutReconnect(port)
  if starttls then
    status, sock = starttls(host, port)
    if not status then
      ctx_log(1, t.protocol, "Can't connect: %s", sock)
      return nil
    end
  else
    sock = nmap.new_socket()
    sock:set_timeout(timeout)
    status, err = sock:connect(host, port)
    if not status then
      ctx_log(1, t.protocol, "Can't connect: %s", err)
      sock:close()
      return nil
    end
  end

  sock:set_timeout(timeout)

  -- Send request.
  local req = tls.client_hello(t)
  status, err = sock:send(req)
  if not status then
    ctx_log(1, t.protocol, "Can't send: %s", err)
    sock:close()
    return nil
  end

  -- Read response.
  local get_next_record = get_record_iter(sock)
  local records = {}
  while true do
    local record
    record, err = get_next_record()
    if not record then
      ctx_log(1, t.protocol, "Couldn't read a TLS record: %s", err)
      sock:close()
      return records
    end
    -- Collect message bodies into one record per type
    records[record.type] = records[record.type] or record
    local done = false
    for j = 1, #record.body do -- no ipairs because we append below
      local b = record.body[j]
      done = ((record.type == "alert" and b.level == "fatal") or
        (record.type == "handshake" and b.type == "server_hello_done"))
      table.insert(records[record.type].body, b)
    end
    if done then
      sock:close()
      return records
    end
  end
end

-- If protocol fails (i.e. no ciphers will ever succeed) then returns false
-- If no ciphers were supported, but the protocol is valid, then returns nil
-- else returns the cipher and dh params
local function get_dhe_params(host, port, protocol, ciphers)
  local cipher, packed
  local t = {}
  local pos = 1
  t.protocol = protocol
  local tlsname = tls.servername(host)
  t.extensions = {
    server_name = tlsname and tls.EXTENSION_HELPERS["server_name"](tlsname),
  }

  -- Keep ClientHello record size below 255 bytes and the number of ciphersuites
  -- to 64 or less in order to avoid implementation issues with some TLS servers

  -- Get handshake record size with just one cipher
  t.ciphers = { "TLS_NULL_WITH_NULL_NULL" }
  local len = #tls.client_hello(t)
  local room = math.floor(math.max(0, (255 - len) / 2))

  local function next_chunk(t, ciphers, pos)

    -- Compute number of ciphers to fit in next chunk
    local last = math.min(#ciphers, pos + math.min(63, room))
    t.ciphers = {}

    for i = pos, last do
      table.insert(t.ciphers, ciphers[i])
    end

    return last + 1
  end

  while pos <= #ciphers do
    pos = next_chunk(t, ciphers, pos)
    local records = get_server_response(host, port, t)
    if not records then
      stdnse.debug1("Connection failed")
      return false
    end

    local alert = records.alert
    if alert then
      for j = 1, #alert.body do
        ctx_log(2, protocol, "Received alert: %s", alert.body[j].description)
        if alert["protocol"] ~= protocol then
          ctx_log(1, protocol, "Protocol rejected.")
          return false
        end
      end
    end

    -- Extract negotiated cipher suite and key exchange data
    local handshake = records.handshake
    if handshake then
      for j = 1, #handshake.body do
        if handshake.body[j].type == "server_hello" then
          if handshake.body[j].protocol ~= protocol then
            ctx_log(1, protocol, "Protocol rejected in server hello")
            return false
          end
          cipher = handshake.body[j].cipher
        elseif handshake.body[j].type == "server_key_exchange" then
          packed = handshake.body[j].data
        end
      end
    end

    -- Only try next chunk if current chunk was rejected
    if cipher and packed then
      local info = tls.cipher_info(cipher)
      local data = tls.KEX_ALGORITHMS[info.kex].server_key_exchange(packed, protocol)
      return cipher, data.dhparams
    end
  end

  return nil
end


local function get_dhe_ciphers()
  local dh_anons = {}
  local dhe_ciphers = {}
  local dhe_exports = {}

  for cipher, _ in pairs(tls.CIPHERS) do
    local info = tls.cipher_info(cipher)
    if DH_anon_ALGORITHMS[info.kex] then
      dh_anons[#dh_anons + 1] = cipher
    end
    if DHE_ALGORITHMS[info.kex] then
      dhe_ciphers[#dhe_ciphers + 1] = cipher
    end
    if DHE_ALGORITHMS_EXPORT[info.kex] then
      dhe_exports[#dhe_exports + 1] = cipher
    end
  end

  return dh_anons, dhe_ciphers, dhe_exports
end

local fields_order = {
  "Cipher Suite",
  "Modulus Type",
  "Modulus Source",
  "Modulus Length",
  "Generator Length",
  "Public Key Length",
}
local group_metatable = {
  __tostring = function(g)
    local out = {}
    for i=1, #fields_order do
      local k = fields_order[i]
      if g[k] then
        out[#out+1] = ("      %s: %s"):format(k, g[k])
      end
    end
    return table.concat(out, "\n")
  end
}

local function check_dhgroup(anondh, logjam, weakdh, nosafe, cipher, dhparams)
  local source = DHE_PRIMES[dhparams.p]
  local length = #dhparams.p * 8
  local genlen = #dhparams.g * 8
  local pubkeylen = #dhparams.y * 8
  local modulus = stdnse.tohex(dhparams.p)
  local generator = stdnse.tohex(dhparams.g)
  local pubkey = stdnse.tohex(dhparams.y)
  local is_prime, is_safe

  local group = {
    ["Cipher Suite"] = cipher,
    ["Modulus Source"] = source or "Unknown/Custom-generated",
    ["Modulus Length"] = length,
    ["Modulus"] = modulus,
    ["Generator Length"] = genlen,
    ["Generator"] = generator,
    ["Public Key Length"] = pubkeylen
  }
  setmetatable(group, group_metatable)

  if have_ssl then
    local bn = openssl.bignum_bin2bn(dhparams.p)
    is_safe, is_prime = openssl.bignum_is_safe_prime(bn)
    group["Modulus Type"] = (is_safe and "Safe prime") or
                     (is_prime and "Non-safe prime") or
                     "Composite"
  end

  if string.find(cipher, "DH_anon") then
    anondh[#anondh + 1] = group
  elseif string.find(cipher, "EXPORT") then
    logjam[#logjam + 1] = group
  elseif length <= 1024 then
    weakdh[#weakdh + 1] = group
  end

  -- The use of non-safe primes requires carefully generated parameters
  -- in order to be secure. Do some rudimentary validation checks here.
  if have_ssl and not is_safe and not DSA_PARAMS[dhparams.p] then
    nosafe[#nosafe + 1] = group
  elseif DSA_PARAMS[dhparams.p] and DSA_PARAMS[dhparams.p] ~= dhparams.g then
    nosafe[#nosafe + 1] = group
  end
end


portrule = function(host, port)
  return shortport.ssl(host, port) or sslcert.getPrepareTLSWithoutReconnect(port)
end

local function format_check(t, label)
  local out = {}
  for i, v in ipairs(t) do
    out[i] = string.format("%s %d\n%s", label, i, v)
  end
  return out
end

action = function(host, port)
  local dh_anons, dhe_ciphers, dhe_exports = get_dhe_ciphers()
  local cipher
  local dhparams
  local anondh = {}
  local logjam = {}
  local weakdh = {}
  local nosafe = {}
  local primes = {}
  local anons = {}

  local vuln_table_anondh = {
    title = "Anonymous Diffie-Hellman Key Exchange MitM Vulnerability",
    description = [[
Transport Layer Security (TLS) services that use anonymous
Diffie-Hellman key exchange only provide protection against passive
eavesdropping, and are vulnerable to active man-in-the-middle attacks
which could completely compromise the confidentiality and integrity
of any data exchanged over the resulting session.]],
    state = vulns.STATE.NOT_VULN,
    references = {
      "https://www.ietf.org/rfc/rfc2246.txt"
    }
  }

  local vuln_table_logjam = {
    title = "Transport Layer Security (TLS) Protocol DHE_EXPORT Ciphers Downgrade MitM (Logjam)",
    description = [[
The Transport Layer Security (TLS) protocol contains a flaw that is
triggered when handling Diffie-Hellman key exchanges defined with
the DHE_EXPORT cipher. This may allow a man-in-the-middle attacker
to downgrade the security of a TLS session to 512-bit export-grade
cryptography, which is significantly weaker, allowing the attacker
to more easily break the encryption and monitor or tamper with
the encrypted stream.]],
    state = vulns.STATE.NOT_VULN,
    IDS = {
      CVE = 'CVE-2015-4000',
      OSVDB = '122331'
    },
    SCORES = {
      CVSSv2 = '4.3'
    },
    dates = {
      disclosure = {
        year = 2015, month = 5, day = 19
      }
    },
    references = {
      "https://weakdh.org"
    }
  }

  local vuln_table_weakdh = {
    title = "Diffie-Hellman Key Exchange Insufficient Group Strength",
    description = [[
Transport Layer Security (TLS) services that use Diffie-Hellman groups
of insufficient strength, especially those using one of a few commonly
shared groups, may be susceptible to passive eavesdropping attacks.]],
    state = vulns.STATE.NOT_VULN,
    references = {
      "https://weakdh.org"
    }
  }

  local vuln_table_nosafe = {
    title = "Diffie-Hellman Key Exchange Incorrectly Generated Group Parameters",
    description = [[
This TLS service appears to be using a modulus that is not a safe prime
and does not correspond to any well-known DSA group for Diffie-Hellman
key exchange.
These parameters MAY be secure if:
- They were generated according to the procedure described in
  FIPS 186-4 for DSA Domain Parameter Generation, or
- The generator g generates a subgroup of large prime order
Additional testing may be required to verify the security of these
parameters.]],
    state = vulns.STATE.NOT_VULN,
    references = {
      "https://weakdh.org",
      "http://www2.esentire.com/TLSUnjammedWP"
    }
  }

  for protocol in pairs(tls.PROTOCOLS) do
    -- Try anonymous DH ciphersuites
    cipher, dhparams = get_dhe_params(host, port, protocol, dh_anons)
    -- Explicit test for false needed because nil just means no ciphers supported.
    if cipher == false then goto NEXT_PROTOCOL end
    if dhparams and not anons[dhparams.p] then
      vuln_table_anondh.state = vulns.STATE.VULN
      check_dhgroup(anondh, logjam, weakdh, nosafe, cipher, dhparams)
      anons[dhparams.p] = 1
    end

    -- Try DHE_EXPORT ciphersuites
    cipher, dhparams = get_dhe_params(host, port, protocol, dhe_exports)
    if dhparams and not primes[dhparams.p] then
      check_dhgroup(anondh, logjam, weakdh, nosafe, cipher, dhparams)
      primes[dhparams.p] = 1
    end

    -- Try non-export DHE ciphersuites
    cipher, dhparams = get_dhe_params(host, port, protocol, dhe_ciphers)
    if dhparams and not primes[dhparams.p] then
      check_dhgroup(anondh, logjam, weakdh, nosafe, cipher, dhparams)
      primes[dhparams.p] = 1
    end
    ::NEXT_PROTOCOL::
  end

  local report = vulns.Report:new(SCRIPT_NAME, host, port)

  vuln_table_anondh.check_results = format_check(anondh, "ANONYMOUS DH GROUP")
  vuln_table_logjam.check_results = format_check(logjam, "EXPORT-GRADE DH GROUP")
  vuln_table_weakdh.check_results = format_check(weakdh, "WEAK DH GROUP")
  vuln_table_nosafe.check_results = format_check(nosafe, "NON-SAFE GROUP")

  if #anondh > 0 then
    vuln_table_anondh.state = vulns.STATE.VULN
  end

  if #logjam > 0 then
    vuln_table_logjam.state = vulns.STATE.VULN
  end

  if #weakdh > 0 then
    vuln_table_weakdh.state = vulns.STATE.VULN
  end

  if #nosafe > 0 then
    vuln_table_nosafe.state = vulns.STATE.LIKELY_VULN
  end

  return report:make_output(vuln_table_anondh, vuln_table_logjam, vuln_table_weakdh, vuln_table_nosafe)
end
