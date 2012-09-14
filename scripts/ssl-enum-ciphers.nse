local bin = require "bin"
local coroutine = require "coroutine"
local io = require "io"
local nmap = require "nmap"
local os = require "os"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
This script repeatedly initiates SSL/TLS connections, each time trying a new
cipher or compressor while recording whether a host accepts or rejects it. The
end result is a list of all the ciphers and compressors that a server accepts.

Each cipher is shown with a strength rating: one of <code>strong</code>,
<code>weak</code>, or <code>unknown strength</code>. The output line
beginning with <code>Least strength</code> shows the strength of the
weakest cipher offered. If you are auditing for weak ciphers, you would
want to look more closely at any port where <code>Least strength</code>
is not <code>strong</code>. The cipher strength database is in the file
<code>nselib/data/ssl-ciphers</code>, or you can use a different file
through the script argument
<code>ssl-enum-ciphers.rankedcipherlist</code>.

SSLv3/TLSv1 requires more effort to determine which ciphers and compression
methods a server supports than SSLv2. A client lists the ciphers and compressors
that it is capable of supporting, and the server will respond with a single
cipher and compressor chosen, or a rejection notice.

This script is intrusive since it must initiate many connections to a server,
and therefore is quite noisy.
]]

---
-- @usage
-- nmap --script ssl-enum-ciphers -p 443 <host>
--
-- @args ssl-enum-ciphers.rankedcipherlist A path to a file of cipher names and strength ratings
--
-- @output
-- PORT    STATE SERVICE REASON
-- 443/tcp open  https   syn-ack
-- | ssl-enum-ciphers:
-- |   SSLv3
-- |     Ciphers (6)
-- |       TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA - unknown strength
-- |       TLS_DHE_RSA_WITH_AES_128_CBC_SHA - strong
-- |       TLS_DHE_RSA_WITH_AES_256_CBC_SHA - unknown strength
-- |       TLS_RSA_WITH_3DES_EDE_CBC_SHA - strong
-- |       TLS_RSA_WITH_AES_128_CBC_SHA - strong
-- |       TLS_RSA_WITH_AES_256_CBC_SHA - unknown strength
-- |     Compressors (1)
-- |       uncompressed
-- |   TLSv1.0
-- |     Ciphers (6)
-- |       TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA - unknown strength
-- |       TLS_DHE_RSA_WITH_AES_128_CBC_SHA - strong
-- |       TLS_DHE_RSA_WITH_AES_256_CBC_SHA - unknown strength
-- |       TLS_RSA_WITH_3DES_EDE_CBC_SHA - strong
-- |       TLS_RSA_WITH_AES_128_CBC_SHA - strong
-- |       TLS_RSA_WITH_AES_256_CBC_SHA - unknown strength
-- |     Compressors (1)
-- |       uncompressed
-- |_  Least strength = unknown strength
--
-- @xmloutput
-- <table key="SSLv3">
--   <table key="ciphers">
--     <table>
--       <elem key="strength">strong</elem>
--       <elem key="name">TLS_RSA_WITH_3DES_EDE_CBC_SHA</elem>
--     </table>
--     <table>
--       <elem key="strength">weak</elem>
--       <elem key="name">TLS_RSA_WITH_DES_CBC_SHA</elem>
--     </table>
--     <table>
--       <elem key="strength">strong</elem>
--       <elem key="name">TLS_RSA_WITH_RC4_128_MD5</elem>
--     </table>
--     <table>
--       <elem key="strength">strong</elem>
--       <elem key="name">TLS_RSA_WITH_RC4_128_SHA</elem>
--     </table>
--   </table>
--   <table key="compressors">
--     <elem>NULL</elem>
--   </table>
-- </table>
-- <table key="TLSv1.0">
--   <table key="ciphers">
--     <table>
--       <elem key="strength">strong</elem>
--       <elem key="name">TLS_RSA_WITH_3DES_EDE_CBC_SHA</elem>
--     </table>
--     <table>
--       <elem key="strength">weak</elem>
--       <elem key="name">TLS_RSA_WITH_DES_CBC_SHA</elem>
--     </table>
--     <table>
--       <elem key="strength">strong</elem>
--       <elem key="name">TLS_RSA_WITH_RC4_128_MD5</elem>
--     </table>
--     <table>
--       <elem key="strength">strong</elem>
--       <elem key="name">TLS_RSA_WITH_RC4_128_SHA</elem>
--     </table>
--   </table>
--   <table key="compressors">
--     <elem>NULL</elem>
--   </table>
-- </table>
-- <elem key="least strength">weak</elem>

author = "Mak Kolybabi <mak@kolybabi.com>, Gabriel Lawrence"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"discovery", "intrusive"}


-- Most of the values in the tables below are from:
-- http://www.iana.org/assignments/tls-parameters/
PROTOCOLS = {
	["SSLv3"]	= 0x0300,
	["TLSv1.0"]	= 0x0301,
	["TLSv1.1"]	= 0x0302,
	["TLSv1.2"]	= 0x0303
}

--
-- TLS Record Types
--
TLS_RECORD_HEADER_LENGTH = 5

TLS_CONTENTTYPE_REGISTRY = {
	["change_cipher_spec"]	= 20,
	["alert"]		= 21,
	["handshake"]		= 22,
	["application_data"]	= 23
}

--
-- TLS Alert Levels
--
TLS_ALERT_LEVELS = {
	["warning"]	= 1,
	["fatal"]	= 2,
}

--
-- TLS Alert Record Types
--
TLS_ALERT_REGISTRY = {
	["close_notify"]			= 0,
	["unexpected_message"]			= 10,
	["bad_record_mac"]			= 20,
	["decryption_failed"]			= 21,
	["record_overflow"]			= 22,
	["decompression_failure"]		= 30,
	["handshake_failure"]			= 40,
	["no_certificate"]			= 41,
	["bad_certificate"]			= 42,
	["unsupported_certificate"]		= 43,
	["certificate_revoked"]			= 44,
	["certificate_expired"]			= 45,
	["certificate_unknown"]			= 46,
	["illegal_parameter"]			= 47,
	["unknown_ca"]				= 48,
	["access_denied"]			= 49,
	["decode_error"]			= 50,
	["decrypt_error"]			= 51,
	["export_restriction"]			= 60,
	["protocol_version"]			= 70,
	["insufficient_security"]		= 71,
	["internal_error"]			= 80,
	["user_canceled"]			= 90,
	["no_renegotiation"]			= 100,
	["unsupported_extension"]		= 110,
	["certificate_unobtainable"]		= 111,
	["unrecognized_name"]			= 112,
	["bad_certificate_status_response"]	= 113,
	["bad_certificate_hash_value"]		= 114,
	["unknown_psk_identity"]		= 115
}

--
-- TLS Handshake Record Types
--
TLS_HANDSHAKETYPE_REGISTRY = {
	["hello_request"]		= 0,
	["client_hello"]		= 1,
	["server_hello"]		= 2,
	["hello_verify_request"]	= 3,
	["NewSessionTicket"]		= 4,
	["certificate"]			= 11,
	["server_key_exchange"]		= 12,
	["certificate_request"]		= 13,
	["server_hello_done"]		= 14,
	["certificate_verify"]		= 15,
	["client_key_exchange"]		= 16,
	["finished"]			= 20,
	["certificate_url"]		= 21,
	["certificate_status"]		= 22,
	["supplemental_data"]		= 23
}

--
-- Compression Algorithms
-- http://www.iana.org/assignments/comp-meth-ids
--
COMPRESSORS = {
	["NULL"]		= 0,
	["DEFLATE"]		= 1,
	["LZS"]			= 64
}

--
-- Encryption Algorithms
--
CIPHERS = {
["TLS_NULL_WITH_NULL_NULL"]                        =  0x0000,
["TLS_RSA_WITH_NULL_MD5"]                          =  0x0001,
["TLS_RSA_WITH_NULL_SHA"]                          =  0x0002,
["TLS_RSA_EXPORT_WITH_RC4_40_MD5"]                 =  0x0003,
["TLS_RSA_WITH_RC4_128_MD5"]                       =  0x0004,
["TLS_RSA_WITH_RC4_128_SHA"]                       =  0x0005,
["TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"]             =  0x0006,
["TLS_RSA_WITH_IDEA_CBC_SHA"]                      =  0x0007,
["TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"]              =  0x0008,
["TLS_RSA_WITH_DES_CBC_SHA"]                       =  0x0009,
["TLS_RSA_WITH_3DES_EDE_CBC_SHA"]                  =  0x000A,
["TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA"]           =  0x000B,
["TLS_DH_DSS_WITH_DES_CBC_SHA"]                    =  0x000C,
["TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA"]               =  0x000D,
["TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA"]           =  0x000E,
["TLS_DH_RSA_WITH_DES_CBC_SHA"]                    =  0x000F,
["TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA"]               =  0x0010,
["TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"]          =  0x0011,
["TLS_DHE_DSS_WITH_DES_CBC_SHA"]                   =  0x0012,
["TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"]              =  0x0013,
["TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"]          =  0x0014,
["TLS_DHE_RSA_WITH_DES_CBC_SHA"]                   =  0x0015,
["TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"]              =  0x0016,
["TLS_DH_anon_EXPORT_WITH_RC4_40_MD5"]             =  0x0017,
["TLS_DH_anon_WITH_RC4_128_MD5"]                   =  0x0018,
["TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA"]          =  0x0019,
["TLS_DH_anon_WITH_DES_CBC_SHA"]                   =  0x001A,
["TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"]              =  0x001B,
["SSL_FORTEZZA_KEA_WITH_NULL_SHA"]                 =  0x001C,
["SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA"]         =  0x001D,
["TLS_KRB5_WITH_DES_CBC_SHA-or-SSL_FORTEZZA_KEA_WITH_RC4_128_SHA"] = 0x001E, --TLS vs SSLv3
["TLS_KRB5_WITH_3DES_EDE_CBC_SHA"]                 =  0x001F,
["TLS_KRB5_WITH_RC4_128_SHA"]                      =  0x0020,
["TLS_KRB5_WITH_IDEA_CBC_SHA"]                     =  0x0021,
["TLS_KRB5_WITH_DES_CBC_MD5"]                      =  0x0022,
["TLS_KRB5_WITH_3DES_EDE_CBC_MD5"]                 =  0x0023,
["TLS_KRB5_WITH_RC4_128_MD5"]                      =  0x0024,
["TLS_KRB5_WITH_IDEA_CBC_MD5"]                     =  0x0025,
["TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA"]            =  0x0026,
["TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA"]            =  0x0027,
["TLS_KRB5_EXPORT_WITH_RC4_40_SHA"]                =  0x0028,
["TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5"]            =  0x0029,
["TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5"]            =  0x002A,
["TLS_KRB5_EXPORT_WITH_RC4_40_MD5"]                =  0x002B,
["TLS_PSK_WITH_NULL_SHA"]                          =  0x002C,
["TLS_DHE_PSK_WITH_NULL_SHA"]                      =  0x002D,
["TLS_RSA_PSK_WITH_NULL_SHA"]                      =  0x002E,
["TLS_RSA_WITH_AES_128_CBC_SHA"]                   =  0x002F,
["TLS_DH_DSS_WITH_AES_128_CBC_SHA"]                =  0x0030,
["TLS_DH_RSA_WITH_AES_128_CBC_SHA"]                =  0x0031,
["TLS_DHE_DSS_WITH_AES_128_CBC_SHA"]               =  0x0032,
["TLS_DHE_RSA_WITH_AES_128_CBC_SHA"]               =  0x0033,
["TLS_DH_anon_WITH_AES_128_CBC_SHA"]               =  0x0034,
["TLS_RSA_WITH_AES_256_CBC_SHA"]                   =  0x0035,
["TLS_DH_DSS_WITH_AES_256_CBC_SHA"]                =  0x0036,
["TLS_DH_RSA_WITH_AES_256_CBC_SHA"]                =  0x0037,
["TLS_DHE_DSS_WITH_AES_256_CBC_SHA"]               =  0x0038,
["TLS_DHE_RSA_WITH_AES_256_CBC_SHA"]               =  0x0039,
["TLS_DH_anon_WITH_AES_256_CBC_SHA"]               =  0x003A,
["TLS_RSA_WITH_NULL_SHA256"]                       =  0x003B,
["TLS_RSA_WITH_AES_128_CBC_SHA256"]                =  0x003C,
["TLS_RSA_WITH_AES_256_CBC_SHA256"]                =  0x003D,
["TLS_DH_DSS_WITH_AES_128_CBC_SHA256"]             =  0x003E,
["TLS_DH_RSA_WITH_AES_128_CBC_SHA256"]             =  0x003F,
["TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"]            =  0x0040,
["TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"]              =  0x0041,
["TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA"]           =  0x0042,
["TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA"]           =  0x0043,
["TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA"]          =  0x0044,
["TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"]          =  0x0045,
["TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA"]          =  0x0046,
["TLS_ECDH_ECDSA_WITH_NULL_SHA-draft"]             =  0x0047,  --draft-ietf-tls-ecc-00
["TLS_ECDH_ECDSA_WITH_RC4_128_SHA-draft"]          =  0x0048,  --draft-ietf-tls-ecc-00
["TLS_ECDH_ECDSA_WITH_DES_CBC_SHA-draft"]          =  0x0049,  --draft-ietf-tls-ecc-00
["TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA-draft"]     =  0x004A,  --draft-ietf-tls-ecc-00
["TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA-draft"]      =  0x004B,  --draft-ietf-tls-ecc-00
["TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA-draft"]      =  0x004C,  --draft-ietf-tls-ecc-00
["TLS_ECDH_ECNRA_WITH_DES_CBC_SHA-draft"]          =  0x004D,  --draft-ietf-tls-ecc-00
["TLS_ECDH_ECNRA_WITH_3DES_EDE_CBC_SHA-draft"]     =  0x004E,  --draft-ietf-tls-ecc-00
["TLS_ECMQV_ECDSA_NULL_SHA-draft"]                 =  0x004F,  --draft-ietf-tls-ecc-00
["TLS_ECMQV_ECDSA_WITH_RC4_128_SHA-draft"]         =  0x0050,  --draft-ietf-tls-ecc-00
["TLS_ECMQV_ECDSA_WITH_DES_CBC_SHA-draft"]         =  0x0051,  --draft-ietf-tls-ecc-00
["TLS_ECMQV_ECDSA_WITH_3DES_EDE_CBC_SHA-draft"]    =  0x0052,  --draft-ietf-tls-ecc-00
["TLS_ECMQV_ECNRA_NULL_SHA-draft"]                 =  0x0053,  --draft-ietf-tls-ecc-00
["TLS_ECMQV_ECNRA_WITH_RC4_128_SHA-draft"]         =  0x0054,  --draft-ietf-tls-ecc-00
["TLS_ECMQV_ECNRA_WITH_DES_CBC_SHA-draft"]         =  0x0055,  --draft-ietf-tls-ecc-00
["TLS_ECMQV_ECNRA_WITH_3DES_EDE_CBC_SHA-draft"]    =  0x0056,  --draft-ietf-tls-ecc-00
["TLS_ECDH_anon_NULL_WITH_SHA-draft"]              =  0x0057,  --draft-ietf-tls-ecc-00
["TLS_ECDH_anon_WITH_RC4_128_SHA-draft"]           =  0x0058,  --draft-ietf-tls-ecc-00
["TLS_ECDH_anon_WITH_DES_CBC_SHA-draft"]           =  0x0059,  --draft-ietf-tls-ecc-00
["TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA-draft"]      =  0x005A,  --draft-ietf-tls-ecc-00
["TLS_ECDH_anon_EXPORT_WITH_DES40_CBC_SHA-draft"]  =  0x005B,  --draft-ietf-tls-ecc-00
["TLS_ECDH_anon_EXPORT_WITH_RC4_40_SHA-draft"]     =  0x005C,  --draft-ietf-tls-ecc-00
["TLS_RSA_EXPORT1024_WITH_RC4_56_MD5"]             =  0x0060,
["TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5"]         =  0x0061,
["TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA"]            =  0x0062,
["TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA"]        =  0x0063,
["TLS_RSA_EXPORT1024_WITH_RC4_56_SHA"]             =  0x0064,
["TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA"]         =  0x0065,
["TLS_DHE_DSS_WITH_RC4_128_SHA"]                   =  0x0066,
["TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"]            =  0x0067,
["TLS_DH_DSS_WITH_AES_256_CBC_SHA256"]             =  0x0068,
["TLS_DH_RSA_WITH_AES_256_CBC_SHA256"]             =  0x0069,
["TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"]            =  0x006A,
["TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"]            =  0x006B,
["TLS_DH_anon_WITH_AES_128_CBC_SHA256"]            =  0x006C,
["TLS_DH_anon_WITH_AES_256_CBC_SHA256"]            =  0x006D,
["TLS_DHE_DSS_WITH_3DES_EDE_CBC_RMD"]       =  0x0072,  --draft-ietf-tls-openpgp-keys-05
["TLS_DHE_DSS_WITH_AES_128_CBC_RMD"]        =  0x0073,  --draft-ietf-tls-openpgp-keys-05
["TLS_DHE_DSS_WITH_AES_256_CBC_RMD"]        =  0x0074,  --draft-ietf-tls-openpgp-keys-05
["TLS_DHE_RSA_WITH_3DES_EDE_CBC_RMD"]       =  0x0077,  --draft-ietf-tls-openpgp-keys-05
["TLS_DHE_RSA_WITH_AES_128_CBC_RMD"]        =  0x0078,  --draft-ietf-tls-openpgp-keys-05
["TLS_DHE_RSA_WITH_AES_256_CBC_RMD"]        =  0x0079,  --draft-ietf-tls-openpgp-keys-05
["TLS_RSA_WITH_3DES_EDE_CBC_RMD"]           =  0x007C,  --draft-ietf-tls-openpgp-keys-05
["TLS_RSA_WITH_AES_128_CBC_RMD"]            =  0x007D,  --draft-ietf-tls-openpgp-keys-05
["TLS_RSA_WITH_AES_256_CBC_RMD"]            =  0x007E,  --draft-ietf-tls-openpgp-keys-05
["TLS_GOSTR341094_WITH_28147_CNT_IMIT"]     =  0x0080,  --draft-chudov-cryptopro-cptls-04
["TLS_GOSTR341001_WITH_28147_CNT_IMIT"]     =  0x0081,  --draft-chudov-cryptopro-cptls-04
["TLS_GOSTR341094_WITH_NULL_GOSTR3411"]     =  0x0082,  --draft-chudov-cryptopro-cptls-04
["TLS_GOSTR341001_WITH_NULL_GOSTR3411"]     =  0x0083,  --draft-chudov-cryptopro-cptls-04
["TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"]              =  0x0084,
["TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA"]           =  0x0085,
["TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA"]           =  0x0086,
["TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA"]          =  0x0087,
["TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"]          =  0x0088,
["TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA"]          =  0x0089,
["TLS_PSK_WITH_RC4_128_SHA"]                       =  0x008A,
["TLS_PSK_WITH_3DES_EDE_CBC_SHA"]                  =  0x008B,
["TLS_PSK_WITH_AES_128_CBC_SHA"]                   =  0x008C,
["TLS_PSK_WITH_AES_256_CBC_SHA"]                   =  0x008D,
["TLS_DHE_PSK_WITH_RC4_128_SHA"]                   =  0x008E,
["TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA"]              =  0x008F,
["TLS_DHE_PSK_WITH_AES_128_CBC_SHA"]               =  0x0090,
["TLS_DHE_PSK_WITH_AES_256_CBC_SHA"]               =  0x0091,
["TLS_RSA_PSK_WITH_RC4_128_SHA"]                   =  0x0092,
["TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA"]              =  0x0093,
["TLS_RSA_PSK_WITH_AES_128_CBC_SHA"]               =  0x0094,
["TLS_RSA_PSK_WITH_AES_256_CBC_SHA"]               =  0x0095,
["TLS_RSA_WITH_SEED_CBC_SHA"]                      =  0x0096,
["TLS_DH_DSS_WITH_SEED_CBC_SHA"]                   =  0x0097,
["TLS_DH_RSA_WITH_SEED_CBC_SHA"]                   =  0x0098,
["TLS_DHE_DSS_WITH_SEED_CBC_SHA"]                  =  0x0099,
["TLS_DHE_RSA_WITH_SEED_CBC_SHA"]                  =  0x009A,
["TLS_DH_anon_WITH_SEED_CBC_SHA"]                  =  0x009B,
["TLS_RSA_WITH_AES_128_GCM_SHA256"]                =  0x009C,
["TLS_RSA_WITH_AES_256_GCM_SHA384"]                =  0x009D,
["TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"]            =  0x009E,
["TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"]            =  0x009F,
["TLS_DH_RSA_WITH_AES_128_GCM_SHA256"]             =  0x00A0,
["TLS_DH_RSA_WITH_AES_256_GCM_SHA384"]             =  0x00A1,
["TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"]            =  0x00A2,
["TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"]            =  0x00A3,
["TLS_DH_DSS_WITH_AES_128_GCM_SHA256"]             =  0x00A4,
["TLS_DH_DSS_WITH_AES_256_GCM_SHA384"]             =  0x00A5,
["TLS_DH_anon_WITH_AES_128_GCM_SHA256"]            =  0x00A6,
["TLS_DH_anon_WITH_AES_256_GCM_SHA384"]            =  0x00A7,
["TLS_PSK_WITH_AES_128_GCM_SHA256"]                =  0x00A8,
["TLS_PSK_WITH_AES_256_GCM_SHA384"]                =  0x00A9,
["TLS_DHE_PSK_WITH_AES_128_GCM_SHA256"]            =  0x00AA,
["TLS_DHE_PSK_WITH_AES_256_GCM_SHA384"]            =  0x00AB,
["TLS_RSA_PSK_WITH_AES_128_GCM_SHA256"]            =  0x00AC,
["TLS_RSA_PSK_WITH_AES_256_GCM_SHA384"]            =  0x00AD,
["TLS_PSK_WITH_AES_128_CBC_SHA256"]                =  0x00AE,
["TLS_PSK_WITH_AES_256_CBC_SHA384"]                =  0x00AF,
["TLS_PSK_WITH_NULL_SHA256"]                       =  0x00B0,
["TLS_PSK_WITH_NULL_SHA384"]                       =  0x00B1,
["TLS_DHE_PSK_WITH_AES_128_CBC_SHA256"]            =  0x00B2,
["TLS_DHE_PSK_WITH_AES_256_CBC_SHA384"]            =  0x00B3,
["TLS_DHE_PSK_WITH_NULL_SHA256"]                   =  0x00B4,
["TLS_DHE_PSK_WITH_NULL_SHA384"]                   =  0x00B5,
["TLS_RSA_PSK_WITH_AES_128_CBC_SHA256"]            =  0x00B6,
["TLS_RSA_PSK_WITH_AES_256_CBC_SHA384"]            =  0x00B7,
["TLS_RSA_PSK_WITH_NULL_SHA256"]                   =  0x00B8,
["TLS_RSA_PSK_WITH_NULL_SHA384"]                   =  0x00B9,
["TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256"]           =  0x00BA,
["TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256"]        =  0x00BB,
["TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256"]        =  0x00BC,
["TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256"]       =  0x00BD,
["TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"]       =  0x00BE,
["TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256"]       =  0x00BF,
["TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256"]           =  0x00C0,
["TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256"]        =  0x00C1,
["TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256"]        =  0x00C2,
["TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256"]       =  0x00C3,
["TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256"]       =  0x00C4,
["TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256"]       =  0x00C5,
["TLS_ECDH_ECDSA_WITH_NULL_SHA"]                   =  0xC001,
["TLS_ECDH_ECDSA_WITH_RC4_128_SHA"]                =  0xC002,
["TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"]           =  0xC003,
["TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"]            =  0xC004,
["TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"]            =  0xC005,
["TLS_ECDHE_ECDSA_WITH_NULL_SHA"]                  =  0xC006,
["TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"]               =  0xC007,
["TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"]          =  0xC008,
["TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"]           =  0xC009,
["TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"]           =  0xC00A,
["TLS_ECDH_RSA_WITH_NULL_SHA"]                     =  0xC00B,
["TLS_ECDH_RSA_WITH_RC4_128_SHA"]                  =  0xC00C,
["TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA"]             =  0xC00D,
["TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"]              =  0xC00E,
["TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"]              =  0xC00F,
["TLS_ECDHE_RSA_WITH_NULL_SHA"]                    =  0xC010,
["TLS_ECDHE_RSA_WITH_RC4_128_SHA"]                 =  0xC011,
["TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"]            =  0xC012,
["TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"]             =  0xC013,
["TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"]             =  0xC014,
["TLS_ECDH_anon_WITH_NULL_SHA"]                    =  0xC015,
["TLS_ECDH_anon_WITH_RC4_128_SHA"]                 =  0xC016,
["TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA"]            =  0xC017,
["TLS_ECDH_anon_WITH_AES_128_CBC_SHA"]             =  0xC018,
["TLS_ECDH_anon_WITH_AES_256_CBC_SHA"]             =  0xC019,
["TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA"]              =  0xC01A,
["TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA"]          =  0xC01B,
["TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA"]          =  0xC01C,
["TLS_SRP_SHA_WITH_AES_128_CBC_SHA"]               =  0xC01D,
["TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA"]           =  0xC01E,
["TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA"]           =  0xC01F,
["TLS_SRP_SHA_WITH_AES_256_CBC_SHA"]               =  0xC020,
["TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA"]           =  0xC021,
["TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA"]           =  0xC022,
["TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"]        =  0xC023,
["TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"]        =  0xC024,
["TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"]         =  0xC025,
["TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"]         =  0xC026,
["TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"]          =  0xC027,
["TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"]          =  0xC028,
["TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256"]           =  0xC029,
["TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"]           =  0xC02A,
["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"]        =  0xC02B,
["TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"]        =  0xC02C,
["TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"]         =  0xC02D,
["TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"]         =  0xC02E,
["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]          =  0xC02F,
["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"]          =  0xC030,
["TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256"]           =  0xC031,
["TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"]           =  0xC032,
["TLS_ECDHE_PSK_WITH_RC4_128_SHA"]                 =  0xC033,
["TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA"]            =  0xC034,
["TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA"]             =  0xC035,
["TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA"]             =  0xC036,
["TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256"]          =  0xC037,
["TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384"]          =  0xC038,
["TLS_ECDHE_PSK_WITH_NULL_SHA"]                    =  0xC039,
["TLS_ECDHE_PSK_WITH_NULL_SHA256"]                 =  0xC03A,
["TLS_ECDHE_PSK_WITH_NULL_SHA384"]                 =  0xC03B,
["TLS_RSA_WITH_ARIA_128_CBC_SHA256"]               =  0xC03C,
["TLS_RSA_WITH_ARIA_256_CBC_SHA384"]               =  0xC03D,
["TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256"]            =  0xC03E,
["TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384"]            =  0xC03F,
["TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256"]            =  0xC040,
["TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384"]            =  0xC041,
["TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256"]           =  0xC042,
["TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384"]           =  0xC043,
["TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256"]           =  0xC044,
["TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384"]           =  0xC045,
["TLS_DH_anon_WITH_ARIA_128_CBC_SHA256"]           =  0xC046,
["TLS_DH_anon_WITH_ARIA_256_CBC_SHA384"]           =  0xC047,
["TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256"]       =  0xC048,
["TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384"]       =  0xC049,
["TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256"]        =  0xC04A,
["TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384"]        =  0xC04B,
["TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256"]         =  0xC04C,
["TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384"]         =  0xC04D,
["TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256"]          =  0xC04E,
["TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384"]          =  0xC04F,
["TLS_RSA_WITH_ARIA_128_GCM_SHA256"]               =  0xC050,
["TLS_RSA_WITH_ARIA_256_GCM_SHA384"]               =  0xC051,
["TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256"]           =  0xC052,
["TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384"]           =  0xC053,
["TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256"]            =  0xC054,
["TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384"]            =  0xC055,
["TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256"]           =  0xC056,
["TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384"]           =  0xC057,
["TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256"]            =  0xC058,
["TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384"]            =  0xC059,
["TLS_DH_anon_WITH_ARIA_128_GCM_SHA256"]           =  0xC05A,
["TLS_DH_anon_WITH_ARIA_256_GCM_SHA384"]           =  0xC05B,
["TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256"]       =  0xC05C,
["TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384"]       =  0xC05D,
["TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256"]        =  0xC05E,
["TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384"]        =  0xC05F,
["TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256"]         =  0xC060,
["TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384"]         =  0xC061,
["TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256"]          =  0xC062,
["TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384"]          =  0xC063,
["TLS_PSK_WITH_ARIA_128_CBC_SHA256"]               =  0xC064,
["TLS_PSK_WITH_ARIA_256_CBC_SHA384"]               =  0xC065,
["TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256"]           =  0xC066,
["TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384"]           =  0xC067,
["TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256"]           =  0xC068,
["TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384"]           =  0xC069,
["TLS_PSK_WITH_ARIA_128_GCM_SHA256"]               =  0xC06A,
["TLS_PSK_WITH_ARIA_256_GCM_SHA384"]               =  0xC06B,
["TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256"]           =  0xC06C,
["TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384"]           =  0xC06D,
["TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256"]           =  0xC06E,
["TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384"]           =  0xC06F,
["TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256"]         =  0xC070,
["TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384"]         =  0xC071,
["TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"]   =  0xC072,
["TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"]   =  0xC073,
["TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"]    =  0xC074,
["TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"]    =  0xC075,
["TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"]     =  0xC076,
["TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384"]     =  0xC077,
["TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256"]      =  0xC078,
["TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384"]      =  0xC079,
["TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256"]           =  0xC07A,
["TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384"]           =  0xC07B,
["TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256"]       =  0xC07C,
["TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384"]       =  0xC07D,
["TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256"]        =  0xC07E,
["TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384"]        =  0xC07F,
["TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256"]       =  0xC080,
["TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384"]       =  0xC081,
["TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256"]        =  0xC082,
["TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384"]        =  0xC083,
["TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256"]       =  0xC084,
["TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384"]       =  0xC085,
["TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"]   =  0xC086,
["TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384"]   =  0xC087,
["TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"]    =  0xC088,
["TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384"]    =  0xC089,
["TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256"]     =  0xC08A,
["TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384"]     =  0xC08B,
["TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256"]      =  0xC08C,
["TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384"]      =  0xC08D,
["TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256"]           =  0xC08E,
["TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384"]           =  0xC08F,
["TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256"]       =  0xC090,
["TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384"]       =  0xC091,
["TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256"]       =  0xC092,
["TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384"]       =  0xC093,
["TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256"]           =  0xC094,
["TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384"]           =  0xC095,
["TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"]       =  0xC096,
["TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"]       =  0xC097,
["TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256"]       =  0xC098,
["TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384"]       =  0xC099,
["TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"]     =  0xC09A,
["TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"]     =  0xC09B,
["TLS_RSA_WITH_AES_128_CCM"]                       =  0xC09C,
["TLS_RSA_WITH_AES_256_CCM"]                       =  0xC09D,
["TLS_DHE_RSA_WITH_AES_128_CCM"]                   =  0xC09E,
["TLS_DHE_RSA_WITH_AES_256_CCM"]                   =  0xC09F,
["TLS_RSA_WITH_AES_128_CCM_8"]                     =  0xC0A0,
["TLS_RSA_WITH_AES_256_CCM_8"]                     =  0xC0A1,
["TLS_DHE_RSA_WITH_AES_128_CCM_8"]                 =  0xC0A2,
["TLS_DHE_RSA_WITH_AES_256_CCM_8"]                 =  0xC0A3,
["TLS_PSK_WITH_AES_128_CCM"]                       =  0xC0A4,
["TLS_PSK_WITH_AES_256_CCM"]                       =  0xC0A5,
["TLS_DHE_PSK_WITH_AES_128_CCM"]                   =  0xC0A6,
["TLS_DHE_PSK_WITH_AES_256_CCM"]                   =  0xC0A7,
["TLS_PSK_WITH_AES_128_CCM_8"]                     =  0xC0A8,
["TLS_PSK_WITH_AES_256_CCM_8"]                     =  0xC0A9,
["TLS_PSK_DHE_WITH_AES_128_CCM_8"]                 =  0xC0AA,
["TLS_PSK_DHE_WITH_AES_256_CCM_8"]                 =  0xC0AB,
["SSL_RSA_FIPS_WITH_DES_CBC_SHA"]                  =  0xFEFE,
["SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA"]             =  0xFEFF,
}

cipherstrength = {
	["broken"] = 0,
	["weak"]	= 1,
	["unknown strength"]	= 2,
	["strong"]	= 3
}

local rankedciphers={}
local mincipherstrength=9999 --artificial "highest value"
local rankedciphersfilename=false
local policy=true

local function record_read(buffer, i)
	local b, h, j, len

	local function find_key(t, value)
		local k, v

		for k, v in pairs(t) do
			if v == value then
				return k
			end
		end

		return nil
	end

	------------
	-- Header --
	------------

	-- Ensure we have enough data for the header.
	if #buffer - i < TLS_RECORD_HEADER_LENGTH then
		return i, nil
	end

	-- Parse header.
	h = {}
	j, h["type"] = bin.unpack("C", buffer, i)
	j, h["protocol"] = bin.unpack(">S", buffer, j)
	j, h["length"] = bin.unpack(">S", buffer, j)

	-- Ensure we have enough data for the body.
	len = j + h["length"] - 1
	if #buffer < len then
		return i, nil
	end

	-- Convert to human-readable form.
	h["type"] = find_key(TLS_CONTENTTYPE_REGISTRY, h["type"])
	h["protocol"] = find_key(PROTOCOLS, h["protocol"])

	----------
	-- Body --
	----------

	b = {}
	h["body"] = b
	if h["type"] == "alert" then
		-- Parse body.
		j, b["level"] = bin.unpack("C", buffer, j)
		j, b["description"] = bin.unpack("C", buffer, j)

		-- Convert to human-readable form.
		b["level"] = find_key(TLS_ALERT_LEVELS, b["level"])
		b["description"] = find_key(TLS_ALERT_REGISTRY, b["description"])
	elseif h["type"] == "handshake" then
		-- Parse body.
		j, b["type"] = bin.unpack("C", buffer, j)
		local _
		j, _ = bin.unpack("A3", buffer, j)

		-- Convert to human-readable form.
		b["type"] = find_key(TLS_HANDSHAKETYPE_REGISTRY, b["type"])

		if b["type"] == "server_hello" then
			-- Parse body.
			j, b["protocol"] = bin.unpack(">S", buffer, j)
			j, b["time"] = bin.unpack(">I", buffer, j)
			j, b["random"] = bin.unpack("A28", buffer, j)
			j, b["session_id_length"] = bin.unpack("C", buffer, j)
			j, b["session_id"] = bin.unpack("A" .. b["session_id_length"], buffer, j)
			j, b["cipher"] = bin.unpack(">S", buffer, j)
			j, b["compressor"] = bin.unpack("C", buffer, j)

			-- Convert to human-readable form.
			b["protocol"] = find_key(PROTOCOLS, b["protocol"])
			b["cipher"] = find_key(CIPHERS, b["cipher"])
			b["compressor"] = find_key(COMPRESSORS, b["compressor"])
		end
	end

	-- Ignore unparsed bytes.
	j = len

	return j, h
end

local function record_write(type, protocol, b)
	local h

	h = ""

	-- Set the header as a handshake.
	h = h .. bin.pack("C", TLS_CONTENTTYPE_REGISTRY[type])

	-- Set the protocol.
	h = h .. bin.pack(">S", PROTOCOLS[protocol])

	-- Set the length of the header body.
	h = h .. bin.pack(">S", #b)

	return h .. b
end

local function client_hello(t)
	local b, cipher, ciphers, compressor, compressors, h, len

	----------
	-- Body --
	----------

	b = ""

	-- Set the protocol.
	b = b .. bin.pack(">S", PROTOCOLS[t["protocol"]])

	-- Set the random data.
	b = b .. bin.pack(">I", os.time())

	-- Set the random data.
	b = b .. string.rep("nmap", 7)

	-- Set the session ID.
	b = b .. bin.pack("C", 0)

	-- Cipher suites.
	ciphers = ""
	if t["ciphers"] ~= nil then
		-- Add specified ciphers.
		for _, cipher in pairs(t["ciphers"]) do
			ciphers = ciphers .. bin.pack(">S", CIPHERS[cipher])
		end
	else
		-- Add all known ciphers.
		for _, cipher in pairs(CIPHERS) do
			ciphers = ciphers .. bin.pack(">S", cipher)
		end
	end
	b = b .. bin.pack(">S", #ciphers)
	b = b .. ciphers

	-- Compression methods.
	compressors = ""
	if t["compressors"] ~= nil then
		-- Add specified compressors.
		for _, compressor in pairs(t["compressors"]) do
      if compressor ~= "NULL" then
        compressors = compressors .. bin.pack("C", COMPRESSORS[compressor])
      end
		end
    compressors = compressors .. bin.pack("C", 0) -- Always include NULL as last choice
	else
		-- Add all known compressors.
		for _, compressor in pairs(COMPRESSORS) do
			compressors = compressors .. bin.pack("C", compressor)
		end
	end
	b = b .. bin.pack("C", #compressors)
	b = b .. compressors

	------------
	-- Header --
	------------

	h = ""

	-- Set type to ClientHello.
	h = h .. bin.pack("C", TLS_HANDSHAKETYPE_REGISTRY["client_hello"])

	-- Set the length of the body.
	len = bin.pack(">I", #b)
	h = h .. bin.pack("CCC", len:byte(2), len:byte(3), len:byte(4))

	return record_write("handshake", t["protocol"], h .. b)
end

local function try_params(host, port, t)
	local buffer, err, i, record, req, resp, sock, status

	-- Create socket.
	sock = nmap.new_socket()
	sock:set_timeout(5000)
	status, err = sock:connect(host, port, "tcp")
	if not status then
		stdnse.print_debug(1, "Can't connect: %s", err)
		sock:close()
		return nil
	end

	-- Send request.
	req = client_hello(t)
	status, err = sock:send(req)
	if not status then
		stdnse.print_debug(1, "Can't send: %s", err)
		sock:close()
		return nil
	end

	-- Read response.
	i = 0
	buffer = ""
	record = nil
	while true do
		status, resp = sock:receive()
		if not status then
			sock:close()
			return nil
		end

		buffer = buffer .. resp

		-- Parse response.
		i, record = record_read(buffer, i)
		if record ~= nil then
			sock:close()
			return record
		end
	end
end

local function keys(t)
  local ret = {}
  for k, _ in pairs(t) do
    ret[#ret+1] = k
  end
  return ret
end

local function keys_in_chunks(t)
  local ret = {{}}
  local c = 0
  local b = 1
  for k, _ in pairs(t) do
    c = c+1
    ret[b][c] = k
    if c > 64 then
      c = 0
      b = b + 1
      ret[b] = {}
    end
  end
  return ret
end

local function remove(t, e)
  for i, v in ipairs(t) do
    if v == e then
      table.remove(t, i)
      return i
    end
  end
  return nil
end

local function find_ciphers(host, port, protocol)
  local name, protocol_worked, record, results, t,cipherstr
  local ciphers = keys_in_chunks(CIPHERS)

  results = {}

  -- Try every cipher.
  protocol_worked = false
  for _, group in ipairs(ciphers) do
    while (next(group)) do
			-- Create structure.
			t = {
				["ciphers"] = group,
				["protocol"] = protocol
			}

      record = try_params(host, port, t)
		
			if record == nil then
				if protocol_worked then
					stdnse.print_debug(2, "%d ciphers rejected. (No handshake)", #group)
				else
					stdnse.print_debug(1, "%d ciphers and/or protocol %s rejected. (No handshake)", #group, protocol)
				end
        break
			elseif record["protocol"] ~= protocol then
				stdnse.print_debug(1, "Protocol %s rejected.", protocol)
        protocol_worked = nil
				break
			elseif record["type"] == "alert" and record["body"]["description"] == "handshake_failure" then
				protocol_worked = true
				stdnse.print_debug(2, "%d ciphers rejected.", #group)
        break
			elseif record["type"] ~= "handshake" or record["body"]["type"] ~= "server_hello" then
				stdnse.print_debug(2, "Unexpected record received.")
        break
			else
				protocol_worked = true
				name = record["body"]["cipher"]
				stdnse.print_debug(2, "Cipher %s chosen.", name)
        remove(group, name)

				-- Add cipher to the list of accepted ciphers.
				table.insert(results, name)
			end
		end
    if protocol_worked == nil then return nil end
  end
  if not protocol_worked then return nil end

  return results
end

local function find_compressors(host, port, protocol, good_cipher)
  local name, protocol_worked, record, results, t
  local compressors = keys(COMPRESSORS)

  results = {}

  -- Try every compressor.
  protocol_worked = false
  while (next(compressors)) do
    -- Create structure.
    t = {
      ["compressors"] = compressors,
      ["ciphers"] = {good_cipher},
      ["protocol"] = protocol
    }

    -- Try connecting with compressor.
    record = try_params(host, port, t)
  
    if record == nil then
      if protocol_worked then
        stdnse.print_debug(2, "%d compressors rejected. (No handshake)", #compressors)
      else
        stdnse.print_debug(1, "%d compressors and/or protocol %s rejected. (No handshake)", #compressors, protocol)
      end
      break
    elseif record["protocol"] ~= protocol then
      stdnse.print_debug(1, "Protocol %s rejected.", protocol)
      break
    elseif record["type"] == "alert" and record["body"]["description"] == "handshake_failure" then
      protocol_worked = true
      stdnse.print_debug(2, "%d compressors rejected.", #compressors)
      break
    elseif record["type"] ~= "handshake" or record["body"]["type"] ~= "server_hello" then
      stdnse.print_debug(2, "Unexpected record received.")
      break
    else
      protocol_worked = true
      name = record["body"]["compressor"]
      stdnse.print_debug(2, "Compressor %s chosen.", name)
      remove(compressors, name)

      -- Add compressor to the list of accepted compressors.
      table.insert(results, name)
      if name == "NULL" then
        break -- NULL is always last choice, and must be included
      end
    end
  end

  return results
end

local function try_protocol(host, port, protocol, upresults)
	local ciphers, compressors, results
  local condvar = nmap.condvar(upresults)

	results = stdnse.output_table()

	-- Find all valid ciphers.
	ciphers = find_ciphers(host, port, protocol)
	if ciphers == nil then
		condvar "signal"
		return nil
	end
  
  if #ciphers == 0 then
    results = {ciphers={},compressors={}}
    setmetatable(results,{
      __tostring=function(t) return "No supported ciphers found" end
    })
    upresults[protocol] = results
    condvar "signal"
    return nil
  end
	-- Find all valid compression methods.
	compressors = find_compressors(host, port, protocol, ciphers[1])

  -- Add rankings to ciphers
	local cipherstr
  for i, name in ipairs(ciphers) do
    if rankedciphersfilename and rankedciphers[name] then
      cipherstr=rankedciphers[name]
    else
      cipherstr="unknown strength"
    end
    stdnse.print_debug(2, "Strength of %s rated %d.",cipherstr,cipherstrength[cipherstr])
    if mincipherstrength>cipherstrength[cipherstr] then
      stdnse.print_debug(2, "Downgrading min cipher strength to %d.",cipherstrength[cipherstr])
      mincipherstrength=cipherstrength[cipherstr]
    end
    local outcipher = {name=name, strength=cipherstr}
    setmetatable(outcipher,{
      __tostring=function(t) return string.format("%s - %s", t.name, t.strength) end
    })
    ciphers[i]=outcipher
  end

	-- Format the cipher table.
	table.sort(ciphers, function(a, b) return a["name"] < b["name"] end)
  results["ciphers"] = ciphers

	-- Format the compressor table.
	table.sort(compressors)
  results["compressors"] = compressors

  upresults[protocol] = results
  condvar "signal"
  return nil
end

-- Shamelessly stolen from nselib/unpwdb.lua and changed a bit. (Gabriel Lawrence)
local filltable = function(filename,table)
	if #table ~= 0 then
		return true
	end

	local file = io.open(filename, "r")

	if not file then
		return false
	end

	while true do
		local l = file:read()

		if not l then
			break
		end

		-- Comments takes up a whole line
		if not l:match("#!comment:") then
			local lsplit=stdnse.strsplit("%s+", l)
			if cipherstrength[lsplit[2]] then
				table[lsplit[1]] = lsplit[2]
			else
				stdnse.print_debug(1,"Strength not defined, ignoring: %s:%s",lsplit[1],lsplit[2])
			end
		end
	end

	file:close()

	return true
end

portrule = shortport.ssl

--- Return a table that yields elements sorted by key when iterated over with pairs()
--  Should probably put this in a formatting library later.
--  Depends on keys() function defined above.
--@param  t    The table whose data should be used
--@return out  A table that can be passed to pairs() to get sorted results
function sorted_by_key(t)
  local out = {}
  setmetatable(out, {
    __pairs = function(_)
      local order = keys(t)
      table.sort(order)
      return coroutine.wrap(function()
        for i,k in ipairs(order) do
          coroutine.yield(k, t[k])
        end
      end)
    end
  })
  return out
end

action = function(host, port)
	local name, result, results

	rankedciphersfilename=stdnse.get_script_args("ssl-enum-ciphers.rankedcipherlist")
	if rankedciphersfilename then
		filltable(rankedciphersfilename,rankedciphers)
	else
		rankedciphersfilename = nmap.fetchfile( "nselib/data/ssl-ciphers" )
		stdnse.print_debug(1, "Ranked ciphers filename: %s", rankedciphersfilename)
		filltable(rankedciphersfilename,rankedciphers)
	end

	results = {}

  local condvar = nmap.condvar(results)
  local threads = {}

	for name, _ in pairs(PROTOCOLS) do
		stdnse.print_debug(1, "Trying protocol %s.", name)
		local co = stdnse.new_thread(try_protocol, host.ip, port.number, name, results)
    threads[co] = true
	end

  repeat
    for thread in pairs(threads) do
      if coroutine.status(thread) == "dead" then threads[thread] = nil end
    end
    if ( next(threads) ) then
      condvar "wait"
    end
  until next(threads) == nil

  if #( keys(results) ) == 0 then
    return nil
  end

	if rankedciphersfilename then
		for k, v in pairs(cipherstrength) do
			if v == mincipherstrength then
				-- Should sort before or after SSLv3, TLSv*
				results["least strength"] = k
			end
		end
	end

	return sorted_by_key(results)
end
