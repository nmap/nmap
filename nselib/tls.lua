---
-- A library providing functions for doing TLS/SSL communications
--
-- These functions will build strings and process buffers. Socket communication
-- is left to the script to implement.
--
-- @author Daniel Miller

local stdnse = require "stdnse"
local bin = require "bin"
local math = require "math"
local os = require "os"
local table = require "table"
_ENV = stdnse.module("tls", stdnse.seeall)

-- Most of the values in the tables below are from:
-- http://www.iana.org/assignments/tls-parameters/
PROTOCOLS = {
  ["SSLv3"]       = 0x0300,
  ["TLSv1.0"]     = 0x0301,
  ["TLSv1.1"]     = 0x0302,
  ["TLSv1.2"]     = 0x0303
}
HIGHEST_PROTOCOL = "TLSv1.2"

--
-- TLS Record Types
--
TLS_RECORD_HEADER_LENGTH = 5

TLS_CONTENTTYPE_REGISTRY = {
  ["change_cipher_spec"]  = 20,
  ["alert"]               = 21,
  ["handshake"]           = 22,
  ["application_data"]    = 23,
  ["heartbeat"]           = 24
}

--
-- TLS Alert Levels
--
TLS_ALERT_LEVELS = {
  ["warning"]     = 1,
  ["fatal"]       = 2,
}

--
-- TLS Alert Record Types
--
TLS_ALERT_REGISTRY = {
  ["close_notify"]                        = 0,
  ["unexpected_message"]                  = 10,
  ["bad_record_mac"]                      = 20,
  ["decryption_failed"]                   = 21,
  ["record_overflow"]                     = 22,
  ["decompression_failure"]               = 30,
  ["handshake_failure"]                   = 40,
  ["no_certificate"]                      = 41,
  ["bad_certificate"]                     = 42,
  ["unsupported_certificate"]             = 43,
  ["certificate_revoked"]                 = 44,
  ["certificate_expired"]                 = 45,
  ["certificate_unknown"]                 = 46,
  ["illegal_parameter"]                   = 47,
  ["unknown_ca"]                          = 48,
  ["access_denied"]                       = 49,
  ["decode_error"]                        = 50,
  ["decrypt_error"]                       = 51,
  ["export_restriction"]                  = 60,
  ["protocol_version"]                    = 70,
  ["insufficient_security"]               = 71,
  ["internal_error"]                      = 80,
  ["inappropriate_fallback"]              = 86,
  ["user_canceled"]                       = 90,
  ["no_renegotiation"]                    = 100,
  ["unsupported_extension"]               = 110,
  ["certificate_unobtainable"]            = 111,
  ["unrecognized_name"]                   = 112,
  ["bad_certificate_status_response"]     = 113,
  ["bad_certificate_hash_value"]          = 114,
  ["unknown_psk_identity"]                = 115
}

--
-- TLS Handshake Record Types
--
TLS_HANDSHAKETYPE_REGISTRY = {
  ["hello_request"]               = 0,
  ["client_hello"]                = 1,
  ["server_hello"]                = 2,
  ["hello_verify_request"]        = 3,
  ["NewSessionTicket"]            = 4,
  ["certificate"]                 = 11,
  ["server_key_exchange"]         = 12,
  ["certificate_request"]         = 13,
  ["server_hello_done"]           = 14,
  ["certificate_verify"]          = 15,
  ["client_key_exchange"]         = 16,
  ["finished"]                    = 20,
  ["certificate_url"]             = 21,
  ["certificate_status"]          = 22,
  ["supplemental_data"]           = 23,
  ["next_protocol"]               = 67,
}

--
-- Compression Algorithms
-- http://www.iana.org/assignments/comp-meth-ids
--
COMPRESSORS = {
  ["NULL"]                = 0,
  ["DEFLATE"]             = 1,
  ["LZS"]                 = 64
}

---
-- RFC 4492 section 5.1.1 "Supported Elliptic Curves Extension".
ELLIPTIC_CURVES = {
  sect163k1 = 1,
  sect163r1 = 2,
  sect163r2 = 3,
  sect193r1 = 4,
  sect193r2 = 5,
  sect233k1 = 6,
  sect233r1 = 7,
  sect239k1 = 8,
  sect283k1 = 9,
  sect283r1 = 10,
  sect409k1 = 11,
  sect409r1 = 12,
  sect571k1 = 13,
  sect571r1 = 14,
  secp160k1 = 15,
  secp160r1 = 16,
  secp160r2 = 17,
  secp192k1 = 18,
  secp192r1 = 19,
  secp224k1 = 20,
  secp224r1 = 21,
  secp256k1 = 22,
  secp256r1 = 23,
  secp384r1 = 24,
  secp521r1 = 25,
  arbitrary_explicit_prime_curves = 0xFF01,
  arbitrary_explicit_char2_curves = 0xFF02,
}

---
-- RFC 4492 section 5.1.2 "Supported Point Formats Extension".
EC_POINT_FORMATS = {
  uncompressed = 0,
  ansiX962_compressed_prime = 1,
  ansiX962_compressed_char2 = 2,
}

---
-- RFC 5246 section 7.4.1.4.1. Signature Algorithms
HashAlgorithms = {
  none = 0,
  md5 = 1,
  sha1 = 2,
  sha224 = 3,
  sha256 = 4,
  sha384 = 5,
  sha512 = 6,
}
SignatureAlgorithms = {
  anonymous = 0,
  rsa = 1,
  dsa = 2,
  ecdsa = 3,
}

---
-- Extensions
-- RFC 6066, draft-agl-tls-nextprotoneg-03
-- https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
--
EXTENSIONS = {
  ["server_name"] = 0,
  ["max_fragment_length"] = 1,
  ["client_certificate_url"] = 2,
  ["trusted_ca_keys"] = 3,
  ["truncated_hmac"] = 4,
  ["status_request"] = 5,
  ["user_mapping"] = 6,
  ["client_authz"] = 7,
  ["server_authz"] = 8,
  ["cert_type"] = 9,
  ["elliptic_curves"] = 10,
  ["ec_point_formats"] = 11,
  ["srp"] = 12,
  ["signature_algorithms"] = 13,
  ["use_srtp"] = 14,
  ["heartbeat"] = 15,
  ["application_layer_protocol_negotiation"] = 16,
  ["status_request_v2"] = 17,
  ["signed_certificate_timestamp"] = 18,
  ["client_certificate_type"] = 19,
  ["server_certificate_type"] = 20,
  ["padding"] = 21, -- Temporary, expires 2015-03-12
  ["SessionTicket TLS"] = 35,
  ["next_protocol_negotiation"] = 13172,
  ["renegotiation_info"] = 65281,
}

---
-- Builds data for each extension
-- Defaults to tostring (i.e. pass in the packed data you want directly)
EXTENSION_HELPERS = {
  ["server_name"] = function (server_name)
    -- Only supports host_name type (0), as per RFC
    -- Support for other types could be added later
    return bin.pack(">P", bin.pack(">CP", 0, server_name))
  end,
  ["max_fragment_length"] = tostring,
  ["client_certificate_url"] = tostring,
  ["trusted_ca_keys"] = tostring,
  ["truncated_hmac"] = tostring,
  ["status_request"] = tostring,
  ["elliptic_curves"] = function (elliptic_curves)
    local list = {}
    for _, name in ipairs(elliptic_curves) do
      list[#list+1] = bin.pack(">S", ELLIPTIC_CURVES[name])
    end
    return bin.pack(">P", table.concat(list))
  end,
  ["ec_point_formats"] = function (ec_point_formats)
    local list = {}
    for _, format in ipairs(ec_point_formats) do
      list[#list+1] = bin.pack(">C", EC_POINT_FORMATS[format])
    end
    return bin.pack(">p", table.concat(list))
  end,
  ["signature_algorithms"] = function(signature_algorithms)
    local list = {}
    for _, pair in ipairs(signature_algorithms) do
      list[#list+1] = bin.pack(">CC",
        HashAlgorithms[pair[1]] or pair[1],
        SignatureAlgorithms[pair[2]] or pair[2]
        )
    end
    return bin.pack(">P", table.concat(list))
  end,
  ["next_protocol_negotiation"] = tostring,
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
["TLS_DHE_DSS_WITH_3DES_EDE_CBC_RMD-draft"]       =  0x0072,  --draft-ietf-tls-openpgp-keys-05
["TLS_DHE_DSS_WITH_AES_128_CBC_RMD-draft"]        =  0x0073,  --draft-ietf-tls-openpgp-keys-05
["TLS_DHE_DSS_WITH_AES_256_CBC_RMD-draft"]        =  0x0074,  --draft-ietf-tls-openpgp-keys-05
["TLS_DHE_RSA_WITH_3DES_EDE_CBC_RMD-draft"]       =  0x0077,  --draft-ietf-tls-openpgp-keys-05
["TLS_DHE_RSA_WITH_AES_128_CBC_RMD-draft"]        =  0x0078,  --draft-ietf-tls-openpgp-keys-05
["TLS_DHE_RSA_WITH_AES_256_CBC_RMD-draft"]        =  0x0079,  --draft-ietf-tls-openpgp-keys-05
["TLS_RSA_WITH_3DES_EDE_CBC_RMD-draft"]           =  0x007C,  --draft-ietf-tls-openpgp-keys-05
["TLS_RSA_WITH_AES_128_CBC_RMD-draft"]            =  0x007D,  --draft-ietf-tls-openpgp-keys-05
["TLS_RSA_WITH_AES_256_CBC_RMD-draft"]            =  0x007E,  --draft-ietf-tls-openpgp-keys-05
["TLS_GOSTR341094_WITH_28147_CNT_IMIT-draft"]     =  0x0080,  --draft-chudov-cryptopro-cptls-04
["TLS_GOSTR341001_WITH_28147_CNT_IMIT-draft"]     =  0x0081,  --draft-chudov-cryptopro-cptls-04
["TLS_GOSTR341094_WITH_NULL_GOSTR3411-draft"]     =  0x0082,  --draft-chudov-cryptopro-cptls-04
["TLS_GOSTR341001_WITH_NULL_GOSTR3411-draft"]     =  0x0083,  --draft-chudov-cryptopro-cptls-04
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
["TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"]    =  0xCC13,
["TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"]  =  0xCC14,
["TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"]      =  0xCC15,
["SSL_RSA_FIPS_WITH_DES_CBC_SHA"]                  =  0xFEFE,
["SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA"]             =  0xFEFF,
}

DEFAULT_CIPHERS = {
  "TLS_RSA_WITH_AES_128_CBC_SHA", -- mandatory TLSv1.2
  "TLS_RSA_WITH_3DES_EDE_CBC_SHA", -- mandatory TLSv1.1
  "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", -- mandatory TLSv1.0
  "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", -- DHE with strong AES
  "TLS_RSA_WITH_RC4_128_MD5", -- Weak and old, but likely supported on old stuff
}

local function find_key(t, value)
  local k, v

  for k, v in pairs(t) do
    if v == value then
      return k
    end
  end

  return nil
end

-- Keep this local to enforce use of the cipher_info function
local cipher_info_cache = {
  -- pre-populate the special cases that break the parser below
  ["TLS_ECDH_anon_NULL_WITH_SHA-draft"] = {
    kex = "ECDH", dh = true, ec = true,
    server_auth = "anon",
    cipher = "NULL",
    hash = "SHA",
    draft = true
  },
  ["TLS_ECMQV_ECDSA_NULL_SHA-draft"] = {
    kex = "ECMQV", ec = true,
    server_auth = "ECDSA",
    cipher = "NULL",
    hash = "SHA",
    draft = true
  },
  ["TLS_ECMQV_ECNRA_NULL_SHA-draft"] = {
    kex = "ECMQV", ec = true,
    server_auth = "ECNRA",
    cipher = "NULL",
    hash = "SHA",
    draft = true
  },
  ["TLS_GOSTR341094_WITH_28147_CNT_IMIT-draft"] = {
    kex = "GOSTR341094",
    server_auth = "GOSTR341094",
    cipher = "GOST28147",
    hash = "IMIT_GOST28147",
    draft = true
  },
  ["TLS_GOSTR341001_WITH_28147_CNT_IMIT-draft"] = {
    kex = "GOSTR341001",
    server_auth = "GOSTR341001",
    cipher = "GOST28147",
    hash = "IMIT_GOST28147",
    draft = true
  },
  ["TLS_GOSTR341094_WITH_NULL_GOSTR3411-draft"] = {
    kex = "GOSTR341094",
    server_auth = "GOSTR341094",
    cipher = "NULL",
    hash = "HMAC_GOSTR3411",
    draft = true
  },
  ["TLS_GOSTR341001_WITH_NULL_GOSTR3411-draft"] = {
    kex = "GOSTR341001",
    server_auth = "GOSTR341001",
    cipher = "NULL",
    hash = "HMAC_GOSTR3411",
    draft = true
  },
}


-- A couple helpers for server_key_exchange parsing
local function unpack_dhparams (blob, pos)
  local p, g, y
  pos, p, g, y = bin.unpack(">PPP", blob, pos)
  return pos, {p=p, g=g, y=y}, #p * 8
end

local function unpack_ecdhparams (blob, pos)
  local eccurvetype
  pos, eccurvetype = bin.unpack("C", blob, pos)
  local ret = {}
  local strength
  if eccurvetype == 1 then
    local p, a, b, base, order, cofactor
    pos, p, a, b, base, order, cofactor = bin.unpack("pppppp", blob, pos)
    strength = math.log(order, 2)
    ret.curve_params = {
      ec_curve_type = "explicit_prime",
      prime_p=p, curve={a=a, b=b}, base=base, order=order, cofactor=cofactor
    }
  elseif eccurvetype == 2 then
    local p = {}
    local m, basis
    pos, m, basis = bin.unpack(">SC", blob, pos)
    if basis == 1 then -- ec_trinomial
      pos, p.k = bin.unpack("p", blob, pos)
    elseif basis == 2 then -- ec_pentanomial
      pos, p.k1, p.k2, p.k3 = bin.unpack("ppp", blob, pos)
    end
    local a, b, base, order, cofactor
    pos, a, b, base, order, cofactor = bin.unpack("ppppp", blob, pos)
    strength = math.log(order, 2)
    ret.curve_params = {
      ec_curve_type = "explicit_char2",
      m=m, basis=basis, field=p, curve={a=a, b=b}, base=base, order=order, cofactor=cofactor
    }
  elseif eccurvetype == 3 then
    local curve
    pos, curve = bin.unpack(">S", blob, pos)
    ret.curve_params = {
      ec_curve_type = "namedcurve",
      curve = find_key(ELLIPTIC_CURVES, curve)
    }
    local size = ret.curve_params.curve:match("(%d+)[rk]%d$")
    if size then
      strength = tonumber(size)
    end
  end
  pos, ret.public = bin.unpack("p", blob, pos)
  return pos, ret, strength
end

local function unpack_signed (blob, pos, protocol)
  if pos > #blob then -- not-signed
    return pos, nil
  end
  local hash_alg, sig_alg, sig
  -- TLSv1.2 changed to allow arbitrary hash and sig algorithms
  if protocol and PROTOCOLS[protocol] >= 0x0303 then
    pos, hash_alg, sig_alg, sig = bin.unpack("CC>P", blob, pos)
  else
    pos, sig = bin.unpack(">P", blob, pos)
  end
  return pos, {hash_algorithm=hash_alg, signature_algorithm=sig_alg, signature=sig}
end

--- Get the strength-equivalent RSA key size
--
-- Based on NIST SP800-57 part 1 rev 3
-- @param ktype Key type ("dh", "ec", "rsa", "dsa")
-- @param bits Size of key in bits
-- @return Size in bits of RSA key with equivalent strength
function rsa_equiv (ktype, bits)
  if ktype == "rsa" or ktype == "dsa" or ktype == "dh" then
    return bits
  elseif ktype == "ec" then
    if bits < 160 then
      return 512 -- Possibly down to 0, but details not published
    elseif bits < 224 then
      return 1024
    elseif bits < 256 then
      return 2048
    elseif bits < 384 then
      return 3072
    elseif bits < 512 then
      return 7680
    else -- 512+
      return 15360
    end
  end
  return nil
end

KEX_ALGORITHMS = {}

-- RFC 5246
KEX_ALGORITHMS.NULL = { anon = true }
KEX_ALGORITHMS.DH_anon = {
  anon = true,
  type = "dh",
  server_key_exchange = function (blob, protocol)
    local pos
    local ret = {}
    pos, ret.dhparams, ret.strength = unpack_dhparams(blob)
    return ret
  end
}
KEX_ALGORITHMS.DH_anon_EXPORT = {
  anon=true,
  export=true,
  type = "dh",
  server_key_exchange = KEX_ALGORITHMS.DH_anon.server_key_exchange
}
KEX_ALGORITHMS.ECDH_anon = {
  anon=true,
  type = "ec",
  server_key_exchange = function (blob, protocol)
    local pos
    local ret = {}
    pos, ret.ecdhparams, ret.strength = unpack_ecdhparams(blob)
    return ret
  end
}
KEX_ALGORITHMS.ECDH_anon_EXPORT = {
  anon=true,
  export=true,
  type = "ec",
  server_key_exchange = KEX_ALGORITHMS.ECDH_anon.server_key_exchange
}

KEX_ALGORITHMS.RSA = {
  pubkey="rsa",
}
-- http://www-archive.mozilla.org/projects/security/pki/nss/ssl/fips-ssl-ciphersuites.html
KEX_ALGORITHMS.RSA_FIPS = KEX_ALGORITHMS.RSA
KEX_ALGORITHMS.RSA_EXPORT = {
  export=true,
  pubkey="rsa",
  type = "rsa",
  server_key_exchange = function (blob, protocol)
    local pos
    local ret = {rsa={}}
    pos, ret.rsa.modulus, ret.rsa.exponent = bin.unpack(">PP", blob)
    pos, ret.signed = unpack_signed(blob, pos)
    ret.strength = #ret.rsa.modulus
    return ret
  end
}
KEX_ALGORITHMS.RSA_EXPORT1024 = KEX_ALGORITHMS.RSA_EXPORT
KEX_ALGORITHMS.DHE_RSA={
  pubkey="rsa",
  type = "dh",
  server_key_exchange = function (blob, protocol)
    local pos
    local ret = {}
    pos, ret.dhparams, ret.strength = unpack_dhparams(blob)
    pos, ret.signed = unpack_signed(blob, pos)
    return ret
  end
}
KEX_ALGORITHMS.DHE_RSA_EXPORT={
  export=true,
  pubkey="rsa",
  type = "dh",
  server_key_exchange = KEX_ALGORITHMS.DHE_RSA.server_key_exchange
}
KEX_ALGORITHMS.DHE_DSS={
  pubkey="dsa",
  type = "dh",
  server_key_exchange = KEX_ALGORITHMS.DHE_RSA.server_key_exchange
}
KEX_ALGORITHMS.DHE_DSS_EXPORT={
  export=true,
  pubkey="dsa",
  type = "dh",
  server_key_exchange = KEX_ALGORITHMS.DHE_RSA.server_key_exchange
}
KEX_ALGORITHMS.DHE_DSS_EXPORT1024 = KEX_ALGORITHMS.DHE_DSS_EXPORT1024

KEX_ALGORITHMS.DH_DSS={
  pubkey="dh",
}
KEX_ALGORITHMS.DH_DSS_EXPORT={
  export=true,
  pubkey="dh",
}
KEX_ALGORITHMS.DH_RSA={
  pubkey="dh",
}
KEX_ALGORITHMS.DH_RSA_EXPORT={
  export=true,
  pubkey="dh",
}

KEX_ALGORITHMS.ECDHE_RSA={
  pubkey="rsa",
  type = "ec",
  server_key_exchange = function (blob, protocol)
    local pos
    local ret = {}
    pos, ret.ecdhparams, ret.strength = unpack_ecdhparams(blob)
    pos, ret.signed = unpack_signed(blob, pos)
    return ret
  end
}
KEX_ALGORITHMS.ECDHE_ECDSA={
  pubkey="ec",
  type = "ec",
  server_key_exchange = KEX_ALGORITHMS.ECDHE_RSA.server_key_exchange
}
KEX_ALGORITHMS.ECDH_ECDSA={
  pubkey="ec",
}
KEX_ALGORITHMS.ECDH_RSA={
  pubkey="ec",
}

-- draft-ietf-tls-ecc-00
KEX_ALGORITHMS.ECDH_ECNRA={
  pubkey="ec",
}
KEX_ALGORITHMS.ECMQV_ECDSA={
  pubkey="ec",
  type = "ecmqv",
  server_key_exchange = function (blob, protocol)
    local pos
    local ret = {}
    pos, ret.mqvparams = bin.unpack("p", blob)
    return ret
  end
}
KEX_ALGORITHMS.ECMQV_ECNRA={
  pubkey="ec",
}

-- rfc4279
KEX_ALGORITHMS.PSK = {
  type = "psk",
  server_key_exchange = function (blob, protocol)
    local pos, hint = bin.unpack(">P", blob)
    return {psk_identity_hint=hint}
  end
}
KEX_ALGORITHMS.RSA_PSK = {
  pubkey="rsa",
  type = "psk",
  server_key_exchange = KEX_ALGORITHMS.PSK.server_key_exchange
}
KEX_ALGORITHMS.DHE_PSK = {
  type = "dh",
  server_key_exchange = function (blob, protocol)
    local pos
    local ret = {}
    pos, ret.psk_identity_hint = bin.unpack(">P", blob)
    pos, ret.dhparams, ret.strength = unpack_dhparams(blob, pos)
    return ret
  end
}
--nomenclature change
KEX_ALGORITHMS.PSK_DHE = KEX_ALGORITHMS.DHE_PSK

--rfc5489
KEX_ALGORITHMS.ECDHE_PSK={
  type = "ec",
  server_key_exchange = function (blob, protocol)
    local pos
    local ret = {}
    pos, ret.psk_identity_hint = bin.unpack(">P", blob)
    pos, ret.ecdhparams, ret.strength = unpack_ecdhparams(blob, pos)
    return ret
  end
}

-- RFC 5054
KEX_ALGORITHMS.SRP_SHA = {
  type = "srp",
  server_key_exchange = function (blob, protocol)
    local pos
    local ret = {srp={}}
    pos, ret.srp.N, ret.srp.g, ret.srp.s, ret.srp.B = bin.unpack(">PPpP", blob)
    pos, ret.signed = unpack_signed(blob, pos)
    ret.strength = #ret.srp.N
    return ret
  end
}
KEX_ALGORITHMS.SRP_SHA_DSS = {
  pubkey="dsa",
  type = "srp",
  server_key_exchange = KEX_ALGORITHMS.SRP_SHA.server_key_exchange
}
KEX_ALGORITHMS.SRP_SHA_RSA = {
  pubkey="rsa",
  type = "srp",
  server_key_exchange = KEX_ALGORITHMS.SRP_SHA.server_key_exchange
}

-- RFC 6101
KEX_ALGORITHMS.FORTEZZA_KEA={}

-- RFC 4491
KEX_ALGORITHMS.GOSTR341001={}
KEX_ALGORITHMS.GOSTR341094={}

-- RFC 2712
KEX_ALGORITHMS.KRB5={}
KEX_ALGORITHMS.KRB5_EXPORT={
  export=true,
}


--- Get info about a cipher suite
--
--  Returned table has "kex", "cipher", "mode", "size", and
--  "hash" keys, as well as boolean flag "draft". The "draft"
--  flag is only supported for some suites that have different enumeration
--  values in draft versus final RFC.
-- @param c The cipher suite name, e.g. TLS_RSA_WITH_AES_128_GCM_SHA256
-- @return A table of info as described above.
function cipher_info (c)
  local info = cipher_info_cache[c]
  if info then return info end
  info = {}
  local tokens = stdnse.strsplit("_", c)
  local i = 1
  if tokens[i] ~= "TLS" and tokens[i] ~= "SSL" then
    stdnse.debug2("cipher_info: Not a TLS ciphersuite: %s", c)
    return nil
  end
  -- kex, cipher, size, mode, hash
  i = i + 1
  while tokens[i] and tokens[i] ~= "WITH" do
    i = i + 1
  end
  info.kex = table.concat(tokens, "_", 2, i-1)

  if tokens[i] and tokens[i] ~= "WITH" then
    stdnse.debug2("cipher_info: Can't parse (no WITH): %s", c)
    return nil
  end

  -- cipher
  i = i + 1
  local t = tokens[i]
  info.cipher = t
  if t == "3DES" then
    i = i + 1 -- 3DES_EDE
  end

  -- key size
  if t == "3DES" then -- NIST SP 800-57
    info.size = 112
  elseif t == "CHACHA20" then
    info.size = 256
  elseif t == "IDEA" then
    info.size = 128
  elseif t == "SEED" then
    info.size = 128
  elseif t == "FORTEZZA" then
    info.size = 80
  elseif t == "DES" then
    info.size = 56
  elseif t == "RC2" or t == "DES40" then
    info.size = 40
  elseif t == "NULL" then
    info.size = 0
  else
    i = i + 1
    info.size = tonumber(tokens[i])
  end

  -- stream ciphers don't have a mode
  if info.cipher == "RC4" then
    info.mode = "stream"
  elseif info.cipher == "CHACHA20" then
    i = i + 1
    info.cipher = "CHACHA20-POLY1305"
    info.mode = "stream"
  elseif info.cipher ~= "NULL" then
    i = i + 1
    info.mode = tokens[i]
  end

  -- export key size override
  if info.export and tonumber(tokens[i+1]) then
    i = i + 1
    info.size = tonumber(tokens[i])
  end

  -- Other key size overrides
  if info.cipher == "RC4" then -- RFC 7465 prohibits RC4 in TLS
    info.size = math.min(info.size or 80, 80) -- Equivalently caps to C grade?
  end

  -- hash
  if info.mode == "CCM" then
    info.hash = "SHA256"
  else
    i = i + 1
    t = (tokens[i]):match("(.*)%-draft$")
    if t then
      info.draft = true
    else
      t = tokens[i]
    end
    info.hash = t
  end

  cipher_info_cache[c] = info
  return info
end

SCSVS = {
["TLS_EMPTY_RENEGOTIATION_INFO_SCSV"]              =  0x00FF, -- rfc5746
["TLS_FALLBACK_SCSV"]                              =  0x5600, -- draft-ietf-tls-downgrade-scsv-00
}

-- Helper function to unpack a 3-byte integer value
local function unpack_3byte (buffer, pos)
  local low, high
  pos, high, low = bin.unpack("C>S", buffer, pos)
  return pos, low + high * 0x10000
end

---
-- Read a SSL/TLS record
-- @param buffer   The read buffer
-- @param i        The position in the buffer to start reading
-- @param fragment Message fragment left over from previous record (nil if none)
-- @return The current position in the buffer
-- @return The record that was read, as a table
function record_read(buffer, i, fragment)
  local b, h, len
  local add = 0

  ------------
  -- Header --
  ------------

  -- Ensure we have enough data for the header.
  if #buffer - i < TLS_RECORD_HEADER_LENGTH then
    return i, nil
  end

  -- Parse header.
  h = {}
  local j, typ, proto = bin.unpack(">CS", buffer, i)
  local name = find_key(TLS_CONTENTTYPE_REGISTRY, typ)
  if name == nil then
    stdnse.debug1("Unknown TLS ContentType: %d", typ)
    return j, nil
  end
  h["type"] = name
  name = find_key(PROTOCOLS, proto)
  if name == nil then
    stdnse.debug1("Unknown TLS Protocol: 0x%04x", proto)
    return j, nil
  end
  h["protocol"] = name

  j, h["length"] = bin.unpack(">S", buffer, j)

  -- Ensure we have enough data for the body.
  len = j + h["length"] - 1
  if #buffer < len then
    return i, nil
  end

  -- Adjust buffer and length to account for message fragment left over
  -- from last record.
  if fragment then
    add = #fragment
    len = len + add
    buffer = buffer:sub(1, j - 1) .. fragment .. buffer:sub(j, -1)
  end

  -- Convert to human-readable form.

  ----------
  -- Body --
  ----------

  h["body"] = {}

  while j <= len do
    -- RFC 2246, 6.2.1 "multiple client messages of the same ContentType may
    -- be coalesced into a single TLSPlaintext record"
    b = {}
    if h["type"] == "alert" then
      -- Parse body.
      j, b["level"] = bin.unpack("C", buffer, j)
      j, b["description"] = bin.unpack("C", buffer, j)

      -- Convert to human-readable form.
      b["level"] = find_key(TLS_ALERT_LEVELS, b["level"])
      b["description"] = find_key(TLS_ALERT_REGISTRY, b["description"])

      table.insert(h["body"], b)
    elseif h["type"] == "handshake" then

      -- Check for message fragmentation.
      if len - j < 3 then
        h.fragment = buffer:sub(j, len)
        return len + 1 - add, h
      end

      -- Parse body.
      j, b["type"] = bin.unpack("C", buffer, j)
      local msg_end
      j, msg_end = unpack_3byte(buffer, j)
      msg_end = msg_end + j

      -- Convert to human-readable form.
      b["type"] = find_key(TLS_HANDSHAKETYPE_REGISTRY, b["type"])

      -- Check for message fragmentation.
      if msg_end > len + 1 then
        h.fragment = buffer:sub(j - 4, len)
        return len + 1 - add, h
      end

      if b["type"] == "server_hello" then
        -- Parse body.
        j, b["protocol"] = bin.unpack(">S", buffer, j)
        j, b["time"] = bin.unpack(">I", buffer, j)
        j, b["random"] = bin.unpack("A28", buffer, j)
        j, b["session_id_length"] = bin.unpack("C", buffer, j)
        j, b["session_id"] = bin.unpack("A" .. b["session_id_length"], buffer, j)
        j, b["cipher"] = bin.unpack(">S", buffer, j)
        j, b["compressor"] = bin.unpack("C", buffer, j)
        -- Optional extensions for TLS only
        if j < msg_end and h["protocol"] ~= "SSLv3" then
          local num_exts
          b["extensions"] = {}
          j, num_exts = bin.unpack(">S", buffer, j)
          for e = 0, num_exts do
            if j >= msg_end then break end
            local extcode, datalen
            j, extcode = bin.unpack(">S", buffer, j)
            extcode = find_key(EXTENSIONS, extcode) or extcode
            j, b["extensions"][extcode] = bin.unpack(">P", buffer, j)
          end
        end

        -- Convert to human-readable form.
        b["protocol"] = find_key(PROTOCOLS, b["protocol"])
        b["cipher"] = find_key(CIPHERS, b["cipher"])
        b["compressor"] = find_key(COMPRESSORS, b["compressor"])
      elseif b["type"] == "certificate" then
        local cert_end
        j, cert_end = unpack_3byte(buffer, j)
        cert_end = cert_end + j
        if cert_end > msg_end then
          stdnse.debug2("server_certificate length > handshake body length!")
        end
        b["certificates"] = {}
        while j < cert_end do
          local cert_len, cert
          j, cert_len = unpack_3byte(buffer, j)
          j, cert = bin.unpack("A" .. cert_len, buffer, j)
          -- parse these with sslcert.parse_ssl_certificate
          table.insert(b["certificates"], cert)
        end
      else
        -- TODO: implement other handshake message types
        stdnse.debug2("Unknown handshake message type: %s", b["type"])
        j, b["data"] = bin.unpack("A" .. msg_end - j, buffer, j)
      end

      table.insert(h["body"], b)
    elseif h["type"] == "heartbeat" then
      j, b["type"], b["payload_length"] = bin.unpack("C>S", buffer, j)
      j, b["payload"], b["padding"] = bin.unpack("PP", buffer, j)
      table.insert(h["body"], b)
    else
      stdnse.debug1("Unknown message type: %s", h["type"])
    end
  end

  -- Ignore unparsed bytes.
  j = len + 1

  return j - add, h
end

---
-- Build a SSL/TLS record
-- @param type The type of record ("handshake", "change_cipher_spec", etc.)
-- @param protocol The protocol and version ("SSLv3", "TLSv1.0", etc.)
-- @param b The record body
-- @return The SSL/TLS record as a string
function record_write(type, protocol, b)
  return table.concat({
    -- Set the header as a handshake.
    bin.pack("C", TLS_CONTENTTYPE_REGISTRY[type]),
    -- Set the protocol.
    bin.pack(">S", PROTOCOLS[protocol]),
    -- Set the length of the header body.
    bin.pack(">S", #b),
    b
  })
end

-- Claim to support every hash and signature algorithm combination (TLSv1.2 only)
--
local signature_algorithms_all
do
  local sigalgs = {}
  for hash, _ in pairs(HashAlgorithms) do
    for sig, _ in pairs(SignatureAlgorithms) do
      -- RFC 5246 7.4.1.4.1.
      -- The "anonymous" value is meaningless in this context but used in
      -- Section 7.4.3.  It MUST NOT appear in this extension.
      if sig ~= "anonymous" then
        sigalgs[#sigalgs+1] = {hash, sig}
      end
    end
  end
  signature_algorithms_all = EXTENSION_HELPERS["signature_algorithms"](sigalgs)
end

---
-- Build a client_hello message
--
-- The options table has the following keys:
-- * <code>"protocol"</code> - The TLS protocol version string
-- * <code>"ciphers"</code> - a table containing the cipher suite names. Defaults to the NULL cipher
-- * <code>"compressors"</code> - a table containing the compressor names. Default: NULL
-- * <code>"extensions"</code> - a table containing the extension names. Default: no extensions
-- @param t Table of options
-- @return The client_hello record as a string
function client_hello(t)
  local b, ciphers, compressor, compressors, h, len
  t = t or {}

  ----------
  -- Body --
  ----------

  b = {}
  -- Set the protocol.
  local protocol = t["protocol"] or HIGHEST_PROTOCOL
  table.insert(b, bin.pack(">S", PROTOCOLS[protocol]))

  -- Set the random data.
  table.insert(b, bin.pack(">I", os.time()))

  -- Set the random data.
  table.insert(b, stdnse.generate_random_string(28))

  -- Set the session ID.
  table.insert(b, '\0')

  -- Cipher suites.
  ciphers = {}
  -- Add specified ciphers.
  for _, cipher in pairs(t["ciphers"] or DEFAULT_CIPHERS) do
    if type(cipher) == "string" then
      cipher = CIPHERS[cipher] or SCSVS[cipher]
    end
    if type(cipher) == "number" and cipher >= 0 and cipher <= 0xffff then
      table.insert(ciphers, bin.pack(">S", cipher))
    else
      stdnse.debug1("Unknown cipher in client_hello: %s", cipher)
    end
  end
  table.insert(b, bin.pack(">P", table.concat(ciphers)))

  -- Compression methods.
  compressors = {}
  if t["compressors"] ~= nil then
    -- Add specified compressors.
    for _, compressor in pairs(t["compressors"]) do
      if compressor ~= "NULL" then
        table.insert(compressors, bin.pack("C", COMPRESSORS[compressor]))
      end
    end
  end
  -- Always include NULL as last choice
  table.insert(compressors, bin.pack("C", COMPRESSORS["NULL"]))
  table.insert(b, bin.pack(">p", table.concat(compressors)))

  -- TLS extensions
  if PROTOCOLS[protocol] and protocol ~= "SSLv3" then
    local extensions = {}
    if t["extensions"] ~= nil then
      -- Do we need to add the signature_algorithms extension?
      local need_sigalg = (protocol == "TLSv1.2")
      -- Add specified extensions.
      for extension, data in pairs(t["extensions"]) do
        if type(extension) == "number" then
          table.insert(extensions, bin.pack(">S", extension))
        else
          if extension == "signature_algorithms" then
            need_sigalg = false
          end
          table.insert(extensions, bin.pack(">S", EXTENSIONS[extension]))
        end
        table.insert(extensions, bin.pack(">P", data))
      end
      if need_sigalg then
        table.insert(extensions, bin.pack(">S", EXTENSIONS["signature_algorithms"]))
        table.insert(extensions, bin.pack(">P", signature_algorithms_all))
      end
    end
    -- Extensions are optional
    if #extensions ~= 0 then
      table.insert(b, bin.pack(">P", table.concat(extensions)))
    end
  end

  ------------
  -- Header --
  ------------

  b = table.concat(b)

  h = {}

  -- Set type to ClientHello.
  table.insert(h, bin.pack("C", TLS_HANDSHAKETYPE_REGISTRY["client_hello"]))

  -- Set the length of the body.
  len = bin.pack(">I", #b)
  -- body length is 24 bits big-endian, so the 3 LSB of len
  table.insert(h, len:sub(2,4))

  table.insert(h, b)

  -- Record layer version should be SSLv3 (lowest compatible record version)
  return record_write("handshake", "SSLv3", table.concat(h))
end

local function read_atleast(s, n)
  local buf = {}
  local count = 0
  while count < n do
    local status, data = s:receive_bytes(n - count)
    if not status then
      return status, data, table.concat(buf)
    end
    buf[#buf+1] = data
    count = count + #data
  end
  return true, table.concat(buf)
end

--- Get an entire record into a buffer
--
--  Caller is responsible for closing the socket if necessary.
-- @param sock The socket to read additional data from
-- @param buffer The string buffer holding any previously-read data
--               (default: "")
-- @param i The position in the buffer where the record should start
--          (default: 1)
-- @return status Socket status
-- @return Buffer containing at least 1 record if status is true
-- @return Error text if there was an error
function record_buffer(sock, buffer, i)
  buffer = buffer or ""
  i = i or 1
  local count = #buffer:sub(i)
  local status, resp, rem
  if count < TLS_RECORD_HEADER_LENGTH then
    status, resp, rem = read_atleast(sock, TLS_RECORD_HEADER_LENGTH - count)
    if not status then
      return false, buffer .. rem, resp
    end
    buffer = buffer .. resp
    count = count + #resp
  end
  -- ContentType, ProtocolVersion, length
  local _, _, _, len = bin.unpack(">CSS", buffer, i)
  if count < TLS_RECORD_HEADER_LENGTH + len then
    status, resp = read_atleast(sock, TLS_RECORD_HEADER_LENGTH + len - count)
    if not status then
      return false, buffer, resp
    end
    buffer = buffer .. resp
  end
  return true, buffer
end

return _ENV;
