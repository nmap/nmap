---
-- A library providing functions for doing TLS/SSL communications
--
-- These functions will build strings and process buffers. Socket communication
-- is left to the script to implement.
--
-- @args tls.servername Hostname to use in the Server Name Indication (SNI)
--                      extension. Overrides the target name given on the
--                      command line and affects all targets.
-- @author Daniel Miller

local stdnse = require "stdnse"
local string = require "string"
local stringaux = require "stringaux"
local math = require "math"
local os = require "os"
local table = require "table"
local tableaux = require "tableaux"
local rand = require "rand"
_ENV = stdnse.module("tls", stdnse.seeall)

local pack = string.pack
local unpack = string.unpack
local tostring = tostring
local concat = table.concat
local insert = table.insert

-- Most of the values in the tables below are from:
-- http://www.iana.org/assignments/tls-parameters/
PROTOCOLS = {
  ["SSLv3"]       = 0x0300,
  ["TLSv1.0"]     = 0x0301,
  ["TLSv1.1"]     = 0x0302,
  ["TLSv1.2"]     = 0x0303,
  ["TLSv1.3"]     = 0x0304,
}
HIGHEST_PROTOCOL = "TLSv1.3"
local TLS_PROTOCOL_VERSIONS = tableaux.invert(PROTOCOLS)

--
-- TLS Record Types
--
TLS_RECORD_HEADER_LENGTH = 5

TLS_CONTENTTYPE_REGISTRY = {
  ["change_cipher_spec"]  = 20,
  ["alert"]               = 21,
  ["handshake"]           = 22,
  ["application_data"]    = 23,
  ["heartbeat"]           = 24,
  ["tls12_cid"]           = 25,
  ["ACK"]                 = 26,
}

local TLS_CONTENTTYPES = tableaux.invert(TLS_CONTENTTYPE_REGISTRY)

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
  ["too_many_cids_requested"]             = 52,
  ["export_restriction"]                  = 60,
  ["protocol_version"]                    = 70,
  ["insufficient_security"]               = 71,
  ["internal_error"]                      = 80,
  ["inappropriate_fallback"]              = 86,
  ["user_canceled"]                       = 90,
  ["no_renegotiation"]                    = 100,
  ["missing_extension"]                   = 109,
  ["unsupported_extension"]               = 110,
  ["certificate_unobtainable"]            = 111,
  ["unrecognized_name"]                   = 112,
  ["bad_certificate_status_response"]     = 113,
  ["bad_certificate_hash_value"]          = 114,
  ["unknown_psk_identity"]                = 115,
  ["certificate_required"]                = 116,
  ["no_application_protocol"]             = 120,
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
  ["end_of_early_data"]           = 5,
  ["hello_retry_request"]         = 6,
  ["encrypted_extensions"]        = 8,
  ["request_connection_id"]       = 9,
  ["new_connection_id"]           = 10,
  ["certificate"]                 = 11,
  ["server_key_exchange"]         = 12,
  ["certificate_request"]         = 13,
  ["server_hello_done"]           = 14,
  ["certificate_verify"]          = 15,
  ["client_key_exchange"]         = 16,
  ["client_certificate_request"]  = 17,
  ["finished"]                    = 20,
  ["certificate_url"]             = 21,
  ["certificate_status"]          = 22,
  ["supplemental_data"]           = 23,
  ["key_update"]                  = 24,
  ["compressed_certificate"]      = 25,
  ["ekt_key"]                     = 26,
  ["next_protocol"]               = 67,
  ["message_hash"]                = 254,
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
-- TLS Supported Groups
-- RFC 4492 section 5.1.1 "Supported Elliptic Curves Extension".
ELLIPTIC_CURVES = {
  sect163k1 = 1, --deprecated
  sect163r1 = 2, --deprecated
  sect163r2 = 3, --deprecated
  sect193r1 = 4, --deprecated
  sect193r2 = 5, --deprecated
  sect233k1 = 6, --deprecated
  sect233r1 = 7, --deprecated
  sect239k1 = 8, --deprecated
  sect283k1 = 9, --deprecated
  sect283r1 = 10, --deprecated
  sect409k1 = 11, --deprecated
  sect409r1 = 12, --deprecated
  sect571k1 = 13, --deprecated
  sect571r1 = 14, --deprecated
  secp160k1 = 15, --deprecated
  secp160r1 = 16, --deprecated
  secp160r2 = 17, --deprecated
  secp192k1 = 18, --deprecated
  secp192r1 = 19, --deprecated
  secp224k1 = 20, --deprecated
  secp224r1 = 21, --deprecated
  secp256k1 = 22, --deprecated
  secp256r1 = 23,
  secp384r1 = 24,
  secp521r1 = 25,
  brainpoolP256r1 = 26, --RFC7027
  brainpoolP384r1 = 27,
  brainpoolP512r1 = 28,
  ecdh_x25519 = 29, -- rfc8422
  ecdh_x448 = 30, -- rfc8422
  brainpoolP256r1tls13 = 31, --RFC8734
  brainpoolP384r1tls13 = 32,
  brainpoolP512r1tls13 = 33,
  GC256A = 34, -- draft-smyshlyaev-tls12-gost-suites
  GC256B = 35,
  GC256C = 36,
  GC256D = 37,
  GC512A = 38,
  GC512B = 39,
  GC512C = 40,
  curveSM2 = 41, -- RFC 8998
  ffdhe2048 = 0x0100, --RFC7919
  ffdhe3072 = 0x0101, --RFC7919
  ffdhe4096 = 0x0102, --RFC7919
  ffdhe6144 = 0x0103, --RFC7919
  ffdhe8192 = 0x0104, --RFC7919
  MLKEM512 = 512 -- draft-connolly-tls-mlkem-key-agreement-03
  MLKEM768 = 513 -- draft-connolly-tls-mlkem-key-agreement-03
  MLKEM1024 = 514 -- draft-connolly-tls-mlkem-key-agreement-03
  arbitrary_explicit_prime_curves = 0xFF01,
  arbitrary_explicit_char2_curves = 0xFF02,
}

-- Most likely set, supported by Firefox and Chrome
DEFAULT_ELLIPTIC_CURVES = {
  "secp256r1",
  "secp384r1",
  "secp521r1",
  "ecdh_x25519",
  "ffdhe2048", -- added for TLSv1.3
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
  intrinsic = 8,
}
SignatureAlgorithms = {
  anonymous = 0,
  rsa = 1,
  dsa = 2,
  ecdsa = 3,
  ed25519 = 7,
  ed448 = 8,
}

---
-- TLS v1.3 Signature Algorithms
SignatureSchemes = {
  -- RSASSA-PKCS1-v1_5 algorithms
  rsa_pkcs1_sha256 = 0x0401,
  rsa_pkcs1_sha384 = 0x0501,
  rsa_pkcs1_sha512 = 0x0601,
  -- ECDSA algorithms
  ecdsa_secp256r1_sha256 = 0x0403,
  ecdsa_secp384r1_sha384 = 0x0503,
  ecdsa_secp521r1_sha512 = 0x0603,
  -- draft-wang-tls-raw-public-key-with-ibc
  eccsi_sha256 = 0x0704,
  iso_ibs1 = 0x0705,
  iso_ibs2 = 0x0706,
  iso_chinese_ibs = 0x0707,
  -- RFC8998
  sm2sig_sm3 = 0x0708,
  -- draft-smyshlyaev-tls13-gost-suites
  gostr34102012_256a = 0x0709,
  gostr34102012_256b = 0x070A,
  gostr34102012_256c = 0x070B,
  gostr34102012_256d = 0x070C,
  gostr34102012_512a = 0x070D,
  gostr34102012_512b = 0x070E,
  gostr34102012_512c = 0x070F,
  -- RSASSA-PSS algorithms with public key OID rsaEncryption
  rsa_pss_rsae_sha256 = 0x0804,
  rsa_pss_rsae_sha384 = 0x0805,
  rsa_pss_rsae_sha512 = 0x0806,
  -- EdDSA algorithms
  ed25519 = 0x0807,
  ed448   = 0x0808,
  -- RSASSA-PSS algorithms with public key OID RSASSA-PSS
  rsa_pss_pss_sha256 = 0x0809,
  rsa_pss_pss_sha384 = 0x080a,
  rsa_pss_pss_sha512 = 0x080b,
  -- ECC Brainpool curves
  ecdsa_brainpoolP256r1tls13_sha256 = 0x081a,
  ecdsa_brainpoolP384r1tls13_sha384 = 0x081b,
  ecdsa_brainpoolP512r1tls13_sha512 = 0x081c,
  -- Legacy algorithms
  rsa_pkcs1_sha1 = 0x0201,
  ecdsa_sha1     = 0x0203,
  -- RFC 8998
  sm2sig_sm3 = 0x0708,
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
  -- TLSv1.3 changed the format for this extension. It's just more convenient
  -- to call it something else.
  ["signature_algorithms_13"] = 13,
  ["use_srtp"] = 14,
  ["heartbeat"] = 15,
  ["application_layer_protocol_negotiation"] = 16,
  ["status_request_v2"] = 17,
  ["signed_certificate_timestamp"] = 18,
  ["client_certificate_type"] = 19,
  ["server_certificate_type"] = 20,
  ["padding"] = 21, -- rfc7685
  ["encrypt_then_mac"] = 22, -- rfc7366
  ["extended_master_secret"] = 23, -- rfc7627
  ["token_binding"] = 24, -- Temporary, expires 2018-02-04
  ["cached_info"] = 25, -- rfc7924
  ["tls_lts"] = 26, -- draft-gutmann-tls-lts
  ["compress_certificate"] = 27, -- rfc8879
  ["record_size_limit"] = 28, -- rfc8449
  ["pwd_protect"] = 29, -- rfc8492
  ["pwd_clear"] = 30, -- rfc8492
  ["password_salt"] = 31, -- rfc8492
  ["ticket_pinning"] = 32,
  ["tls_cert_with_extern_psk"] = 33,
  ["delegated_credentials"] = 34,
  ["TLMSP"] = 35,
  ["TLMSP_proxying"] = 36,
  ["TLMSP_delegate"] = 37,
  ["supported_ekt_ciphers"] = 38,
  ["SessionTicket TLS"] = 39,
  -- TLSv1.3
  ["pre_shared_key"] = 41,
  ["early_data"] = 42,
  ["supported_versions"] = 43,
  ["cookie"] = 44,
  ["psk_key_exchange_modes"] = 45,
  ["certificate_authorities"] = 47,
  ["oid_filters"] = 48,
  ["post_handshake_auth"] = 49,
  ["signature_algorithms_cert"] = 50,
  ["key_share"] = 51,
  ["transparency_info"] = 52,
  ["connection_id-deprecated"] = 53,
  ["connection_id"] = 54,
  ["external_id_hash"] = 55,
  ["external_session_id"] = 56,
  ["quic_transport_parameters"] = 57,
  ["ticket_request"] = 58,
  ["dnssec_chain"] = 59,
  --
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
    return pack(">s2", pack(">Bs2", 0, server_name))
  end,
  ["max_fragment_length"] = tostring,
  ["client_certificate_url"] = tostring,
  ["trusted_ca_keys"] = tostring,
  ["truncated_hmac"] = tostring,
  ["status_request"] = tostring,
  ["elliptic_curves"] = function (elliptic_curves)
    local list = {}
    for _, name in ipairs(elliptic_curves) do
      list[#list+1] = pack(">I2", ELLIPTIC_CURVES[name])
    end
    return pack(">s2", concat(list))
  end,
  ["ec_point_formats"] = function (ec_point_formats)
    local list = {}
    for _, format in ipairs(ec_point_formats) do
      list[#list+1] = pack(">B", EC_POINT_FORMATS[format])
    end
    return pack(">s1", concat(list))
  end,
  ["signature_algorithms"] = function(signature_algorithms)
    local list = {}
    for _, pair in ipairs(signature_algorithms) do
      list[#list+1] = pack(">BB",
        HashAlgorithms[pair[1]] or pair[1],
        SignatureAlgorithms[pair[2]] or pair[2]
        )
    end
    return pack(">s2", concat(list))
  end,
  ["signature_algorithms_13"] = function (signature_schemes)
    local list = {}
    for _, name in ipairs(signature_schemes) do
      list[#list+1] = pack(">I2", SignatureSchemes[name])
    end
    return pack(">s2", concat(list))
  end,
  ["application_layer_protocol_negotiation"] = function(protocols)
    local list = {}
    for _, proto in ipairs(protocols) do
      list[#list+1] = pack(">s1", proto)
    end
    return pack(">s2", concat(list))
  end,
  ["next_protocol_negotiation"] = tostring,
  ["supported_versions"] = function(versions)
    local list = {}
    for _, name in ipairs(versions) do
      list[#list+1] = pack(">I2", PROTOCOLS[name])
    end
    return pack(">s1", concat(list))
  end,
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
["TLS_ECDHE_ECDSA_WITH_AES_128_CCM"]               =  0xC0AC,
["TLS_ECDHE_ECDSA_WITH_AES_256_CCM"]               =  0xC0AD,
["TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8"]             =  0xC0AE,
["TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8"]             =  0xC0AF,
["TLS_ECCPWD_WITH_AES_128_GCM_SHA256"]             =  0xC0B0, -- RFC8492
["TLS_ECCPWD_WITH_AES_256_GCM_SHA384"]             =  0xC0B1, -- RFC8492
["TLS_ECCPWD_WITH_AES_128_CCM_SHA256"]             =  0xC0B2, -- RFC8492
["TLS_ECCPWD_WITH_AES_256_CCM_SHA384"]             =  0xC0B3, -- RFC8492
["TLS_AKE_WITH_NULL_SHA256"]             =  0xC0B4, -- RFC9150
["TLS_AKE_WITH_NULL_SHA384"]             =  0xC0B5, -- RFC9150
["TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC"] =  0xC100, -- RFC9189
["TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC"]      =  0xC101, -- RFC9189
["TLS_GOSTR341112_256_WITH_28147_CNT_IMIT"]      =  0xC102, -- RFC9189
["TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L"]    =  0xC103, -- draft-smyshlyaev-tls13-gost-suites
["TLS_GOSTR341112_256_WITH_MAGMA_MGM_L"]         =  0xC104, -- draft-smyshlyaev-tls13-gost-suites
["TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S"]    =  0xC105, -- draft-smyshlyaev-tls13-gost-suites
["TLS_GOSTR341112_256_WITH_MAGMA_MGM_S"]         =  0xC106, -- draft-smyshlyaev-tls13-gost-suites
["TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256-draft"]    =  0xCC13, -- RFC7905 superseded
["TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256-draft"]  =  0xCC14, -- RFC7905 superseded
["TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256-draft"]      =  0xCC15, -- RFC7905 superseded
["TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"]    =  0xCCA8,
["TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"]  =  0xCCA9,
["TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"]      =  0xCCAA,
["TLS_PSK_WITH_CHACHA20_POLY1305_SHA256"]          =  0xCCAB,
["TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256"]    =  0xCCAC,
["TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256"]      =  0xCCAD,
["TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256"]      =  0xCCAE,
["TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256"]          = 0xD001, -- RFC 8442
["TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384"]          = 0xD002, -- RFC 8442
["TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256"]        = 0xD003, -- RFC 8442
["TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256"]          = 0xD005, -- RFC 8442
["SSL_RSA_FIPS_WITH_DES_CBC_SHA"]                  =  0xFEFE,
["SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA"]             =  0xFEFF,
-- TLSv1.3:
-- "Although TLS 1.3 uses the same cipher suite space as previous versions of
-- TLS, TLS 1.3 cipher suites are defined differently, only specifying the
-- symmetric ciphers, and cannot be used for TLS 1.2.  Similarly, TLS 1.2 and
-- lower cipher suites cannot be used with TLS 1.3."
-- We designate these as AKE (Authenticated Key Exchange) ciphersuites, in
-- order to simplify use of the cipher_info function.
TLS_AKE_WITH_AES_128_GCM_SHA256       = 0x1301,
TLS_AKE_WITH_AES_256_GCM_SHA384       = 0x1302,
TLS_AKE_WITH_CHACHA20_POLY1305_SHA256 = 0x1303,
TLS_AKE_WITH_AES_128_CCM_SHA256       = 0x1304,
TLS_AKE_WITH_AES_128_CCM_8_SHA256     = 0x1305,
TLS_AKE_WITH_SM4_GCM_SM3 = 0x00C6, -- RFC 8998
TLS_AKE_WITH_SM4_CCM_SM3 = 0x00C7, -- RFC 8998
}

-- Default ciphers sent by tls.client_hello for TLSv1.2 or earlier
DEFAULT_TLS12_CIPHERS = {
  "TLS_RSA_WITH_AES_128_CBC_SHA", -- mandatory TLSv1.2
  "TLS_RSA_WITH_3DES_EDE_CBC_SHA", -- mandatory TLSv1.1
  "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", -- mandatory TLSv1.0
  "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", -- DHE with strong AES
  "TLS_RSA_WITH_RC4_128_MD5", -- Weak and old, but likely supported on old stuff
}
-- Same, but for TLSv1.3
DEFAULT_TLS13_CIPHERS = {
  "TLS_AKE_WITH_AES_128_GCM_SHA256", -- mandatory TLSv1.3
  "TLS_AKE_WITH_AES_256_GCM_SHA384", -- stronger TLSv1.3
  "TLS_AKE_WITH_CHACHA20_POLY1305_SHA256", -- alternate TLSv1.3
}
-- Same, but for handshakes compatible with any TLS version
local DEFAULT_CIPHERS = {
  table.unpack(DEFAULT_TLS13_CIPHERS)
}
for _, c in ipairs(DEFAULT_TLS12_CIPHERS) do
  insert(DEFAULT_CIPHERS, c)
end

local function find_key(t, value)
  local found, v = tableaux.contains(t, value)
  return v
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
  p, g, y, pos = unpack(">s2s2s2", blob, pos)
  return pos, {p=p, g=g, y=y}, #p * 8
end

local function named_group_info (group)
  if group:match("^arbitrary") then
    return "ec"
  end
  local ktype, size = group:match("^(%D+)(%d+)")
  assert(ktype and size, ("Invalid named group: %s"):format(group))
  size = tonumber(size)
  if ktype == "ffdhe" then
    ktype = "dh"
  else
    if group == "ecdh_x25519" or group == "curveSM2" then
      size = 256
    end
    ktype = "ec"
  end
  return ktype, size
end

local function unpack_ecdhparams (blob, pos)
  local eccurvetype
  eccurvetype, pos = unpack("B", blob, pos)
  local ret = {}
  local strength
  if eccurvetype == 1 then
    local p, a, b, base, order, cofactor
    p, a, b, base, order, cofactor, pos = unpack("s1s1s1s1s1s1", blob, pos)
    strength = math.log(order, 2)
    ret.curve_params = {
      ec_curve_type = "explicit_prime",
      prime_p=p, curve={a=a, b=b}, base=base, order=order, cofactor=cofactor
    }
  elseif eccurvetype == 2 then
    local p = {}
    local m, basis
    m, basis, pos = unpack(">I2B", blob, pos)
    if basis == 1 then -- ec_trinomial
      p.k, pos = unpack("s1", blob, pos)
    elseif basis == 2 then -- ec_pentanomial
      p.k1, p.k2, p.k3, pos = unpack("s1s1s1", blob, pos)
    end
    local a, b, base, order, cofactor
    a, b, base, order, cofactor, pos = unpack("s1s1s1s1s1", blob, pos)
    strength = math.log(order, 2)
    ret.curve_params = {
      ec_curve_type = "explicit_char2",
      m=m, basis=basis, field=p, curve={a=a, b=b}, base=base, order=order, cofactor=cofactor
    }
  elseif eccurvetype == 3 then
    local curve
    curve, pos = unpack(">I2", blob, pos)
    ret.curve_params = {
      ec_curve_type = "namedcurve",
      curve = find_key(ELLIPTIC_CURVES, curve)
    }
    local _
    _, strength = named_group_info(ret.curve_params.curve)
  end
  ret.public, pos = unpack("s1", blob, pos)
  return pos, ret, strength
end

local function unpack_signed (blob, pos, protocol)
  if pos > #blob then -- not-signed
    return pos, nil
  end
  local hash_alg, sig_alg, sig
  -- TLSv1.2 changed to allow arbitrary hash and sig algorithms
  if protocol and PROTOCOLS[protocol] >= 0x0303 then
    hash_alg, sig_alg, sig, pos = unpack(">BBs2", blob, pos)
  else
    sig, pos = unpack(">s2", blob, pos)
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
    ret.rsa.modulus, ret.rsa.exponent, pos = unpack(">s2s2", blob)
    pos, ret.signed = unpack_signed(blob, pos, protocol)
    ret.strength = #ret.rsa.modulus
    return ret
  end
}
KEX_ALGORITHMS.RSA_EXPORT1024 = KEX_ALGORITHMS.RSA_EXPORT
KEX_ALGORITHMS.DHE_RSA={
  pubkey="rsa",
  type = "dh",
  pfs = true,
  server_key_exchange = function (blob, protocol)
    local pos
    local ret = {}
    pos, ret.dhparams, ret.strength = unpack_dhparams(blob)
    pos, ret.signed = unpack_signed(blob, pos, protocol)
    return ret
  end
}
KEX_ALGORITHMS.DHE_RSA_EXPORT={
  export=true,
  pubkey="rsa",
  type = "dh",
  pfs = true,
  server_key_exchange = KEX_ALGORITHMS.DHE_RSA.server_key_exchange
}
KEX_ALGORITHMS.DHE_DSS={
  pubkey="dsa",
  type = "dh",
  pfs = true,
  server_key_exchange = KEX_ALGORITHMS.DHE_RSA.server_key_exchange
}
KEX_ALGORITHMS.DHE_DSS_EXPORT={
  export=true,
  pubkey="dsa",
  type = "dh",
  pfs = true,
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
  pfs = true,
  server_key_exchange = function (blob, protocol)
    local pos
    local ret = {}
    pos, ret.ecdhparams, ret.strength = unpack_ecdhparams(blob)
    pos, ret.signed = unpack_signed(blob, pos, protocol)
    return ret
  end
}
KEX_ALGORITHMS.ECDHE_ECDSA={
  pubkey="ec",
  type = "ec",
  pfs = true,
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
    ret.mqvparams, pos = unpack("s1", blob)
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
    local hint, pos = unpack(">s2", blob)
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
  pfs = true,
  server_key_exchange = function (blob, protocol)
    local pos
    local ret = {}
    ret.psk_identity_hint, pos = unpack(">s2", blob)
    pos, ret.dhparams, ret.strength = unpack_dhparams(blob, pos)
    return ret
  end
}
--nomenclature change
KEX_ALGORITHMS.PSK_DHE = KEX_ALGORITHMS.DHE_PSK

--rfc5489
KEX_ALGORITHMS.ECDHE_PSK={
  type = "ec",
  pfs = true,
  server_key_exchange = function (blob, protocol)
    local pos
    local ret = {}
    ret.psk_identity_hint, pos = unpack(">s2", blob)
    pos, ret.ecdhparams, ret.strength = unpack_ecdhparams(blob, pos)
    return ret
  end
}

-- RFC 5054
KEX_ALGORITHMS.SRP_SHA = {
  type = "srp",
  pfs = true,
  server_key_exchange = function (blob, protocol)
    local pos
    local ret = {srp={}}
    ret.srp.N, ret.srp.g, ret.srp.s, ret.srp.B, pos = unpack(">s2s2s1s2", blob)
    pos, ret.signed = unpack_signed(blob, pos, protocol)
    ret.strength = #ret.srp.N
    return ret
  end
}
KEX_ALGORITHMS.SRP_SHA_DSS = {
  pubkey="dsa",
  type = "srp",
  pfs = true,
  server_key_exchange = KEX_ALGORITHMS.SRP_SHA.server_key_exchange
}
KEX_ALGORITHMS.SRP_SHA_RSA = {
  pubkey="rsa",
  type = "srp",
  pfs = true,
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

-- TLSv1.3
KEX_ALGORITHMS.AKE = {
	tls13ok=true,
	tls13only=true,
	pfs=true,
	-- TLSv1.3 swaps the ServerKeyExchange message for the key_share extension.
	-- We'll just pretend that's what this is:
  server_key_exchange = function (blob, protocol)
    local named_group, pos = unpack(">I2", blob)
    stdnse.debug1("named_group = %d", named_group)
    named_group = find_key(ELLIPTIC_CURVES, named_group)
    local gtype, strength = named_group_info(named_group)
    return {
      type = gtype,
      strength = strength,
      ecdhparams={ -- Not always ECC, but reusing structure simplifies things
        curve_params={
          ec_curve_type = "namedcurve",
          curve = named_group,
        }
      }
    }
  end,
}
-- RFC 8492
KEX_ALGORITHMS.ECCPWD = {
	tls13ok=true,
	tls13only=false,
}

local algorithms = {
  ["3DES"] = {s=112, b=64}, --NIST SP 800-57
  CHACHA20 = {s=256, b=128},
  IDEA = {s=128, b=64},
  SEED = {s=128, b=128},
  FORTEZZA = {s=80, b=64},
  DES = {s=56, b=64},
  RC2 = {s=40, b=64},
  DES40 = {s=40, b=64},
  NULL = {s=0},
  CAMELLIA = {b=128},
  ARIA = {b=128},
  AES = {b=128},
  SM4 = {s=128, b=128},
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
  local tokens = stringaux.strsplit("_", c)
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
  local kex = concat(tokens, "_", 2, i-1)
  info = KEX_ALGORITHMS[kex]
  if info then
    info = tableaux.tcopy(info)
    info.kex = kex
  else
    info = {kex = kex}
  end

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
  local tmp = algorithms[t]
  if tmp then
    info.size = tmp.s
    info.block_size = tmp.b
  end
  if info.size == nil then
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
  end
  i = i + 1
  if i <= #tokens then
    if tokens[i] == "8" and info.mode == "CCM" then
      info.mode = "CCM_8"
      i = i + 1
    elseif info.export and (tokens[i]):match("^%d+$") then
      info.size = tonumber(tokens[i])
      i = i + 1
    end
    if i <= #tokens then
      local t, w = (tokens[i]):match("(.+)%-([a-z]+)")
      if t then
        if w == "draft" then
          info.draft = true
        end
        -- else "or"
      else
        t = tokens[i]
      end
      info.hash = t
    end
  end

  cipher_info_cache[c] = info
  return info
end

SCSVS = {
["TLS_EMPTY_RENEGOTIATION_INFO_SCSV"]              =  0x00FF, -- rfc5746
["TLS_FALLBACK_SCSV"]                              =  0x5600, -- draft-ietf-tls-downgrade-scsv-00
}

handshake_parse = {
      server_hello = function (buffer, j, msg_end, protocol)
        local b = {}
        -- Parse body.
        b.protocol, b.time, b.random, b.session_id, j = unpack(">I2 I4 c28 s1", buffer, j)
        b.cipher, b.compressor, j = unpack(">I2 B", buffer, j)
        -- Optional extensions for TLS only
        if j < msg_end and protocol ~= "SSLv3" then
          local num_exts
          b["extensions"] = {}
          num_exts, j = unpack(">I2", buffer, j)
          for e = 0, num_exts do
            if j >= msg_end then break end
            local extcode, datalen
            extcode, j = unpack(">I2", buffer, j)
            extcode = find_key(EXTENSIONS, extcode) or extcode
            b["extensions"][extcode], j = unpack(">s2", buffer, j)
          end
        end

        -- Convert to human-readable form.
        b["protocol"] = find_key(PROTOCOLS, b["protocol"])
        b["cipher"] = find_key(CIPHERS, b["cipher"])
        b["compressor"] = find_key(COMPRESSORS, b["compressor"])

        -- RFC 8446: HelloRetryRequest message uses the same structure as the
        -- ServerHello, but with Random set to the special value of the SHA-256
        -- of "HelloRetryRequest"
        if b.protocol == "TLSv1.2" -- TLSv1.3 legacy version
          and b.random == "\xCF\x21\xAD\x74\xE5\x9A\x61\x11\xBE\x1D\x8C\x02\x1E\x65\xB8\x91\xC2\xA2\x11\x16\x7A\xBB\x8C\x5E\x07\x9E\x09\xE2\xC8\xA8\x33\x9C"
          then
          b.helloretry = true
        end

        -- RFC 8446: "the legacy_version field MUST be set to 0x0303,
        -- which is the version number for TLS 1.2"
        if (b.protocol == "TLSv1.2" and b.extensions
            and b.extensions.supported_versions == "\x03\x04") then
          b.protocol = "TLSv1.3"
        end

        return b, j
      end,

      certificate = function (buffer, j, msg_end, protocol)
        local cert_end
        cert_end, j = unpack(">I3", buffer, j)
        cert_end = cert_end + j
        if cert_end > msg_end then
          stdnse.debug2("server_certificate length > handshake body length!")
        end
        local b = {certificates = {}}
        while j < cert_end do
          local cert_len = unpack(">I3", buffer, j)
          if cert_len + 3 + j > cert_end then
            stdnse.debug1("server_certificate parsing error!")
            j = cert_end
            break
          end
          local cert
          cert, j = unpack(">s3", buffer, j)
          -- parse these with sslcert.parse_ssl_certificate
          insert(b["certificates"], cert)
        end

        return b, j
      end,

      NewSessionTicket = function (buffer, j, msg_end, protocol)
        -- Need 4 bytes for parsing.
        local have = #buffer - j + 1
        if have < 4 then
          return nil, j, 4
        end

        local b = {}
        -- Parse body.
        b.ticket_lifetime_hint, b.ticket, j = unpack(">I4 s2", buffer, j)

        return b, j
      end,
}

message_parse = {
    alert = function (buffer, j)
      local b = {}
      -- Parse body.
      b.level, b.description, j = unpack("BB", buffer, j)

      -- Convert to human-readable form.
      b["level"] = find_key(TLS_ALERT_LEVELS, b["level"])
      b["description"] = find_key(TLS_ALERT_REGISTRY, b["description"])

      return b, j
    end,

    handshake = function (buffer, j, protocol)
      -- Check for message fragmentation.
      -- Need 4 bytes for message header with length
      local have = #buffer - j + 1
      if have < 4 then
        return nil, j, 4
      end

      -- Parse body.
      local btype, len
      btype, len, j = unpack("B>I3", buffer, j)
      local msg_end = len + j

      -- Convert to human-readable form.
      btype = find_key(TLS_HANDSHAKETYPE_REGISTRY, btype)

      -- Check for message fragmentation.
      -- Need 4 bytes for header plus length of message
      if have < len + 4 then
        return nil, j - 4, len + 4
      end

      local parser = handshake_parse[btype]
      local b
      if parser then
        b, j = parser(buffer, j, msg_end, protocol)
        b.type = btype
      else
        -- TODO: implement other handshake message types
        b = { type = btype }
        stdnse.debug2("Unknown handshake message type: %s", b["type"])
        b.data, j = unpack("c" .. msg_end - j, buffer, j)
      end

      return b, j
    end,

    heartbeat = function (buffer, j)
      local b = {}
      b.type, b.payload, j = unpack(">B s2", buffer, j)
      -- Heartbeat messages are one per record; consume the rest of the record as padding.
      b.padding = buffer:sub(j)
      return b, #buffer + 1
    end,
}


--- Parse a series of TLS messages from a buffer
--@param mbuffer The buffer to parse
--@param mi The index into that buffer to begin parsing
--@param h The TLS/DTLS header. Must contain "type" and "protocol" fields
--@return A table of parsed messages
--@return The position where parsing stopped
function parse_messages (mbuffer, mi, h)
  local messages = {}
  while mi < #mbuffer do
    -- RFC 2246, 6.2.1 "multiple client messages of the same ContentType may
    -- be coalesced into a single TLSPlaintext record"
    local parser = message_parse[h.type]
    if not parser then
      stdnse.debug1("Unknown message type: %s", h["type"])
      break
    end
    local b, need
    b, mi, need = parser(mbuffer, mi, h.protocol)
    if b then
      messages[#messages+1] = b
    elseif need then
      -- Can't finish parsing this message, it'll be left in the fragment
      break
    end
  end

  return messages, mi
end

---
-- Read a SSL/TLS record
-- @param buffer   The read buffer
-- @param i        The position in the buffer to start reading (default: 1)
-- @param fragment Message fragment left over from previous record (nil if none)
-- @return The current position in the buffer
-- @return The record that was read, as a table
-- @return Whether parsing can continue if more data becomes available.
function record_read(buffer, i, fragment)
  i = i or 1

  -- Ensure we have enough data for the header.
  if #buffer - i < TLS_RECORD_HEADER_LENGTH then
    return i, nil, true
  end

  -- Parse header.
  local h = {}
  local typ, proto, rlength, j = unpack(">B I2 I2", buffer, i)
  h.length = rlength
  local name = find_key(TLS_CONTENTTYPE_REGISTRY, typ)
  if name == nil then
    stdnse.debug1("Unknown TLS ContentType: %d", typ)
    return j, nil, false
  end
  h["type"] = name
  name = find_key(PROTOCOLS, proto)
  if name == nil then
    stdnse.debug1("Unknown TLS Protocol: 0x%04x", proto)
    return j, nil, false
  end
  h["protocol"] = name

  -- Ensure we have enough data for the body.
  if #buffer < j + rlength - 1 then
    return i, nil, true
  end

  -- Adjust buffer and length to account for message fragment left over
  -- from last record.
  local mbuffer
  if fragment then
    mbuffer = fragment .. buffer:sub(j, j + rlength)
  else
    mbuffer = buffer:sub(j, j + rlength)
  end

  -- Body
  local mi = 1
  h.body, mi = parse_messages(mbuffer, mi, h)
  if mi < #mbuffer then
    -- Fragmented message
    h.fragment = mbuffer:sub(mi)
  end
  -- Skip to the end of the record. Ignore unparsed bytes.
  -- These should be handled as fragmentation above
  j = j + rlength

  return j, h, true
end

---
-- Get the record version field appropriate for the protocol version
--
-- TLSv1.3 introduced a change in the interpretation of the record version
-- field. Previously, this was an indication of the TLS protocol, but now it is
-- frozen at TLSv1.2.
-- @param proto_version The numeric value of the protocol, e.g. 0x0303 for TLSv1.2
-- @return The numeric value that should be used in the record layer version field
local function legacy_version (proto_version)
  -- TLSv1.2 was the last version where protocol version was negotiated via the
  -- record layer version. Later versions use the supported_versions extension
  return proto_version <= 0x0303 and proto_version or 0x0303
end

function record_version_ok(received_version, proto_version)
  if proto_version == "TLSv1.3" then
    return received_version == "TLSv1.2"
  end
  return proto_version == received_version
end

---
-- Build a SSL/TLS record
-- @param type The type of record ("handshake", "change_cipher_spec", etc.)
-- @param protocol The protocol and version ("SSLv3", "TLSv1.0", etc.)
-- @param b The record body
-- @return The SSL/TLS record as a string
function record_write(type, protocol, b)
  return concat({
    -- Set the header as a handshake.
    pack("B", TLS_CONTENTTYPE_REGISTRY[type]),
    -- Set the protocol.
    pack(">I2", legacy_version(PROTOCOLS[protocol])),
    -- Set the length of the header body.
    pack(">s2", b)
  })
end

-- Claim to support common hash and signature algorithm combinations (TLSv1.2 only)
--
local DEFAULT_SIGALGS
do
  local sigalgs = {
    -- most likely signature is rsa, so even use it for weak hashes
    {"md5","rsa"},
    {"sha1","rsa"},
    {"sha224","rsa"},
    -- most likely are sha256 and sha512.
    {"sha256","rsa"},
    {"sha256","dsa"},
    {"sha256","ecdsa"},
    {"sha512","rsa"},
    {"sha512","dsa"},
    {"sha512","ecdsa"},
    {"intrinsic","ed25519"},
    {"intrinsic","ed448"},
  }
  DEFAULT_SIGALGS = EXTENSION_HELPERS["signature_algorithms"](sigalgs)
end
-- Equivalent for TLSv1.3 is SignatureScheme
-- We'll offer all the sha256 and sha512 variants, plus a few extra
local DEFAULT_SIGSCHEMES
do
  local sigalgs = {
  "rsa_pkcs1_sha256",
  "rsa_pkcs1_sha512",
  "ecdsa_secp256r1_sha256",
  "ecdsa_secp521r1_sha512",
  "rsa_pss_rsae_sha256",
  "rsa_pss_rsae_sha512",
  "ed25519",
  "ed448",
  "rsa_pss_pss_sha256",
  "rsa_pss_pss_sha512",
  "rsa_pkcs1_sha1",
  "ecdsa_sha1",
  }
  DEFAULT_SIGSCHEMES = EXTENSION_HELPERS["signature_algorithms_13"](sigalgs)
end

---
-- Build a client_hello message
--
-- The options table has the following keys:
-- * <code>"protocol"</code> - The TLS protocol version string for the client_hello. This indicates the highest protocol version supported.
-- * <code>"record_protocol"</code> - The TLS protocol version string for the TLS record. This indicates the lowest protocol version supported.
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
  insert(b, pack(">I2 I4",
    legacy_version(PROTOCOLS[protocol]),
    -- Set the random data.
    os.time()
  ))
  local record_proto = t.record_protocol

  -- Set the random data.
  insert(b, rand.random_string(28))

  -- Set the session ID.
  local sid = t["session_id"] or ""
  insert(b, pack(">s1", sid))

  local eccpwd = false
  local shangmi = false
  -- Cipher suites.
  ciphers = {}
  -- Add specified ciphers.
  for _, cipher in pairs(t.ciphers -- user-specified list
    or (record_proto == "TLSv1.3" and DEFAULT_TLS13_CIPHERS) -- TLSv1.3 only
    or (PROTOCOLS[protocol] < PROTOCOLS["TLSv1.3"] and DEFAULT_TLS12_CIPHERS) -- non-TLSv1.3
    or DEFAULT_CIPHERS) -- combined/compatible handshake
  do
    if type(cipher) == "string" then
      if cipher:match("^TLS_ECCPWD_") then
        -- RFC 8492 has specific requirements
        eccpwd = true
      elseif protocol == "TLSv1.3" and cipher:match("_SM3$") then
        -- RFC 8998 has specific requirements
        shangmi = true
      end
      cipher = CIPHERS[cipher] or SCSVS[cipher]
    end
    if type(cipher) == "number" and cipher >= 0 and cipher <= 0xffff then
      insert(ciphers, pack(">I2", cipher))
    else
      stdnse.debug1("Unknown cipher in client_hello: %s", cipher)
    end
  end
  insert(b, pack(">s2", concat(ciphers)))

  -- Compression methods.
  compressors = {}
  if t["compressors"] ~= nil then
    -- Add specified compressors.
    for _, compressor in pairs(t["compressors"]) do
      if compressor ~= "NULL" then
        insert(compressors, pack("B", COMPRESSORS[compressor]))
      end
    end
  end
  -- Always include NULL as last choice
  insert(compressors, pack("B", COMPRESSORS["NULL"]))
  insert(b, pack("s1", concat(compressors)))

  -- TLS extensions
  local proto_ver = PROTOCOLS[protocol]
  if proto_ver and protocol ~= "SSLv3" then
    local extensions = {}
    -- TLSv1.3 requires supported_versions and key_share extensions
    -- OpenSSL also appears to want supported_groups in some cases?
    local need_supported_versions = (proto_ver >= PROTOCOLS["TLSv1.3"])
    local need_key_share = need_supported_versions
    local need_elliptic_curves = need_supported_versions
    -- Do we need to add the signature_algorithms extension?
    local need_sigalg = (proto_ver >= PROTOCOLS["TLSv1.2"])
    -- Add specified extensions.
    if t.extensions then
      for extension, data in pairs(t["extensions"]) do
        if type(extension) == "number" then
          insert(extensions, pack(">I2", extension))
        else
          if extension == "signature_algorithms" or extension == "signature_algorithms_13" then
            need_sigalg = false
            if shangmi then
              local sm2sig_sm3 = pack(">I2", SignatureSchemes.sm2sig_sm3)
              if not data:match("^..(..)*" .. sm2sig_sm3) then
                data = pack(">s2", data:sub(3) .. sm2sig_sm3)
              end
            end
          elseif extension == "supported_versions" then
            need_supported_versions = false
          elseif extension == "key_share" then
            need_key_share = false
          elseif extension == "elliptic_curves" then
            need_elliptic_curves = false
            if shangmi then
              -- For now, RFC 8998 is the only one that enforces particular curves
              local curveSM2 = pack(">I2", ELLIPTIC_CURVES.curveSM2)
              if not data:match("^..(..)*" .. curveSM2) then
                data = pack(">s2", data:sub(3) .. curveSM2)
              end
            end
          end
          insert(extensions, pack(">I2", EXTENSIONS[extension]))
        end
        insert(extensions, pack(">s2", data))
      end
    end
    if need_supported_versions then
      insert(extensions, pack(">I2", EXTENSIONS["supported_versions"]))
      -- We'd prefer TLS 1.2 or 1.1, since we've tested our scripts on those.
      insert(extensions, pack(">s2", EXTENSION_HELPERS["supported_versions"]({"TLSv1.2", "TLSv1.1", "TLSv1.3", "SSLv3"})))
    end
    if need_sigalg then
      insert(extensions, pack(">I2", EXTENSIONS["signature_algorithms"]))
      local data = proto_ver >= PROTOCOLS["TLSv1.3"] and DEFAULT_SIGSCHEMES or DEFAULT_SIGALGS
      if shangmi then
        data = pack(">s2", data:sub(3) .. pack(">I2", SignatureSchemes.sm2sig_sm3))
      end
      insert(extensions, pack(">s2", data))
    end
    if need_key_share then
      -- RFC 8446: Clients MAY send an empty client_shares vector in order to request
      -- group selection from the server, at the cost of an additional round trip
      insert(extensions, pack(">I2", EXTENSIONS["key_share"]))
      insert(extensions, pack(">s2", "\0\0"))
    end
    if need_elliptic_curves then
      local curves = {table.unpack(DEFAULT_ELLIPTIC_CURVES)}
      if shangmi then
        curves[#curves+1] = "curveSM2"
      end
      insert(extensions, pack(">I2", EXTENSIONS["elliptic_curves"]))
      insert(extensions, pack(">s2", EXTENSION_HELPERS["elliptic_curves"](curves)))
    end
    -- Extensions are optional
    if #extensions ~= 0 then
      insert(b, pack(">s2", concat(extensions)))
    end
  end

  ------------
  -- Header --
  ------------

  b = concat(b)

  h = {}

  -- Set type to ClientHello.
  insert(h, pack("B", TLS_HANDSHAKETYPE_REGISTRY["client_hello"]))

  -- Set the length of the body.
  insert(h, pack(">s3", b))

  -- Record layer version should be SSLv3 (lowest compatible record version)
  -- But some implementations (OpenSSL) will not finish a handshake that could
  -- be downgraded by a MITM to SSLv3. So we use TLSv1.0 unless the caller
  -- explicitly tries to set SSLv3.0 somewhere (t.record_protocol or
  -- t.protocol)
  if not record_proto then
    record_proto = (t.protocol == "SSLv3") and "SSLv3" or "TLSv1.0"
  elseif record_proto == "TLSv1.3" then
    -- RFC 8446: "MUST be set to 0x0303 for all records generated by a TLS 1.3
    -- implementation other than an initial ClientHello (i.e., one not generated
    -- after a HelloRetryRequest), where it MAY also be 0x0301 for compatibility
    -- purposes.
    record_proto = "TLSv1.2"
  end
  return record_write("handshake", record_proto, concat(h))
end

local function read_atleast(s, n)
  local buf = {}
  local count = 0
  while count < n do
    local status, data = s:receive_bytes(n - count)
    if not status then
      return status, data, concat(buf)
    end
    buf[#buf+1] = data
    count = count + #data
  end
  return true, concat(buf)
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
  local ctype, pversion, len = unpack(">BI2I2", buffer, i)
  if not TLS_PROTOCOL_VERSIONS[pversion] or not TLS_CONTENTTYPES[ctype] then
    return false, buffer, "Unknown TLS protocol version or content type"
  end
  if count < TLS_RECORD_HEADER_LENGTH + len then
    status, resp = read_atleast(sock, TLS_RECORD_HEADER_LENGTH + len - count)
    if not status then
      return false, buffer, resp
    end
    buffer = buffer .. resp
  end
  return true, buffer
end

-- Get a server_name for use with the TLS Server Name Indication extension.
--
-- This returns the value of the script argument "tls.servername" if given.  Otherwise, it
-- returns the target name of the host parameter.
--
-- @param host Host table as received by the action function
-- @return String of the selected host name
function servername(host)
    local script_arg = stdnse.get_script_args("tls.servername")
    if script_arg then
        return script_arg
    elseif type(host) == "table" then
        return host.targetname
    end
end

local unittest = require "unittest"
if not unittest.testing() then
  return _ENV
end
test_suite = unittest.TestSuite:new()
for name, code in pairs(CIPHERS) do
  test_suite:add_test(unittest.not_nil(cipher_info(name).kex), name .. ".kex")
end
return _ENV;
