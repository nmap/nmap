
/***************************************************************************
 * nse_ssl_cert.cc -- NSE userdatum representing an SSL certificate.       *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *
 * The Nmap Security Scanner is (C) 1996-2023 Nmap Software LLC ("The Nmap
 * Project"). Nmap is also a registered trademark of the Nmap Project.
 *
 * This program is distributed under the terms of the Nmap Public Source
 * License (NPSL). The exact license text applying to a particular Nmap
 * release or source code control revision is contained in the LICENSE
 * file distributed with that version of Nmap or source code control
 * revision. More Nmap copyright/legal information is available from
 * https://nmap.org/book/man-legal.html, and further information on the
 * NPSL license itself can be found at https://nmap.org/npsl/ . This
 * header summarizes some key points from the Nmap license, but is no
 * substitute for the actual license text.
 *
 * Nmap is generally free for end users to download and use themselves,
 * including commercial use. It is available from https://nmap.org.
 *
 * The Nmap license generally prohibits companies from using and
 * redistributing Nmap in commercial products, but we sell a special Nmap
 * OEM Edition with a more permissive license and special features for
 * this purpose. See https://nmap.org/oem/
 *
 * If you have received a written Nmap license agreement or contract
 * stating terms other than these (such as an Nmap OEM license), you may
 * choose to use and redistribute Nmap under those terms instead.
 *
 * The official Nmap Windows builds include the Npcap software
 * (https://npcap.com) for packet capture and transmission. It is under
 * separate license terms which forbid redistribution without special
 * permission. So the official Nmap Windows builds may not be redistributed
 * without special permission (such as an Nmap OEM license).
 *
 * Source is provided to this software because we believe users have a
 * right to know exactly what a program is going to do before they run it.
 * This also allows you to audit the software for security holes.
 *
 * Source code also allows you to port Nmap to new platforms, fix bugs, and add
 * new features. You are highly encouraged to submit your changes as a Github PR
 * or by email to the dev@nmap.org mailing list for possible incorporation into
 * the main distribution. Unless you specify otherwise, it is understood that
 * you are offering us very broad rights to use your submissions as described in
 * the Nmap Public Source License Contributor Agreement. This is important
 * because we fund the project by selling licenses with various terms, and also
 * because the inability to relicense code has caused devastating problems for
 * other Free Software projects (such as KDE and NASM).
 *
 * The free version of Nmap is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranties,
 * indemnification and commercial support are all available through the
 * Npcap OEM program--see https://nmap.org/oem/
 *
 ***************************************************************************/

/* $Id:$ */

#include "nbase.h"

#ifdef HAVE_CONFIG_H
#include "nmap_config.h"
#endif

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined LIBRESSL_VERSION_NUMBER
/* Technically some of these things were added in 0x10100006
 * but that was pre-release. */
#define HAVE_OPAQUE_STRUCTS 1
#else
#define X509_get0_notBefore X509_get_notBefore
#define X509_get0_notAfter X509_get_notAfter
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
/* Deprecated in OpenSSL 3.0 */
#define SSL_get_peer_certificate SSL_get1_peer_certificate
#else
#include <openssl/rsa.h>
#endif


/* struct tm */
#include <time.h>

#include "nse_lua.h"

#include "nse_nsock.h"
#include "nse_openssl.h"

struct cert_userdata {
  X509 *cert;
  int attributes_table;
};

SSL *nse_nsock_get_ssl(lua_State *L);

/* This is a reference to a table that will be used as the metatable for
   certificate attribute tables. It has an __index entry that points to the
   global table of certificate functions like digest. */
static int ssl_cert_methods_index_ref = LUA_NOREF;

/* Calculate the digest of the certificate using the given algorithm. */
static int ssl_cert_digest(lua_State *L)
{
  struct cert_userdata *udata;
  const char *algorithm;
  unsigned char buf[256];
  unsigned int n;
  const EVP_MD *md;

  udata = (struct cert_userdata *) luaL_checkudata(L, 1, "SSL_CERT");
  algorithm = luaL_checkstring(L, 2);

  md = EVP_get_digestbyname(algorithm);
  if (md == NULL)
      return 0;

  n = sizeof(buf);
  if (X509_digest(udata->cert, md, buf, &n) != 1)
      return 0;
  lua_pushlstring(L, (char *) buf, n);

  return 1;
}

/* These are the contents of the table that is pointed to by the table that has
   ssl_cert_methods_index_ref as a reference. */
static struct luaL_Reg ssl_cert_methods[] = {
  { "digest", ssl_cert_digest },
  { NULL, NULL },
};

/* This is a helper function for x509_name_to_table. It takes the ASN1_OBJECT
   passed as an argument, turns it into a table key, and pushes it on the stack.
   The key is a string (like "commonName") if the object has an NID known by
   OBJ_obj2nid; otherwise it is an array containing the OID components as
   strings: { "2", "5", "4", "3" }. */
static void obj_to_key(lua_State *L, const ASN1_OBJECT *obj)
{
  int nid;

  nid = OBJ_obj2nid(obj);
  if (nid == NID_undef) {
    size_t size = 1;
    char *buf = (char *) lua_newuserdata(L, size);
    const char *p, *q;
    int i, n;

    while ((n = OBJ_obj2txt(buf, size, obj, 1)) < 0 || (unsigned) n >= size) {
      size = size * 2;
      buf = (char *) lua_newuserdata(L, size);
      memcpy(lua_touserdata(L, -1), lua_touserdata(L, -2), lua_rawlen(L, -2));
      lua_replace(L, -2);
    }

    lua_newtable(L);

    i = 1;
    p = buf;
    q = p;
    while (*q != '\0') {
      q = strchr(p, '.');
      if (q == NULL)
        q = strchr(p, '\0');
      lua_pushlstring(L, p, q - p);
      lua_rawseti(L, -2, i++);
      p = q + 1;
    }
    lua_replace(L, -2); /* replace userdata with table */
  } else {
    lua_pushstring(L, OBJ_nid2ln(nid));
  }
}

/* This is a helper function for l_get_ssl_certificate. It builds a table from
   the given X509_NAME, using keys returned from obj_to_key as keys. The result
   is pushed on the stack. */
static void x509_name_to_table(lua_State *L, X509_NAME *name)
{
  int i;

  lua_createtable(L, 0, X509_NAME_entry_count(name));

  for (i = 0; i < X509_NAME_entry_count(name); i++) {
    X509_NAME_ENTRY *entry;
    const ASN1_OBJECT *obj;
    const ASN1_STRING *value;

    entry = X509_NAME_get_entry(name, i);
    obj = X509_NAME_ENTRY_get_object(entry);
    value = X509_NAME_ENTRY_get_data(entry);

    obj_to_key(L, obj);
    lua_pushlstring(L, (const char *) value->data, value->length);

    lua_settable(L, -3);
  }
}

static bool x509_extensions_to_table(lua_State *L, const STACK_OF(X509_EXTENSION) *exts)
{
  if (sk_X509_EXTENSION_num(exts) <= 0)
    return false;

  lua_createtable(L, sk_X509_EXTENSION_num(exts), 0);

  for (int i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
    ASN1_OBJECT *obj;
    X509_EXTENSION *ext;
    char *value = NULL;
    BIO *out;

    ext = sk_X509_EXTENSION_value(exts, i);
    obj = X509_EXTENSION_get_object(ext);

#define NSE_NUM_X509_EXTENSION_FIELDS 3
    lua_createtable(L, 0, NSE_NUM_X509_EXTENSION_FIELDS);
    char objname[256];
    long len = 0;
    len = OBJ_obj2txt(objname, 256, obj, 0);
    lua_pushlstring(L, objname, MIN(len, 256));
    lua_setfield(L, -2, "name");


    if (X509_EXTENSION_get_critical(ext)) {
      lua_pushboolean(L, true);
      lua_setfield(L, -2, "critical");
    }

    out = BIO_new(BIO_s_mem());
    if (!X509V3_EXT_print(out, ext, 0, 0)) {
      lua_pushboolean(L, true);
      lua_setfield(L, -2, "error");
    }
    else {
      len = BIO_get_mem_data(out, &value);
      lua_pushlstring(L, value, len);
      lua_setfield(L, -2, "value");
    }
    BIO_free_all(out);

    lua_rawseti(L, -2, i+1);
  }

  return true;

}

/* Parse as a decimal integer the len characters starting at s. This function
   can only process positive numbers; if the return value is negative then a
   parsing error occurred. */
static int parse_int(const unsigned char *s, size_t len)
{
  char buf[32];
  char *tail;
  long v;

  if (len == 0)
    return -1;
  if (!isdigit((int) (unsigned char) s[0]))
    return -1;
  if (len > sizeof(buf) - 1)
    return -1;
  memcpy(buf, s, len);
  buf[len] = '\0';

  errno = 0;
  v = strtol(buf, &tail, 10);
  if (errno != 0 || *tail != '\0')
    return -1;
  if ((int) v != v || v < 0)
    return -1;

  return (int) v;
}

/* This is a helper function for asn1_time_to_obj. It parses a textual ASN1_TIME
   value and stores the time in the given struct tm. It returns 0 on success and
   -1 on a parse error. */
static int time_to_tm(const ASN1_TIME *t, struct tm *result)
{
  const unsigned char *p;

  p = t->data;
  if (t->length == 13 && t->data[t->length - 1] == 'Z') {
    /* yymmddhhmmssZ */
    int year;

    year = parse_int(t->data, 2);
    if (year < 0)
      return -1;
    /* "In coming up with the worlds least efficient machine-readable time
       encoding format, the ISO nevertheless decided to forgo the encoding of
       centuries, a problem which has been kludged around by redefining the time
       as UTCTime if the date is 2049 or earlier, and GeneralizedTime if the date
       is 2050 or later."
       http://www.cs.auckland.ac.nz/~pgut001/pubs/x509guide.txt */
    if (year < 50)
      result->tm_year = 2000 + year;
    else
      result->tm_year = 1900 + year;
    p = t->data + 2;
  } else if (t->length == 15 && t->data[t->length - 1] == 'Z') {
    /* yyyymmddhhmmssZ */
    result->tm_year = parse_int(t->data, 4);
    if (result->tm_year < 0)
      return -1;
    p = t->data + 4;
  } else {
    return -1;
  }

  result->tm_mon = parse_int(p, 2);
  /* struct tm uses zero-indexed months. */
  if (result->tm_mon == 0)
    return -1;
  result->tm_mon--;
  result->tm_mday = parse_int(p + 2, 2);
  result->tm_hour = parse_int(p + 4, 2);
  result->tm_min = parse_int(p + 6, 2);
  result->tm_sec = parse_int(p + 8, 2);

  if (result->tm_mon < 0 || result->tm_mday < 0 || result->tm_hour < 0
      || result->tm_min < 0 || result->tm_sec < 0) {
    return -1;
  }

  return 0;
}

/* This is a helper function for asn1_time_to_obj. It converts a struct tm into
   a date table as returned by the Lua date os.date("!*t"), with the exception
   that the wday and yday fields are not present. */
static void tm_to_table(lua_State *L, const struct tm *tm)
{
#define NSE_NUM_TM_FIELDS 6
  lua_createtable(L, 0, NSE_NUM_TM_FIELDS);

  lua_pushinteger(L, tm->tm_year);
  lua_setfield(L, -2, "year");
  /* Lua uses one-indexed months. */
  lua_pushinteger(L, tm->tm_mon + 1);
  lua_setfield(L, -2, "month");
  lua_pushinteger(L, tm->tm_mday);
  lua_setfield(L, -2, "day");
  lua_pushinteger(L, tm->tm_hour);
  lua_setfield(L, -2, "hour");
  lua_pushinteger(L, tm->tm_min);
  lua_setfield(L, -2, "min");
  lua_pushinteger(L, tm->tm_sec);
  lua_setfield(L, -2, "sec");
  /* Omit tm_wday and tm_yday. */
}

/* This is a helper function for x509_validity_to_table. It takes the given
   ASN1_TIME and converts it to a value on the stack, which is one of
     nil, if the time is NULL;
     a date table, if the date can be parsed; and
     a string of the raw bytes, if the date cannot be parsed. */
static void asn1_time_to_obj(lua_State *L, const ASN1_TIME *s)
{
  struct tm tm;

  if (s == NULL) {
      lua_pushnil(L);
  } else if (time_to_tm(s, &tm) == 0) {
      tm_to_table(L, &tm);
  } else {
      lua_pushlstring(L, (const char *) s->data, s->length);
  }
}

/* This is a helper function for x509_validity_to_table. It builds a table with
   the two members "notBefore" and "notAfter", whose values are what is returned
   from asn1_time_to_obj. */
static void x509_validity_to_table(lua_State *L, X509 *cert)
{
#define NSE_NUM_VALIDITY_FIELDS 2
  lua_createtable(L, 0, NSE_NUM_VALIDITY_FIELDS);

  asn1_time_to_obj(L, X509_get0_notBefore(cert));
  lua_setfield(L, -2, "notBefore");
  asn1_time_to_obj(L, X509_get0_notAfter(cert));
  lua_setfield(L, -2, "notAfter");
}

/* This is a helper function for l_get_ssl_certificate. It converts the
   certificate into a PEM-encoded string on the stack. */
static void cert_pem_to_string(lua_State *L, X509 *cert)
{
  BIO *bio;
  char *buf;
  long size;

  bio = BIO_new(BIO_s_mem());
  assert(bio != NULL);

  assert(PEM_write_bio_X509(bio, cert));

  size = BIO_get_mem_data(bio, &buf);
  lua_pushlstring(L, buf, size);

  BIO_vfree(bio);
}

/* This is a helper function for l_get_ssl_certificate. It converts the
   public-key type to a string. */
static const char *pkey_type_to_string(int type)
{
  switch (type) {
  case EVP_PKEY_RSA:
    return "rsa";
  case EVP_PKEY_DSA:
    return "dsa";
  case EVP_PKEY_DH:
    return "dh";
#ifdef EVP_PKEY_EC
  case EVP_PKEY_EC:
    return "ec";
#endif
  default:
    return "unknown";
  }
}

int lua_push_ecdhparams(lua_State *L, EVP_PKEY *pubkey) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  char tmp[64] = {0};
  size_t len = 0;
  /* This structure (ecdhparams.curve_params) comes from tls.lua */
  lua_createtable(L, 0, 1); /* ecdhparams */
  lua_createtable(L, 0, 2); /* curve_params */
  if (EVP_PKEY_get_utf8_string_param(pubkey, OSSL_PKEY_PARAM_GROUP_NAME,
        tmp, sizeof(tmp), &len)) {
    lua_pushlstring(L, tmp, len);
    lua_setfield(L, -2, "curve");
    lua_pushliteral(L, "namedcurve");
    lua_setfield(L, -2, "ec_curve_type");
  }
  else if (EVP_PKEY_get_utf8_string_param(pubkey, OSSL_PKEY_PARAM_EC_FIELD_TYPE,
        tmp, sizeof(tmp), &len)) {
    /* According to RFC 5480 section 2.1.1, explicit curves must not be used with
       X.509. This may change in the future, but for now it doesn't seem worth it
       to add in code to extract the extra parameters. */
    if (0 == strncmp(tmp, "prime-field", len)) {
      lua_pushliteral(L, "explicit_prime");
    }
    else if (0 == strncmp(tmp, "characteristic-two-field", len)) {
      lua_pushliteral(L, "explicit_char2");
    }
    else {
      /* Something weird happened. */
      lua_pushlstring(L, tmp, len);
    }
    lua_setfield(L, -2, "ec_curve_type");
  }
  lua_setfield(L, -2, "curve_params");
  return 1;
#elif !defined(OPENSSL_NO_EC)
  EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pubkey);
  const EC_GROUP *group = EC_KEY_get0_group(ec_key);
  int nid;
  /* This structure (ecdhparams.curve_params) comes from tls.lua */
  lua_createtable(L, 0, 1); /* ecdhparams */
  lua_createtable(L, 0, 2); /* curve_params */
  if ((nid = EC_GROUP_get_curve_name(group)) != 0) {
    lua_pushstring(L, OBJ_nid2sn(nid));
    lua_setfield(L, -2, "curve");
    lua_pushstring(L, "namedcurve");
    lua_setfield(L, -2, "ec_curve_type");
  }
  else {
    /* According to RFC 5480 section 2.1.1, explicit curves must not be used with
       X.509. This may change in the future, but for now it doesn't seem worth it
       to add in code to extract the extra parameters. */
    nid = EC_METHOD_get_field_type(EC_GROUP_method_of(group));
    if (nid == NID_X9_62_prime_field) {
      lua_pushstring(L, "explicit_prime");
    }
    else if (nid == NID_X9_62_characteristic_two_field) {
      lua_pushstring(L, "explicit_char2");
    }
    else {
      /* Something weird happened. */
      lua_pushstring(L, "UNKNOWN");
    }
    lua_setfield(L, -2, "ec_curve_type");
  }
  lua_setfield(L, -2, "curve_params");
  EC_KEY_free(ec_key);
  return 1;
#else
  return 0;
#endif
}

static int parse_ssl_cert(lua_State *L, X509 *cert);

int l_parse_ssl_certificate(lua_State *L)
{
  X509 *cert;
  size_t l;
  const char *der;

  der = luaL_checklstring(L, 1, &l);
  if (der == NULL) {
    lua_pushnil(L);
    return 1;
  }

  cert = d2i_X509(NULL, (const unsigned char **) &der, l);
  if (cert == NULL) {
    lua_pushnil(L);
    return 1;
  }
  return parse_ssl_cert(L, cert);
}

int l_get_ssl_certificate(lua_State *L)
{
  SSL *ssl;
  X509 *cert;

  ssl = nse_nsock_get_ssl(L);
  cert = SSL_get_peer_certificate(ssl);
  if (cert == NULL) {
    lua_pushnil(L);
    return 1;
  }
  return parse_ssl_cert(L, cert);
}

static int parse_ssl_cert(lua_State *L, X509 *cert)
{
  struct cert_userdata *udata;
  X509_NAME *subject, *issuer;
  EVP_PKEY *pubkey;
  int pkey_type;

  udata = (struct cert_userdata *) lua_newuserdata(L, sizeof(*udata));
  udata->cert = cert;

#define NSE_NUM_CERT_FIELDS 7
  lua_createtable(L, 0, NSE_NUM_CERT_FIELDS);

  subject = X509_get_subject_name(cert);
  if (subject != NULL) {
    x509_name_to_table(L, subject);
    lua_setfield(L, -2, "subject");
  }

#if HAVE_OPAQUE_STRUCTS
  const char *sig_algo = OBJ_nid2ln(X509_get_signature_nid(cert));
#else
  const char *sig_algo = OBJ_nid2ln(OBJ_obj2nid(cert->sig_alg->algorithm));
#endif
  lua_pushstring(L, sig_algo);
  lua_setfield(L, -2, "sig_algorithm");

  issuer = X509_get_issuer_name(cert);
  if (issuer != NULL) {
    x509_name_to_table(L, issuer);
    lua_setfield(L, -2, "issuer");
  }

  x509_validity_to_table(L, cert);
  lua_setfield(L, -2, "validity");

  cert_pem_to_string(L, cert);
  lua_setfield(L, -2, "pem");

#if HAVE_OPAQUE_STRUCTS
  if (x509_extensions_to_table(L, X509_get0_extensions(cert))) {
#else
  if (x509_extensions_to_table(L, cert->cert_info->extensions)) {
#endif
    lua_setfield(L, -2, "extensions");
  }

  pubkey = X509_get_pubkey(cert);
  if (pubkey == NULL) {
    lua_pushnil(L);
    lua_pushfstring(L, "Error parsing cert: %s", ERR_error_string(ERR_get_error(), NULL));
    X509_free(cert);
    return 2;
  }
#define NSE_NUM_PKEY_FIELDS 4
  lua_createtable(L, 0, NSE_NUM_PKEY_FIELDS);
#if HAVE_OPAQUE_STRUCTS
  pkey_type = EVP_PKEY_base_id(pubkey);
#else
  pkey_type = EVP_PKEY_type(pubkey->type);
#endif
#ifdef EVP_PKEY_EC
  if (pkey_type == EVP_PKEY_EC) {
    lua_push_ecdhparams(L, pubkey);
    lua_setfield(L, -2, "ecdhparams");
  }
  else
#endif
  if (pkey_type == EVP_PKEY_RSA) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    BIGNUM *n = NULL, *e = NULL;
    bool should_free = true;
    EVP_PKEY_get_bn_param(pubkey, OSSL_PKEY_PARAM_RSA_E, &e);
    EVP_PKEY_get_bn_param(pubkey, OSSL_PKEY_PARAM_RSA_N, &n);
#else
    bool should_free = false;
    RSA *rsa = EVP_PKEY_get1_RSA(pubkey);
    if (!rsa) {
      // This should be impossible for this key type
      return luaL_error(L, "EVP_PKEY_RSA missing RSA key!");
    }
# if HAVE_OPAQUE_STRUCTS
    const BIGNUM *n = NULL, *e = NULL;
    RSA_get0_key(rsa, &n, &e, NULL);
# endif
#endif
#if HAVE_OPAQUE_STRUCTS
# define PASS_RSA_PARAM(_P) ((BIGNUM *)(_P))
#else /* not HAVE_OPAQUE_STRUCTS */
# define PASS_RSA_PARAM(_P) (rsa->_P)
#endif
    /* exponent */
    nse_pushbn(L, PASS_RSA_PARAM(e), should_free);
    lua_setfield(L, -2, "exponent");
    /* modulus */
    nse_pushbn(L, PASS_RSA_PARAM(n), should_free);
    lua_setfield(L, -2, "modulus");
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    RSA_free(rsa);
#endif
  }
  lua_pushstring(L, pkey_type_to_string(pkey_type));
  lua_setfield(L, -2, "type");
  lua_pushinteger(L, EVP_PKEY_bits(pubkey));
  lua_setfield(L, -2, "bits");
  lua_setfield(L, -2, "pubkey");
  EVP_PKEY_free(pubkey);

  /* At this point the certificate-specific table of attributes is at the top of
     the stack. We give it a metatable with an __index entry that points into
     the global shared table of certificate functions. */
  lua_rawgeti(L, LUA_REGISTRYINDEX, ssl_cert_methods_index_ref);
  lua_setmetatable(L, -2);

  udata->attributes_table = luaL_ref(L, LUA_REGISTRYINDEX);

  luaL_getmetatable(L, "SSL_CERT");
  lua_setmetatable(L, -2);

  return 1;
}

static int l_ssl_cert_index(lua_State *L)
{
  struct cert_userdata *udata;

  udata = (struct cert_userdata *) luaL_checkudata(L, 1, "SSL_CERT");
  lua_rawgeti(L, LUA_REGISTRYINDEX, udata->attributes_table);
  /* The key. */
  lua_pushvalue(L, 2);
  /* Look it up in the table of attributes. */
  lua_gettable(L, -2);

  return 1;
}

static int l_ssl_cert_gc(lua_State *L)
{
  struct cert_userdata *udata;

  udata = (struct cert_userdata *) luaL_checkudata(L, 1, "SSL_CERT");
  X509_free(udata->cert);
  luaL_unref(L, LUA_REGISTRYINDEX, udata->attributes_table);

  return 0;
}

void nse_nsock_init_ssl_cert(lua_State *L)
{
  luaL_newmetatable(L, "SSL_CERT");
  lua_pushcclosure(L, l_ssl_cert_index, 0);
  lua_setfield(L, -2, "__index");
  lua_pushcclosure(L, l_ssl_cert_gc, 0);
  lua_setfield(L, -2, "__gc");

  /* Create a table with an __index entry that will be used as a metatable for
     per-certificate attribute tables. This gives the tables access to the
     global shared table of certificate functions. */
  lua_newtable(L);
  lua_newtable(L);
  luaL_setfuncs(L, ssl_cert_methods, 0);
  lua_setfield(L, -2, "__index");
  ssl_cert_methods_index_ref = luaL_ref(L, LUA_REGISTRYINDEX);
}
