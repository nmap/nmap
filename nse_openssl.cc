/* OpenSSL library for lua
 * adapted from lmd5 library (http://www.tecgraf.puc-rio.br/~lhf/ftp/lua/)
 * Original code written by Luiz Henrique de Figueiredo <lhf@tecgraf.puc-rio.br>
 * Adapted for Nmap by Thomas Buchanan <tbuchanan@thecompassgrp.net>
 * bignum and rand_bytes functions added by Sven Klemm <sven@c3d2.de>
 * Primality tests added by Jacob Gajek <jgajek@gmail.com>
 */

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined LIBRESSL_VERSION_NUMBER
#define HAVE_OPAQUE_STRUCTS 1
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
# include <openssl/provider.h>
#endif
#else
#define EVP_MD_CTX_new EVP_MD_CTX_create
#define EVP_MD_CTX_free EVP_MD_CTX_destroy
#define EVP_CIPHER_CTX_free EVP_CIPHER_CTX_cleanup
#endif

#include "nse_lua.h"
/* Needed for get_random_bytes */
#include <nbase.h>
#include "NmapOps.h"
#include "output.h"
extern NmapOps o;

#include "nse_openssl.h"

#define NSE_SSL_LUA_ERR(_L) \
    luaL_error(_L, "OpenSSL error: %s", ERR_error_string(ERR_get_error(), NULL))

typedef struct bignum_data {
  BIGNUM * bn;
  bool should_free;
} bignum_data_t;

int nse_pushbn( lua_State *L, BIGNUM *num, bool should_free)
{
  bignum_data_t * data = (bignum_data_t *) lua_newuserdata( L, sizeof(bignum_data_t));
  luaL_getmetatable( L, "BIGNUM" );
  lua_setmetatable( L, -2 );
  data->bn = num;
  /* Currently this is true for all uses in this file. */
  data->should_free = should_free;
  return 1;
}

static int l_bignum_bin2bn( lua_State *L ) /** bignum_bin2bn( string s ) */
{
  size_t len;
  const unsigned char * s = (unsigned char *) luaL_checklstring( L, 1, &len );
  BIGNUM * num = BN_new();
  BN_bin2bn( s, len, num );
  return nse_pushbn(L, num, true);
}

static int l_bignum_dec2bn( lua_State *L ) /** bignum_dec2bn( string s ) */
{
  const char * s = luaL_checkstring( L, 1 );
  BIGNUM * num = BN_new();
  BN_dec2bn( &num, s );
  return nse_pushbn(L, num, true);
}

static int l_bignum_hex2bn( lua_State *L ) /** bignum_hex2bn( string s ) */
{
  const char * s = luaL_checkstring( L, 1 );
  BIGNUM * num = BN_new();
  BN_hex2bn( &num, s );
  return nse_pushbn(L, num, true);
}

static int l_bignum_rand( lua_State *L ) /** bignum_rand( number bits ) */
{
  size_t bits = luaL_checkinteger( L, 1 );
  BIGNUM * num = BN_new();
  BN_rand( num, bits, -1, 0 );
  return nse_pushbn(L, num, true);
}

static int l_bignum_mod_exp( lua_State *L ) /** bignum_mod_exp( BIGNUM a, BIGNUM p, BIGNUM m ) */
{
  bignum_data_t * a = (bignum_data_t *) luaL_checkudata(L, 1, "BIGNUM");
  bignum_data_t * p = (bignum_data_t *) luaL_checkudata(L, 2, "BIGNUM");
  bignum_data_t * m = (bignum_data_t *) luaL_checkudata(L, 3, "BIGNUM");
  BIGNUM * result = BN_new();
  BN_CTX * ctx = BN_CTX_new();
  BN_mod_exp( result, a->bn, p->bn, m->bn, ctx );
  BN_CTX_free( ctx );
  return nse_pushbn(L, result, true);
}

static int l_bignum_div( lua_State *L ) /* bignum_div( BIGNUM a, BIGNUM d ) */
{
  bignum_data_t * a = (bignum_data_t *) luaL_checkudata(L, 1, "BIGNUM");
  bignum_data_t * d = (bignum_data_t *) luaL_checkudata(L, 2, "BIGNUM");
  BIGNUM * dv = BN_new();
  BIGNUM * rem = BN_new();
  BN_CTX * ctx = BN_CTX_new();
  BN_div(dv, rem, a->bn, d->bn, ctx);
  BN_CTX_free( ctx );
  nse_pushbn(L, dv, true);
  nse_pushbn(L, rem, true);
  return 2;
}

static int l_bignum_add( lua_State *L ) /** bignum_add( BIGNUM a, BIGNUM b ) */
{
  bignum_data_t * a = (bignum_data_t *) luaL_checkudata(L, 1, "BIGNUM");
  bignum_data_t * b = (bignum_data_t *) luaL_checkudata(L, 2, "BIGNUM");
  BIGNUM * result = BN_new();
  BN_add( result, a->bn, b->bn );
  return nse_pushbn(L, result, true);
}

static int l_bignum_num_bits( lua_State *L ) /** bignum_num_bits( BIGNUM bn ) */
{
  bignum_data_t * userdata = (bignum_data_t *) luaL_checkudata(L, 1, "BIGNUM");
  lua_pushinteger( L, BN_num_bits( userdata->bn) );
  return 1;
}

static int l_bignum_num_bytes( lua_State *L ) /** bignum_num_bytes( BIGNUM bn ) */
{
  bignum_data_t * userdata = (bignum_data_t *) luaL_checkudata(L, 1, "BIGNUM");
  lua_pushinteger( L, BN_num_bytes( userdata->bn) );
  return 1;
}

static int l_bignum_set_bit( lua_State *L ) /** bignum_set_bit( BIGNUM bn, number position ) */
{
  bignum_data_t * userdata = (bignum_data_t *) luaL_checkudata(L, 1, "BIGNUM");
  int position = luaL_checkinteger( L, 2 );
  BN_set_bit( userdata->bn, position );
  return 0;
}

static int l_bignum_clear_bit( lua_State *L ) /** bignum_clear_bit( BIGNUM bn, number position ) */
{
  bignum_data_t * userdata = (bignum_data_t *) luaL_checkudata(L, 1, "BIGNUM");
  int position = luaL_checkinteger( L, 2 );
  BN_clear_bit( userdata->bn, position );
  return 0;
}

static int l_bignum_is_bit_set( lua_State *L ) /** bignum_set_bit( BIGNUM bn, number position ) */
{
  bignum_data_t * userdata = (bignum_data_t *) luaL_checkudata(L, 1, "BIGNUM");
  int position = luaL_checkinteger( L, 2 );
  lua_pushboolean( L, BN_is_bit_set( userdata->bn, position ) );
  return 1;
}

static int l_bignum_is_prime( lua_State *L ) /** bignum_is_prime( BIGNUM p ) */
{
  bignum_data_t * p = (bignum_data_t *) luaL_checkudata( L, 1, "BIGNUM" );
  BN_CTX * ctx = BN_CTX_new();
  int is_prime =
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    BN_is_prime_ex( p->bn, BN_prime_checks, ctx, NULL );
#else
    BN_check_prime( p->bn, ctx, NULL );
#endif
  BN_CTX_free( ctx );
  lua_pushboolean( L, is_prime );
  return 1;
}

static int l_bignum_is_safe_prime( lua_State *L ) /** bignum_is_safe_prime( BIGNUM p ) */
{
  bignum_data_t * p = (bignum_data_t *) luaL_checkudata( L, 1, "BIGNUM" );
  BN_CTX * ctx = BN_CTX_new();
  int is_prime =
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    BN_is_prime_ex( p->bn, BN_prime_checks, ctx, NULL );
#else
    BN_check_prime( p->bn, ctx, NULL );
#endif
  int is_safe = 0;
  if (is_prime) {
    BIGNUM * n = BN_dup( p->bn );
    BN_sub_word( n, (BN_ULONG)1 );
    BN_div_word( n, (BN_ULONG)2 );
    is_safe =
#if OPENSSL_VERSION_NUMBER < 0x30000000L
      BN_is_prime_ex( n, BN_prime_checks, ctx, NULL );
#else
      BN_check_prime( n, ctx, NULL );
#endif
    BN_clear_free( n );
  }
  BN_CTX_free( ctx );
  lua_pushboolean( L, is_safe );
  lua_pushboolean( L, is_prime );
  return 2;
}

static int l_bignum_bn2bin( lua_State *L ) /** bignum_bn2bin( BIGNUM bn ) */
{
  bignum_data_t * userdata = (bignum_data_t *) luaL_checkudata(L, 1, "BIGNUM");
  unsigned char * result = (unsigned char *) malloc( BN_num_bytes( userdata->bn ) );
  if (!result) return luaL_error( L, "Couldn't allocate memory.");

  int len = BN_bn2bin( userdata->bn, result );
  lua_pushlstring( L, (char *) result, len );
  free( result );
  return 1;
}

static int l_bignum_bn2mpi( lua_State *L ) /** bignum_bn2mpi( BIGNUM bn ) */
{
  bignum_data_t * userdata = (bignum_data_t *) luaL_checkudata(L, 1, "BIGNUM");
  unsigned char * result = (unsigned char *) malloc( BN_bn2mpi( userdata->bn, NULL ) );
  if (!result) return luaL_error( L, "Couldn't allocate memory.");

  int len = BN_bn2mpi( userdata->bn, result );
  lua_pushlstring( L, (char *) result, len );
  free( result );
  return 1;
}

static int l_bignum_bn2dec( lua_State *L ) /** bignum_bn2dec( BIGNUM bn ) */
{
  bignum_data_t * userdata = (bignum_data_t *) luaL_checkudata(L, 1, "BIGNUM");
  char * result = BN_bn2dec( userdata->bn );
  lua_pushstring( L, result );
  OPENSSL_free( result );
  return 1;
}

static int l_bignum_bn2hex( lua_State *L ) /** bignum_bn2hex( BIGNUM bn ) */
{
  bignum_data_t * userdata = (bignum_data_t *) luaL_checkudata(L, 1, "BIGNUM");
  char * result = BN_bn2hex( userdata->bn );
  lua_pushstring( L, result );
  OPENSSL_free( result );
  return 1;
}

static int l_bignum_free( lua_State *L ) /** bignum_free( bignum ) */
{
  bignum_data_t * userdata = (bignum_data_t *) luaL_checkudata(L, 1, "BIGNUM");
  if (userdata->should_free) {
    BN_clear_free( userdata->bn );
  }
  return 0;
}

static int l_rand_bytes( lua_State *L ) /** rand_bytes( number bytes ) */
{
  size_t len = luaL_checkinteger( L, 1 );
  unsigned char * result = (unsigned char *) malloc( len );
  if (!result) return luaL_error( L, "Couldn't allocate memory.");

  if (RAND_bytes( result, len ) != 1) {
    return luaL_error(L, "Failure in RAND_bytes.");
  }
  lua_pushlstring( L, (char *) result, len );
  free( result );
  return 1;
}

static int l_rand_pseudo_bytes( lua_State *L ) /** rand_pseudo_bytes( number bytes ) */
{
  size_t len = luaL_checkinteger( L, 1 );
  unsigned char * result = (unsigned char *) malloc( len );
  if (!result) return luaL_error( L, "Couldn't allocate memory.");

  get_random_bytes( result, len );
  lua_pushlstring( L, (char *) result, len );
  free( result );
  return 1;
}

static int l_digest(lua_State *L)     /** digest(string algorithm, string message) */
{
  size_t msg_len;
  unsigned int digest_len;
  const char *algorithm = luaL_checkstring( L, 1 );
  const unsigned char *msg = (unsigned char *) luaL_checklstring( L, 2, &msg_len );
  unsigned char digest[EVP_MAX_MD_SIZE];
  const EVP_MD * evp_md;
  EVP_MD_CTX *mdctx = NULL;

  evp_md = EVP_get_digestbyname( algorithm );

  if (!evp_md) return luaL_error( L, "Unknown digest algorithm: %s", algorithm );

  mdctx = EVP_MD_CTX_new();
  if (!mdctx) return NSE_SSL_LUA_ERR(L);

  if (!(
      EVP_DigestInit_ex( mdctx, evp_md, NULL ) &&
      EVP_DigestUpdate( mdctx, msg, msg_len ) &&
      EVP_DigestFinal_ex( mdctx, digest, &digest_len ))) {
    EVP_MD_CTX_free( mdctx );
    return NSE_SSL_LUA_ERR(L);
  }
  EVP_MD_CTX_free( mdctx );

  lua_pushlstring( L, (char *) digest, digest_len );
  return 1;
}

/** md4(string s) */
#define NSE_DECLARE_DIGEST(_mdname) \
static int l_##_mdname(lua_State *L) \
{ \
  lua_pushliteral(L, #_mdname); \
  lua_insert(L, 1); \
  return l_digest(L); \
}

NSE_DECLARE_DIGEST(md4)
NSE_DECLARE_DIGEST(md5)
NSE_DECLARE_DIGEST(sha1)
NSE_DECLARE_DIGEST(ripemd160)

static int l_hmac(lua_State *L)     /** hmac(string algorithm, string key, string message) */
{
  size_t key_len, msg_len;
  unsigned int digest_len;
  const char *algorithm = luaL_checkstring( L, 1 );
  const unsigned char *key = (unsigned char *) luaL_checklstring( L, 2, &key_len );
  const unsigned char *msg = (unsigned char *) luaL_checklstring( L, 3, &msg_len );
  unsigned char digest[EVP_MAX_MD_SIZE];
  const EVP_MD * evp_md;
  evp_md = EVP_get_digestbyname( algorithm );

  if (!evp_md) return luaL_error( L, "Unknown digest algorithm: %s", algorithm );

  HMAC( evp_md, key, key_len, msg, msg_len, digest, &digest_len );

  lua_pushlstring( L, (char *) digest, digest_len );
  return 1;
}

struct enumerator_data {
  lua_State * L;
  int index;
};

static void enumerate_algorithms( const OBJ_NAME * name, void * arg )
{
  struct enumerator_data* data = (struct enumerator_data *) arg;
  lua_pushstring( data->L, name->name );
  lua_rawseti( data->L, -2, data->index );
  data->index++;
}

static int l_supported_digests(lua_State *L) /** supported_digests() */
{
  enumerator_data data;
  data.L = L;
  data.index = 1;

  lua_newtable( L );
  OBJ_NAME_do_all_sorted( OBJ_NAME_TYPE_MD_METH,enumerate_algorithms, &data );

  return 1;
}

static int l_supported_ciphers(lua_State *L) /** supported_ciphers() */
{
  enumerator_data data;
  data.L = L;
  data.index = 1;

  lua_newtable( L );
  OBJ_NAME_do_all_sorted( OBJ_NAME_TYPE_CIPHER_METH,enumerate_algorithms, &data );

  return 1;
}

static int l_encrypt(lua_State *L) /** encrypt( string algorithm, string key, string iv, string data, bool padding = false ) */
{
  const char *algorithm = luaL_checkstring( L, 1 );
  const EVP_CIPHER * evp_cipher = EVP_get_cipherbyname( algorithm );
  if (!evp_cipher) return luaL_error( L, "Unknown cipher algorithm: %s", algorithm );

  size_t key_len, iv_len, data_len;
  const unsigned char *key = (unsigned char *) luaL_checklstring( L, 2, &key_len );
  const unsigned char *iv = (unsigned char *) luaL_optlstring( L, 3, "", &iv_len );
  const unsigned char *data = (unsigned char *) luaL_checklstring( L, 4, &data_len );
  int padding = lua_toboolean( L, 5 );
  if (iv[0] == '\0')
    iv = NULL;

#if HAVE_OPAQUE_STRUCTS
  EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
#else
  EVP_CIPHER_CTX stack_ctx;
  EVP_CIPHER_CTX *cipher_ctx = &stack_ctx;
  EVP_CIPHER_CTX_init( cipher_ctx );
#endif

  /* First create the cipher context, then set the key length and padding, and
     check the iv length. Below we set the key and iv. */
  if (!(
      EVP_EncryptInit_ex( cipher_ctx, evp_cipher, NULL, NULL, NULL ) &&
      EVP_CIPHER_CTX_set_key_length( cipher_ctx, key_len ) &&
      EVP_CIPHER_CTX_set_padding( cipher_ctx, padding ))) {
    EVP_CIPHER_CTX_free(cipher_ctx);
    return NSE_SSL_LUA_ERR(L);
  }

  if (iv != NULL && (int) iv_len != EVP_CIPHER_CTX_iv_length( cipher_ctx )) {
    EVP_CIPHER_CTX_free(cipher_ctx);
    return luaL_error( L, "Length of iv is %d; should be %d",
      (int) iv_len, EVP_CIPHER_CTX_iv_length( cipher_ctx ));
  }

  int out_len, final_len;
  unsigned char * out = (unsigned char *) malloc( data_len + EVP_MAX_BLOCK_LENGTH );
  if (!out) {
    EVP_CIPHER_CTX_free(cipher_ctx);
    return luaL_error( L, "Couldn't allocate memory.");
  }

  if (!(
      EVP_EncryptInit_ex( cipher_ctx, NULL, NULL, key, iv ) &&
      EVP_EncryptUpdate( cipher_ctx, out, &out_len, data, data_len ) &&
      EVP_EncryptFinal_ex( cipher_ctx, out + out_len, &final_len ) )) {
    EVP_CIPHER_CTX_free(cipher_ctx);
    free( out );
    return NSE_SSL_LUA_ERR(L);
  }

  lua_pushlstring( L, (char *) out, out_len + final_len );

  EVP_CIPHER_CTX_free( cipher_ctx );
  free( out );

  return 1;
}

static int l_decrypt(lua_State *L) /** decrypt( string algorithm, string key, string iv, string data, bool padding = false ) */
{
  const char *algorithm = luaL_checkstring( L, 1 );
  const EVP_CIPHER * evp_cipher = EVP_get_cipherbyname( algorithm );
  if (!evp_cipher) return luaL_error( L, "Unknown cipher algorithm: %s", algorithm );

  size_t key_len, iv_len, data_len;
  const unsigned char *key = (unsigned char *) luaL_checklstring( L, 2, &key_len );
  const unsigned char *iv = (unsigned char *) luaL_optlstring( L, 3, "", &iv_len );
  const unsigned char *data = (unsigned char *) luaL_checklstring( L, 4, &data_len );
  int padding = lua_toboolean( L, 5 );
  if (iv[0] == '\0')
    iv = NULL;

#if HAVE_OPAQUE_STRUCTS
  EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
#else
  EVP_CIPHER_CTX stack_ctx;
  EVP_CIPHER_CTX *cipher_ctx = &stack_ctx;
  EVP_CIPHER_CTX_init( cipher_ctx );
#endif

  if (!(
      EVP_DecryptInit_ex( cipher_ctx, evp_cipher, NULL, NULL, NULL ) &&
      EVP_CIPHER_CTX_set_key_length( cipher_ctx, key_len ) &&
      EVP_CIPHER_CTX_set_padding( cipher_ctx, padding ))) {
    EVP_CIPHER_CTX_free(cipher_ctx);
    return NSE_SSL_LUA_ERR(L);
  }

  if (iv != NULL && (int) iv_len != EVP_CIPHER_CTX_iv_length( cipher_ctx )) {
    EVP_CIPHER_CTX_free(cipher_ctx);
    return luaL_error( L, "Length of iv is %d; should be %d",
      (int) iv_len, EVP_CIPHER_CTX_iv_length( cipher_ctx ));
  }

  int out_len, final_len;
  unsigned char * out = (unsigned char *) malloc( data_len );
  if (!out) {
    EVP_CIPHER_CTX_free(cipher_ctx);
    return luaL_error( L, "Couldn't allocate memory.");
  }

  if (!(
      EVP_DecryptInit_ex( cipher_ctx, NULL, NULL, key, iv ) &&
      EVP_DecryptUpdate( cipher_ctx, out, &out_len, data, data_len ) &&
      EVP_DecryptFinal_ex( cipher_ctx, out + out_len, &final_len ) )) {
    EVP_CIPHER_CTX_free( cipher_ctx );
    free( out );
    return NSE_SSL_LUA_ERR(L);
  }

  lua_pushlstring( L, (char *) out, out_len + final_len );

  EVP_CIPHER_CTX_free( cipher_ctx );
  free( out );

  return 1;
}

static int l_DES_string_to_key(lua_State *L) /** DES_string_to_key( string data ) */
{
  size_t len;
  const unsigned char *data = (unsigned char *) luaL_checklstring( L, 1, &len );
  if (len != 7 )
    return luaL_error( L, "String must have length of 7 bytes." );

  unsigned char key[8] = {0};
  // key is each 7 bits of data separated by 0 bit
  // Clear the lsb of the first byte:
  key[0] = data[0] & ~1;
  // Least significant i bits of i-1 byte plus most significant 8-i bits of i-th byte
  // clearing the lsb of result to keep only the 7-i bits of i-th byte
  for( int i = 1; i < 8; i++ )
    key[i] = (data[i-1] << (8-i) | data[i] >> i) & ~1;

  // DES_set_odd_parity( &key ); // lgtm [cpp/weak-cryptographic-algorithm]

  lua_pushlstring( L, (char *) key, 8 );
  return 1;
}

static const struct luaL_Reg bignum_methods[] = {
  { "num_bits", l_bignum_num_bits },
  { "num_bytes", l_bignum_num_bytes },
  { "tobin", l_bignum_bn2bin },
  { "tompi", l_bignum_bn2mpi },
  { "todec", l_bignum_bn2dec },
  { "tohex", l_bignum_bn2hex },
  { "is_bit_set", l_bignum_is_bit_set },
  { "set_bit", l_bignum_set_bit },
  { "clear_bit", l_bignum_clear_bit },
  { "is_bit_set", l_bignum_is_bit_set },
  { "is_prime", l_bignum_is_prime },
  { "is_safe_prime", l_bignum_is_safe_prime },
  { "__gc", l_bignum_free },
  { NULL, NULL }
};

static const struct luaL_Reg openssllib[] = {
  { "bignum_num_bits", l_bignum_num_bits },
  { "bignum_num_bytes", l_bignum_num_bytes },
  { "bignum_set_bit", l_bignum_set_bit },
  { "bignum_clear_bit", l_bignum_clear_bit },
  { "bignum_is_bit_set", l_bignum_is_bit_set },
  { "bignum_is_prime", l_bignum_is_prime },
  { "bignum_is_safe_prime", l_bignum_is_safe_prime },
  { "bignum_bin2bn", l_bignum_bin2bn },
  { "bignum_dec2bn", l_bignum_dec2bn },
  { "bignum_hex2bn", l_bignum_hex2bn },
  { "bignum_rand", l_bignum_rand },
  { "bignum_pseudo_rand", l_bignum_rand },
  { "bignum_bn2bin", l_bignum_bn2bin },
  { "bignum_bn2mpi", l_bignum_bn2mpi },
  { "bignum_bn2dec", l_bignum_bn2dec },
  { "bignum_bn2hex", l_bignum_bn2hex },
  { "bignum_add", l_bignum_add },
  { "bignum_mod_exp", l_bignum_mod_exp },
  { "bignum_div", l_bignum_div },
  { "rand_bytes", l_rand_bytes },
  { "rand_pseudo_bytes", l_rand_pseudo_bytes },
  // These functions declared above with NSE_DECLARE_DIGEST
  { "md4", l_md4 },
  { "md5", l_md5 },
  { "sha1", l_sha1 },
  { "ripemd160", l_ripemd160 },

  { "digest", l_digest },
  { "hmac", l_hmac },
  { "encrypt", l_encrypt },
  { "decrypt", l_decrypt },
  { "DES_string_to_key", l_DES_string_to_key },
  { "supported_digests", l_supported_digests },
  { "supported_ciphers", l_supported_ciphers },
  { NULL, NULL }
};

LUALIB_API int luaopen_openssl(lua_State *L) {

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined LIBRESSL_VERSION_NUMBER
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
#elif OPENSSL_VERSION_NUMBER >= 0x30000000L
  if (NULL == OSSL_PROVIDER_load(NULL, "legacy") && o.debugging > 1)
  {
    // Legacy provider may not be available.
    // On Windows, legacy crypto is still available even though this fails.
    log_write(LOG_STDOUT, "%s: OpenSSL legacy provider failed to load: %s\n", SCRIPT_ENGINE, ERR_error_string(ERR_get_error(), NULL));
  }
  if (NULL == OSSL_PROVIDER_load(NULL, "default") && o.verbose)
  {
    log_write(LOG_STDOUT, "%s: OpenSSL default provider failed to load: %s\n", SCRIPT_ENGINE, ERR_error_string(ERR_get_error(), NULL));
  }
#endif

  luaL_newlib(L, openssllib);

  // create metatable for bignum
  luaL_newmetatable( L, "BIGNUM" );
  // metatable.__index = metatable
  lua_pushvalue( L, -1 );
  lua_setfield( L, -2, "__index" );
  // metatable.__tostring = bignum_bn2hex
  lua_pushcfunction( L, l_bignum_bn2hex );
  lua_setfield( L, -2, "__tostring" );
  // register methods
  luaL_setfuncs(L, bignum_methods, 0);

  lua_pop( L, 1 ); // BIGNUM

  return 1;
}
