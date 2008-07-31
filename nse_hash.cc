#include <ctype.h>
#include <string.h>
extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}
#include "nse_hash.h"

#include "nbase/nbase_md5.h"
#include "nbase/nbase_sha1.h"


static int l_md5(lua_State *L)
{
  size_t len;
  const char *str = luaL_checklstring(L, 1, &len);
  
  MD5_CTX c;
  unsigned char digest[MD5_DIGEST_LENGTH];
  luaL_Buffer buf;
  char hdigit[3];

  luaL_buffinit(L,&buf);

  if (!nb_MD5_Init(&c)) {
    /* ERROR */
    luaL_error(L, "MD5 init error");
  }

  nb_MD5_Update(&c, str, len);
  nb_MD5_Final(digest, &c);
  
  for (int ii = 0; ii < MD5_DIGEST_LENGTH; ii++) {
    sprintf(hdigit, "%02x", digest[ii]);
    luaL_addlstring(&buf, hdigit, 2);
  }
  luaL_pushresult(&buf);
  return 1;
}

static int l_md5bin(lua_State *L)
{
  size_t len;
  const char *str = luaL_checklstring(L, 1, &len);
  
  MD5_CTX c;
  unsigned char digest[MD5_DIGEST_LENGTH];
  luaL_Buffer buf;
  char hdigit[3];

  luaL_buffinit(L,&buf);

  if (!nb_MD5_Init(&c)) {
    /* ERROR */
    luaL_error(L, "MD5 init error");
  }

  nb_MD5_Update(&c, str, len);
  nb_MD5_Final(digest, &c);
  

  //  luaL_addlstring(&buf, digest, MD5_DIGEST_LENGTH);

  //  luaL_pushresult(&buf);

  lua_pushlstring(L, (char *)digest, MD5_DIGEST_LENGTH);
  return 1;
}

static int l_sha1(lua_State *L)
{
  size_t len;
  const char *str = luaL_checklstring(L, 1, &len);
  
  SHA_CTX c;
  unsigned char digest[SHA_DIGEST_LENGTH];
  luaL_Buffer buf;
  char hdigit[3];

  luaL_buffinit(L,&buf);

  if (!nb_SHA1_Init(&c)) {
    /* ERROR */
    luaL_error(L, "sha1 init error");
  }

  nb_SHA1_Update(&c, str, len);
  nb_SHA1_Final(digest, &c);
  
  for (int ii = 0; ii < SHA_DIGEST_LENGTH; ii++) {
    sprintf(hdigit, "%02x", digest[ii]);
    luaL_addlstring(&buf, hdigit, 2);
  }
  luaL_pushresult(&buf);
  return 1;
}


static int l_sha1bin(lua_State *L)
{
  size_t len;
  const char *str = luaL_checklstring(L, 1, &len);
  
  SHA_CTX c;
  unsigned char digest[SHA_DIGEST_LENGTH];
  luaL_Buffer buf;


  luaL_buffinit(L,&buf);

  if (!nb_SHA1_Init(&c)) {
    /* ERROR */
    luaL_error(L, "sha1 init error");
  }

  nb_SHA1_Update(&c, str, len);
  nb_SHA1_Final(digest, &c);
  
  lua_pushlstring(L, (char *) digest, SHA_DIGEST_LENGTH);
  return 1;
}


static const luaL_reg hashlib[] =
{
	{"md5",	l_md5},
	{"sha1", l_sha1},
	{"md5bin", l_md5bin},
	{NULL,	NULL}
};

LUALIB_API int luaopen_hashlib (lua_State *L) {
  luaL_register(L, NSE_HASHLIBNAME, hashlib);
  return 1;
}
