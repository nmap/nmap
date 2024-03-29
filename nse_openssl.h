#ifndef OPENSSLLIB
#define OPENSSLLIB

#define OPENSSLLIBNAME "openssl"

LUALIB_API int luaopen_openssl(lua_State *L);

#if HAVE_OPENSSL
#include <openssl/bn.h>
int nse_pushbn( lua_State *L, BIGNUM *num, bool should_free);
#endif
#endif

