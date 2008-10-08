#ifndef OPENSSLLIB
#define OPENSSLLIB

#define OPENSSLLIBNAME "openssl"

extern "C" {
#include "lua.h"
#include "lauxlib.h"
}

LUALIB_API int luaopen_openssl(lua_State *L);

#endif
