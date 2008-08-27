#ifndef BITLIB
#define BITLIB

#define BITLIBNAME "bit"

extern "C" {
#include "lauxlib.h"
#include "lua.h"
}

LUALIB_API int luaopen_bit(lua_State *L);

#endif

