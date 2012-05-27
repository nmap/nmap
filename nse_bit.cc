/* Bitwise operations library 
 * by Reuben Thomas (rrt@sc3d.org)
 * bitlib is a C library for Lua 5.x that provides bitwise operations
 * It is copyright Reuben Thomas 2000-2006, and is released under the
 * MIT license, like Lua (see http://www.lua.org/copyright.html for the
 * full license; it's basically the same as the BSD license). There is no
 * warranty.
 * the most recent copy can be found at http://rrt.sc3d.org/Software/Lua/
 **/

extern "C" {
  #include "lauxlib.h"
  #include "lua.h"
}

#include "nse_bit.h"

typedef long long Integer;
typedef unsigned long long UInteger;

#define luaL_checkbit(L, n)  ((Integer)luaL_checknumber(L, n))
#define luaL_checkubit(L, n) ((UInteger)luaL_checkbit(L, n))

#define TDYADIC(name, op, checkbit1, checkbit2) \
  static int bit_ ## name(lua_State* L) { \
    lua_pushnumber(L, \
      (lua_Number)(checkbit1(L, 1) op checkbit2(L, 2))); \
    return 1; \
  }

#define DYADIC(name, op) \
  TDYADIC(name, op, luaL_checkbit, luaL_checkbit)

#define MONADIC(name, op) \
  static int bit_ ## name(lua_State* L) { \
    lua_pushnumber(L, (lua_Number)(op luaL_checkbit(L, 1))); \
    return 1; \
  }

#define VARIADIC(name, op) \
  static int bit_ ## name(lua_State *L) { \
    int n = lua_gettop(L), i; \
    Integer w = luaL_checkbit(L, 1); \
    for (i = 2; i <= n; i++) \
      w op luaL_checkbit(L, i); \
    lua_pushnumber(L, (lua_Number)w); \
    return 1; \
  }

MONADIC(bnot,     ~)
VARIADIC(band,    &=)
VARIADIC(bor,     |=)
VARIADIC(bxor,    ^=)
TDYADIC(lshift,  <<, luaL_checkbit, luaL_checkubit)
TDYADIC(rshift,  >>, luaL_checkubit, luaL_checkubit)
TDYADIC(arshift, >>, luaL_checkbit, luaL_checkubit)
DYADIC(mod,      %)

static const struct luaL_Reg bitlib[] = {
  {"bnot",    bit_bnot},
  {"band",    bit_band},
  {"bor",     bit_bor},
  {"bxor",    bit_bxor},
  {"lshift",  bit_lshift},
  {"rshift",  bit_rshift},
  {"arshift", bit_arshift},
  {"mod",     bit_mod},
  {NULL, NULL}
};

LUALIB_API int luaopen_bit(lua_State *L) {
  luaL_newlib(L, bitlib);
  return 1;
}

