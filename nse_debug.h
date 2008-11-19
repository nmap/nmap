#ifndef NSE_DEBUG
#define NSE_DEBUG

extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}

void value_dump(lua_State *L, int i, int depth_limit);
void stack_dump(lua_State *L);
void lua_state_dump(lua_State *L);

#endif

