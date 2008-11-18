#ifndef NSE_DEBUG
#define NSE_DEBUG

extern "C" {
	#include "lua.h"
	#include "lualib.h"
	#include "lauxlib.h"
}

void stack_dump(lua_State *L);

#endif

