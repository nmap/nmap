#ifndef NSE_DEBUG
#define NSE_DEBUG

extern "C" {
	#include "lua.h"
	#include "lualib.h"
	#include "lauxlib.h"
}

void l_dumpStack(lua_State* l);
void l_dumpValue(lua_State* l, int index);
void l_dumpTable(lua_State *l, int index);
void l_dumpFunction(lua_State* l, int index);

#endif

