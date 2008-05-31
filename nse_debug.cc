#include "nse_debug.h"
#include "output.h"

void l_dumpStack(lua_State *L) {
	int stack_height = lua_gettop(L);
	int i;
	
	log_write(LOG_PLAIN, "-== Stack Dump Begin ==-\n");
	for(i = -1; i >= 0 - stack_height; i--) {
		log_write(LOG_PLAIN, "%d: ", i);
		l_dumpValue(L, i);
	}

	log_write(LOG_PLAIN, "-== Stack Dump End ==-\n");
}

void l_dumpValue(lua_State *L, int i) {
    switch (lua_type(L, i))
    {
      case LUA_TTABLE:
		l_dumpTable(L, i);
        break;
      case LUA_TFUNCTION:
		l_dumpFunction(L, i);
        break;
      case LUA_TSTRING:
		log_write(LOG_PLAIN, "string '%s'\n", lua_tostring(L, i));
        break;
      case LUA_TBOOLEAN:
		log_write(LOG_PLAIN, "boolean: %s\n",
            lua_toboolean(L, i) ? "true" : "false"); 
        break;
      case LUA_TNUMBER:
		log_write(LOG_PLAIN, "number: %g\n", lua_tonumber(L, i));
        break;
      default:
		log_write(LOG_PLAIN, "%s\n", lua_typename(L, lua_type(L, i)));
    }
}

void l_dumpTable(lua_State *L, int index) {
	log_write(LOG_PLAIN, "table\n");
	lua_pushnil(L);

	if (index<0) --index;
	while(lua_next(L, index) != 0)
	{
		l_dumpValue(L, -2);
		l_dumpValue(L, -1);
		lua_pop(L, 1); 
	}
}

void l_dumpFunction(lua_State *L, int index) {
//	lua_Debug ar;

	log_write(LOG_PLAIN, "function\n");	

//	lua_pushvalue(L, index);
//	lua_getinfo(L, ">n", &ar);
//	
//	log_write(LOG_PLAIN, "\tname: %s %s\n", ar.namewhat, ar.name);
	fflush(stdout);
}
