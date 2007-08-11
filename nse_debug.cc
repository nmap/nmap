#include "nse_debug.h"
#include "output.h"

void l_dumpStack(lua_State* l) {
	int stack_height = lua_gettop(l);
	int i;
	
	log_write(LOG_PLAIN, "-== Stack Dump Begin ==-\n");
	for(i = -1; i >= 0 - stack_height; i--) {
		log_write(LOG_PLAIN, "%d: ", i);
		l_dumpValue(l, i);
	}

	log_write(LOG_PLAIN, "-== Stack Dump End ==-\n");
}

void l_dumpValue(lua_State* l, int i) {
	if(lua_istable(l, i))
		l_dumpTable(l, i);
	else if(lua_isfunction(l, i))
		l_dumpFunction(l, i);
	else if(lua_isstring(l, i)) {
		lua_pushvalue(l, i);
		log_write(LOG_PLAIN, "string '%s'\n", lua_tostring(l, -1));
		lua_pop(l, 1);
	}
	else if(lua_isboolean(l, i))
		log_write(LOG_PLAIN, "boolean: %s", lua_toboolean(l, i) ? "true\n" : "false\n"); 
	else if(lua_isnumber(l, i))
		log_write(LOG_PLAIN, "number: %g\n", lua_tonumber(l, i));
	else
		log_write(LOG_PLAIN, "%s\n", lua_typename(l, lua_type(l, i)));
}

void l_dumpTable(lua_State *l, int index) {
	log_write(LOG_PLAIN, "table\n");
	lua_pushnil(l);

	if (index<0) --index;
	while(lua_next(l, index) != 0)
	{
		l_dumpValue(l, -2);
		l_dumpValue(l, -1);
		lua_pop(l, 1); 
	}
}

void l_dumpFunction(lua_State* l, int index) {
//	lua_Debug ar;

	log_write(LOG_PLAIN, "function\n");	

//	lua_pushvalue(l, index);
//	lua_getinfo(l, ">n", &ar);
//	
//	log_write(LOG_PLAIN, "\tname: %s %s\n", ar.namewhat, ar.name);
	fflush(stdout);
}

