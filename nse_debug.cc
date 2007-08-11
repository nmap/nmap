#include "nse_debug.h"

void l_dumpStack(lua_State* l) {
	int stack_height = lua_gettop(l);
	int i;
	
	printf("-== Stack Dump Begin ==-\n");
	for(i = -1; i >= 0 - stack_height; i--) {
		printf("%d: ", i);
		l_dumpValue(l, i);
	}

	printf("-== Stack Dump End ==-\n");
}

void l_dumpValue(lua_State* l, int i) {
	if(lua_istable(l, i))
		l_dumpTable(l, i);
	else if(lua_isfunction(l, i))
		l_dumpFunction(l, i);
	else if(lua_isstring(l, i)) {
		lua_pushvalue(l, i);
		printf("string '%s'\n", lua_tostring(l, -1));
		lua_pop(l, 1);
	}
	else if(lua_isboolean(l, i))
		printf("boolean: %s", lua_toboolean(l, i) ? "true\n" : "false\n"); 
	else if(lua_isnumber(l, i))
		printf("number: %g\n", lua_tonumber(l, i));
	else
		printf("%s\n", lua_typename(l, lua_type(l, i)));
}

void l_dumpTable(lua_State *l, int index) {
	printf("table\n");
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

	printf("function\n");	

//	lua_pushvalue(l, index);
//	lua_getinfo(l, ">n", &ar);
//	
//	printf("\tname: %s %s\n", ar.namewhat, ar.name);
	fflush(stdout);
}

