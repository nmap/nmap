#ifndef NSE_INIT
#define NSE_INIT

extern "C" {
	#include "lua.h"
	#include "lualib.h"
	#include "lauxlib.h"
}

#include <vector>
#include <string>
#include <string.h>

// initialize the lua state
// opens the standard libraries and the nmap lua library
int init_lua(lua_State* l);

// you give it a description of scripts to run and it
// populates the tables 'hosttests' and 'porttests' in l with
// activation records for tests
int init_rules(lua_State* l, std::vector<std::string> chosenScripts);
int init_updatedb(lua_State* l);

#endif

