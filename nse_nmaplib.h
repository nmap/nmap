#ifndef NSE_NMAPLIB
#define NSE_NMAPLIB

extern "C" {
	#include "lua.h"
	#include "lualib.h"
	#include "lauxlib.h"
}

class Target;
class Port;

int set_nmaplib(lua_State* l);
void set_hostinfo(lua_State* l, Target* currenths);
void set_portinfo(lua_State* l, Port* port);

#endif

