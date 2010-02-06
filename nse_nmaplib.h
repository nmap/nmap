#ifndef NSE_NMAPLIB
#define NSE_NMAPLIB

#define NSE_NMAPLIBNAME  "nmap"
#define NSE_STDNSELIBNAME  "stdnse.c"

class Target;
class Port;

int luaopen_nmap(lua_State* l);
int luaopen_stdnse_c (lua_State *L);
void set_hostinfo(lua_State* l, Target* currenths);
void set_portinfo(lua_State* l, const Target *target, const Port* port);
Target *get_target (lua_State *L, int index);
Port *get_port (lua_State *L, Target *target, Port *port, int index);

#endif

