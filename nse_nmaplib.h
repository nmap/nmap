#ifndef NSE_NMAPLIB
#define NSE_NMAPLIB

#define NSE_NMAPLIBNAME  "nmap"

class Target;
class Port;

int luaopen_nmap(lua_State* l);
void set_hostinfo(lua_State* l, Target* currenths);
void set_portinfo(lua_State* l, const Target *target, const Port* port);

#endif

