#ifndef NSE_NMAPLIB
#define NSE_NMAPLIB

#define NSE_NMAPLIBNAME  "nmap"

class Target;
class Port;

int luaopen_nmap(lua_State* l);
#define NSE_NUM_HOSTINFO_FIELDS 17
void set_hostinfo(lua_State* l, Target* currenths);
#define NSE_NUM_PORTINFO_FIELDS 7
void set_portinfo(lua_State* l, const Target *target, const Port* port);

#endif

