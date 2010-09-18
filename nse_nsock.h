#ifndef NMAP_LUA_NSOCK_H
#define NMAP_LUA_NSOCK_H

#include "nse_main.h"

LUALIB_API int luaopen_nsock (lua_State *);
LUALIB_API int l_nsock_new (lua_State *);
LUALIB_API int l_nsock_sleep (lua_State *);

#define NSE_NSOCK_LOOP "NSOCK_LOOP"

#endif

