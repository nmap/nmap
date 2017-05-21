#ifndef NMAP_LUA_NSOCK_H
#define NMAP_LUA_NSOCK_H

extern "C" {
  #include "lua.h"
}

LUALIB_API int luaopen_nsock (lua_State *);

#endif

