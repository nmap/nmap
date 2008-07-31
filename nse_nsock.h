#ifndef NMAP_LUA_NSOCK_H
#define NMAP_LUA_NSOCK_H

extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}

int luaopen_nsock(lua_State *);
int l_nsock_new(lua_State *);
int l_nsock_loop(int tout);

int l_dnet_new(lua_State *);
int l_dnet_open(lua_State *);
int l_dnet_get_interface_link(lua_State *);

#endif

