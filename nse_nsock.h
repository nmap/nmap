#ifndef NMAP_LUA_NSOCK_H
#define NMAP_LUA_NSOCK_H

extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}

int l_nsock_open(lua_State* l);
int l_nsock_new(lua_State* l);
int l_nsock_loop(int tout);

int l_dnet_new(lua_State* l);
int l_dnet_open(lua_State* l);
int l_dnet_get_interface_link(lua_State* l);

#endif

