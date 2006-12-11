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

#endif

