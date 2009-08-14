#ifndef NMAP_LUA_NSOCK_H
#define NMAP_LUA_NSOCK_H

#ifdef HAVE_CONFIG_H
#include "nmap_config.h"
#endif

int luaopen_nsock(lua_State *);
int l_nsock_new(lua_State *);
int l_nsock_sleep(lua_State *L);

int l_dnet_new(lua_State *);
int l_dnet_get_interface_link(lua_State *);

#define NSE_NSOCK_LOOP "NSOCK_LOOP"

#if HAVE_OPENSSL
#include <openssl/ssl.h>
const SSL *nse_nsock_get_ssl(lua_State *L);
#endif

#endif

