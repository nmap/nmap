#ifndef NMAP_LUA_DNET_H
#define NMAP_LUA_DNET_H

LUALIB_API int l_dnet_new (lua_State *);
LUALIB_API int l_dnet_get_interface_link (lua_State *);
LUALIB_API int l_dnet_get_interface_info (lua_State *);
LUALIB_API int luaopen_dnet (lua_State *L);

#endif
