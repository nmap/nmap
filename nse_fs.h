#ifndef NSE_FS
#define NSE_FS

int fetchscript (lua_State *L);

int fetchfile_absolute (lua_State *L);

int nse_readdir (lua_State *L);

int luaopen_fs (lua_State *L);

#endif
