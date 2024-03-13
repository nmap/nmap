#ifndef NSE_LUA_H
#define NSE_LUA_H

#ifdef HAVE_CONFIG_H
#include "nmap_config.h"
#else
#ifdef WIN32
#include "nmap_winconfig.h"
#endif /* WIN32 */
#endif /* HAVE_CONFIG_H */

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_LUA5_4_LUA_H
  #include <lua5.4/lua.h>
  #include <lua5.4/lauxlib.h>
  #include <lua5.4/lualib.h>
#elif defined HAVE_LUA_5_4_LUA_H
  #include <lua/5.4/lua.h>
  #include <lua/5.4/lauxlib.h>
  #include <lua/5.4/lualib.h>
#elif defined HAVE_LUA_H || defined LUA_INCLUDED
  #include <lua.h>
  #include <lauxlib.h>
  #include <lualib.h>
#elif defined HAVE_LUA_LUA_H
  #include <lua/lua.h>
  #include <lua/lauxlib.h>
  #include <lua/lualib.h>
#endif

#ifdef __cplusplus
} /* End of 'extern "C"' */
#endif

#endif /* NSE_LUA_H */
