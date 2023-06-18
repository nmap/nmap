#ifdef HAVE_CONFIG_H
/* Needed for HAVE_PCRE_PCRE_H below */
#include "nmap_config.h"
#endif /* HAVE_CONFIG_H */

#ifdef HAVE_PCRE2
#ifndef NSE_PCRELIB
#define NSE_PCRELIB

#define NSE_PCRELIBNAME "pcre"

LUALIB_API int luaopen_rex_pcre2 (lua_State *L);

#endif
#else
#ifndef NSE_PCRELIB
#define NSE_PCRELIB

#define NSE_PCRELIBNAME "pcre"

LUALIB_API int luaopen_pcrelib (lua_State *L);

#endif
#endif
