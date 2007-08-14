#ifndef PCRE_H
#define PCRE_H

#ifdef WIN32
#define vsnprintf _vsnprintf
#endif /* WIN32 */
#define NSE_PCRELIBNAME "pcre"

LUALIB_API int luaopen_pcre(lua_State *L);

#endif

