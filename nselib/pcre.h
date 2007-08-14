#ifndef PCRE_H
#define PCRE_H

#ifdef WIN32
#define _CRT_SECURE_NO_DEPRECATE 1
#define _CRT_SECURE_NO_WARNINGS 1 /* otherwise msvc++ complains even for 
safe operations, and request us to use their str*_s() functions */
#pragma warning(disable: 4996)
#define vsnprintf _vsnprintf
#define strdup _strdup
#endif /* WIN32 */
#define NSE_PCRELIBNAME "pcre"

LUALIB_API int luaopen_pcre(lua_State *L);

#endif

