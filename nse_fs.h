#ifndef NSE_FS
#define NSE_FS

extern "C" {
	#include "lua.h"
	#include "lualib.h"
	#include "lauxlib.h"
}

#include <vector>
#include <string>
#include <string.h>

int nse_check_extension (const char* ext, const char* path);

int nse_fetchfile(char *path, size_t path_len, const char *file);

int nse_fetchfile_absolute(char *path, size_t path_len, const char *file);

int nse_scandir (lua_State *L);

#endif
