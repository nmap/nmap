#ifndef NSE_FS
#define NSE_FS

int nse_check_extension (const char* ext, const char* path);

int nse_fetchfile(char *path, size_t path_len, const char *file);

int nse_fetchfile_absolute(char *path, size_t path_len, const char *file);

int nse_scandir (lua_State *L);

#define NSE_FILES 1
#define NSE_DIRS  2

#endif
