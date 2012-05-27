
extern "C" {
  #include "lua.h"
  #include "lauxlib.h"
}

#include "nmap.h"
#include "nse_fs.h"
#include "nse_utility.h"
#include "nmap_error.h"
#include "NmapOps.h"

#include <errno.h>
#include <string.h>

#include <string>

enum {
  DIR_METATABLE = lua_upvalueindex(1),
};

#ifndef WIN32
#include "dirent.h"
#endif

#ifndef MAXPATHLEN
#   define MAXPATHLEN 2048
#endif

#ifndef MAX_DIR_LENGTH
#   define MAX_DIR_LENGTH 1024
#endif

typedef struct dir_data {
  int  closed;
#ifdef WIN32
  long hFile;
  char pattern[MAX_DIR_LENGTH+1];
#else
  DIR *dir;
#endif
} dir_data;

extern NmapOps o;

static bool filename_is_absolute(const char *file) {
  if (file[0] == '/')
    return true;
#ifdef WIN32
  if ((file[0] != '\0' && file[1] == ':') || file[0] == '\\')
    return true;
#endif
  return false;
}

/* This is a modification of nmap_fetchfile specialized to look for files
 * in the scripts subdirectory. If the path is absolute, it is always tried
 * verbatim. Otherwise, the file is looked for under scripts/, and then finally
 * in the current directory.
 */
static int nse_fetchscript(char *path, size_t path_len, const char *file) {
  std::string scripts_path = std::string(SCRIPT_ENGINE_LUA_DIR) + std::string(file);
  int type;

  if (filename_is_absolute(file)) {
    if (o.debugging > 1)
      log_write(LOG_STDOUT, "%s: Trying absolute path %s\n", SCRIPT_ENGINE, file);
    Strncpy(path, file, path_len);
    return nmap_fileexistsandisreadable(file);
  }

  // lets look in <path>/scripts
  type = nmap_fetchfile(path, path_len, scripts_path.c_str());

  if (type == 0) {
    // current directory
    Strncpy(path, file, path_len);
    return nmap_fileexistsandisreadable(file);
  }

  return type;
}

/* This is a modification of nmap_fetchfile that first looks for an
 * absolute file name.
 */
static int nse_fetchfile_absolute(char *path, size_t path_len, const char *file) {
  if (filename_is_absolute(file)) {
    if (o.debugging > 1)
      log_write(LOG_STDOUT, "%s: Trying absolute path %s\n", SCRIPT_ENGINE, file);
    Strncpy(path, file, path_len);
    return nmap_fileexistsandisreadable(file);
  }

  return nmap_fetchfile(path, path_len, file);
}

static int nse_fetch (lua_State *L, int (*fetch)(char *, size_t, const char *))
{
  char path[MAXPATHLEN];
  switch (fetch(path, sizeof(path), luaL_checkstring(L, 1)))
  {
    case 0: // no such path
      lua_pushnil(L);
      lua_pushfstring(L, "no path to file/directory: %s", lua_tostring(L, 1));
      break;
    case 1: // file returned
      lua_pushliteral(L, "file");
      lua_pushstring(L, path);
      break;
    case 2: // directory returned
      lua_pushliteral(L, "directory");
      lua_pushstring(L, path);
      break;
    default:
      return luaL_error(L, "nse_fetch returned bad code");
  }
  return 2;
}

static int l_fetchscript (lua_State *L)
{
  return nse_fetch(L, nse_fetchscript);
}

static int l_fetchfile_absolute (lua_State *L)
{
  return nse_fetch(L, nse_fetchfile_absolute);
}


/* LuaFileSystem directory iterator port.
 * 
 * LuaFileSystem library:
 * by Roberto Ierusalimschy, Andre Carregal and Tomas Guisasola
 * as part of the Kepler Project.
 * LuaFileSystem is currently maintained by Fabio Mascarenhas.
 * 
 * LuaFileSystem is a Lua library developed to complement the set
 * of functions related to file systems offered by the standard
 * Lua distribution.
 * LuaFileSystem offers a portable way to access the underlying
 * directory structure and file attributes.
 *
 * LuaFileSystem is free software and uses the same license as Lua 5.1.
 * 
 * the most recent copy can be found at
 * http://www.keplerproject.org/luafilesystem/
 *
 * Note: this is a port of the LuaFileSystem directory iterator for the
 * Nmap project http://nmap.org
 **/

/*
** Directory iterator
*/
static int dir_iter (lua_State *L) {
#ifdef WIN32
  struct _finddata_t c_file;
#else
  struct dirent *entry;
#endif
  dir_data *d = (dir_data *) nseU_checkudata(L, 1, DIR_METATABLE, "directory");
  luaL_argcheck(L, !d->closed, 1, "closed directory");
#ifdef WIN32
  if (d->hFile == 0L) { /* first entry */
    if ((d->hFile = _findfirst(d->pattern, &c_file)) == -1L) {
        lua_pushnil(L);
        lua_pushstring(L, strerror (errno));
        return 2;
    } else {
	lua_pushstring(L, c_file.name);
	return 1;
    }
  } else { /* next entry */
    if (_findnext(d->hFile, &c_file) == -1L) {
      /* no more entries => close directory */
      _findclose(d->hFile);
      d->closed = 1;
      return 0;
    } else {
        lua_pushstring(L, c_file.name);
        return 1;
    }
  }
#else
  if ((entry = readdir(d->dir)) != NULL) {
    lua_pushstring(L, entry->d_name);
    return 1;
  } else {
    /* no more entries => close directory */
    closedir(d->dir);
    d->closed = 1;
    return 0;
  }
#endif
}

/*
** Closes directory iterators
*/
static int dir_close (lua_State *L) {
  dir_data *d = (dir_data *) nseU_checkudata(L, 1, DIR_METATABLE, "directory");
#ifdef WIN32
  if (!d->closed && d->hFile) {
    _findclose(d->hFile);
    d->closed = 1;
  }
#else
  if (!d->closed && d->dir) {
    closedir(d->dir);
    d->closed = 1;
  }
#endif
  return 0;
}

/*
** Factory of directory iterators
*/
static int l_readdir (lua_State *L) {
  const char *dirname = luaL_checkstring(L, 1);
  dir_data *d;
  lua_pushcfunction(L, dir_iter);
  d = (dir_data *)lua_newuserdata(L, sizeof(dir_data));
  d->closed = 0;
#ifdef  WIN32
  d->hFile = 0L;
  lua_pushvalue(L, DIR_METATABLE);
  lua_setmetatable(L, -2);
  if (strlen(dirname) > MAX_DIR_LENGTH)
    luaL_error(L, "%s: Path too long '%s'.", SCRIPT_ENGINE, dirname);
  else
    Snprintf(d->pattern, MAX_DIR_LENGTH, "%s/*", dirname);
#else
  lua_pushvalue(L, DIR_METATABLE);
  lua_setmetatable(L, -2);
  d->dir = opendir(dirname);
  if (d->dir == NULL)
    luaL_error(L, "%s: Could not open directory '%s'.", SCRIPT_ENGINE, dirname);
#endif
  return 2;
}

LUALIB_API int luaopen_fs(lua_State *L)
{
  static const luaL_Reg metatable_index[] = {
    {"next", dir_iter},
    {"close", dir_close},
    {NULL, NULL}
  };

  static const luaL_Reg lib[] = {
    {"fetchscript", l_fetchscript},
    {"fetchfile_absolute", l_fetchfile_absolute},
    {"readdir", l_readdir},
    {NULL, NULL}
  };

  int top = lua_gettop(L);
  lua_newtable(L); /* DIR_METATABLE */

  luaL_newlibtable(L, metatable_index);
  lua_pushvalue(L, top+1);
  luaL_setfuncs(L, metatable_index, 1);
  lua_getfield(L, -1, "close");
  lua_setfield(L, top+1, "__gc");
  lua_setfield(L, top+1, "__index");

  luaL_newlibtable(L, lib);
  lua_pushvalue(L, top+1);
  luaL_setfuncs(L, lib, 1);

  return 1;
}
