/*
** Note: this is a port of LuaFileSystem for the
** Nmap project (https://nmap.org).
** Many functions have been removed, because we only really
** need: dir, mkdir, rmdir and possibly link.
 */

/*
 * LuaFileSystem library:
 * by Roberto Ierusalimschy, Andre Carregal and Tomas Guisasola
 * as part of the Kepler Project.
 * LuaFileSystem is currently maintained by Fabio Mascarenhas.
 *
 * Copyright Kepler Project 2003 (http://www.keplerproject.org/luafilesystem)
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
 **/

extern "C" {
  #include "lauxlib.h"
  #include "lua.h"
}

#include "nmap.h"
#include "nse_fs.h"
#include "nse_utility.h"
#include "nmap_error.h"
#include "NmapOps.h"

#ifdef _WIN32
#include <direct.h>
#include <sys/utime.h>
#else
#include <dirent.h>
#include <utime.h>
#endif

#include <errno.h>
#include <string.h>

#include <string>

#define DIR_METATABLE "directory metatable"

#ifndef MAX_PATH
#define MAX_PATH 2048
#endif

/* Define 'strerror' for systems that do not implement it */
#ifdef NO_STRERROR
#define strerror(_)  "System unable to describe the error"
#endif

typedef struct dir_data {
  int  closed;
#ifdef _WIN32
  long hFile;
  char pattern[MAX_PATH+1];
#else
  DIR *dir;
#endif
} dir_data;

/*
** Utility functions
*/
static int pusherror(lua_State *L, const char *info)
{
  lua_pushnil(L);
  if (info==NULL)
    lua_pushstring(L, strerror(errno));
  else
    lua_pushfstring(L, "%s: %s", info, strerror(errno));
  lua_pushinteger(L, errno);
  return 3;
}

static int pushresult(lua_State *L, int i, const char *info)
{
  if (i==-1)
    return pusherror(L, info);
  lua_pushboolean(L, true);
  return 1;
}

/*
** Creates a link.
** @param #1 Object to link to.
** @param #2 Name of link.
** @param #3 True if link is symbolic (optional).
*/
static int make_link(lua_State *L)
{
#ifndef _WIN32
  const char *oldpath = luaL_checkstring(L, 1);
  const char *newpath = luaL_checkstring(L, 2);
  return pushresult(L,
    (lua_toboolean(L,3) ? symlink : link)(oldpath, newpath), NULL);
#else
  return pusherror(L, "make_link is not supported on Windows");
#endif
}

/*
** Creates a directory.
** @param #1 Directory path.
*/
static int make_dir (lua_State *L) {
  const char *path = luaL_checkstring (L, 1);
  int fail;
#ifdef _WIN32
  fail = _mkdir (path);
#else
  fail =  mkdir (path, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP |
                       S_IWGRP | S_IXGRP | S_IROTH | S_IXOTH );
#endif
  if (fail) {
    lua_pushnil (L);
        lua_pushfstring (L, "%s", strerror(errno));
    return 2;
  }
  lua_pushboolean (L, 1);
  return 1;
}

/*
** Removes a directory.
** @param #1 Directory path.
*/
static int remove_dir (lua_State *L) {
  const char *path = luaL_checkstring (L, 1);
  int fail;

  fail = rmdir (path);

  if (fail) {
    lua_pushnil (L);
    lua_pushfstring (L, "%s", strerror(errno));
    return 2;
  }
  lua_pushboolean (L, 1);
  return 1;
}

/*
** Directory iterator
*/
static int dir_iter (lua_State *L) {
#ifdef _WIN32
  struct _finddata_t c_file;
#else
  struct dirent *entry;
#endif
  dir_data *d = (dir_data *)luaL_checkudata (L, 1, DIR_METATABLE);
  luaL_argcheck (L, d->closed == 0, 1, "closed directory");
#ifdef _WIN32
  if (d->hFile == 0L) { /* first entry */
    if ((d->hFile = _findfirst (d->pattern, &c_file)) == -1L) {
      lua_pushnil (L);
      lua_pushstring (L, strerror (errno));
      d->closed = 1;
      return 2;
    } else {
      lua_pushstring (L, c_file.name);
      return 1;
    }
  } else { /* next entry */
    if (_findnext (d->hFile, &c_file) == -1L) {
      /* no more entries => close directory */
      _findclose (d->hFile);
      d->closed = 1;
      return 0;
    } else {
      lua_pushstring (L, c_file.name);
      return 1;
    }
  }
#else
  if ((entry = readdir (d->dir)) != NULL) {
    lua_pushstring (L, entry->d_name);
    return 1;
  } else {
    /* no more entries => close directory */
    closedir (d->dir);
    d->closed = 1;
    return 0;
  }
#endif
}

/*
** Closes directory iterators
*/
static int dir_close (lua_State *L) {
  dir_data *d = (dir_data *)lua_touserdata (L, 1);
#ifdef _WIN32
  if (!d->closed && d->hFile) {
    _findclose(d->hFile);
  }
#else
  if (!d->closed && d->dir) {
    closedir(d->dir);
  }
#endif
  d->closed = 1;
  return 0;
}

/*
** Factory of directory iterators
*/
static int dir_iter_factory (lua_State *L) {
  const char *path = luaL_checkstring (L, 1);
  dir_data *d;
  lua_pushcfunction (L, dir_iter);
  d = (dir_data *) lua_newuserdata (L, sizeof(dir_data));
  luaL_getmetatable (L, DIR_METATABLE);
  lua_setmetatable (L, -2);
  d->closed = 0;
#ifdef _WIN32
  d->hFile = 0L;
  if (strlen(path) > MAX_PATH-2)
    luaL_error (L, "path too long: %s", path);
  else
    sprintf (d->pattern, "%s/*", path);
#else
  d->dir = opendir (path);
  if (d->dir == NULL)
          luaL_error (L, "cannot open %s: %s", path, strerror (errno));
#endif
 return 2;
}


/*
** Creates directory metatable.
*/
static int dir_create_meta (lua_State *L) {
  luaL_newmetatable (L, DIR_METATABLE);

  /* Method table */
  lua_newtable(L);
  lua_pushcfunction (L, dir_iter);
  lua_setfield(L, -2, "next");
  lua_pushcfunction (L, dir_close);
  lua_setfield(L, -2, "close");

  /* Metamethods */
  lua_setfield(L, -2, "__index");
  lua_pushcfunction (L, dir_close);
  lua_setfield (L, -2, "__gc");
  return 1;
}

/*
** Assumes the table is on top of the stack.
*/
static void set_info (lua_State *L) {
  lua_pushliteral (L, "_COPYRIGHT");
  lua_pushliteral (L, "Copyright (C) 2003-2009 Kepler Project");
  lua_settable (L, -3);
  lua_pushliteral (L, "_DESCRIPTION");
  lua_pushliteral (L, "LuaFileSystem is a Lua library developed to complement the set of functions related to file systems offered by the standard Lua distribution");
  lua_settable (L, -3);
  lua_pushliteral (L, "_VERSION");
  lua_pushliteral (L, "LuaFileSystem 1.5.0");
  lua_settable (L, -3);
}

static int get_path_separator(lua_State *L){
#ifdef WIN32
  lua_pushstring(L, "\\");
#else
  lua_pushstring(L, "/");
#endif
  return 1;
}

static const struct luaL_Reg fslib[] = {
  {"dir", dir_iter_factory},
  {"link", make_link},
  {"mkdir", make_dir},
  {"rmdir", remove_dir},
  {"get_path_separator", get_path_separator},
  {NULL, NULL},
};

LUALIB_API int luaopen_lfs(lua_State *L) {
  dir_create_meta (L);
  luaL_newlib(L, fslib);
  set_info (L);
  return 1;
}
