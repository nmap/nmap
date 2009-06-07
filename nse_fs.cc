
extern "C" {
  #include "lua.h"
  #include "lauxlib.h"
}

#include <vector>
#include <string>
#include <string.h>

#ifndef WIN32
#include "dirent.h"
#endif

#include "errno.h"
#include "nse_fs.h"
#include "nmap.h"
#include "nmap_error.h"
#include "NmapOps.h"

#define MAX_FILENAME_LEN 4096

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

/* This is simply the most portable way to check
 * if a file has a given extension.
 * The portability comes at the price of reduced
 * flexibility.
 */
int nse_check_extension (const char* ext, const char* path)
{
  int pathlen = strlen(path);
  int extlen = strlen(ext);
  if (extlen > pathlen || pathlen > MAX_FILENAME_LEN)
    return 0;
  else
    return strcmp(path + pathlen - extlen, ext) == 0;
}

int nse_fetchfile(char *path, size_t path_len, const char *file) {
  int type = nmap_fetchfile(path, path_len, file);

  // lets look in <nmap>/scripts too
  if(type == 0) {
    std::string alt_path = std::string(SCRIPT_ENGINE_LUA_DIR) + std::string(file);
    type = nmap_fetchfile(path, path_len, alt_path.c_str());
  }

  return type;
}

/* This is a modification of nse_fetchfile that first looks for an
 * absolute file name.
 */
int nse_fetchfile_absolute(char *path, size_t path_len, const char *file) {
  if (filename_is_absolute(file)) {
    if (o.debugging > 1)
      log_write(LOG_STDOUT, "%s: Trying absolute path %s\n", SCRIPT_ENGINE, file);
    Strncpy(path, file, path_len);
    return nmap_fileexistsandisreadable(file);
  }

  return nse_fetchfile(path, path_len, file);
}

#ifdef WIN32

int nse_scandir (lua_State *L) {
  HANDLE dir;
  WIN32_FIND_DATA entry;
  std::string path;
  BOOL morefiles = FALSE;
  const char *dirname = luaL_checkstring(L, 1);
  int files_or_dirs = luaL_checkint(L, 2);

  lua_createtable(L, 100, 0); // 100 files average

  dir = FindFirstFile((std::string(dirname) + "\\*").c_str(), &entry);

  if (dir == INVALID_HANDLE_VALUE)
  {
    error("%s: No files in '%s\\*'", SCRIPT_ENGINE, dirname);
    return 0;
  }

  while(!(morefiles == FALSE && GetLastError() == ERROR_NO_MORE_FILES)) {
    // if we are looking for files and this file doesn't end with .nse or
    // is a directory, then we don't look further at it
    if(files_or_dirs == NSE_FILES) {
      if(!((nse_check_extension(SCRIPT_ENGINE_EXTENSION, entry.cFileName))
            && !(entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
          )) {
        morefiles = FindNextFile(dir, &entry);
        continue;
      }

      // if we are looking for dirs and this dir
      // isn't a directory, then we don't look further at it
    } else if(files_or_dirs == NSE_DIRS) {
      if(!(entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
        morefiles = FindNextFile(dir, &entry);
        continue;
      }

      // they have passed an invalid value for files_or_dirs
    } else {
      fatal("%s: In: %s:%i This should never happen.",
        SCRIPT_ENGINE, __FILE__, __LINE__);
    }

    // otherwise we add it to the results
    // we assume that dirname ends with a directory separator of some kind
    path = std::string(dirname) + "\\" + std::string(entry.cFileName);
    lua_pushstring(L, path.c_str());
    lua_rawseti(L, -2, lua_objlen(L, -2) + 1);
    morefiles = FindNextFile(dir, &entry);
  }


  return 1;
}

#else

int nse_scandir (lua_State *L) {
  DIR* dir;
  struct dirent* entry;
  struct stat stat_entry;
  const char *dirname = luaL_checkstring(L, 1);
  int files_or_dirs = luaL_checkint(L, 2);

    lua_createtable(L, 100, 0); // 100 files average

  dir = opendir(dirname);
  if(dir == NULL) {
    error("%s: Could not open directory '%s'.", SCRIPT_ENGINE, dirname);
    return 0;
  }

  // note that if there is a symlink in the dir, we have to rely on
  // the .nse extension
  // if they provide a symlink to a dir which ends with .nse, things
  // break :/
  while((entry = readdir(dir)) != NULL) {
    std::string path = std::string(dirname) + "/" + std::string(entry->d_name);

    if(stat(path.c_str(), &stat_entry) != 0)
      fatal("%s: In: %s:%i This should never happen.",
        SCRIPT_ENGINE, __FILE__, __LINE__);

    // if we are looking for files and this file doesn't end with .nse and
    // isn't a file or a link, then we don't look further at it
    if(files_or_dirs == NSE_FILES) {
      if(!(nse_check_extension(SCRIPT_ENGINE_EXTENSION, entry->d_name)
           && (S_ISREG(stat_entry.st_mode)
               || S_ISLNK(stat_entry.st_mode))
          )) {
        continue;
      }

      // if we are looking for dirs and this dir
      // isn't a dir or a link, then we don't look further at it
    } else if(files_or_dirs == NSE_DIRS) {
      if(!(S_ISDIR(stat_entry.st_mode)
           || S_ISLNK(stat_entry.st_mode)
          )) {
        continue;
      }

      // they have passed an invalid value for files_or_dirs
    } else {
      fatal("%s: In: %s:%i This should never happen.",
        SCRIPT_ENGINE, __FILE__, __LINE__);
    }

    // otherwise we add it to the results
    lua_pushstring(L, path.c_str());
    lua_rawseti(L, -2, lua_objlen(L, -2) + 1);
  }

  closedir(dir);

  return 1;
}

#endif
