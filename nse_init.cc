#include "nse_init.h"
#include "nse_nmaplib.h"
#include "nse_macros.h"
#include "nse_debug.h"
#include "nse_fs.h"

// 3rd Party libs
#include "nse_pcrelib.h"
#include "nse_bit.h"

#include "nse_binlib.h"
#include "nse_hash.h"

#include "nbase.h"

#include "nmap.h"
#include "nmap_error.h"
#include "NmapOps.h"

#include "errno.h"

#include <algorithm>

extern NmapOps o;

extern int current_hosts;
extern int errfunc;

#define REQUIRE_ERRORS "require_error"

/* int error_function (lua_State *L)
 *
 * Arguments:
 *   -- error_message  (passed by Lua)
 *
 * This function is for use with lua_pcall as the error handler.
 * Because the stack is not unwound when this is called,
 * we are able to obtain a traceback of the current stack frame.
 * We use debug.traceback (an upvalue set in init_lua) for the real work.
 */
static int error_function (lua_State *L) // for use with lua_pcall
{
  luaL_where(L, 1);
  lua_insert(L, 1);
  lua_pushvalue(L, lua_upvalueindex(1)); // debug.traceback
  lua_pushthread(L);
  lua_pushliteral(L, "");
  lua_pushinteger(L, 2);
  lua_call(L, 3, 1);
  lua_concat(L, 3);
  return 1;
}

/* int loadfile (lua_State *L)
 *
 * Arguments
 *   -- filename  File to load
 *
 * This function loads a file as a new script, unless it has already been
 * loaded.
 *
 * The file is loaded with it's own environment that has access to the Global
 * Environment. The function is tested to be sure it set a global with a valid
 * required_fields[?] ("action", "description", ...), port or host rule.
 * If it did, the script is added to the SCRIPTFILES table and the script's
 * PORT/HOST rule (function) is saved in the registry PORTTESTS or HOSTTESTS
 * table with its file closure as a value. This is important to allow each
 * thread to have its own action closure with its own locals.
 */
static int loadfile (lua_State *L)
{
  int i;
  const char *filename = luaL_checkstring(L, 1);
  static const char *required_fields[] = {ACTION, DESCRIPTION};

  lua_settop(L, 1); // removes other arguments

  /* Is this file already loaded? */
  lua_getfield(L, LUA_REGISTRYINDEX, SCRIPTFILES);
  lua_pushvalue(L, 1);
  lua_gettable(L, -2);
  if (lua_toboolean(L, -1))
    return 0;
  lua_pop(L, 2);

  lua_createtable(L, 0, 11); // Environment for script (index 2)
  
  lua_pushvalue(L, 1); // tell the script about its filename
  lua_setfield(L, -2, FILENAME);

  lua_pushnumber(L, 1.0); // set a default RUNLEVEL
  lua_setfield(L, -2, RUNLEVEL);

  lua_createtable(L, 0, 1); // script gets access to global env
  lua_pushvalue(L, LUA_GLOBALSINDEX); // We may want to use G(L)->mainthread 
                                      // later if this function becomes
                                      // exposed. See lstate.h
  lua_setfield(L, -2, "__index");
  lua_setmetatable(L, -2);

  if (luaL_loadfile(L, filename) != 0) // load the file (index 3)
  {
    error("%s: '%s' could not be compiled.", SCRIPT_ENGINE, filename);
    SCRIPT_ENGINE_DEBUGGING(
      error("%s", lua_tostring(L, -1));
    )
    return 0;
  }
  lua_pushvalue(L, -1);
  lua_pushvalue(L, 2); // push environment table
  lua_setfenv(L, -2); // set it
  if (lua_pcall(L, 0, 0, 0) != 0) // Call the function (loads globals)
  {
    // Check for dependency errors
    lua_getfield(L, LUA_REGISTRYINDEX, REQUIRE_ERRORS);
    lua_pushvalue(L, -2); // the error
    lua_gettable(L, -2);
    if (lua_toboolean(L, -1)) // The error was thrown by require
    {
      if (o.verbose > 3 && !o.debugging)
        error("%s: '%s' could not be loaded due to missing dependency '%s'",
            SCRIPT_ENGINE, filename, lua_tostring(L, -1));
      SCRIPT_ENGINE_DEBUGGING(
        error("%s: '%s' threw a run time error and could not be loaded.\n%s",
            SCRIPT_ENGINE, filename, lua_tostring(L, -3));
      )
    } else {
      error("%s: '%s' threw a run time error and could not be loaded.",
          SCRIPT_ENGINE, filename);
      SCRIPT_ENGINE_DEBUGGING(
        error("%s", lua_tostring(L, -3));
      )
    }
    return 0;
  }

  // Check some required fields
  for (i = 0; i < ARRAY_LEN(required_fields); i++)
  {
    lua_pushstring(L, required_fields[i]);
    lua_gettable(L, 2);
    if (lua_isnil(L, -1))
    {
      error("%s: '%s' does not have required field '%s'", SCRIPT_ENGINE, filename,
          required_fields[i]);
      return 0;
    }
    lua_pop(L, 1);
  }

  /* store the initialized test in either
   * the hosttests or the porttests
   */
  lua_getfield(L, 2, PORTRULE); // script's portrule
  lua_getfield(L, 2, HOSTRULE); // script's hostrule

  /* if we are looking at a portrule then store it in the porttestsets table,
   * else if it is a hostrule, then it goes into the hosttestsets table,
   * otherwise we fail if there.
   */
  if (!lua_isnil(L, -2)) // script has a port rule
  {
    lua_getfield(L, LUA_REGISTRYINDEX, PORTTESTS); // Get PORTTESTS table
    lua_pushvalue(L, -3); // script's portrule
    lua_pushvalue(L, 3); // script's file closure
    lua_getfenv(L, -1);
    lua_pushliteral(L, FILENAME);
    lua_pushvalue(L, 1); // filename
    lua_settable(L, -3);
    lua_pop(L, 1); // file closure environment
    lua_settable(L, -3);
  }
  else if (!lua_isnil(L, -1)) // script has a hostrule
  {
    lua_getfield(L, LUA_REGISTRYINDEX, HOSTTESTS);
    lua_pushvalue(L, -2); // script's hostrule
    lua_pushvalue(L, 3); // script's file closure
    lua_getfenv(L, -1);
    lua_pushliteral(L, FILENAME);
    lua_pushvalue(L, 1); // filename
    lua_settable(L, -3);
    lua_pop(L, 1); // file closure environment
    lua_settable(L, -3);
  }
  else
    error("%s: '%s' does not have a portrule or hostrule.", SCRIPT_ENGINE,
        filename);

  /* Record the file as loaded. */
  lua_getfield(L, LUA_REGISTRYINDEX, SCRIPTFILES);
  lua_pushstring(L, filename);
  lua_pushboolean(L, true);
  lua_settable(L, -3);
  lua_pop(L, 1);

  return 0;
}

/* int loaddir (lua_State *L)
 *
 * Arguments
 *   -- directory  Directory (string) to load.
 *
 * Loads all the scripts (files with a .nse extension), using loadfile.
 */
static int loaddir (lua_State *L)
{
  int i;
  luaL_checkstring(L, 1); // directory to load
  
  lua_pushcclosure(L, nse_scandir, 0);
  lua_pushvalue(L, 1);
  lua_pushinteger(L, FILES);
  lua_call(L, 2, 1);

  lua_pushcclosure(L, loadfile, 0);
  for (i = 1; i <= (int) lua_objlen(L, -2); i++)
  {
    lua_pushvalue(L, -1); // loadfile closure
    lua_rawgeti(L, -3, i); // filename
    lua_call(L, 1, 0); // load it
  }
  return 0;
}

/* int init_setpath (lua_State *L)
 *
 * Sets the search path of require function to include:
 *   ./nselib/   For Lua Path (.lua files)
 */
static int init_setpath (lua_State *L)
{
  char path[MAX_FILENAME_LEN];
  
  /* set the path lua searches for modules*/
  if (nmap_fetchfile(path, MAX_FILENAME_LEN, SCRIPT_ENGINE_LIB_DIR) != 2)
    luaL_error(L, "'%s' not a directory", SCRIPT_ENGINE_LIB_DIR);

  lua_getfield(L, LUA_REGISTRYINDEX, "_LOADED");
  lua_getfield(L, -1, LUA_LOADLIBNAME); /* "package" */

  lua_pushstring(L, path);
  lua_pushliteral(L, "?.lua;");
  lua_getfield(L, -3, "path"); /* package.path */
  lua_concat(L, 3);
  lua_setfield(L, -2, "path");

  return 0;
}

/* int nse_require (lua_State *L)
 *
 * This hooks the standard require function to allow us to properly catch
 * dependency errors. Basically an error message is saved in the error table
 * (upvalue 1) that can be indexed later to check if it was unhandled by
 * the script (see loadfile in particular).
 */
static int nse_require (lua_State *L)
{
  luaL_checkstring(L, 1); // ensure first argument is a string
  lua_pushvalue(L, 1);
  lua_insert(L, 1); // save a copy of the library name at stack bottom
  lua_pushvalue(L, lua_upvalueindex(1)); // require function
  lua_insert(L, 2);
  if (lua_pcall(L, lua_gettop(L)-2, LUA_MULTRET, 0) != 0)
  {
    lua_pushvalue(L, -1); // the error message
    lua_pushvalue(L, 1); // the library name that caused the error
    lua_settable(L, lua_upvalueindex(2));
    return lua_error(L);
  }
  return lua_gettop(L)-1; // omit the saved first argument
}

/* int init_lua (lua_State *L)
 *
 * Initializes the Lua State.
 * Opens standard libraries as well as nmap and pcre.
 * Sets an error function for use by pcall.
 * Sets the path for require.
 */
int init_lua (lua_State *L)
{
  int i;
  static const luaL_Reg libs[] = {
    {NSE_PCRELIBNAME, luaopen_pcrelib}, // pcre library
    {"nmap", luaopen_nmap}, // nmap bindings
    {NSE_BINLIBNAME, luaopen_binlib},
    {NSE_HASHLIBNAME, luaopen_hashlib},
    {BITLIBNAME, luaopen_bit}, // bit library
  };

  luaL_openlibs(L); // opens all standard libraries

  lua_getfield(L, LUA_REGISTRYINDEX, "_LOADED"); // Loaded libraries
  for (i = 0; i < ARRAY_LEN(libs); i++) // for each in libs
  {
    lua_pushstring(L, libs[i].name);
    lua_pushcclosure(L, libs[i].func, 0);
    lua_pushvalue(L, -2);
    lua_call(L, 1, 1);
    if (lua_isnil(L, -1))
    {
      lua_getglobal(L, libs[i].name); // library?
      if (!lua_istable(L, -1))
      {
        lua_pop(L, 2);
        lua_pushboolean(L, true);
      }
      else
        lua_replace(L, -2);
    }
    lua_settable(L, -3);
  }
  lua_pop(L, 1); // _LOADED

  lua_getglobal(L, "debug"); // debug
  lua_getfield(L, -1, "traceback"); lua_replace(L, -2); // replace debug table
  lua_pushcclosure(L, error_function, 1);
  errfunc = luaL_ref(L, LUA_REGISTRYINDEX);

  lua_pushcclosure(L, init_setpath, 0);
  lua_call(L, 0, 0);
  
  lua_newtable(L);
  current_hosts = luaL_ref(L, LUA_REGISTRYINDEX);

  lua_newtable(L); // nse_require error table
  lua_createtable(L, 0, 1); // metatable
  lua_pushliteral(L, "k");
  lua_setfield(L, -2, "__mode"); // weak keys
  lua_setmetatable(L, -2);
  lua_getglobal(L, "require");
  lua_pushvalue(L, -2); // nse_require error table
  lua_pushcclosure(L, nse_require, 2);
  lua_setglobal(L, "require");
  lua_setfield(L, LUA_REGISTRYINDEX, REQUIRE_ERRORS); // save nse_require table

  return 0;
}

/* int init_parseargs (lua_State *L)
 *
 * Arguments
 *   args    Arguments passed through --script-args
 * Returns
 *   function    Function that returns a table with the arguments, or an error
 *               message describing why the arguments could not be parsed.
 */
int init_parseargs (lua_State *L)
{
  const char *arg;
  size_t len;

  luaL_checkstring(L, 1);
  lua_getfield(L, 1, "gsub"); // string.gsub
  lua_pushvalue(L, 1);
  lua_pushliteral(L, "=([^{},]+)"); // make strings quoted
  lua_pushliteral(L, "=\"%1\"");
  lua_call(L, 3, 1);

  lua_pushliteral(L, "return {");
  lua_insert(L, -2);
  lua_pushliteral(L, "}");
  lua_concat(L, 3);
  arg = lua_tolstring(L, -1, &len);
  luaL_loadbuffer(L, arg, len, "Script-Args");

  return 1; // return function from luaL_loadbuffer or error message returned
}

/* int init_setargs (lua_State *L)
 *
 * Takes the function returned by init_parseargs(), calls it, and puts
 * the returned table in nmap.registry.args
 */
int init_setargs (lua_State *L)
{
  lua_getglobal(L, "nmap");
  lua_getfield(L, -1, "registry");

  lua_pushcclosure(L, init_parseargs, 0);
  lua_pushstring(L, o.scriptargs);
  lua_call(L, 1, 1);

  if (!lua_isfunction(L, -1))
    luaL_error(L, "Bad script arguments!\n\t%s", lua_tostring(L, -1));

  lua_call(L, 0, 1); /* get returned table */

  lua_setfield(L, -2, "args");

  return 0;
}

/* int init_updatedb (lua_State *L)
 *
 * Loads all the files in ./scripts and puts them in the database.
 * Each file is loaded and for each of its categories, an entry in the
 * database is made in the following format:
 *   Entry{ category = "category1", filename = "somefile" }\n"
 *   Entry{ category = "category2", filename = "somefile" }\n"
 * Each file will have an entry per category.
 */
int init_updatedb (lua_State *L)
{
  int i;
  char path[MAX_FILENAME_LEN];
  FILE *scriptdb;
  lua_settop(L, 0); // clear all args

  if (nmap_fetchfile(path, sizeof(path) - sizeof(SCRIPT_ENGINE_DATABASE),
        SCRIPT_ENGINE_LUA_DIR) == 0)
    luaL_error(L, "Couldn't find '%s'", SCRIPT_ENGINE_LUA_DIR);

  lua_pushcclosure(L, nse_scandir, 0);
  lua_pushstring(L, path);
  lua_pushinteger(L, FILES);
  lua_call(L, 2, 1); // get all the .nse files in ./scripts

  // we rely on the fact that nmap_fetchfile returned a string which leaves enough room
  // to append the db filename (see call to nmap_fetchfile above)
  strncat(path, SCRIPT_ENGINE_DATABASE, MAX_FILENAME_LEN-1);

  scriptdb = fopen(path, "w");
  if (scriptdb == NULL)
    luaL_error(L, "Could not open file '%s' for writing.", path);

  SCRIPT_ENGINE_DEBUGGING(
      log_write(LOG_STDOUT, "%s: Trying to add %u scripts to the database.\n", 
        SCRIPT_ENGINE, lua_objlen(L, 1));
      )

  // give the script global namespace access
  lua_createtable(L, 0, 1); // metatable
  lua_pushvalue(L, LUA_GLOBALSINDEX);
  lua_setfield(L, -2, "__index");

  for (i = 1; i <= (int) lua_objlen(L, 1); i++)
  {
    const char *file;
    lua_rawgeti(L, 1, i); // integer key from scan_dir() table
    file = lua_tostring(L, -1);
    if (nse_check_extension(SCRIPT_ENGINE_EXTENSION, file) &&
        strstr(file, SCRIPT_ENGINE_DATABASE) == NULL)
    {
      char *filebase = path_get_basename(file);
      lua_newtable(L); // script environment
      lua_pushvalue(L, -3); // script metatable
      lua_setmetatable(L, -2); // set it
      if (luaL_loadfile(L, file) != 0) // load file
        luaL_error(L, "file '%s' could not be loaded", file);
      lua_pushvalue(L, -2); // push environment
      lua_setfenv(L, -2); // set it
      lua_call(L, 0, 0);

      lua_getfield(L, -1, "categories");
      if (lua_isnil(L, -1))
        luaL_error(L, "Script, '%s', being added to the database "
                      "has no categories.", file);

      if (filebase == NULL)
        luaL_error(L, "filename basename could not be generated");

      lua_getglobal(L, "string");
      lua_getfield(L, -1, "lower"); lua_replace(L, -2);
      lua_pushnil(L);
      while (lua_next(L, -3) != 0)
      {
        lua_pushvalue(L, -3); // string.lower
        lua_insert(L, -2); // put below category string
        lua_call(L, 1, 1); // lowered string on stack
        fprintf(scriptdb, "Entry{ category = \"%s\", filename = \"%s\" }\n",
            lua_tostring(L, -1), filebase);
        lua_pop(L, 1);
      }
      lua_pop(L, 3); // script environment, categories, string.lower
      free(filebase);
    }
    lua_pop(L, 1); // filename
  }

  if (fclose(scriptdb) != 0)
    luaL_error(L, "Could not close script.db: %s.", strerror(errno));

  return 0;
}

typedef struct extensional_category {
  const char *category;
  int option;
} extensional_category;

/* int pick_default_categories (lua_State *L)
 *
 * This function takes as arguments all the scripts/categories/directories
 * passed to the --script command line option, and augments them with any other
 * categories that should be added. These are "default" if script scanning was
 * requested and no scripts were given on the command line, and "version" if
 * version scanning was requested.
 *
 * If a "reserved" category (currently only "version") was listed on the command
 * line, give a fatal error.
 */
static int pick_default_categories (lua_State *L)
{
  int i, top = lua_gettop(L);
  extensional_category reserved_categories[] = {
    {"version", o.scriptversion},
  };

  if (top > 0)
  {
    // if they tried to explicitely select an implicit category, we complain
    // ... for each in reserved_categories
    for (i = 0; i < ARRAY_LEN(reserved_categories); i++)
    {
      int j;
      lua_pushstring(L, reserved_categories[i].category);
      for (j = 1; j <= top; j++)
      {
        lua_getglobal(L, "string");
        lua_getfield(L, -1, "lower"); lua_replace(L, -2);
        lua_pushvalue(L, j);
        lua_call(L, 1, 1);
        if (lua_equal(L, -1, -2))
        {
          fatal("%s: specifying the \"%s\" category explicitly is not allowed.",
              SCRIPT_ENGINE, lua_tostring(L, -1));
        }
        lua_pop(L, 1);
      }
      lua_pop(L, 1);
    }
  }
  else if (o.script == 1)
    lua_pushliteral(L, "default"); // default set of categories

  // for each in reserved_categories
  for (i = 0; i < ARRAY_LEN(reserved_categories); i++)
    if (reserved_categories[i].option == 1)
      lua_pushstring(L, reserved_categories[i].category);

  return lua_gettop(L);
}

/* int entry (lua_State *L)
 *
 * This function is called for each line of script.db, and is responsible for
 * loading the scripts that are in requested categories.
 *
 * script.db is executable Lua code that makes calls to this function, with
 * lines like
 *
 *  Entry{ category = "default", filename = "script.nse" }
 *
 * The function has one upvalue, which is used to accumulate results while the
 * database is executed. It is a table of the categories/scripts/directories
 * requested, all initially mapping to false, plus canonicalization mappings
 * (see loadcategories).
 *
 * This function receives a table with a category and a filename. A filename is
 * loaded if
 *   1. its category is in the list of requested categories/scripts/directories,
 *      or
 *   2. the category "all" was requested and the category of the script is not
 *      "version".
 */
static int entry (lua_State *L)
{
  char script_path[MAX_FILENAME_LEN];
  int not_all;

  luaL_checktype(L, 1, LUA_TTABLE); // Sole argument is a table
  lua_settop(L, 1);
  lua_getfield(L, 1, CATEGORY); // index 2
  lua_getfield(L, 1, FILENAME); // index 3
  if (!(lua_isstring(L, 2) && lua_isstring(L, 3)))
    luaL_error(L, "bad entry in script database");
  lua_pushvalue(L, 3); // filename

  /* Push values that are used to decide whether to load this file. */
  lua_pushvalue(L, 2); // Category name.
  lua_gettable(L, lua_upvalueindex(1)); // If non-nil: a requested category.
  lua_pushliteral(L, "version"); // For literal comparison against the "version" category.
  lua_getfield(L, lua_upvalueindex(1), "all"); // If non-nil: "all" was requested.

  // If category chosen OR ("all" chosen AND category != "version")
  if ((not_all = (!lua_isnil(L, -3))) ||
      (!(lua_isnil(L, -1) || lua_equal(L, 2, -2))))
  {
    /* Mark this category as used. */
    if (not_all)
      lua_pushvalue(L, 2);
    else
      lua_pushliteral(L, "all");
    lua_pushvalue(L, -1);
    lua_gettable(L, lua_upvalueindex(1));

    /* Is this a canonicalization entry pointing to the real key? (See
     * loadcategories.) */
    if (!lua_isboolean(L, -1)) // points to real key?
    {
      /* If yes, point the real key to true. */
      lua_pushvalue(L, -1);
      lua_pushboolean(L, true);
      lua_settable(L, lua_upvalueindex(1));
    }
    else
    {
      /* If no, just point the category name to true. */
      lua_pushvalue(L, -2);
      lua_pushboolean(L, true);
      lua_settable(L, lua_upvalueindex(1));
    }
    lua_pop(L, 1); // Pop Boolean.

    /* Load the file and insert its name into the second upvalue, the table of
     * loaded filenames. The value is true. */
    if (nse_fetchfile(script_path, sizeof(script_path),
        lua_tostring(L, 3)) != 1)
      luaL_error(L, "%s is not a file!", lua_tostring(L, 3));

    /* Finally, load the file (load its portrule or hostrule). */
    lua_pushcclosure(L, loadfile, 0);
    lua_pushstring(L, script_path);
    lua_call(L, 1, 0);
  }
  return 0;
}

/* int loadcategories (lua_State *L)
 *
 * This function takes all the categories/scripts/directories passed to it,
 * loads the script files belonging to any of the arguments that are categories,
 * and returns what's left over (script filenames, directory names, or possibly
 * unused category names) in a table. The unused names all map to false. */
static int loadcategories (lua_State *L)
{
  int i, top = lua_gettop(L);
  char c_dbpath[MAX_FILENAME_LEN];
  static const char *dbpath = SCRIPT_ENGINE_LUA_DIR SCRIPT_ENGINE_DATABASE; 

  /* Build the script database if it doesn't exist. */
  if (nmap_fetchfile(c_dbpath, sizeof(c_dbpath), dbpath) == 0)
  {
    lua_pushcclosure(L, init_updatedb, 0);
    lua_call(L, 0, 0);
  }

  /* Create a table that is used to keep track of which categories/scripts/
   * directories are used and unused. (Because this function deals only with
   * categories, script filenames and directory names always come out unused.)
   * We build a table with every script/category/directory mapped to false.
   * Additionally we map a lower-case version of every string to the original
   * string (this is to canonicalize category names). Logic in the entry
   * function checks for this canonicalization step.
   *
   * The entry function adjusts the values in the table to true as files are
   * loaded. Later, all the keys that map to true are removed, leaving only the
   * unused scripts/categories/directories. Because all strings are considered
   * true, the canonicalization entries will be considered "used" and
   * removed as well. */
  lua_createtable(L, 0, top); // categories table
  for (i = 1; i <= top; i++)
  {
    /* Create the canonicalization entry mapping the lower-case string to the
     * original string. Do this first in case the string maps to itself (i.e.,
     * it was lower-case to begin with). In that case the mapping to false will
     * replace this mapping, and no canonicalization is needed. */
    lua_getglobal(L, "string");
    lua_getfield(L, -1, "lower"); lua_replace(L, -2);
    lua_pushvalue(L, i); // Category/script/directory.
    lua_call(L, 1, 1); // Canonicalize it.
    lua_pushvalue(L, i);
    lua_settable(L, -3);

    /* Now map the name to false, meaning we assume the category/script/
     * directory is unused until the entry function marks it as used. */
    lua_pushvalue(L, i); // Category/script/directory.
    lua_pushboolean(L, false);
    lua_settable(L, -3);
  }

  /* Execute script.db with the Entry closure as the only thing in its
   * environment (see the entry function). Entry has an upvalue: the used/unused
   * table just created. Entry will mark categories/scripts/directories as used
   * in the table as files are loaded. */
  luaL_loadfile(L, c_dbpath);
  lua_createtable(L, 0, 1);
  lua_pushliteral(L, "Entry");
  lua_pushvalue(L, -4); // Used/unused table.
  lua_pushcclosure(L, entry, 1);
  lua_settable(L, -3);
  lua_setfenv(L, -2); // Put the Entry function in the global environment.
  lua_call(L, 0, 0); // Execute the script database, letting errors go through.

  /* Go through and remove all the used categories, leaving only the unused
   * categories/scripts/directories. */
  lua_pushnil(L);
  while (lua_next(L, -2) != 0)
  {
    if (lua_toboolean(L, -1)) // If used
    {
      lua_pushvalue(L, -2);
      lua_pushnil(L);
      lua_settable(L, -5); // remove the category
    }
    lua_pop(L, 1);
  }

  return 1; // Table of unused categories/scripts/directories.
}

/* int init_rules (lua_State *L)
 *
 * Arguments
 *   ...    All the categories/scripts/directories passed via --script
 *
 * This function adds the PORTTESTS and HOSTTESTS to the main state.
 * Then it calls pick_default_categories to check for illegally passed implicit
 * categories (which it will add otherwise). Next, loadcategories is called
 * to load all the viable files for which a category was chosen. The unused
 * tags (files/directories, and possibly unused or invalid categories) are
 * then each loaded (attempted). If any do not load then an error is raised.
 */
int init_rules (lua_State *L)
{
  int top = lua_gettop(L); // number of categories/scripts

  lua_newtable(L);
  lua_setfield(L, LUA_REGISTRYINDEX, PORTTESTS);

  lua_newtable(L);
  lua_setfield(L, LUA_REGISTRYINDEX, HOSTTESTS);

  /* This table holds a list of all loaded script filenames, to avoid loading
   * any more than once. */
  lua_newtable(L);
  lua_setfield(L, LUA_REGISTRYINDEX, SCRIPTFILES);

  lua_pushcclosure(L, pick_default_categories, 0);
  lua_insert(L, 1);
  lua_call(L, top, LUA_MULTRET);
  top = lua_gettop(L); // new number of categories & scripts

  lua_pushcclosure(L, loadcategories, 0);
  lua_insert(L, 1);
  lua_call(L, top, 1); // returns unused tags table

  lua_pushcclosure(L, loadfile, 0);
  lua_pushnil(L);
  while (lua_next(L, -3) != 0)
  {
	char path[MAX_FILENAME_LEN];
    int type = nse_fetchfile_absolute(path, sizeof(path),
        lua_tostring(L, -2));

    if (type == 0)
    {
      lua_pushvalue(L, -2); // copy of key
      lua_pushliteral(L, SCRIPT_ENGINE_EXTENSION);
      lua_concat(L, 2);
      lua_replace(L, -2); // remove value
      type = nse_fetchfile_absolute(path, sizeof(path), lua_tostring(L, -1));
    }
    
    switch (type)
    {
      case 0: // no such path
        luaL_error(L, "No such category, file or directory: '%s'",
            lua_tostring(L, -2));
      case 1: // nmap_fetchfile returned a file
        if (!nse_check_extension(SCRIPT_ENGINE_EXTENSION, path))
        {
          error("%s: Warning: Loading '%s' - the recommended file extension is '.nse'.",
              SCRIPT_ENGINE, path);
        }
        lua_pushvalue(L, -3); // loadfile closure
        lua_pushstring(L, path);
        lua_call(L, 1, 0);
        break;
      case 2: // nmap_fetchfile returned a dir
        lua_pushcclosure(L, loaddir, 0);
        lua_pushstring(L, path);
        lua_call(L, 1, 0);
        break;
      default:
        fatal("%s: In: %s:%i This should never happen.", 
            SCRIPT_ENGINE, __FILE__, __LINE__);
    }
    lua_pop(L, 1);
  }

  // Compute some stats 
  SCRIPT_ENGINE_DEBUGGING(
      size_t rules_count;
      lua_getfield(L, LUA_REGISTRYINDEX, HOSTTESTS);
      lua_getfield(L, LUA_REGISTRYINDEX, PORTTESTS);
      rules_count = table_length(L, -2) + table_length(L, -1);
      lua_pop(L, 2);
      log_write(LOG_STDOUT, "%s: Initialized %d rules\n", SCRIPT_ENGINE, rules_count);
   )
  return 0;
}
