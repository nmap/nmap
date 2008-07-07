#include "nse_init.h"
#include "nse_nmaplib.h"
#include "nse_macros.h"
#include "nse_debug.h"
#include "nse_fs.h"

// 3rd Party libs
#include "nse_pcrelib.h"

#include "nbase.h"

#include "nmap.h"
#include "nmap_error.h"
#include "NmapOps.h"

#include "errno.h"

#include <algorithm>

extern NmapOps o;

extern int current_hosts;
extern int errfunc;

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
 * This function loads a file as a new script.
 * The file is loaded with it's own environment that has access to the Global
 * Environment. The function is tested to be sure it set a global with a valid
 * required_fields[?] ("action", "description", ...), port or host rule.
 * If it did, the script's environment (table) is saved in the global PORTTESTS
 * or HOSTTESTS table.
 */
static int loadfile (lua_State *L)
{
  int i;
  const char *filename = luaL_checkstring(L, 1);
  static const char *required_fields[] = {ACTION, DESCRIPTION};
  lua_settop(L, 1); // removes other arguments

  lua_createtable(L, 0, 11); // Environment for script
  
  lua_pushvalue(L, 1); // tell the script about its filename
  lua_setfield(L, -2, "filename");

  lua_pushnumber(L, 1.0); // set a default RUNLEVEL
  lua_setfield(L, -2, RUNLEVEL);

  lua_createtable(L, 0, 1); // script gets access to global env
  lua_pushvalue(L, LUA_GLOBALSINDEX); // We may want to use G(L)->mainthread 
                                      // later if this function becomes
                                      // exposed. See lstate.h
  lua_setfield(L, -2, "__index");
  lua_setmetatable(L, -2);

  if (luaL_loadfile(L, filename) != 0) // load the file
    luaL_error(L, "'%s' could not be loaded!", filename);
  lua_pushvalue(L, -2); // push environment table
  lua_setfenv(L, -2); // set it
  lua_call(L, 0, 0); // Call the function (loads globals)

  /* Check some required fields */
  for (i = 0; i < ARRAY_LEN(required_fields); i++)
  {
    lua_pushstring(L, required_fields[i]);
    lua_gettable(L, -2);
    if (lua_isnil(L, -1))
      luaL_error(L, "No '%s' field in script '%s'.", required_fields[i],
          filename);
    lua_pop(L, 1);
  }

  /* store the initialized test in either
   * the hosttests or the porttests
   */
  lua_getfield(L, -1, PORTRULE); // script's portrule
  lua_getfield(L, -2, HOSTRULE); // script's hostrule

  /* if we are looking at a portrule then store it in the porttestsets table,
   * else if it is a hostrule, then it goes into the hosttestsets table,
   * otherwise we fail if there.
   */
  if (!lua_isnil(L, -2))
  {
    lua_pop(L, 2); // pop port/host rules
    lua_getglobal(L, PORTTESTS); // Get global PORTTESTS table
    lua_pushvalue(L, -2); // script's environment
    lua_rawseti(L, -2, lua_objlen(L, -2) + 1); // add it
    lua_pop(L, 1); // pop the porttests table
  }
  else if (!lua_isnil(L, -1))
  {
    lua_pop(L, 2);
    lua_getglobal(L, HOSTTESTS);
    lua_pushvalue(L, -2);
    lua_rawseti(L, -2, lua_objlen(L, -2) + 1);
    lua_pop(L, 1); // pop the hosttests table
  }
  else
    luaL_error(L, "No rules in script '%s'.", filename);
  return 0;
}

/* int loaddir (lua_State *L)
 *
 * Arguments
 *   -- directory  Directory (string) to load.
 *
 * Loads all the scripts (files with a .nse extension), using loadfile.
 */
static int loaddir(lua_State *L)
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
 *   ./nselib-bin/  For C Path (.so files)
 */
static int init_setpath (lua_State *L)
{
  char path[MAX_FILENAME_LEN], cpath[MAX_FILENAME_LEN];
  
  /* set the path lua searches for modules*/
  if (nmap_fetchfile(path, MAX_FILENAME_LEN, SCRIPT_ENGINE_LIB_DIR) != 2)
    luaL_error(L, "'%s' not a directory", SCRIPT_ENGINE_LIB_DIR);
  if (nmap_fetchfile(cpath, MAX_FILENAME_LEN, SCRIPT_ENGINE_LIBEXEC_DIR) != 2)
    luaL_error(L, "'%s' not a directory", SCRIPT_ENGINE_LIBEXEC_DIR);

  lua_getfield(L, LUA_REGISTRYINDEX, "_LOADED");
  lua_getfield(L, -1, LUA_LOADLIBNAME); /* "package" */
  lua_pushstring(L, cpath);
#ifdef WIN32
  lua_pushliteral(L, "?.dll;");
#else
  lua_pushliteral(L, "?.so;");
#endif
  lua_getfield(L, -3, "cpath"); /* package.cpath */
  lua_concat(L, 3);
  lua_setfield(L, -2, "cpath");

  lua_pushstring(L, path);
  lua_pushliteral(L, "?.lua;");
  lua_getfield(L, -3, "path"); /* package.path */
  lua_concat(L, 3);
  lua_setfield(L, -2, "path");

  return 0;
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
    {"nmap", luaopen_nmap} // nmap bindings
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

  lua_getglobal(L, "debug"); // _LOADED.debug
  lua_getfield(L, -1, "traceback");
  lua_pushcclosure(L, error_function, 1);
  errfunc = luaL_ref(L, LUA_REGISTRYINDEX);

  lua_pushcclosure(L, init_setpath, 0);
  lua_call(L, 0, 0);
  
  lua_newtable(L);
  current_hosts = luaL_ref(L, LUA_REGISTRYINDEX);

  return 0;
}

/* int init_parseargs (lua_State *L)
 *
 * Arguments
 *   args    Arguments passed through --script-args, or "" if it wasn't used
 * Returns
 *   function    Function that returns a table with the arguments, or an error
 *               message describing why the arguments could not be parsed.
 */
int init_parseargs (lua_State *L)
{
  const char *arg;
  size_t len;

  luaL_checkstring(L, 1);
  luaL_getmetafield(L, 1, "__index"); // string library
  lua_getfield(L, -1, "gsub"); // string.gsub
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
      luaL_loadfile(L, file); // load file
      lua_pushvalue(L, -2); // push environment
      lua_setfenv(L, -2); // set it
      lua_call(L, 0, 0);

      lua_getfield(L, -1, "categories");
      if (lua_isnil(L, -1))
        luaL_error(L, "Script, '%s', being added to the database "
                      "has no categories.", file);

      if (filebase == NULL)
        luaL_error(L, "filename basename could not be generated");

      lua_pushnil(L);
      while (lua_next(L, -2) != 0)
      {
        fprintf(scriptdb, "Entry{ category = \"%s\", filename = \"%s\" }\n",
            lua_tostring(L, -1), filebase);
        lua_pop(L, 1);
      }
      lua_pop(L, 2); // script environment and categories
      free(filebase);
    }
    lua_pop(L, 1); // filename
  }

  if (fclose(scriptdb) != 0)
    luaL_error(L, "Could not close script.db: %s.", strerror(errno));

  return 0;
}

typedef struct extensional_category {
  char *category;
  int option;
} extensional_category;

/* int pick_default_categories (lua_State *L)
 *
 * The function is passed all the scripts/directories/categories passed
 * through --scripts argument. For each of these, we check if a reserved
 * category (currently "version") has been chosen, and raise a fatal error
 * if so. Finally the reserved categories are added. Basically, explicitly
 * adding the reserved categories is illegal.
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
        if (lua_equal(L, j, -1))
        {
          fatal("%s: specifying the \"%s\" category explicitly is not allowed.",
              SCRIPT_ENGINE, lua_tostring(L, -1));
        }
      lua_pop(L, 1);
    }
  }
  else if (o.script == 1)
  {
    // default set of categories
    lua_pushliteral(L, "default");
  }

  // for each in reserved_categories
  for (i = 0; i < ARRAY_LEN(reserved_categories); i++)
    if (reserved_categories[i].option == 1)
      lua_pushstring(L, reserved_categories[i].category);

  return lua_gettop(L);
}

/* int entry (lua_State *L)
 *
 * This function is called from the script.db file. It has two upvalues:
 *   [1] Categories   The categories/files/directories passed via --script.
 *   [2] Files        The Files currently loaded (initially an empty table).
 * A table is passed from the script database with a category and filename.
 * The function tests if either the script's (filename's) category was chosen
 * by checking [1]. Or, it loads the file if [1] has the 'category' "all" and
 * the script's category is not "version".
 */
static int entry (lua_State *L)
{
  char script_path[MAX_FILENAME_LEN];
  int not_all;

  luaL_checktype(L, 1, LUA_TTABLE); // Sole argument is a table
  lua_settop(L, 1);
  lua_getfield(L, 1, "category"); // index 2
  lua_getfield(L, 1, "filename"); // index 3
  if (!(lua_isstring(L, 2) && lua_isstring(L, 3)))
    luaL_error(L, "bad entry in script database");
  lua_pushvalue(L, 3); // filename
  lua_gettable(L, lua_upvalueindex(2)); // already loaded?
  if (!lua_isnil(L, -1))
    return 0;
  lua_pushvalue(L, 2); // category
  lua_gettable(L, lua_upvalueindex(1)); // check 1
  lua_pushliteral(L, "version"); // check 2
  lua_getfield(L, lua_upvalueindex(1), "all"); // check 3

  // if category chosen OR category != "version" and [1].all exists
  if ((not_all = (!lua_isnil(L, -3))) ||
      (!(lua_isnil(L, -1) || lua_equal(L, 2, -2))))
  {
    if (not_all)
      lua_pushvalue(L, 2);
    else
      lua_pushliteral(L, "all");
    lua_pushboolean(L, 1); // set category to true
    lua_settable(L, lua_upvalueindex(1));

    if (nse_fetchfile(script_path, sizeof(script_path),
        lua_tostring(L, 3)) != 1)
      luaL_error(L, "%s: %s is not a file!", lua_tostring(L, 3));
    
    lua_pushvalue(L, 3); // filename
    lua_pushboolean(L, 1);
    lua_settable(L, lua_upvalueindex(2)); // loaded 
    lua_pushcclosure(L, loadfile, 0);
    lua_pushstring(L, script_path);
    lua_call(L, 1, 0);
  }
  return 0;
}

/* int loadcategories (lua_State *L)
 *
 * This function takes all the categories/scripts/directories
 * passed to it and puts them in a table.
 * This table along with an empty one are used as upvalues to the
 * Entry closure (see entry above). Finally, the ./scripts/script.db
 * file is loaded and it's environment set to only include the Entry
 * closure. The entry function will do the work to load all script files with
 * chosen categories. After the script database is executed. Any remainining
 * fields (files/directories and possibly unused categories) are left in the
 * table to be handled later.
 */
static int loadcategories (lua_State *L)
{
  int i, top = lua_gettop(L);
  char c_dbpath[MAX_FILENAME_LEN];
  static const char *dbpath = SCRIPT_ENGINE_LUA_DIR SCRIPT_ENGINE_DATABASE; 

  if (nmap_fetchfile(c_dbpath, sizeof(c_dbpath), dbpath) == 0)
  {
    lua_pushcclosure(L, init_updatedb, 0);
    lua_call(L, 0, 0);
  }

  lua_createtable(L, 0, top); // categories table
  for (i = 1; i <= top; i++)
  {
    lua_pushvalue(L, i); // category/files/directory
    lua_pushboolean(L, 0); // false (not used)
    lua_settable(L, -3);
  }

  luaL_loadfile(L, c_dbpath);
  lua_createtable(L, 0, 1);
  lua_pushliteral(L, "Entry");
  lua_pushvalue(L, -4); // categories table
  lua_newtable(L); // files loaded
  lua_pushcclosure(L, entry, 2);
  lua_settable(L, -3);
  lua_setfenv(L, -2);
  lua_call(L, 0, 0); // Let errors go through

  lua_pushnil(L);
  while (lua_next(L, -2) != 0)
  {
    if (lua_toboolean(L, -1)) // category was used?
    {
      lua_pushvalue(L, -2);
      lua_pushnil(L);
      lua_settable(L, -5); // remove the category
    }
    lua_pop(L, 1);
  }

  return 1; // unused tags (what's left in categories table)
}

/* int init_rules (lua_State *L)
 *
 * Arguments
 *   ...    All the categories/scripts/directories passed via --script
 *
 * This function adds the PORTTESTS and HOSTTESTS globals to the main state.
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
  lua_setglobal(L, PORTTESTS);

  lua_newtable(L);
  lua_setglobal(L, HOSTTESTS);

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
      int rules_count;
      
      lua_getglobal(L, HOSTTESTS);
      rules_count = lua_objlen(L, -1);
      
      lua_getglobal(L, PORTTESTS);
      rules_count += lua_objlen(L, -1);
      lua_pop(L, 2);
      log_write(LOG_STDOUT, "%s: Initialized %d rules\n", SCRIPT_ENGINE, rules_count);
   )
  return 0;
}
