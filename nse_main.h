#ifndef NMAP_LUA_H
#define NMAP_LUA_H

#include <vector>
#include <list>
#include <string>
#include <string.h>
#include <iostream>

extern "C" {
  #include "lua.h"
  #include "lauxlib.h"
  #include "lualib.h"
}

#include "nmap.h"
#include "global_structures.h"

class ScriptResult
{
  private:
    std::string output;
    std::string id;
  public:
    void set_output (const char *);
    const char *get_output (void) const;
    void set_id (const char *);
    const char *get_id (void) const;
};

typedef std::list<ScriptResult> ScriptResults;

/* Call this to get a ScriptResults object which can be
 * used to store Pre-Scan and Post-Scan script Results */
ScriptResults *get_script_scan_results_obj (void);

class Target;


/* API */
int nse_yield (lua_State *, int, lua_CFunction);
void nse_restore (lua_State *, int);
void nse_destructor (lua_State *, char);
void nse_base (lua_State *);
void nse_selectedbyname (lua_State *);
void nse_gettarget (lua_State *, int);

void open_nse (void);
void script_scan (std::vector<Target *> &targets, stype scantype);
void close_nse (void);

#define SCRIPT_ENGINE "NSE"

#ifdef WIN32
#  define SCRIPT_ENGINE_LUA_DIR "scripts\\"
#  define SCRIPT_ENGINE_LIB_DIR "nselib\\"
#else
#  define SCRIPT_ENGINE_LUA_DIR "scripts/"
#  define SCRIPT_ENGINE_LIB_DIR "nselib/"
#endif

#define SCRIPT_ENGINE_DATABASE SCRIPT_ENGINE_LUA_DIR "script.db"
#define SCRIPT_ENGINE_EXTENSION ".nse"

#endif
