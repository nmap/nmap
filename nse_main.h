#ifndef NMAP_LUA_H
#define NMAP_LUA_H

#include <vector>
#include <list>
#include <string>
#include <string.h>
#include <iostream>

extern "C" {
  #include "lua.h"
  #include "lualib.h"
  #include "lauxlib.h"
}

class ScriptResult
{
  private:
    std::string output;
    std::string id;
  public:
    void set_output (const char *);
    std::string get_output (void);
    void set_id (const char *);
    std::string get_id (void);
};

typedef std::vector<ScriptResult> ScriptResults;

class Target;


/* API */
void nse_restore (lua_State *, int);
void nse_destructor (lua_State *, char);

void open_nse (void);
void script_scan (std::vector<Target *> &targets);
void close_nse (void);

int script_updatedb (void);

#define SCRIPT_ENGINE "NSE"

#ifdef WIN32
#  define SCRIPT_ENGINE_LUA_DIR "scripts\\"
#  define SCRIPT_ENGINE_LIB_DIR "nselib\\"
#else
#  define SCRIPT_ENGINE_LUA_DIR "scripts/"
#  define SCRIPT_ENGINE_LIB_DIR "nselib/"
#endif

#define SCRIPT_ENGINE_DATABASE "script.db"
#define SCRIPT_ENGINE_EXTENSION ".nse"

#endif
