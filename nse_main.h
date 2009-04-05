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

int script_updatedb();
void script_scan_free();

void nse_restore (lua_State *, int);

int open_nse (void);
int script_scan(std::vector<Target *> &targets);
void close_nse (void);

#endif
