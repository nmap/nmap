#ifndef NMAP_LUA_H
#define NMAP_LUA_H

extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}

#include <vector>
#include <list>
#include <string>
#include <string.h>
#include <iostream>

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
int script_scan(std::vector<Target *> &targets);
int script_updatedb();
void script_scan_free();

//parses the arguments provided to scripts via nmap's --script-args option 
int script_check_args();

int process_waiting2running(lua_State *, int);

/* Useful auxiliary functions */
size_t table_length(lua_State *, int);


#endif
