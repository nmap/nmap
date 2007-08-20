#ifndef NMAP_LUA_H
#define NMAP_LUA_H

#include <vector>
#include <list>
#include <string>
#include <string.h>
#include <iostream>

struct script_scan_result {
	char* id;
	char* output;
};

typedef std::vector<struct script_scan_result> ScriptResults;

class Target;
int script_scan(std::vector<Target *> &targets);
int script_updatedb();

//parses the arguments provided to scripts via nmap's --script-args option 
int script_check_args();
#endif

