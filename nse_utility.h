#ifndef NMAP_NSE_UTILITY_H
#define NMAP_NSE_UTILITY_H

size_t table_length (lua_State *, int);
void setsfield (lua_State *, int, const char *, const char *);
void setnfield (lua_State *, int, const char *, lua_Number);
void setbfield (lua_State *, int, const char *, int);
void weak_table (lua_State *, int, int, const char *);

int success (lua_State *);
int safe_error (lua_State *, const char *, ...);

void check_target (lua_State *, int, const char **, const char **);
unsigned short check_port (lua_State *, int, const char **);

Target *get_target (lua_State *, int);
Port *get_port (lua_State *, Target *, Port *, int);

#endif
