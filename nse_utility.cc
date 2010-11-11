#include <stdlib.h>
#include <stdarg.h>

#include "Target.h"
#include "portlist.h"

#include "nse_main.h"
#include "nse_utility.h"

/* size_t table_length (lua_State *L, int index)
 *
 * Returns the length of the table at index index.
 * This length is the number of elements, not just array elements.
 */
size_t table_length (lua_State *L, int index)
{
  size_t len = 0;

  lua_pushvalue(L, index);
  lua_pushnil(L);
  while (lua_next(L, -2))
  {
    len++;
    lua_pop(L, 1);
  }
  lua_pop(L, 1);

  return len;
}

void setsfield (lua_State *L, int idx, const char *field, const char *what)
{
  lua_pushvalue(L, idx);
  lua_pushstring(L, what); /* what can be NULL */
  lua_setfield(L, -2, field);
  lua_pop(L, 1);
}

void setnfield (lua_State *L, int idx, const char *field, lua_Number n)
{
  lua_pushvalue(L, idx);
  lua_pushnumber(L, n);
  lua_setfield(L, -2, field);
  lua_pop(L, 1);
}

void setbfield (lua_State *L, int idx, const char *field, int b)
{
  lua_pushvalue(L, idx);
  lua_pushboolean(L, b);
  lua_setfield(L, -2, field);
  lua_pop(L, 1);
}

int success (lua_State *L)
{
  lua_pushboolean(L, true);
  return 1;
}

int safe_error (lua_State *L, const char *fmt, ...)
{
  va_list va;
  lua_pushboolean(L, false);
  va_start(va, fmt);
  lua_pushvfstring(L, fmt, va);
  va_end(va);
  return 2;
}

void weak_table (lua_State *L, int narr, int nrec, const char *mode)
{
  lua_createtable(L, narr, nrec);
  lua_createtable(L, 0, 1);
  lua_pushstring(L, mode);
  lua_setfield(L, -2, "__mode");
  lua_setmetatable(L, -2);
}

/* const char *check_target (lua_State *L, int idx)
 *
 * Check for a valid target specification at index idx.
 * This function checks for a string at idx or a table containing
 * the typical host table fields, 'ip' and 'targetname' in particular.
 */
void check_target (lua_State *L, int idx, const char **address, const char **targetname)
{
  if (lua_istable(L, idx)) {
    lua_getfield(L, idx, "ip");
    *address = lua_tostring(L, -1);
    lua_getfield(L, idx, "targetname");
    *targetname = lua_tostring(L, -1);
    if (address == NULL && targetname == NULL)
      luaL_argerror(L, idx, "host table lacks 'ip' or 'targetname' fields");
    *address = *address ? *address : *targetname;
    lua_pop(L, 2); /* no point replacing idx, need 2 only have 1 */
  } else {
    *address = *targetname = luaL_checkstring(L, idx);
  }
}

/* unsigned short check_port (lua_State *L, int idx)
 *
 * Check for a valid port specification at index idx.
 */
unsigned short check_port (lua_State *L, int idx, const char **protocol)
{
  unsigned short port;

  if (lua_istable(L, idx)) {
    lua_getfield(L, idx, "number");
    if (!lua_isnumber(L, -1))
      luaL_argerror(L, idx, "port table lacks numeric 'number' field");
    port = (unsigned short) lua_tointeger(L, -1);
    lua_getfield(L, idx, "protocol");
    *protocol = lua_tostring(L, -1);
    lua_pop(L, 2);
  } else {
    port = (unsigned short) luaL_checkint(L, idx);
  }
  return port;
}

/* Target *get_target (lua_State *L, int index)
 *
 * This function checks the value at index for a valid host table. It locates
 * the associated Target (C++) class object associated with the host and
 * returns it. If the Target is not being scanned then an error will be raised.
 */
Target *get_target (lua_State *L, int index)
{
  int top = lua_gettop(L);
  Target *target;
  luaL_checktype(L, index, LUA_TTABLE);
  lua_getfield(L, index, "targetname");
  lua_getfield(L, index, "ip");
  if (!(lua_isstring(L, -2) || lua_isstring(L, -1)))
    luaL_error(L, "host table does not have a 'ip' or 'targetname' field");
  if (lua_isstring(L, -2)) /* targetname */
  {
    nse_gettarget(L, -2); /* use targetname */
    if (lua_islightuserdata(L, -1))
      goto done;
    else
      lua_pop(L, 1);
  }
  if (lua_isstring(L, -1)) /* ip */
    nse_gettarget(L, -1); /* use ip */
  if (!lua_islightuserdata(L, -1))
    luaL_argerror(L, 1, "host is not being processed right now");
done:
  target = (Target *) lua_touserdata(L, -1);
  lua_settop(L, top); /* reset stack */
  return target;
}

/* Target *get_port (lua_State *L, Target *target, Port *port, int index)
 *
 * This function checks the value at index for a valid port table. It locates
 * the associated Port (C++) class object associated with the host and
 * returns it.
 */
Port *get_port (lua_State *L, Target *target, Port *port, int index)
{
  Port *p = NULL;
  int portno, protocol;
  luaL_checktype(L, index, LUA_TTABLE);
  lua_getfield(L, index, "number");
  if (!lua_isnumber(L, -1))
    luaL_error(L, "port 'number' field must be a number");
  lua_getfield(L, index, "protocol");
  if (!lua_isstring(L, -1))
    luaL_error(L, "port 'protocol' field must be a string");
  portno = (int) lua_tointeger(L, -2);
  protocol = strcmp(lua_tostring(L, -1), "tcp") == 0 ? IPPROTO_TCP :
             strcmp(lua_tostring(L, -1), "udp") == 0 ? IPPROTO_UDP :
             strcmp(lua_tostring(L, -1), "sctp") == 0 ? IPPROTO_SCTP :
             luaL_error(L, "port 'protocol' field must be \"udp\", \"sctp\" or \"tcp\"");
  while ((p = target->ports.nextPort(p, port, protocol, PORT_UNKNOWN)) != NULL)
    if (p->portno == portno)
      break;
  lua_pop(L, 2);
  return p;
}
