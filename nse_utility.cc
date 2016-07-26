#include <stdlib.h>
#include <stdarg.h>
#include <math.h>

#include "Target.h"
#include "portlist.h"

#include "nse_main.h"
#include "nse_utility.h"

int nseU_checkinteger (lua_State *L, int arg)
{
  lua_Number n = luaL_checknumber(L, arg);
  int i;
  if (!lua_numbertointeger(floor(n), &i)) {
    return luaL_error(L, "Number cannot be converted to an integer");
  }
  return i;
}

int nseU_traceback (lua_State *L)
{
  if (lua_isstring(L, 1))
    luaL_traceback(L, L, lua_tostring(L, 1), 1);
  return 1;
}

int nseU_placeholder (lua_State *L)
{
  lua_pushnil(L);
  return lua_error(L);
}

size_t nseU_tablen (lua_State *L, int idx)
{
  size_t len = 0;
  idx = lua_absindex(L, idx);

  for (lua_pushnil(L); lua_next(L, idx); lua_pop(L, 1))
    len++;

  return len;
}

void nseU_setsfield (lua_State *L, int idx, const char *field, const char *what)
{
  idx = lua_absindex(L, idx);
  lua_pushstring(L, what); /* what can be NULL */
  lua_setfield(L, idx, field);
}

void nseU_setnfield (lua_State *L, int idx, const char *field, lua_Number n)
{
  idx = lua_absindex(L, idx);
  lua_pushnumber(L, n);
  lua_setfield(L, idx, field);
}

void nseU_setifield (lua_State *L, int idx, const char *field, lua_Integer i)
{
  idx = lua_absindex(L, idx);
  lua_pushinteger(L, i);
  lua_setfield(L, idx, field);
}

void nseU_setbfield (lua_State *L, int idx, const char *field, int b)
{
  idx = lua_absindex(L, idx);
  lua_pushboolean(L, b);
  lua_setfield(L, idx, field);
}

void nseU_appendfstr (lua_State *L, int idx, const char *fmt, ...)
{
  va_list va;
  idx = lua_absindex(L, idx);
  va_start(va, fmt);
  lua_pushvfstring(L, fmt, va);
  va_end(va);
  lua_rawseti(L, idx, lua_rawlen(L, idx)+1);
}

int nseU_success (lua_State *L)
{
  lua_pushboolean(L, true);
  return 1;
}

int nseU_safeerror (lua_State *L, const char *fmt, ...)
{
  va_list va;
  lua_pushboolean(L, false);
  va_start(va, fmt);
  lua_pushvfstring(L, fmt, va);
  va_end(va);
  return 2;
}

void nseU_weaktable (lua_State *L, int narr, int nrec, const char *mode)
{
  lua_createtable(L, narr, nrec);
  lua_createtable(L, 0, 1);
  lua_pushstring(L, mode);
  lua_setfield(L, -2, "__mode");
  lua_setmetatable(L, -2);
}

void nseU_typeerror (lua_State *L, int idx, const char *type)
{
  const char *msg = lua_pushfstring(L, "%s expected, got %s", type, luaL_typename(L, idx));
  luaL_argerror(L, idx, msg);
}

void *nseU_checkudata (lua_State *L, int idx, int upvalue, const char *name)
{
  idx = lua_absindex(L, idx);

  lua_getmetatable(L, idx);
  if (!(lua_isuserdata(L, idx) && lua_rawequal(L, -1, upvalue)))
    nseU_typeerror(L, idx, name);
  lua_pop(L, 1);
  return lua_touserdata(L, idx);
}

void nseU_checktarget (lua_State *L, int idx, const char **address, const char **targetname)
{
  idx = lua_absindex(L, idx);
  if (lua_istable(L, idx)) {
    lua_getfield(L, idx, "ip");
    *address = lua_tostring(L, -1);
    lua_getfield(L, idx, "targetname");
    *targetname = lua_tostring(L, -1);
    if (*address == NULL && *targetname == NULL)
      luaL_argerror(L, idx, "host table lacks 'ip' or 'targetname' fields");
    *address = *address ? *address : *targetname;
    lua_pop(L, 2); /* no point replacing idx, need 2 only have 1 */
  } else {
    *address = *targetname = luaL_checkstring(L, idx);
  }
}

void nseU_opttarget (lua_State *L, int idx, const char **address, const char **targetname)
{
  if (lua_isnoneornil(L, idx)) {
    *address = NULL;
    *targetname = NULL;
    return;
  } else {
    return nseU_checktarget(L, idx, address, targetname);
  }
}

uint16_t nseU_checkport (lua_State *L, int idx, const char **protocol)
{
  uint16_t port;
  idx = lua_absindex(L, idx);

  if (lua_istable(L, idx)) {
    lua_getfield(L, idx, "number");
    if (!lua_isnumber(L, -1))
      luaL_argerror(L, idx, "port table lacks numeric 'number' field");
    port = (uint16_t) lua_tointeger(L, -1);
    lua_getfield(L, idx, "protocol");
    if (lua_isstring(L, -1))
      *protocol = lua_tostring(L, -1);
    lua_pop(L, 2);
  } else {
    port = (uint16_t) luaL_checkinteger(L, idx);
  }
  return port;
}

Target *nseU_gettarget (lua_State *L, int idx)
{
  int top = lua_gettop(L);
  Target *target;
  idx = lua_absindex(L, idx);
  luaL_checktype(L, idx, LUA_TTABLE);
  lua_getfield(L, idx, "targetname");
  lua_getfield(L, idx, "ip");
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

Port *nseU_getport (lua_State *L, Target *target, Port *port, int idx)
{
  Port *p = NULL;
  int portno, protocol;
  idx = lua_absindex(L, idx);
  luaL_checktype(L, idx, LUA_TTABLE);
  lua_getfield(L, idx, "number");
  if (!lua_isnumber(L, -1))
    luaL_error(L, "port 'number' field must be a number");
  lua_getfield(L, idx, "protocol");
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
