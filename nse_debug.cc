
extern "C" {
  #include "lua.h"
  #include "lauxlib.h"
}

#include "nmap.h"
#include "nse_debug.h"
#include "output.h"

/* Print a Lua table. depth_limit is the limit on recursive printing of
   subtables. */
static void table_dump (lua_State *L, int idx, int depth_limit)
{
  idx = lua_absindex(L, idx);
  assert(lua_type(L, idx) == LUA_TTABLE);
  printf("{ ");
  for (lua_pushnil(L); lua_next(L, idx); lua_pop(L, 1))
  {
    value_dump(L, -2, depth_limit - 1);
    printf(" = ");
    value_dump(L, -1, depth_limit - 1);
    printf(", ");
  }
  printf("}");
}

/* Print a Lua value. depth_limit controls the depth to which tables will be
   printed recursively (0 for no recursion). */
void value_dump (lua_State *L, int idx, int depth_limit)
{
  idx = lua_absindex(L, idx);
  int t = lua_type(L, idx);
  switch (t)
  {
    case LUA_TSTRING:  /* strings */
      printf("'%s'", lua_tostring(L, idx));
      break;
    case LUA_TBOOLEAN:  /* booleans */
      printf(lua_toboolean(L, idx) ? "true" : "false");
      break;
    case LUA_TNUMBER:  /* numbers */
      printf("%g", lua_tonumber(L, idx));
      break;
    case LUA_TTABLE:
      if (depth_limit > 0)
        table_dump(L, idx, depth_limit);
      else
        printf("table: %p", lua_topointer(L, idx));
      break;
    case LUA_TTHREAD:
    case LUA_TFUNCTION:
    case LUA_TUSERDATA:
    case LUA_TLIGHTUSERDATA:
      printf("%s: %p", lua_typename(L, t), lua_topointer(L, idx));
      break;
    default:  /* other values */
      printf("%s", lua_typename(L, t));
      break;
  }
}

void stack_dump (lua_State *L)
{
  int i, top = lua_gettop(L);
  for (i = 1; i <= top; i++)
  {
    printf("[%d, %d] = ", i, (-top + i - 1));
    value_dump(L, i, 0);
    printf("\n");
  }
}

void lua_state_dump (lua_State *L)
{
  int top;

  printf("=== LUA STATE ===\n");

  top = lua_gettop(L);
  printf("=== STACK (height %d)\n", top);
  stack_dump(L);

  printf("=== GLOBALS\n");
  lua_rawgeti(L, LUA_REGISTRYINDEX, LUA_RIDX_GLOBALS);
  table_dump(L, -1, 0);
  lua_pop(L, 1); /* LUA_RIDX_GLOBALS */
  printf("\n");

  printf("=== REGISTRY\n");
  table_dump(L, LUA_REGISTRYINDEX, 0);
  printf("\n");

  printf("=== nmap.registry\n");
  lua_getglobal(L, "nmap");
  lua_getfield(L, -1, "registry");
  table_dump(L, -1, 1);
  lua_pop(L, 2);
  printf("\n");

  assert(lua_gettop(L) == top);
}
