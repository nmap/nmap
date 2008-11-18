#include "nse_debug.h"
#include "output.h"

void stack_dump (lua_State *L)
{
  int i, top = lua_gettop(L);
  for (i = 1; i <= top; i++)
  {  /* repeat for each level */
    int t = lua_type(L, i);
    printf("[%d, %d] = ", i, (-top + i - 1));
    switch (t)
    {
      case LUA_TSTRING:  /* strings */
        printf("'%s'", lua_tostring(L, i));
        break;
      case LUA_TBOOLEAN:  /* booleans */
        printf(lua_toboolean(L, i) ? "true" : "false");
        break;
      case LUA_TNUMBER:  /* numbers */
        printf("%g", lua_tonumber(L, i));
        break;
      case LUA_TTABLE:
      case LUA_TTHREAD:
      case LUA_TFUNCTION:
      case LUA_TUSERDATA:
      case LUA_TLIGHTUSERDATA:
        printf("%s: %p", lua_typename(L, t), lua_topointer(L, i));
        break;
      default:  /* other values */
        printf("%s", lua_typename(L, t));
        break;
    }
    printf("\n");
  }
}
