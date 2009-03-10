#ifndef NSE_DEBUG
#define NSE_DEBUG

void value_dump(lua_State *L, int i, int depth_limit);
void stack_dump(lua_State *L);
void lua_state_dump(lua_State *L);

#endif

