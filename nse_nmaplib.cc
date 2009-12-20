
extern "C" {
  #include "lua.h"
  #include "lauxlib.h"
}

#include <math.h>

#include "nmap.h"
#include "nmap_error.h"
#include "NmapOps.h"
#include "Target.h"
#include "portlist.h"
#include "nmap_rpc.h"
#include "nmap_dns.h"
#include "osscan.h"
#include "protocols.h"

/* #include "output.h"  UNNECESSARY?? */

#include "nse_nmaplib.h"
#include "nse_nsock.h"

#define SCRIPT_ENGINE_PUSHSTRING_NOTNULL(c_str, str) if(c_str != NULL) {\
  lua_pushstring(L, c_str); \
  lua_setfield(L, -2, str); \
}

extern NmapOps o;

void set_version(lua_State *L, const struct serviceDeductions *sd) {
  SCRIPT_ENGINE_PUSHSTRING_NOTNULL(sd->name, "name");

  lua_pushnumber(L, sd->name_confidence);
  lua_setfield(L, -2, "name_confidence");

  SCRIPT_ENGINE_PUSHSTRING_NOTNULL(sd->product, "product");
  SCRIPT_ENGINE_PUSHSTRING_NOTNULL(sd->version, "version");
  SCRIPT_ENGINE_PUSHSTRING_NOTNULL(sd->extrainfo, "extrainfo");
  SCRIPT_ENGINE_PUSHSTRING_NOTNULL(sd->hostname, "hostname");
  SCRIPT_ENGINE_PUSHSTRING_NOTNULL(sd->ostype, "ostype");
  SCRIPT_ENGINE_PUSHSTRING_NOTNULL(sd->devicetype, "devicetype");

  switch(sd->service_tunnel) {
    case(SERVICE_TUNNEL_NONE):
      SCRIPT_ENGINE_PUSHSTRING_NOTNULL("none", "service_tunnel");
      break;
    case(SERVICE_TUNNEL_SSL):
      SCRIPT_ENGINE_PUSHSTRING_NOTNULL("ssl", "service_tunnel");
      break;
    default:
      fatal("%s: In: %s:%i This should never happen.",
        SCRIPT_ENGINE, __FILE__, __LINE__);
      break;
  }

  SCRIPT_ENGINE_PUSHSTRING_NOTNULL(sd->service_fp, "service_fp");

  switch(sd->dtype) {
    case(SERVICE_DETECTION_TABLE):
      SCRIPT_ENGINE_PUSHSTRING_NOTNULL("table", "service_fp");
      break;
    case(SERVICE_DETECTION_PROBED):
      SCRIPT_ENGINE_PUSHSTRING_NOTNULL("probed", "service_fp");
      break;
    default:
      fatal("%s: In: %s:%i This should never happen.",
        SCRIPT_ENGINE, __FILE__, __LINE__);
      break;
  }

  switch(sd->rpc_status) {
    case(RPC_STATUS_UNTESTED):
      SCRIPT_ENGINE_PUSHSTRING_NOTNULL("untested", "rpc_status");
      break;
    case(RPC_STATUS_UNKNOWN):
      SCRIPT_ENGINE_PUSHSTRING_NOTNULL("unknown", "rpc_status");
      break;
    case(RPC_STATUS_GOOD_PROG):
      SCRIPT_ENGINE_PUSHSTRING_NOTNULL("good_prog", "rpc_status");
      break;
    case(RPC_STATUS_NOT_RPC):
      SCRIPT_ENGINE_PUSHSTRING_NOTNULL("not_rpc", "rpc_status");
      break;
    default:
      fatal("%s: In: %s:%i This should never happen.",
        SCRIPT_ENGINE, __FILE__, __LINE__);
      break;
  }

  if(sd->rpc_status == RPC_STATUS_GOOD_PROG) {
    lua_pushnumber(L, sd->rpc_program);
    lua_setfield(L, -2, "rpc_program");

    lua_pushnumber(L, sd->rpc_lowver);
    lua_setfield(L, -2, "rpc_lowver");

    lua_pushnumber(L, sd->rpc_highver);
    lua_setfield(L, -2, "rpc_highver");
  }
}

/* set some port state information onto the
 * table which is currently on the stack
 * */
void set_portinfo(lua_State *L, const Target *target, const Port *port) {
  struct serviceDeductions sd;

  target->ports.getServiceDeductions(port->portno, port->proto, &sd);

  lua_pushnumber(L, (double) port->portno);
  lua_setfield(L, -2, "number");

  if (sd.name != NULL) {
    lua_pushstring(L, sd.name);
    lua_setfield(L, -2, "service");
  }

  lua_newtable(L);
  set_version(L, &sd);
  lua_setfield(L, -2, "version");

  lua_pushstring(L, IPPROTO2STR(port->proto));
  lua_setfield(L, -2, "protocol");

  lua_pushstring(L, statenum2str(port->state));
  lua_setfield(L, -2, "state");

  lua_pushstring(L, reason_str(port->reason.reason_id, 1));
  lua_setfield(L, -2, "reason");
}

/* set host ip, host name and target name onto the
 * table which is currently on the stack
 * set name of the os run by the host onto the
 * table which is currently on the stack
 * the os name is really an array with perfect
 * matches
 * if an os scan wasn't performed, the array
 * points to nil!
 * */
void set_hostinfo(lua_State *L, Target *currenths) {
  unsigned int i;

  lua_pushstring(L, currenths->targetipstr());
  lua_setfield(L, -2, "ip");

  lua_pushstring(L, currenths->HostName());
  lua_setfield(L, -2, "name");

  if ( currenths->TargetName() ) { // else nil
    lua_pushstring(L, currenths->TargetName());
    lua_setfield(L, -2, "targetname");
  }

  if(currenths->directlyConnectedOrUnset() != -1){
    lua_pushboolean(L, currenths->directlyConnected());
    lua_setfield(L, -2, "directly_connected");
  }

  if(currenths->MACAddress()){  // else nil
    lua_pushlstring (L, (const char*)currenths->MACAddress() , 6);
    lua_setfield(L, -2, "mac_addr");
  }
  if(currenths->SrcMACAddress()){ // else nil
    lua_pushlstring(L, (const char*)currenths->SrcMACAddress(), 6);
    lua_setfield(L, -2, "mac_addr_src");
  }
  if(currenths->deviceName()){
    lua_pushstring(L, currenths->deviceName());
    lua_setfield(L, -2, "interface");
  }
  if( (u32)(currenths->v4host().s_addr) ){
    struct in_addr  adr = currenths->v4host();
    lua_pushlstring(L, (char*)&adr, 4);
    lua_setfield(L, -2, "bin_ip");
  }
  if( (u32)(currenths->v4source().s_addr) ){
    struct in_addr  adr = currenths->v4source();
    lua_pushlstring(L, (char*)&adr, 4);
    lua_setfield(L, -2, "bin_ip_src");
  }

  FingerPrintResults *FPR = NULL;

  FPR = currenths->FPR;

  /* if there has been an os scan which returned a pretty certain
   * result, we will use it in the scripts
   * matches which aren't perfect are not needed in the scripts
   */
  if(currenths->osscanPerformed() &&
    FPR != NULL &&
    FPR->overall_results == OSSCAN_SUCCESS &&
    FPR->num_perfect_matches > 0 &&
    FPR->num_perfect_matches <= 8 ) {

    lua_newtable(L);

    // this will run at least one time and at most 8 times, see if condition
    for(i = 0; FPR->accuracy[i] == 1; i++) {
      lua_pushstring(L, FPR->prints[i]->OS_name);
      lua_rawseti(L, -2, i+1);
    }
    lua_setfield(L, -2, "os");
  }
}

static int l_clock_ms (lua_State *L)
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  /* milliseconds since Epoch */
  lua_pushnumber(L,
    ceil((lua_Number)tv.tv_sec*1000+(lua_Number)tv.tv_usec/1000));
  return 1;
}

/* The actual mutex returned by the nmap.mutex function.
 * This function has 4 upvalues:
 * (1) Table (array) of waiting threads.
 * (2) The running thread or nil.
 * (3) A unique table key used for destructors.
 * (4) The destructor function, aux_mutex_done.
 */
static int aux_mutex (lua_State *L)
{
  enum what {LOCK, DONE, TRYLOCK, RUNNING};
  static const char * op[] = {"lock", "done", "trylock", "running", NULL};
  switch (luaL_checkoption(L, 1, NULL, op))
  {
    case LOCK:
      if (lua_isnil(L, lua_upvalueindex(2))) // check running
      {
        lua_pushthread(L);
        lua_replace(L, lua_upvalueindex(2)); // set running
        lua_pushvalue(L, lua_upvalueindex(3)); // unique identifier
        lua_pushvalue(L, lua_upvalueindex(4)); // aux_mutex_done closure
        nse_destructor(L, 'a');
        return 0;
      }
      lua_pushthread(L);
      lua_rawseti(L, lua_upvalueindex(1), lua_objlen(L, lua_upvalueindex(1))+1);
      return nse_yield(L);
    case DONE:
      lua_pushthread(L);
      if (!lua_equal(L, -1, lua_upvalueindex(2)))
        luaL_error(L, "%s", "do not have a lock on this mutex");
      /* remove destructor */
      lua_pushvalue(L, lua_upvalueindex(3));
      nse_destructor(L, 'r');
      /* set new thread to lock the mutex */
      lua_getfield(L, LUA_REGISTRYINDEX, "_LOADED");
      lua_getfield(L, -1, "table");
      lua_getfield(L, -1, "remove");
      lua_pushvalue(L, lua_upvalueindex(1));
      lua_pushinteger(L, 1);
      lua_call(L, 2, 1);
      lua_replace(L, lua_upvalueindex(2));
      if (lua_isthread(L, lua_upvalueindex(2))) // waiting threads had a thread
      {
        lua_State *thread = lua_tothread(L, lua_upvalueindex(2));
        lua_pushvalue(L, lua_upvalueindex(3)); // destructor key
        lua_pushvalue(L, lua_upvalueindex(4)); // destructor
        luaL_checkstack(thread, 2, "adding destructor");
        lua_xmove(L, thread, 2);
        nse_destructor(thread, 'a');
        nse_restore(thread, 0);
      }
      return 0;
    case TRYLOCK:
      if (lua_isnil(L, lua_upvalueindex(2)))
      {
        lua_pushthread(L);
        lua_replace(L, lua_upvalueindex(2));
        lua_pushvalue(L, lua_upvalueindex(3)); // unique identifier
        lua_pushvalue(L, lua_upvalueindex(4)); // aux_mutex_done closure
        nse_destructor(L, 'a');
        lua_pushboolean(L, true);
      }
      else
        lua_pushboolean(L, false);
      return 1;
    case RUNNING:
      lua_pushvalue(L, lua_upvalueindex(2));
      return 1;
  }
  return 0;
}

/* This is the mutex destructor called when a thread ends but failed to 
 * unlock the mutex.
 * It has 1 upvalue: The nmap.mutex function closure.
 */
static int aux_mutex_done (lua_State *L)
{
  lua_State *thread = lua_tothread(L, 1);
  lua_pushvalue(L, lua_upvalueindex(1)); // aux_mutex, actual mutex closure
  lua_pushliteral(L, "done");
  luaL_checkstack(thread, 2, "aux_mutex_done");
  lua_xmove(L, thread, 2);
  if (lua_pcall(thread, 1, 0, 0) != 0) lua_pop(thread, 1); // pop error msg
  return 0;
}

static int l_mutex (lua_State *L)
{
  int t = lua_type(L, 1);
  if (t == LUA_TNONE || t == LUA_TNIL || t == LUA_TBOOLEAN || t == LUA_TNUMBER)
    luaL_argerror(L, 1, "object expected");
  lua_pushvalue(L, 1);
  lua_gettable(L, lua_upvalueindex(1));
  if (lua_isnil(L, -1))
  {
    lua_newtable(L); // waiting threads
    lua_pushnil(L); // running thread
    lua_newtable(L); // unique object as an identifier
    lua_pushnil(L); // placeholder for aux_mutex_done
    lua_pushcclosure(L, aux_mutex, 4);
    lua_pushvalue(L, -1); // mutex closure
    lua_pushcclosure(L, aux_mutex_done, 1);
    lua_setupvalue(L, -2, 4); // replace nil upvalue with aux_mutex_done
    lua_pushvalue(L, 1); // "mutex object"
    lua_pushvalue(L, -2); // mutex function
    lua_settable(L, lua_upvalueindex(1)); // Add to mutex table
  }
  return 1; // aux_mutex closure
}

static int aux_condvar (lua_State *L)
{
  size_t i, n = 0;
  enum {WAIT, SIGNAL, BROADCAST};
  static const char * op[] = {"wait", "signal", "broadcast"};
  switch (luaL_checkoption(L, 1, NULL, op))
  {
    case WAIT:
      lua_pushthread(L);
      lua_rawseti(L, lua_upvalueindex(1), lua_objlen(L, lua_upvalueindex(1))+1);
      return nse_yield(L);
    case SIGNAL:
      n = lua_objlen(L, lua_upvalueindex(1));
      break;
    case BROADCAST:
      n = 1;
      break;
  }
  lua_pushvalue(L, lua_upvalueindex(1));
  for (i = lua_objlen(L, -1); i >= n; i--)
  {
    lua_rawgeti(L, -1, i); /* get the thread */
    if (lua_isthread(L, -1))
      nse_restore(lua_tothread(L, -1), 0);
    lua_pop(L, 1); /* pop the thread */
    lua_pushnil(L);
    lua_rawseti(L, -2, i);
  }
  return 0;
}

static int aux_condvar_done (lua_State *L)
{
  lua_State *thread = lua_tothread(L, 1);
  lua_pushvalue(L, lua_upvalueindex(1)); // aux_condvar closure
  lua_pushliteral(L, "broadcast"); // wake up all threads waiting
  luaL_checkstack(thread, 2, "aux_condvar_done");
  lua_xmove(L, thread, 2);
  if (lua_pcall(thread, 1, 0, 0) != 0) lua_pop(thread, 1); // pop error msg
  return 0;
}

static int l_condvar (lua_State *L)
{
  int t = lua_type(L, 1);
  if (t == LUA_TNONE || t == LUA_TNIL || t == LUA_TBOOLEAN || t == LUA_TNUMBER)
   luaL_argerror(L, 1, "object expected");
  lua_pushvalue(L, 1);
  lua_gettable(L, lua_upvalueindex(1));
  if (lua_isnil(L, -1))
  {
    lua_newtable(L); // waiting threads
    lua_pushnil(L); // placeholder for aux_mutex_done
    lua_pushcclosure(L, aux_condvar, 2);
    lua_pushvalue(L, -1); // aux_condvar closure
    lua_pushcclosure(L, aux_condvar_done, 1);
    lua_setupvalue(L, -2, 2); // replace nil upvalue with aux_condvar_done
    lua_pushvalue(L, 1); // "condition variable object"
    lua_pushvalue(L, -2); // condvar function
    lua_settable(L, lua_upvalueindex(1)); // Add to condition variable table
  }
  lua_pushvalue(L, -1); // aux_condvar closure
  lua_getupvalue(L, -1, 2); // aux_mutex_done closure
  nse_destructor(L, 'a');
  return 1; // condition variable closure
}

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

/* this function can be called from lua to obtain the port state
 * of a port different from the one the script rule is matched
 * against
 * it retrieves the host.ip of the host on which the script is
 * currently running, looks up the host in the table of currently
 * processed hosts and returns a table containing the state of
 * the port we have been asked for
 * this function is useful if we want rules which want to know
 * the state of more than one port
 * */
static int l_get_port_state (lua_State *L)
{
  Target *target;
  Port port, *p;
  target = get_target(L, 1);
  p = get_port(L, target, &port, 2);
  if (p == NULL)
    lua_pushnil(L);
  else
  {
    lua_newtable(L);
    set_portinfo(L, target, p);
  }
  return 1;
}

/* unlike set_portinfo() this function sets the port state in nmap.
 * if for example a udp port was seen by the script as open instead of
 * filtered, the script is free to say so.
 * */
static int l_set_port_state (lua_State *L)
{
  static const int opstate[] = {PORT_OPEN, PORT_CLOSED};
  static const char *op[] = {"open", "closed", NULL};
  Target *target;
  Port port, *p;
  target = get_target(L, 1);
  if ((p = get_port(L, target, &port, 2)) != NULL)
  {
    switch (opstate[luaL_checkoption(L, 3, NULL, op)])
    {
      case PORT_OPEN:
        if (p->state == PORT_OPEN)
          return 0;
        target->ports.setPortState(p->portno, p->proto, PORT_OPEN);
        break;
      case PORT_CLOSED:
        if (p->state == PORT_CLOSED)
          return 0;
        target->ports.setPortState(p->portno, p->proto, PORT_CLOSED);
        break;
    }
    target->ports.setStateReason(p->portno, p->proto, ER_SCRIPT, 0, 0);
  }
  return 0;
}

static int l_set_port_version (lua_State *L)
{
  static const enum serviceprobestate opversion[] = {
    PROBESTATE_FINISHED_HARDMATCHED,
    PROBESTATE_FINISHED_SOFTMATCHED,
    PROBESTATE_FINISHED_NOMATCH,
    PROBESTATE_FINISHED_TCPWRAPPED,
    PROBESTATE_INCOMPLETE
  };
  static const char *ops[] = {
    "hardmatched",
    "softmatched",
    "nomatch",
    "tcpwrapped",
    "incomplete"
  };
  Target *target;
  Port port, *p;
  enum service_tunnel_type tunnel = SERVICE_TUNNEL_NONE;
  enum serviceprobestate probestate =
      opversion[luaL_checkoption(L, 3, "hardmatched", ops)];

  target = get_target(L, 1);
  if ((p = get_port(L, target, &port, 2)) == NULL)
    return 0; /* invalid port */

  lua_settop(L, 3);
  lua_getfield(L, 2, "version"); /* index 4 */
  if (!lua_istable(L, -1))
    luaL_error(L, "port 'version' field must be a table");
  const char
    *name           = (lua_getfield(L, 4, "name"),       lua_tostring(L, -1)),
    *product        = (lua_getfield(L, 4, "product"),    lua_tostring(L, -1)),
    *version        = (lua_getfield(L, 4, "version"),    lua_tostring(L, -1)),
    *extrainfo      = (lua_getfield(L, 4, "extrainfo"),  lua_tostring(L, -1)),
    *hostname       = (lua_getfield(L, 4, "hostname"),   lua_tostring(L, -1)),
    *ostype         = (lua_getfield(L, 4, "ostype"),     lua_tostring(L, -1)),
    *devicetype     = (lua_getfield(L, 4, "devicetype"), lua_tostring(L, -1)),
    *service_tunnel = (lua_getfield(L, 4, "service_tunnel"),
                                                         lua_tostring(L, -1));
  if (service_tunnel == NULL || strcmp(service_tunnel, "none") == 0)
    tunnel = SERVICE_TUNNEL_NONE;
  else if (strcmp(service_tunnel, "ssl") == 0)
    tunnel = SERVICE_TUNNEL_SSL;
  else
    luaL_argerror(L, 2, "invalid value for port.version.service_tunnel");

  if (o.servicescan)
    target->ports.setServiceProbeResults(p->portno, p->proto,
        probestate, name, tunnel, product,
        version, extrainfo, hostname, ostype, devicetype, NULL);
  else
    target->ports.setServiceProbeResults(p->portno, p->proto,
        probestate, name, tunnel, NULL, NULL,
        NULL, NULL, NULL, NULL, NULL);

  return 0;
}

static int l_log_write (lua_State *L)
{
  static const char * const ops[] = {"stdout", "stderr", NULL};
  static const int logs[] = {LOG_STDOUT, LOG_STDERR};
  int log = logs[luaL_checkoption(L, 1, NULL, ops)];
  log_write(log, "%s: %s\n", SCRIPT_ENGINE, luaL_checkstring(L, 2));
  log_flush(log);
  return 0;
}

static int new_try_finalize (lua_State *L)
{
  if (!(lua_isboolean(L, 1) || lua_isnoneornil(L, 1)))
    error("finalizing a non-conforming function that did not first "
          "return a boolean");
  if (!lua_toboolean(L, 1))
  {
    if (!lua_isnil(L, lua_upvalueindex(1)))
    {
      lua_pushvalue(L, lua_upvalueindex(1));
      lua_call(L, 0, 0);
    }
    lua_settop(L, 2);
    lua_error(L);
  }
  return lua_gettop(L)-1; /* omit first boolean argument */
}

static int l_new_try (lua_State *L)
{
  lua_settop(L, 1);
  lua_pushcclosure(L, new_try_finalize, 1);
  return 1;
}

static int l_get_verbosity (lua_State *L)
{
  int verbosity;

  verbosity = o.verbose;
  /* Check if script is selected by name. When a script is selected by name,
     we lie to it and say the verbosity is one higher than it really is. */
  verbosity += (nse_selectedbyname(L), lua_toboolean(L, -1) ? 1 : 0);

  lua_pushnumber(L, verbosity);
  return 1;
}

static int l_get_debugging (lua_State *L)
{
  lua_pushnumber(L, o.debugging);
  return 1;
}

static int l_get_have_ssl (lua_State *L) {
#if HAVE_OPENSSL
  lua_pushboolean(L, true);
#else
  lua_pushboolean(L, false);
#endif
  return 1;
}

static int l_fetchfile (lua_State *L)
{
  char buf[FILENAME_MAX];
  if (nmap_fetchfile(buf, sizeof(buf), luaL_checkstring(L, 1)) != 1)
    lua_pushnil(L);
  else
    lua_pushstring(L, buf);
  return 1;
}

static int l_get_timing_level (lua_State *L)
{
  lua_pushnumber(L, o.timing_level);
  return 1;
}

// returns a table with DNS servers known to nmap
static int l_get_dns_servers (lua_State *L)
{
  std::list<std::string> servs2 = get_dns_servers();
  std::list<std::string>::iterator servI2;
  int i = 1;

  lua_newtable(L);
  for(servI2 = servs2.begin(); servI2 != servs2.end(); servI2++) {
    lua_pushstring(L, servI2->c_str());
    lua_rawseti(L, -2, i++);
  }
  return 1;
}

int luaopen_nmap (lua_State *L)
{
  static const luaL_reg nmaplib [] = {
    {"get_port_state", l_get_port_state},
    {"set_port_state", l_set_port_state},
    {"set_port_version", l_set_port_version},
    {"new_socket", l_nsock_new},
    {"new_dnet", l_dnet_new},
    {"get_interface_link", l_dnet_get_interface_link},
    {"clock_ms", l_clock_ms},
    {"log_write", l_log_write},
    {"new_try", l_new_try},
    {"verbosity", l_get_verbosity},
    {"debugging", l_get_debugging},
    {"have_ssl", l_get_have_ssl},
    {"fetchfile", l_fetchfile},
    {"timing_level", l_get_timing_level},
    {"get_dns_servers", l_get_dns_servers},
    {NULL, NULL}
  };

  lua_settop(L, 0); // clear stack
  luaL_register(L, "nmap", nmaplib);

  lua_newtable(L);
  lua_createtable(L, 0, 1);
  lua_pushliteral(L, "v");
  lua_setfield(L, -2, "__mode");
  lua_setmetatable(L, -2); // Allow closures to be collected (see l_mutex)
  lua_pushcclosure(L, l_mutex, 1); /* mutex function */
  lua_setfield(L, -2, "mutex");

  lua_newtable(L);
  lua_createtable(L, 0, 1);
  lua_pushliteral(L, "v");
  lua_setfield(L, -2, "__mode");
  lua_setmetatable(L, -2); // Allow closures to be collected (see l_condvar)
  lua_pushcclosure(L, l_condvar, 1); // condvar function
  lua_setfield(L, -2, "condvar");

  lua_newtable(L);
  lua_setfield(L, -2, "registry");

  lua_pushcclosure(L, luaopen_nsock, 0);
  lua_pushliteral(L, "nsock");
  lua_call(L, 1, 0);

  lua_settop(L, 1); // just nmap lib on stack

  return 1;
}

/* Register C functions that belong in the stdnse namespace. They are loaded
   from here in stdnse.lua. */
int luaopen_stdnse_c (lua_State *L)
{
  static const luaL_reg stdnse_clib [] = {
    {"sleep", l_nsock_sleep},
    {NULL, NULL}
  };

  luaL_register(L, "stdnse.c", stdnse_clib);

  return 1;
}
