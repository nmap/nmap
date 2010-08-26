
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
#include "service_scan.h"
#include "nmap_rpc.h"
#include "nmap_dns.h"
#include "osscan.h"
#include "protocols.h"

#include "nse_nmaplib.h"
#include "nse_nsock.h"

extern NmapOps o;

static const char *NSE_PROTOCOL_OP[] = {"tcp", "udp", "sctp", NULL};
static const int NSE_PROTOCOL[] = {IPPROTO_TCP, IPPROTO_UDP, IPPROTO_SCTP};

static void setsfield (lua_State *L, int idx, const char *field, const char *what)
{
  lua_pushvalue(L, idx);
  lua_pushstring(L, what); /* what can be NULL */
  lua_setfield(L, -2, field);
  lua_pop(L, 1);
}

static void setnfield (lua_State *L, int idx, const char *field, lua_Number n)
{
  lua_pushvalue(L, idx);
  lua_pushnumber(L, n);
  lua_setfield(L, -2, field);
  lua_pop(L, 1);
}

static void setbfield (lua_State *L, int idx, const char *field, int b)
{
  lua_pushvalue(L, idx);
  lua_pushboolean(L, b);
  lua_setfield(L, -2, field);
  lua_pop(L, 1);
}

void set_version (lua_State *L, const struct serviceDeductions *sd)
{
  setsfield(L, -1, "name", sd->name);
  setnfield(L, -1, "name_confidence", sd->name_confidence);
  setsfield(L, -1, "product", sd->product);
  setsfield(L, -1, "version", sd->version);
  setsfield(L, -1, "extrainfo", sd->extrainfo);
  setsfield(L, -1, "hostname", sd->hostname);
  setsfield(L, -1, "ostype", sd->ostype);
  setsfield(L, -1, "devicetype", sd->devicetype);
  setsfield(L, -1, "service_tunnel",
      sd->service_tunnel == SERVICE_TUNNEL_NONE ? "none" :
      sd->service_tunnel == SERVICE_TUNNEL_SSL ? "ssl" :
      NULL);
  setsfield(L, -1, "service_fp", sd->service_fp);
  setsfield(L, -1, "service_dtype",
      sd->dtype == SERVICE_DETECTION_TABLE ? "table" :
      sd->dtype == SERVICE_DETECTION_PROBED ? "probed" :
      NULL);
  setsfield(L, -1, "rpc_status",
      sd->rpc_status == RPC_STATUS_UNTESTED ? "untested" :
      sd->rpc_status == RPC_STATUS_UNKNOWN ? "unknown" :
      sd->rpc_status == RPC_STATUS_GOOD_PROG ? "good_prog" :
      sd->rpc_status == RPC_STATUS_NOT_RPC ? "not_rpc" :
      NULL);
  if (sd->rpc_status == RPC_STATUS_GOOD_PROG)
  {
    setnfield(L, -1, "rpc_program", sd->rpc_program);
    setnfield(L, -1, "rpc_lowver", sd->rpc_lowver);
    setnfield(L, -1, "rpc_highver", sd->rpc_highver);
  }
}

/* set some port state information onto the
 * table which is currently on the stack
 * */
void set_portinfo (lua_State *L, const Target *target, const Port *port)
{
  struct serviceDeductions sd;

  target->ports.getServiceDeductions(port->portno, port->proto, &sd);

  setnfield(L, -1, "number", port->portno);
  setsfield(L, -1, "service", sd.name);
  setsfield(L, -1, "protocol", IPPROTO2STR(port->proto));
  setsfield(L, -1, "state", statenum2str(port->state));
  setsfield(L, -1, "reason", reason_str(port->reason.reason_id, 1));
  lua_newtable(L);
  set_version(L, &sd);
  lua_setfield(L, -2, "version");
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
  setsfield(L, -1, "ip", currenths->targetipstr());
  setsfield(L, -1, "name", currenths->HostName());
  setsfield(L, -1, "targetname", currenths->TargetName());
  if (currenths->directlyConnectedOrUnset() != -1)
    setbfield(L, -1, "directly_connected", currenths->directlyConnected());
  if (currenths->MACAddress())
  {
    lua_pushlstring(L, (const char *) currenths->MACAddress() , 6);
    lua_setfield(L, -2, "mac_addr");
  }
  if (currenths->NextHopMACAddress())
  {
    lua_pushlstring(L, (const char *) currenths->NextHopMACAddress() , 6);
    lua_setfield(L, -2, "mac_addr_next_hop");
  }
  if (currenths->SrcMACAddress())
  {
    lua_pushlstring(L, (const char *) currenths->SrcMACAddress(), 6);
    lua_setfield(L, -2, "mac_addr_src");
  }
  setsfield(L, -1, "interface", currenths->deviceName());
  setnfield(L, -1, "interface_mtu", currenths->MTU());
  if ((u32)(currenths->v4host().s_addr))
  {
    struct in_addr adr = currenths->v4host();
    lua_pushlstring(L, (const char *) &adr, 4);
    lua_setfield(L, -2, "bin_ip");
  }
  if ((u32)(currenths->v4source().s_addr))
  {
    struct in_addr adr = currenths->v4source();
    lua_pushlstring(L, (const char *) &adr, 4);
    lua_setfield(L, -2, "bin_ip_src");
  }

  lua_newtable(L);
  setnfield(L, -1, "srtt", (lua_Number) currenths->to.srtt / 1000000.0);
  setnfield(L, -1, "rttvar", (lua_Number) currenths->to.rttvar / 1000000.0);
  setnfield(L, -1, "timeout", (lua_Number) currenths->to.timeout / 1000000.0);
  lua_setfield(L, -2, "times");

  FingerPrintResults *FPR = currenths->FPR;

  /* add distance (in hops) if traceroute has been performed */
  if (currenths->traceroute_hops.size() > 0) {
    int i;
    std::list<TracerouteHop>::iterator it;

    lua_newtable(L);

    for (i=0, it=currenths->traceroute_hops.begin(); 
        it!=currenths->traceroute_hops.end(); i++, it++) {

      lua_pushstring(L, inet_ntop_ez(&(*it).addr, sizeof((*it).addr)));
      lua_rawseti(L, -2, i+1);
    }
    lua_setfield(L, -2, "traceroute");
  }
  

  /* if there has been an os scan which returned a pretty certain
   * result, we will use it in the scripts
   * matches which aren't perfect are not needed in the scripts
   */
  if (currenths->osscanPerformed() && FPR != NULL &&
      FPR->overall_results == OSSCAN_SUCCESS && FPR->num_perfect_matches > 0 &&
      FPR->num_perfect_matches <= 8 )
  {
    int i;

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

static int l_clock (lua_State *L)
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  /* floating point seconds since Epoch */
  lua_pushnumber(L, TIMEVAL_SECS(tv));
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

/* Generates an array of port data for the given host and leaves it on
 * the top of the stack
 */
static int l_get_ports (lua_State *L)
{
  static const char *state_op[] = {"open", "filtered", "unfiltered", "closed",
      "open|filtered", "closed|filtered", NULL};
  static const int states[] = {PORT_OPEN, PORT_FILTERED, PORT_UNFILTERED,
      PORT_CLOSED, PORT_OPENFILTERED, PORT_CLOSEDFILTERED};
  Port *p = NULL, port;
  Target *target = get_target(L, 1);
  int protocol = NSE_PROTOCOL[luaL_checkoption(L, 3, NULL, NSE_PROTOCOL_OP)];
  int state = states[luaL_checkoption(L, 4, NULL, state_op)];

  if (!lua_isnil(L, 2))
    p = get_port(L, target, &port, 2);

  if (!(p = target->ports.nextPort(p, &port, protocol, state))) {
    lua_pushnil(L);
  } else {
    lua_newtable(L);
    set_portinfo(L, target, p);
  }
  return 1;
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

/* this function must be used by version category scripts or any other
 * lua code to check if a given port with it's protocol are in the
 * exclude directive found in the nmap-service-probes file.
 * */
static int l_port_is_excluded (lua_State *L)
{
  unsigned short portno = (unsigned short) luaL_checkint(L, 1);
  int protocol = NSE_PROTOCOL[luaL_checkoption(L, 2, NULL, NSE_PROTOCOL_OP)];

  lua_pushboolean(L, AllProbes::check_excluded_port(portno, protocol)); 
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

static int l_is_privileged(lua_State *L)
{
  lua_pushboolean(L, o.isr00t);
  return 1;
}

int luaopen_nmap (lua_State *L)
{
  static const luaL_reg nmaplib [] = {
    {"get_port_state", l_get_port_state},
    {"get_ports", l_get_ports},
    {"set_port_state", l_set_port_state},
    {"set_port_version", l_set_port_version},
    {"port_is_excluded", l_port_is_excluded},
    {"new_socket", l_nsock_new},
    {"new_dnet", l_dnet_new},
    {"get_interface_link", l_dnet_get_interface_link},
    {"clock_ms", l_clock_ms},
    {"clock", l_clock},
    {"log_write", l_log_write},
    {"new_try", l_new_try},
    {"verbosity", l_get_verbosity},
    {"debugging", l_get_debugging},
    {"have_ssl", l_get_have_ssl},
    {"fetchfile", l_fetchfile},
    {"timing_level", l_get_timing_level},
    {"get_dns_servers", l_get_dns_servers},
    {"is_privileged", l_is_privileged},
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
