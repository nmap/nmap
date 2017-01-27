
extern "C" {
  #include "lua.h"
  #include "lauxlib.h"
  #include "lualib.h"
}

#include <math.h>

#include "nmap.h"
#include "nmap_error.h"
#include "NmapOps.h"
#include "FingerPrintResults.h"
#include "Target.h"
#include "TargetGroup.h"
#include "portlist.h"
#include "service_scan.h"
#include "nmap_dns.h"
#include "osscan.h"
#include "protocols.h"
#include "libnetutil/netutil.h"

#include "nse_nmaplib.h"
#include "nse_utility.h"
#include "nse_nsock.h"
#include "nse_dnet.h"

extern NmapOps o;

static const char *NSE_PROTOCOL_OP[] = {"tcp", "udp", "sctp", NULL};
static const int NSE_PROTOCOL[] = {IPPROTO_TCP, IPPROTO_UDP, IPPROTO_SCTP};

void set_version (lua_State *L, const struct serviceDeductions *sd)
{
  nseU_setsfield(L, -1, "name", sd->name);
  nseU_setnfield(L, -1, "name_confidence", sd->name_confidence);
  nseU_setsfield(L, -1, "product", sd->product);
  nseU_setsfield(L, -1, "version", sd->version);
  nseU_setsfield(L, -1, "extrainfo", sd->extrainfo);
  nseU_setsfield(L, -1, "hostname", sd->hostname);
  nseU_setsfield(L, -1, "ostype", sd->ostype);
  nseU_setsfield(L, -1, "devicetype", sd->devicetype);
  nseU_setsfield(L, -1, "service_tunnel",
      sd->service_tunnel == SERVICE_TUNNEL_NONE ? "none" :
      sd->service_tunnel == SERVICE_TUNNEL_SSL ? "ssl" :
      NULL);
  nseU_setsfield(L, -1, "service_fp", sd->service_fp);
  nseU_setsfield(L, -1, "service_dtype",
      sd->dtype == SERVICE_DETECTION_TABLE ? "table" :
      sd->dtype == SERVICE_DETECTION_PROBED ? "probed" :
      NULL);
  lua_newtable(L);
  for (size_t i = 0; i < sd->cpe.size(); i++) {
    lua_pushstring(L, sd->cpe[i]);
    lua_rawseti(L, -2, i+1);
  }
  lua_setfield(L, -2, "cpe");
}

/* set some port state information onto the
 * table which is currently on the stack
 * */
void set_portinfo (lua_State *L, const Target *target, const Port *port)
{
  struct serviceDeductions sd;

  target->ports.getServiceDeductions(port->portno, port->proto, &sd);

  nseU_setifield(L, -1, "number", port->portno);
  nseU_setsfield(L, -1, "service", sd.name);
  nseU_setsfield(L, -1, "protocol", IPPROTO2STR(port->proto));
  nseU_setsfield(L, -1, "state", statenum2str(port->state));
  nseU_setsfield(L, -1, "reason", reason_str(port->reason.reason_id, 1));
  nseU_setifield(L, -1, "reason_ttl", port->reason.ttl);
  lua_newtable(L);
  set_version(L, &sd);
  lua_setfield(L, -2, "version");
}

/* Push a string containing the binary contents of the given address. If ss has
   an unknown address family, push nil. */
static void push_bin_ip(lua_State *L, const struct sockaddr_storage *ss)
{
  if (ss->ss_family == AF_INET) {
    const struct sockaddr_in *sin;

    sin = (struct sockaddr_in *) ss;
    lua_pushlstring(L, (char *) &sin->sin_addr.s_addr, IP_ADDR_LEN);
  } else if (ss->ss_family == AF_INET6) {
    const struct sockaddr_in6 *sin6;

    sin6 = (struct sockaddr_in6 *) ss;
    lua_pushlstring(L, (char *) &sin6->sin6_addr.s6_addr, IP6_ADDR_LEN);
  } else {
    lua_pushnil(L);
  }
}

static void set_string_or_nil(lua_State *L, const char *fieldname, const char *value) {
  if (value != NULL) {
    lua_pushstring(L, value);
    lua_setfield(L, -2, fieldname);
  }
}

static void push_osclass_table(lua_State *L,
  const struct OS_Classification *osclass) {
  unsigned int i;

  lua_newtable(L);

  set_string_or_nil(L, "vendor", osclass->OS_Vendor);
  set_string_or_nil(L, "osfamily", osclass->OS_Family);
  set_string_or_nil(L, "osgen", osclass->OS_Generation);
  set_string_or_nil(L, "type", osclass->Device_Type);

  lua_newtable(L);
  for (i = 0; i < osclass->cpe.size(); i++) {
    lua_pushstring(L, osclass->cpe[i]);
    lua_rawseti(L, -2, i + 1);
  }
  lua_setfield(L, -2, "cpe");
}

static void push_osmatch_table(lua_State *L, const FingerMatch *match,
  const OS_Classification_Results *OSR) {
  int i;

  lua_newtable(L);

  lua_pushstring(L, match->OS_name);
  lua_setfield(L, -2, "name");

  lua_newtable(L);
  for (i = 0; i < OSR->OSC_num_matches; i++) {
    push_osclass_table(L, OSR->OSC[i]);
    lua_rawseti(L, -2, i + 1);
  }
  lua_setfield(L, -2, "classes");
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
  nseU_setsfield(L, -1, "ip", currenths->targetipstr());
  nseU_setsfield(L, -1, "name", currenths->HostName());
  nseU_setsfield(L, -1, "targetname", currenths->TargetName());
  nseU_setsfield(L, -1, "reason", reason_str(currenths->reason.reason_id, SINGULAR));
  nseU_setifield(L, -1, "reason_ttl", currenths->reason.ttl);

  if (currenths->directlyConnectedOrUnset() != -1)
    nseU_setbfield(L, -1, "directly_connected", currenths->directlyConnected());
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
  nseU_setsfield(L, -1, "interface", currenths->deviceName());
  nseU_setifield(L, -1, "interface_mtu", currenths->MTU());

  push_bin_ip(L, currenths->TargetSockAddr());
  lua_setfield(L, -2, "bin_ip");
  push_bin_ip(L, currenths->SourceSockAddr());
  lua_setfield(L, -2, "bin_ip_src");

  lua_newtable(L);
  nseU_setnfield(L, -1, "srtt", (lua_Number) currenths->to.srtt / 1000000.0);
  nseU_setnfield(L, -1, "rttvar", (lua_Number) currenths->to.rttvar / 1000000.0);
  nseU_setnfield(L, -1, "timeout", (lua_Number) currenths->to.timeout / 1000000.0);
  lua_setfield(L, -2, "times");

  lua_newtable(L);
  lua_setfield(L, -2, "registry");

  /* add distance (in hops) if traceroute has been performed */
  if (currenths->traceroute_hops.size() > 0)
  {
    std::list<TracerouteHop>::iterator it;

    lua_newtable(L);
    for (it = currenths->traceroute_hops.begin(); it != currenths->traceroute_hops.end(); it++)
    {
      lua_newtable(L);
      /* fill the table if the hop has not timed out, otherwise an empty table
       * is inserted */
      if (!it->timedout) {
        nseU_setsfield(L, -1, "ip", inet_ntop_ez(&it->addr, sizeof(it->addr)));
        if (!it->name.empty())
          nseU_setsfield(L, -1, "name", it->name.c_str());
        lua_newtable(L);
        nseU_setnfield(L, -1, "srtt", it->rtt / 1000.0);
        lua_setfield(L, -2, "times");
      }
      lua_rawseti(L, -2, lua_rawlen(L, -2)+1);
    }
    lua_setfield(L, -2, "traceroute");
  }

  FingerPrintResults *FPR = currenths->FPR;

  /* if there has been an os scan which returned a pretty certain
   * result, we will use it in the scripts
   * matches which aren't perfect are not needed in the scripts
   */
  if (currenths->osscanPerformed() && FPR != NULL &&
      FPR->overall_results == OSSCAN_SUCCESS && FPR->num_perfect_matches > 0 &&
      FPR->num_perfect_matches <= 8 )
  {
    int i;
    const OS_Classification_Results *OSR = FPR->getOSClassification();

    lua_newtable(L);
    for (i = 0; i < FPR->num_perfect_matches; i++) {
      push_osmatch_table(L, FPR->matches[i], OSR);
      lua_rawseti(L, -2, i + 1);
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
      lua_rawseti(L, lua_upvalueindex(1), lua_rawlen(L, lua_upvalueindex(1))+1);
      return nse_yield(L, 0, NULL);
    case DONE:
      lua_pushthread(L);
      if (!lua_rawequal(L, -1, lua_upvalueindex(2)))
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
      lua_rawseti(L, lua_upvalueindex(1), lua_rawlen(L, lua_upvalueindex(1))+1);
      return nse_yield(L, 0, NULL);
    case SIGNAL:
      n = lua_rawlen(L, lua_upvalueindex(1));
      if (n == 0)
        n = 1;
      break;
    case BROADCAST:
      n = 1;
      break;
  }
  lua_pushvalue(L, lua_upvalueindex(1));
  for (i = lua_rawlen(L, -1); i >= n; i--)
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

/* Generates an array of port data for the given host and leaves it on
 * the top of the stack
 */
static int l_get_ports (lua_State *L)
{
  static const char *state_op[] = {"open", "filtered", "unfiltered", "closed",
      "open|filtered", "closed|filtered", NULL};
  static const int states[] = {PORT_OPEN, PORT_FILTERED, PORT_UNFILTERED,
      PORT_CLOSED, PORT_OPENFILTERED, PORT_CLOSEDFILTERED};
  Port *p = NULL;
  Port port; /* dummy Port for nextPort */
  Target *target = nseU_gettarget(L, 1);
  int protocol = NSE_PROTOCOL[luaL_checkoption(L, 3, NULL, NSE_PROTOCOL_OP)];
  int state = states[luaL_checkoption(L, 4, NULL, state_op)];

  if (!lua_isnil(L, 2))
    p = nseU_getport(L, target, &port, 2);

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
  Port *p;
  Port port; /* dummy Port */
  target = nseU_gettarget(L, 1);
  p = nseU_getport(L, target, &port, 2);
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
 * lua code to check if a given port with its protocol are in the
 * exclude directive found in the nmap-service-probes file.
 * */
static int l_port_is_excluded (lua_State *L)
{
  unsigned short portno = (unsigned short) luaL_checkinteger(L, 1);
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
  Port *p;
  Port port;
  target = nseU_gettarget(L, 1);
  if ((p = nseU_getport(L, target, &port, 2)) != NULL)
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
    target->ports.setStateReason(p->portno, p->proto, ER_SCRIPT, 0, NULL);
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
  Port *p;
  Port port;
  std::vector<const char *> cpe;
  enum service_tunnel_type tunnel = SERVICE_TUNNEL_NONE;
  enum serviceprobestate probestate =
      opversion[luaL_checkoption(L, 3, "hardmatched", ops)];

  target = nseU_gettarget(L, 1);
  if ((p = nseU_getport(L, target, &port, 2)) == NULL)
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
    *service_fp     = (lua_getfield(L, 4, "service_fp"), lua_tostring(L, -1)),
    *service_tunnel = (lua_getfield(L, 4, "service_tunnel"),
                                                         lua_tostring(L, -1));
  if (service_tunnel == NULL || strcmp(service_tunnel, "none") == 0)
    tunnel = SERVICE_TUNNEL_NONE;
  else if (strcmp(service_tunnel, "ssl") == 0)
    tunnel = SERVICE_TUNNEL_SSL;
  else
    luaL_argerror(L, 2, "invalid value for port.version.service_tunnel");

  lua_getfield(L, 4, "cpe");
  if (lua_isnil(L, -1))
    ;
  else if(lua_istable(L, -1))
    for (lua_pushnil(L); lua_next(L, -2); lua_pop(L, 1)) {
      cpe.push_back(lua_tostring(L, -1));
    }
  else
    luaL_error(L, "port.version 'cpe' field must be a table");

  target->ports.setServiceProbeResults(p->portno, p->proto,
      probestate, name, tunnel, product,
      version, extrainfo, hostname, ostype, devicetype,
      (cpe.size() > 0) ? &cpe : NULL,
      probestate==PROBESTATE_FINISHED_HARDMATCHED ? NULL : service_fp);
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

static int finalize_cleanup (lua_State *L, int status, lua_KContext ctx)
{
  lua_settop(L, 2);
  return lua_error(L);
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
      lua_callk(L, 0, 0, 0, finalize_cleanup);
    }
    return finalize_cleanup(L, LUA_OK, 0);
  }
  return lua_gettop(L)-1; /* omit first boolean argument */
}

static int l_new_try (lua_State *L)
{
  lua_settop(L, 1);
  lua_pushcclosure(L, new_try_finalize, 1);
  return 1;
}

static int l_get_version_intensity (lua_State *L)
{
  static int intensity = -1;

  const int max_intensity = 9;

  bool selected_by_name;
  nse_selectedbyname(L);
  selected_by_name = lua_toboolean(L, -1);
  lua_pop(L,1);

  if (selected_by_name) {
    lua_pushnumber(L, max_intensity);
    return 1;
  }

  if (intensity < 0) {
    int is_script_intensity_set;
    int script_intensity;

    lua_getglobal(L, "nmap");
    lua_getfield(L, -1, "registry");
    lua_getfield(L, -1, "args");
    lua_getfield(L, -1, "script-intensity");

    script_intensity = lua_tointegerx(L, lua_gettop(L), &is_script_intensity_set);

    lua_pop(L, 4);

    if (is_script_intensity_set) {
      if (script_intensity < 0 || script_intensity > 9)
        error("Warning: Valid values of script arg script-intensity are between "
              "0 and 9. Using %d nevertheless.\n", script_intensity);
      intensity = script_intensity;
    } else {
      intensity = o.version_intensity;
    }
  }

  lua_pushnumber(L, intensity);

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

/* Save new discovered targets.
 *
 * This function can take a Vararg expression:
 *  A vararg expression that represents targets (IPs or Hostnames).
 *
 * Returns two values if it receives target arguments:
 *   The number of targets that were added, or 0 on failures.
 *   An error message on failures.
 *
 * If this function was called without an argument then it
 * will simply return the number of pending targets that are
 * in the queue (waiting to be passed to Nmap).
 *
 * If the function was only able to add a one target, then we
 * consider this success. */
static int l_add_targets (lua_State *L)
{
  int n;
  unsigned long ntarget = 0;

  if (lua_gettop(L) > 0) {
    for (n = 1; n <= lua_gettop(L); n++) {
      if (!NewTargets::insert(luaL_checkstring(L, n)))
        break;
      ntarget++;
    }
    /* was able to add some targets */
    if (ntarget) {
      lua_pushnumber(L, ntarget);
      return 1;
    /* errors */
    } else {
      lua_pushnumber(L, ntarget);
      lua_pushstring(L, "failed to add new targets.");
      return 2;
    }
  } else {
      /* function called without arguments */
      /* push the number of pending targets that are in the queue */
      lua_pushnumber(L, NewTargets::insert(""));
      return 1;
  }
}

/* Return the number of added targets */
static int l_get_new_targets_num (lua_State *L)
{
  lua_pushnumber(L, NewTargets::get_number());
  return 1;
}

// returns a table with DNS servers known to nmap
static int l_get_dns_servers (lua_State *L)
{
  std::list<std::string> servs2 = get_dns_servers();
  std::list<std::string>::iterator servI2;

  lua_newtable(L);
  for (servI2 = servs2.begin(); servI2 != servs2.end(); servI2++)
    nseU_appendfstr(L, -1, "%s", servI2->c_str());
  return 1;
}

static int l_is_privileged(lua_State *L)
{
  lua_pushboolean(L, o.isr00t);
  return 1;
}

/* Takes a host and optional address family and returns a table of
 * addresses
 */
static int l_resolve(lua_State *L)
{
  static const char *fam_op[] = { "inet", "inet6", "unspec", NULL };
  static const int fams[] = { AF_INET, AF_INET6, AF_UNSPEC };
  struct sockaddr_storage ss;
  struct addrinfo *addr, *addrs;
  const char *host = luaL_checkstring(L, 1);
  int af = fams[luaL_checkoption(L, 2, "unspec", fam_op)];

  addrs = resolve_all(host, af);

  if (!addrs)
    return nseU_safeerror(L, "Failed to resolve");

  lua_pushboolean(L, true);

  lua_newtable(L);

  for (addr = addrs; addr != NULL; addr = addr->ai_next) {
    if (af != AF_UNSPEC && addr->ai_family != af)
      continue;
    if (addr->ai_addrlen > sizeof(ss))
      continue;
    memcpy(&ss, addr->ai_addr, addr->ai_addrlen);
    nseU_appendfstr(L, -1, "%s", inet_socktop(&ss));
  }

  if (addrs != NULL)
    freeaddrinfo(addrs);

  return 2;
}

static int l_address_family(lua_State *L)
{
  if (o.af() == AF_INET)
    lua_pushliteral(L, "inet");
  else
    lua_pushliteral(L, "inet6");
  return 1;
}

/* return the interface name that was specified with
 * the -e option
 */
static int l_get_interface (lua_State *L)
{
  if (*o.device)
    lua_pushstring(L, o.device);
  else
    lua_pushnil(L);
  return 1;
}

/* returns a list of tables where each table contains information about each
 * interface.
 */
static int l_list_interfaces (lua_State *L)
{
  int numifs = 0;
  struct interface_info *iflist;
  char errstr[256];
  errstr[0]='\0';
  char ipstr[INET6_ADDRSTRLEN];
  struct addr src, bcast;

  iflist = getinterfaces(&numifs, errstr, sizeof(errstr));

  int i;

  if (iflist==NULL || numifs<=0) {
    return nseU_safeerror(L, "%s", errstr);
  } else {
    memset(ipstr, 0, INET6_ADDRSTRLEN);
    memset(&src, 0, sizeof(src));
    memset(&bcast, 0, sizeof(bcast));
    lua_newtable(L); //base table

    for(i=0; i< numifs; i++) {
      lua_newtable(L); //interface table
      nseU_setsfield(L, -1, "device", iflist[i].devfullname);
      nseU_setsfield(L, -1, "shortname", iflist[i].devname);
      nseU_setifield(L, -1, "netmask", iflist[i].netmask_bits);
      nseU_setsfield(L, -1, "address", inet_ntop_ez(&(iflist[i].addr),
            sizeof(iflist[i].addr) ));

      switch (iflist[i].device_type){
        case devt_ethernet:
          nseU_setsfield(L, -1, "link", "ethernet");
          lua_pushlstring(L, (const char *) iflist[i].mac, 6);
          lua_setfield(L, -2, "mac");

          /* calculate the broadcast address */
          if (iflist[i].addr.ss_family == AF_INET) {
          src.addr_type = ADDR_TYPE_IP;
          src.addr_bits = iflist[i].netmask_bits;
          src.addr_ip = ((struct sockaddr_in *)&(iflist[i].addr))->sin_addr.s_addr;
          addr_bcast(&src, &bcast);
          memset(ipstr, 0, INET6_ADDRSTRLEN);
          if (addr_ntop(&bcast, ipstr, INET6_ADDRSTRLEN) != NULL)
            nseU_setsfield(L, -1, "broadcast", ipstr);
          }
          break;
        case devt_loopback:
          nseU_setsfield(L, -1, "link", "loopback");
          break;
        case devt_p2p:
          nseU_setsfield(L, -1, "link", "p2p");
          break;
        case devt_other:
        default:
          nseU_setsfield(L, -1, "link", "other");
      }

      nseU_setsfield(L, -1, "up", (iflist[i].device_up ? "up" : "down"));
      nseU_setifield(L, -1, "mtu", iflist[i].mtu);

      /* After setting the fields, add the interface table to the base table */
      lua_rawseti(L, -2, i + 1);
    }
  }
  return 1;
}

/* return the ttl (time to live) specified with the
 * --ttl command line option. If a wrong value is
 * specified it defaults to 64.
 */
static int l_get_ttl (lua_State *L)
{
  if (o.ttl < 0 || o.ttl > 255)
    lua_pushnumber(L, 64); //default TTL
  else
    lua_pushnumber(L, o.ttl);
  return 1;
}

/* return the payload length specified by the --data-length
 * command line option. If it  * isn't specified or the value
 * is out of range then the default value (0) is returned.
 */
static int l_get_payload_length(lua_State *L)
{
  if (o.extra_payload_length < 0)
    lua_pushnumber(L, 0); //default payload length
  else
    lua_pushnumber(L, o.extra_payload_length);
  return 1;
}

int luaopen_nmap (lua_State *L)
{
  static const luaL_Reg nmaplib [] = {
    {"get_port_state", l_get_port_state},
    {"get_ports", l_get_ports},
    {"set_port_state", l_set_port_state},
    {"set_port_version", l_set_port_version},
    {"port_is_excluded", l_port_is_excluded},
    {"clock_ms", l_clock_ms},
    {"clock", l_clock},
    {"log_write", l_log_write},
    {"new_try", l_new_try},
    {"version_intensity", l_get_version_intensity},
    {"verbosity", l_get_verbosity},
    {"debugging", l_get_debugging},
    {"have_ssl", l_get_have_ssl},
    {"fetchfile", l_fetchfile},
    {"timing_level", l_get_timing_level},
    {"add_targets", l_add_targets},
    {"new_targets_num",l_get_new_targets_num},
    {"get_dns_servers", l_get_dns_servers},
    {"is_privileged", l_is_privileged},
    {"resolve", l_resolve},
    {"address_family", l_address_family},
    {"get_interface", l_get_interface},
    {"list_interfaces", l_list_interfaces},
    {"get_ttl", l_get_ttl},
    {"get_payload_length",l_get_payload_length},
    {"new_dnet", nseU_placeholder}, /* imported from nmap.dnet */
    {"get_interface_info", nseU_placeholder}, /* imported from nmap.dnet */
    {"new_socket", nseU_placeholder}, /* imported from nmap.socket */
    {"mutex", nseU_placeholder}, /* placeholder */
    {"condvar", nseU_placeholder}, /* placeholder */
    {NULL, NULL}
  };

  luaL_newlib(L, nmaplib);
  int nmap_idx = lua_gettop(L);

  nseU_weaktable(L, 0, 0, "v"); /* allow closures to be collected (see l_mutex) */
  lua_pushcclosure(L, l_mutex, 1); /* mutex function */
  lua_setfield(L, nmap_idx, "mutex");

  nseU_weaktable(L, 0, 0, "v"); /* allow closures to be collected (see l_condvar) */
  lua_pushcclosure(L, l_condvar, 1); /* condvar function */
  lua_setfield(L, nmap_idx, "condvar");

  lua_newtable(L);
  lua_setfield(L, nmap_idx, "registry");

  /* Pull out some functions from the nmap.socket and nmap.dnet libraries.
     http://seclists.org/nmap-dev/2012/q1/299. */
  luaL_requiref(L, "nmap.socket", luaopen_nsock, 0);
  /* nmap.socket.new -> nmap.new_socket. */
  lua_getfield(L, -1, "new");
  lua_setfield(L, nmap_idx, "new_socket");
  /* Store nmap.socket; used by nse_main.lua. */
  lua_setfield(L, nmap_idx, "socket");

  luaL_requiref(L, "nmap.dnet", luaopen_dnet, 0);
  /* nmap.dnet.new -> nmap.new_dnet. */
  lua_getfield(L, -1, "new");
  lua_setfield(L, nmap_idx, "new_dnet");
  /* nmap.dnet.get_interface_info -> nmap.get_interface_info. */
  lua_getfield(L, -1, "get_interface_info");
  lua_setfield(L, nmap_idx, "get_interface_info");
  /* Store nmap.socket. */
  lua_setfield(L, nmap_idx, "dnet");

  lua_settop(L, nmap_idx);

  return 1;
}
