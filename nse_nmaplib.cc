#include "nse_nmaplib.h"
#include "nse_nsock.h"
#include "nse_macros.h"
#include "nse_debug.h"

#include "nmap.h"
#include "nmap_error.h"
#include "osscan.h"
#include "NmapOps.h"
#include "nmap_rpc.h"
#include "Target.h"
#include "output.h"
#include "portlist.h"

#define SCRIPT_ENGINE_GETSTRING(name) \
	char* name; \
	lua_getfield(L, -1, #name); \
	if(lua_isnil(L, -1)) \
		name = NULL; \
	else \
		name = strdup(lua_tostring(L, -1)); \
	lua_pop(L, 1); \

#define SCRIPT_ENGINE_PUSHSTRING_NOTNULL(c_str, str) if(c_str != NULL) {\
	lua_pushstring(L, c_str); \
	lua_setfield(L, -2, str); \
}

extern NmapOps o;
/* extern std::map<std::string, Target*> current_hosts; */
extern int current_hosts;

void set_version(lua_State *L, struct serviceDeductions sd);

static int l_exc_newtry(lua_State *L);
static int l_port_accessor(lua_State *L);
static int l_print_debug_unformatted(lua_State *L);
static int l_get_port_state(lua_State *L, Target* target, Port* port);
static int l_set_port_state(lua_State *L, Target* target, Port* port);
static int l_set_port_version(lua_State *L, Target* target, Port* port);
static int l_get_verbosity(lua_State *);
static int l_get_debugging(lua_State *);
static int l_get_have_ssl(lua_State *L);
static int l_fetchfile(lua_State *L);
static int l_get_timing_level(lua_State *L);

int l_clock_ms(lua_State *L);

/* register the nmap lib 
 * we assume that we can write to a table at -1 on the stack
 * */
/* int set_nmaplib(lua_State *L) {
	static luaL_reg nmaplib [] = {
		{"get_port_state", l_port_accessor},
		{"set_port_state", l_port_accessor},
		{"set_port_version", l_port_accessor},
		{"new_socket", l_nsock_new},
		{"new_dnet", l_dnet_new},
		{"get_interface_link", l_dnet_get_interface_link},
		{"clock_ms", l_clock_ms},
		{"print_debug_unformatted", l_print_debug_unformatted},
		{"new_try", l_exc_newtry},
		{"verbosity", l_get_verbosity},
		{"debugging", l_get_debugging},
		{"have_ssl", l_get_have_ssl},
		{"fetchfile", l_fetchfile},
		{"timing_level", l_get_timing_level},
		{NULL, NULL} 
	};

	const luaL_Reg* lib;
	for (lib = nmaplib; lib->func; lib++) {
		lua_pushcfunction(L, lib->func);
		lua_setfield(L, -2, lib->name);
	}

	lua_newtable(L);
	lua_setfield(L, -2, "registry");

	SCRIPT_ENGINE_TRY(l_nsock_open(L));
	SCRIPT_ENGINE_TRY(l_dnet_open(L));

	return SCRIPT_ENGINE_SUCCESS;
} */

int luaopen_nmap (lua_State *L)
{
  static luaL_reg nmaplib [] = {
    {"get_port_state", l_port_accessor},
    {"set_port_state", l_port_accessor},
    {"set_port_version", l_port_accessor},
    {"new_socket", l_nsock_new},
    {"new_dnet", l_dnet_new},
    {"get_interface_link", l_dnet_get_interface_link},
    {"clock_ms", l_clock_ms},
    {"print_debug_unformatted", l_print_debug_unformatted},
    {"new_try", l_exc_newtry},
    {"verbosity", l_get_verbosity},
    {"debugging", l_get_debugging},
    {"have_ssl", l_get_have_ssl},
    {"fetchfile", l_fetchfile},
    {"timing_level", l_get_timing_level},
    {NULL, NULL} 
  };

  luaL_register(L, "nmap", nmaplib);

  lua_newtable(L);
  lua_setfield(L, -2, "registry");

  SCRIPT_ENGINE_TRY(l_nsock_open(L));
  SCRIPT_ENGINE_TRY(l_dnet_open(L));

  return 0;
}

/* set some port state information onto the
 * table which is currently on the stack
 * */
void set_portinfo(lua_State *L, Port* port) {
	struct serviceDeductions sd;

	port->getServiceDeductions(&sd);

	lua_pushnumber(L, (double) port->portno);
	lua_setfield(L, -2, "number");

	lua_pushstring(L, sd.name);
	lua_setfield(L, -2, "service");

	lua_pushstring(L, (port->proto == IPPROTO_TCP)? "tcp": "udp");
	lua_setfield(L, -2, "protocol");

	lua_newtable(L);
	set_version(L, sd);
	lua_setfield(L, -2, "version");

	lua_pushstring(L, statenum2str(port->state));
	lua_setfield(L, -2, "state");

	lua_pushstring(L, reason_str(port->reason.reason_id, 1));
	lua_setfield(L, -2, "reason");
}

void set_version(lua_State *L, struct serviceDeductions sd) {
	SCRIPT_ENGINE_PUSHSTRING_NOTNULL(sd.name, "name");

	lua_pushnumber(L, sd.name_confidence);
	lua_setfield(L, -2, "name_confidence");

	SCRIPT_ENGINE_PUSHSTRING_NOTNULL(sd.product, "product");
	SCRIPT_ENGINE_PUSHSTRING_NOTNULL(sd.version, "version");
	SCRIPT_ENGINE_PUSHSTRING_NOTNULL(sd.extrainfo, "extrainfo");
	SCRIPT_ENGINE_PUSHSTRING_NOTNULL(sd.hostname, "hostname");
	SCRIPT_ENGINE_PUSHSTRING_NOTNULL(sd.ostype, "ostype");
	SCRIPT_ENGINE_PUSHSTRING_NOTNULL(sd.devicetype, "devicetype");

	switch(sd.service_tunnel) {
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

	SCRIPT_ENGINE_PUSHSTRING_NOTNULL(sd.service_fp, "service_fp");

	switch(sd.dtype) {
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

	switch(sd.rpc_status) {
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

	if(sd.rpc_status == RPC_STATUS_GOOD_PROG) {
		lua_pushnumber(L, sd.rpc_program);
		lua_setfield(L, -2, "rpc_program");

		lua_pushnumber(L, sd.rpc_lowver);
		lua_setfield(L, -2, "rpc_lowver");

		lua_pushnumber(L, sd.rpc_highver);
		lua_setfield(L, -2, "rpc_highver");
	}
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
	char hostname[1024];

	lua_pushstring(L, strncpy(hostname, currenths->targetipstr(), 1024));
	lua_setfield(L, -2, "ip");

	lua_pushstring(L, strncpy(hostname, currenths->HostName(), 1024));
	lua_setfield(L, -2, "name");

	if ( currenths->TargetName() ) { // else nil
		lua_pushstring(L, strncpy(hostname, currenths->TargetName(), 1024));
		lua_setfield(L, -2, "targetname");
	}

	if(currenths->directlyConnectedOrUnset() != -1){
	    lua_pushboolean(L, currenths->directlyConnected());
	    lua_setfield(L, -2, "directly_connected");
	}

	if(currenths->MACAddress()){	// else nil
		lua_pushlstring (L, (const char*)currenths->MACAddress() , 6);
		lua_setfield(L, -2, "mac_addr");
	}
	if(currenths->SrcMACAddress()){	// else nil
		lua_pushlstring(L, (const char*)currenths->SrcMACAddress(), 6);
		lua_setfield(L, -2, "mac_addr_src");
	}
	if(currenths->deviceName()){
		lua_pushstring(L, strncpy(hostname, currenths->deviceName(), 1024));
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
	if(	currenths->osscanPerformed() &&
		FPR != NULL &&
		FPR->overall_results == OSSCAN_SUCCESS &&
		FPR->num_perfect_matches > 0 &&
		FPR->num_perfect_matches <= 8 ) {

		lua_newtable(L);

		// this will run at least one time and at most 8 times, see if condition
		for(i = 0; FPR->accuracy[i] == 1; i++) {
			lua_pushstring(L, FPR->prints[i]->OS_name);
			lua_rawseti(L, -2, i);
		}
		lua_setfield(L, -2, "os");
	}
}

static int l_port_accessor(lua_State *L) {
	int retvalues = 0;

	char* function_name;
	const char *target_ip;
	int portno;
	int proto;

	Target* target;
	PortList* plist;
	Port* port;

	lua_Debug ldebug;
	lua_getstack(L, 0, &ldebug);
	lua_getinfo(L, "n", &ldebug);
	function_name = strdup(ldebug.name);

	luaL_checktype(L, 1, LUA_TTABLE);
	luaL_checktype(L, 2, LUA_TTABLE);

	lua_getfield(L, 1, "ip");
	luaL_checktype(L, -1, LUA_TSTRING);
	target_ip = lua_tostring(L, -1);
	lua_pop(L, 1);

	lua_getfield(L, 2, "number");
	luaL_checktype(L, -1, LUA_TNUMBER);
	portno = lua_tointeger(L, -1);
	lua_pop(L, 1);

	lua_getfield(L, 2, "protocol");
	luaL_checktype(L, -1, LUA_TSTRING);
	proto = (strcmp(lua_tostring(L, -1), "tcp") == 0)? IPPROTO_TCP : IPPROTO_UDP;
	lua_pop(L, 1);

    lua_rawgeti(L, LUA_REGISTRYINDEX, current_hosts);
    lua_pushstring(L, target_ip);
    lua_gettable(L, -2);
    if (lua_isnil(L, -1))
      return luaL_argerror(L, 1, "Host isn't being processed right now.");
    else
    {
      target = (Target *) lua_touserdata(L, -1);
      lua_pop(L, 2);
    }

	plist = &(target->ports);
	port = NULL;

	while((port = plist->nextPort(port, proto, PORT_UNKNOWN)) != NULL) {
		if(port->portno == portno)
			break;
	}

	// if the port wasn't scanned we return nil
	if(port == NULL) {
		free(function_name);
		return 0;
	}

	if(strcmp(function_name, "set_port_state") == 0)
		retvalues = l_set_port_state(L, target, port);
	else if(strcmp(function_name, "set_port_version") == 0)
		retvalues = l_set_port_version(L, target, port);
	else if(strcmp(function_name, "get_port_state") == 0)
		retvalues = l_get_port_state(L, target, port);

	// remove host and port argument from the stack
	lua_remove(L, 2);
	lua_remove(L, 1);
	free(function_name);
	return retvalues;
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
static int l_get_port_state(lua_State *L, Target* target, Port* port) {
	lua_newtable(L);
	set_portinfo(L, port);

	return 1;
}

/* unlike set_portinfo() this function sets the port state in nmap.
 * if for example a udp port was seen by the script as open instead of
 * filtered, the script is free to say so.
 * */
static int l_set_port_state(lua_State *L, Target* target, Port* port) {
	char* state;
	PortList* plist = &(target->ports);

	luaL_checktype(L, -1, LUA_TSTRING);
	state = strdup(lua_tostring(L, -1));
	lua_pop(L, 1);

	switch(state[0]) {
		case 'o':
			if (strcmp(state, "open")) 
				luaL_argerror (L, 4, "Invalid port state.");
			if (port->state == PORT_OPEN)
				goto noset;
			plist->addPort(port->portno, port->proto, NULL, PORT_OPEN);
			port->state = PORT_OPEN;
			break;
		case 'c':
			if (strcmp(state, "closed"))
				luaL_argerror (L, 4, "Invalid port state.");
			if (port->state == PORT_CLOSED)
				goto noset;
			plist->addPort(port->portno, port->proto, NULL, PORT_CLOSED);
			port->state = PORT_CLOSED;
			break;
		default:
			luaL_argerror (L, 4, "Invalid port state.");
	}	

	port->reason.reason_id = ER_SCRIPT;

noset:
	free(state);
	return 0;
}

static int l_set_port_version(lua_State *L, Target* target, Port* port) {
	luaL_checktype(L, 3, LUA_TSTRING);
	char* c_probestate = strdup(lua_tostring(L, -1));
	lua_pop(L, 1);

	enum service_tunnel_type tunnel = SERVICE_TUNNEL_NONE;
	enum serviceprobestate probestate = PROBESTATE_INITIAL;

	lua_getfield(L, -1, "version");
		SCRIPT_ENGINE_GETSTRING(name);
		SCRIPT_ENGINE_GETSTRING(product);
		SCRIPT_ENGINE_GETSTRING(version);
		SCRIPT_ENGINE_GETSTRING(extrainfo);
		SCRIPT_ENGINE_GETSTRING(hostname);
		SCRIPT_ENGINE_GETSTRING(ostype);
		SCRIPT_ENGINE_GETSTRING(devicetype);
		// SCRIPT_ENGINE_GETSTRING(fingerprint);
	
		SCRIPT_ENGINE_GETSTRING(service_tunnel);
		if(service_tunnel == NULL)
			tunnel = SERVICE_TUNNEL_NONE;	
		else if(strcmp(service_tunnel, "none") == 0)
			tunnel = SERVICE_TUNNEL_NONE;	
		else if(strcmp(service_tunnel, "ssl") == 0)
			tunnel = SERVICE_TUNNEL_SSL;
		else
			luaL_argerror(L, 2, "Invalid value for port.version.service_tunnel");
	lua_pop(L, 1);

	if(c_probestate == NULL)
		probestate = PROBESTATE_INITIAL;
	if(strcmp(c_probestate, "hardmatched") == 0)
		probestate = PROBESTATE_FINISHED_HARDMATCHED;	
	else if(strcmp(c_probestate, "softmatched") == 0)
		probestate = PROBESTATE_FINISHED_SOFTMATCHED;
	else if(strcmp(c_probestate, "nomatch") == 0)
		probestate = PROBESTATE_FINISHED_NOMATCH;
	else if(strcmp(c_probestate, "tcpwrapped") == 0)
		probestate = PROBESTATE_FINISHED_TCPWRAPPED;
	else if(strcmp(c_probestate, "incomplete") == 0)
		probestate = PROBESTATE_INCOMPLETE;
	else
		luaL_argerror(L, 3, "Invalid value for probestate.");

//	port->setServiceProbeResults(probestate, name,
//			tunnel, product, version,
//			extrainfo, hostname, ostype, 
//			devicetype, fingerprint);

//should prevent a assertion-failure during output if the OutputTable does 
//not contain columns for the fields other than the name
	if(o.servicescan){
		port->setServiceProbeResults(probestate, name,
				tunnel, product, version,
				extrainfo, hostname, ostype, 
				devicetype, NULL);
	}else{
		port->setServiceProbeResults(probestate, name,
			tunnel, NULL, NULL,
			NULL, NULL, NULL, 
			NULL, NULL);
	}


	free(service_tunnel);
	free(name);
	free(product);
	free(version);
	free(extrainfo);
	free(hostname);
	free(ostype);
	free(devicetype);
//	free(fingerprint);
	return 0;
}

static int l_print_debug_unformatted(lua_State *L) {
  int verbosity=1;
  const char *out;
  
  if (lua_gettop(L) != 2) return luaL_error(L, "Incorrect number of arguments\n");
  
  verbosity = luaL_checkinteger(L, 1);
  if (verbosity > o.verbose) return 0;
  out = luaL_checkstring(L, 2);
  
  log_write(LOG_STDOUT, "%s DEBUG: %s\n", SCRIPT_ENGINE, out);
  
  return 0;
}

static int l_exc_finalize(lua_State *L) {
	if (!lua_toboolean(L, 1)) {
		/* false or nil. */
		lua_pushvalue(L, lua_upvalueindex(1));
		lua_call(L, 0, 0);
		lua_settop(L, 2);
		lua_error(L);
		return 0;
	} else if(lua_isboolean(L, 1) && lua_toboolean(L, 1)) {
		/* true. */
		lua_remove(L, 1);
		return lua_gettop(L);
	} else {
		fatal("%s: In: %s:%i Trying to finalize a non conforming function. Are you sure you return true on success followed by the remaining return values and nil on failure followed by an error string?", 
			SCRIPT_ENGINE, __FILE__, __LINE__);

		return 0;
	}
}

static int l_exc_do_nothing(lua_State *L) {
	(void) L;
	return 0;
}

static int l_exc_newtry(lua_State *L) {
	lua_settop(L, 1);
	if (lua_isnil(L, 1)) 
		lua_pushcfunction(L, l_exc_do_nothing);
	lua_pushcclosure(L, l_exc_finalize, 1);
	return 1;
}

static int l_get_verbosity(lua_State *L)
{
	lua_pushnumber(L, o.verbose);
	return 1;
}

static int l_get_debugging(lua_State *L)
{
	lua_pushnumber(L, o.debugging);
	return 1;
}

static int l_get_have_ssl(lua_State *L) {
#if HAVE_OPENSSL
	lua_pushboolean(L, true);
#else
	lua_pushboolean(L, false);
#endif
	return 1;
}

static int l_fetchfile(lua_State *L)
{
	char buf[FILENAME_MAX];
	const char *req = lua_tostring(L, -1);

	if (!req)
		goto err;

	if (nmap_fetchfile(buf, sizeof buf, (char *) req) != 1)
		goto err;

	lua_pop(L, 1);
	lua_pushstring(L, buf);
	return 1;
err:
	lua_pop(L, 1);
	lua_pushnil(L);
	return 0;
}

static int l_get_timing_level(lua_State *L)
{
	lua_pushnumber(L, o.timing_level);
	return 1;
}
