#include "nse_nmaplib.h"
#include "nse_nsock.h"
#include "nse_macros.h"
#include "nse_debug.h"

#include "nmap_error.h"
#include "osscan.h"
#include "NmapOps.h"
#include "nmap_rpc.h"
#include "Target.h"
#include "output.h"
#include "portlist.h"

#define SCRIPT_ENGINE_GETSTRING(name) \
	char* name; \
	lua_getfield(l, -1, #name); \
	if(lua_isnil(l, -1)) \
		name = NULL; \
	else \
		name = strdup(lua_tostring(l, -1)); \
	lua_pop(l, 1); \

#define SCRIPT_ENGINE_PUSHSTRING_NOTNULL(c_str, str) if(c_str != NULL) {\
	lua_pushstring(l, c_str); \
	lua_setfield(l, -2, str); \
}

extern NmapOps o;
extern std::map<std::string, Target*> current_hosts;

void set_version(lua_State* l, struct serviceDeductions sd);

static int l_exc_newtry(lua_State *l);
static int l_port_accessor(lua_State* l);
static int l_print_debug_unformatted(lua_State *l);
static int l_get_port_state(lua_State* l, Target* target, Port* port);
static int l_set_port_state(lua_State* l, Target* target, Port* port);
static int l_set_port_version(lua_State* l, Target* target, Port* port);

/* register the nmap lib 
 * we assume that we can write to a table at -1 on the stack
 * */
int set_nmaplib(lua_State* l) {
	static luaL_reg nmaplib [] = {
		{"get_port_state", l_port_accessor},
		{"set_port_state", l_port_accessor},
		{"set_port_version", l_port_accessor},
		{"new_socket", l_nsock_new},
		{"print_debug_unformatted", l_print_debug_unformatted},
		{"new_try", l_exc_newtry},
		{NULL, NULL} 
	};

	const luaL_Reg* lib;
	for (lib = nmaplib; lib->func; lib++) {
		lua_pushcfunction(l, lib->func);
		lua_setfield(l, -2, lib->name);
	}

	lua_newtable(l);
	lua_setfield(l, -2, "registry");

	SCRIPT_ENGINE_TRY(l_nsock_open(l));

	return SCRIPT_ENGINE_SUCCESS;
}

/* set some port state information onto the
 * table which is currently on the stack
 * */
void set_portinfo(lua_State* l, Port* port) {
	struct serviceDeductions sd;

	port->getServiceDeductions(&sd);

	lua_pushnumber(l, (double) port->portno);
	lua_setfield(l, -2, "number");

	lua_pushstring(l, sd.name);
	lua_setfield(l, -2, "service");

	lua_pushstring(l, (port->proto == IPPROTO_TCP)? "tcp": "udp");
	lua_setfield(l, -2, "protocol");

	lua_newtable(l);
	set_version(l, sd);
	lua_setfield(l, -2, "version");

	lua_pushstring(l, statenum2str(port->state));
	lua_setfield(l, -2, "state");
}

void set_version(lua_State* l, struct serviceDeductions sd) {
	SCRIPT_ENGINE_PUSHSTRING_NOTNULL(sd.name, "name");

	lua_pushnumber(l, sd.name_confidence);
	lua_setfield(l, -2, "name_confidence");

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
		lua_pushnumber(l, sd.rpc_program);
		lua_setfield(l, -2, "rpc_program");

		lua_pushnumber(l, sd.rpc_lowver);
		lua_setfield(l, -2, "rpc_lowver");

		lua_pushnumber(l, sd.rpc_highver);
		lua_setfield(l, -2, "rpc_highver");
	}
}

/* set host ip and host name onto the
 * table which is currently on the stack
 * set name of the os run by the host onto the
 * table which is currently on the stack
 * the os name is really an array with perfect
 * matches
 * if an os scan wasn't performed, the array
 * points to nil!
 * */
void set_hostinfo(lua_State* l, Target *currenths) {
	unsigned int i;
	char hostname[1024];

	lua_pushstring(l, strncpy(hostname, currenths->targetipstr(), 1024));
	lua_setfield(l, -2, "ip");

	lua_pushstring(l, strncpy(hostname, currenths->HostName(), 1024));
	lua_setfield(l, -2, "name");

	
	FingerPrintResults *FPR = NULL;
	int osscanSys;

	if (currenths->FPR != NULL && currenths->FPR1 == NULL) {
		osscanSys = 2;
		FPR = currenths->FPR;
	} else if(currenths->FPR == NULL && currenths->FPR1 != NULL) {
		osscanSys = 1;
		FPR = currenths->FPR1;
	} 

	/* if there has been an os scan which returned a pretty certain
	 * result, we will use it in the scripts
	 * matches which aren't perfect are not needed in the scripts
	 */
	if(	currenths->osscanPerformed() &&
		FPR != NULL &&
		FPR->overall_results == OSSCAN_SUCCESS &&
		FPR->num_perfect_matches > 0 &&
		FPR->num_perfect_matches <= 8 ) {

		lua_newtable(l);

		// this will run at least one time and at most 8 times, see if condition
		for(i = 0; FPR->accuracy[i] == 1; i++) {
			lua_pushstring(l, FPR->prints[i]->OS_name);
			lua_rawseti(l, -2, i);
		}
		lua_setfield(l, -2, "os");
	}
}

static int l_port_accessor(lua_State* l) {
	int retvalues = 0;

	char* function_name;
	char* target_ip;
	int portno;
	int proto;

	Target* target;
	PortList* plist;
	Port* port;

	lua_Debug ldebug;
	lua_getstack(l, 0, &ldebug);
	lua_getinfo(l, "n", &ldebug);
	function_name = strdup(ldebug.name);

	luaL_checktype(l, 1, LUA_TTABLE);
	luaL_checktype(l, 2, LUA_TTABLE);

	lua_getfield(l, 1, "ip");
	luaL_checktype(l, -1, LUA_TSTRING);
	target_ip = strdup(lua_tostring(l, -1));
	lua_pop(l, 1);

	lua_getfield(l, 2, "number");
	luaL_checktype(l, -1, LUA_TNUMBER);
	portno = lua_tointeger(l, -1);
	lua_pop(l, 1);

	lua_getfield(l, 2, "protocol");
	luaL_checktype(l, -1, LUA_TSTRING);
	proto = (strcmp(lua_tostring(l, -1), "tcp") == 0)? IPPROTO_TCP : IPPROTO_UDP;
	lua_pop(l, 1);

	std::string key = std::string(target_ip);
	std::map<std::string, Target*>::iterator iter = current_hosts.find(key);
	if(iter == current_hosts.end()) {
		luaL_argerror (l, 1, "Host isn't being processed right now.");
		return 0;
	} else {
		target = (Target*) iter->second;
	}

	plist = &(target->ports);
	port = NULL;

	while((port = plist->nextPort(port, proto, PORT_UNKNOWN)) != NULL) {
		if(port->portno == portno)
			break;
	}

	// if the port wasn't scanned we return nil
	if(port == NULL)
		return 0;

	if(strcmp(function_name, "set_port_state") == MATCH)
		retvalues = l_set_port_state(l, target, port);
	else if(strcmp(function_name, "set_port_version") == MATCH)
		retvalues = l_set_port_version(l, target, port);
	else if(strcmp(function_name, "get_port_state") == MATCH)
		retvalues = l_get_port_state(l, target, port);

	// remove host and port argument from the stack
	lua_remove(l, 2);
	lua_remove(l, 1);
	free(target_ip);
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
static int l_get_port_state(lua_State* l, Target* target, Port* port) {
	lua_newtable(l);
	set_portinfo(l, port);

	return 1;
}

/* unlike set_portinfo() this function sets the port state in nmap.
 * if for example a udp port was seen by the script as open instead of
 * filtered, the script is free to say so.
 * */
static int l_set_port_state(lua_State* l, Target* target, Port* port) {
	char* state;
	PortList* plist = &(target->ports);

	luaL_checktype(l, -1, LUA_TSTRING);
	state = strdup(lua_tostring(l, -1));
	lua_pop(l, 1);

	switch(state[0]) {
		case 'o':
			if (strcmp(state, "open")) 
				luaL_argerror (l, 4, "Invalid port state.");
			plist->addPort(port->portno, port->proto, NULL, PORT_OPEN);
			port->state = PORT_OPEN;
			break;
		case 'c':
			if (strcmp(state, "closed"))
				luaL_argerror (l, 4, "Invalid port state.");
			plist->addPort(port->portno, port->proto, NULL, PORT_CLOSED);
			port->state = PORT_CLOSED;
			break;
		default:
			luaL_argerror (l, 4, "Invalid port state.");
	}	

	free(state);
	return 0;
}

static int l_set_port_version(lua_State* l, Target* target, Port* port) {
	luaL_checktype(l, 3, LUA_TSTRING);
	char* c_probestate = strdup(lua_tostring(l, -1));
	lua_pop(l, 1);

	enum service_tunnel_type tunnel = SERVICE_TUNNEL_NONE;
	enum serviceprobestate probestate = PROBESTATE_INITIAL;

	lua_getfield(l, -1, "version");
		SCRIPT_ENGINE_GETSTRING(name);
		SCRIPT_ENGINE_GETSTRING(product);
		SCRIPT_ENGINE_GETSTRING(version);
		SCRIPT_ENGINE_GETSTRING(extrainfo);
		SCRIPT_ENGINE_GETSTRING(hostname);
		SCRIPT_ENGINE_GETSTRING(ostype);
		SCRIPT_ENGINE_GETSTRING(devicetype);
		// SCRIPT_ENGINE_GETSTRING(fingerprint);
	
		SCRIPT_ENGINE_GETSTRING(service_tunnel);
		if(strcmp(service_tunnel, "none") == 0)
			tunnel = SERVICE_TUNNEL_NONE;	
		else if(strcmp(service_tunnel, "ssl") == 0)
			tunnel = SERVICE_TUNNEL_SSL;
		else
			luaL_argerror(l, 2, "Invalid value for port.version.service_tunnel");
	lua_pop(l, 1);

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
		luaL_argerror(l, 3, "Invalid value for probestate.");

//	port->setServiceProbeResults(probestate, name,
//			tunnel, product, version,
//			extrainfo, hostname, ostype, 
//			devicetype, fingerprint);
	port->setServiceProbeResults(probestate, name,
			tunnel, product, version,
			extrainfo, hostname, ostype, 
			devicetype, NULL);



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

static int l_print_debug_unformatted(lua_State *l) {
	int verbosity=1, stack_counter(1);
	const char *out;

	if (lua_gettop(l) != 2) return luaL_error(l, "Incorrect number of arguments\n");

	verbosity = luaL_checkinteger(l, 1);
	if (verbosity > o.verbose) return 0;
	out = luaL_checkstring(l, 2);

	log_write(LOG_STDOUT, "%s DEBUG: %s\n", SCRIPT_ENGINE, out);

	return 0;
}

static int l_exc_finalize(lua_State *l) {
	if (lua_isnil(l, 1)) {
		lua_pushvalue(l, lua_upvalueindex(1));
		lua_call(l, 0, 0);
		lua_settop(l, 2);
		lua_error(l);
		return 0;
	} else if(lua_toboolean(l, 1)) {
		lua_remove(l, 1);
		return lua_gettop(l);
	} else {
		fatal("%s: In: %s:%i Trying to finalize a non conforming function. Are you sure you return true on success followed by the remaining return values and nil on failure followed by an error string?", 
			SCRIPT_ENGINE, __FILE__, __LINE__);

		return 0;
	}
}

static int l_exc_do_nothing(lua_State *l) {
	(void) l;
	return 0;
}

static int l_exc_newtry(lua_State *l) {
	lua_settop(l, 1);
	if (lua_isnil(l, 1)) 
		lua_pushcfunction(l, l_exc_do_nothing);
	lua_pushcclosure(l, l_exc_finalize, 1);
	return 1;
}

