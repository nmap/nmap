#include "nse_nsock.h"
#include "nse_macros.h"

#include "nse_debug.h"

#include "nsock.h"
#include "nmap_error.h"
/* #include "osscan.h" */
#include "NmapOps.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sstream>
#include <iomanip>

#include "utils.h"
#include "tcpip.h"

#if HAVE_OPENSSL
#include <openssl/ssl.h>
#endif

#define SCRIPT_ENGINE			"SCRIPT ENGINE"
#define NSOCK_WRAPPER			"NSOCK WRAPPER"
#define NSOCK_WRAPPER_SUCCESS		0 
#define NSOCK_WRAPPER_ERROR		2 

#define NSOCK_WRAPPER_BUFFER_OK 1
#define NSOCK_WRAPPER_BUFFER_MOREREAD 2

#define FROM 	1
#define TO 	2

#define DEFAULT_TIMEOUT 30000

extern NmapOps o;

// defined in nse_main.cc but also declared here
// to keep the .h files clean
int process_waiting2running(lua_State *L, int resume_arguments);

static int l_nsock_connect(lua_State *L);
static int l_nsock_send(lua_State *L);
static int l_nsock_receive(lua_State *L);
static int l_nsock_receive_lines(lua_State *L);
static int l_nsock_receive_bytes(lua_State *L);
static int l_nsock_get_info(lua_State *L);
static int l_nsock_gc(lua_State *L);
static int l_nsock_close(lua_State *L);
static int l_nsock_set_timeout(lua_State *L);
static int l_nsock_receive_buf(lua_State *L);

static int l_nsock_ncap_open(lua_State *L);
static int l_nsock_ncap_close(lua_State *L);
static int l_nsock_ncap_register(lua_State *L);
static int l_nsock_pcap_receive(lua_State *L);


void l_nsock_connect_handler(nsock_pool nsp, nsock_event nse, void *lua_state);
void l_nsock_send_handler(nsock_pool nsp, nsock_event nse, void *lua_state);
void l_nsock_receive_handler(nsock_pool nsp, nsock_event nse, void *lua_state);
void l_nsock_receive_buf_handler(nsock_pool nsp, nsock_event nse, void *lua_state);

int l_nsock_check_buf(lua_State *L);

int l_nsock_checkstatus(lua_State *L, nsock_event nse);

void l_nsock_trace(nsock_iod nsiod, const char* message, int direction);
const char* inet_ntop_both(int af, const void* v_addr, char* ipstring);
unsigned short inet_port_both(int af, const void* v_addr);


static std::string hexify (const char *str, size_t len)
{
  size_t num = 0;
  std::ostringstream ret;

  // If more than 95% of the chars are printable, we escape unprintable chars
  for (size_t i = 0; i < len; i++)
    if (isprint(str[i]))
      num++;
  if ((double) num / (double) len >= 0.95)
  {
    for (size_t i = 0; i < len; i++)
    {
      if (isprint(str[i]) || isspace(str[i]))
        ret << str[i];
      else
        ret << std::setw(3) << "\\" << (unsigned int) str[i];
    }
    return ret.str();
  }

  ret << std::setbase(16) << std::setfill('0');
  for (size_t i = 0; i < len; i += 16)
  {
    ret << std::setw(8) << i << ": ";
    for (size_t j = i; j < i + 16; j++)
      if (j < len)
        ret << std::setw(2) << (unsigned int) str[j] << " ";
      else
        ret << "   ";
    for (size_t j = i; j < i + 16 && j < len; j++)
      ret.put(isgraph(str[j]) ? (unsigned char) str[j] : ' ');
    ret << std::endl;
  }
  return ret.str();
}

/* Some constants used for enforcing a limit on the number of open sockets
 * in use by threads. The maximum value between MAX_PARALLELISM and
 * o.maxparallelism is the max # of threads that can have connected sockets
 * (open). THREAD_PROXY, SOCKET_PROXY, and CONNECT_WAITING are tables in the
 * nsock C functions' environment, at LUA_ENVIRONINDEX, that hold sockets and
 * threads used to enforce this. THREAD_PROXY has <Thread, Userdata> pairs
 * that associate a thread to a proxy userdata. This table has weak keys and
 * values so threads and the proxy itself can be collected. SOCKET_PROXY
 * has <Socket, Userdata> pairs that associate a socket to a proxy userdata.
 * SOCKET_PROXY has weak keys (to allow the collection of sockets) and strong
 * values, so the proxies are not collected when an associated socket is open.
 *
 * All the sockets used by a thread have the same Proxy Userdata. When all
 * sockets in use by a thread are closed or collected, the entry in the
 * THREAD_PROXY table is cleared, freeing up a slot for another thread
 * to make connections. When a slot is freed, proxy_gc is called, via the
 * userdata's __gc metamethod, which will add a thread in WAITING to running.
 */
#define MAX_PARALLELISM   10
#define THREAD_PROXY       1 /* <Thread, Userdata> */
#define SOCKET_PROXY       2 /* <Socket, Userdata> */
#define CONNECT_WAITING    3 /* Threads waiting to lock */
#define PROXY_META         4 /* Proxy userdata's metatable */

static int proxy_gc (lua_State *L)
{
  lua_rawgeti(L, LUA_ENVIRONINDEX, CONNECT_WAITING);
  lua_pushnil(L);
  if (lua_next(L, -2) != 0)
  {
    lua_State *thread = lua_tothread(L, -2);
    process_waiting2running(thread, 0);
    lua_pushnil(L);
    lua_replace(L, -2); // replace boolean
    lua_settable(L, -3); // remove thread from waiting
  }
  return 0;
}

static void new_proxy (lua_State *L)
{
  lua_newuserdata(L, 0);
  lua_rawgeti(L, LUA_ENVIRONINDEX, PROXY_META);
  lua_setmetatable(L, -2);
}

/* int socket_lock (lua_State *L)
 *
 * Arguments
 *   socket  A socket to "lock".
 *
 * This function is called by Lua to get a "lock" on a socket.
 * See the connect function (in Lua) in luaopen_nsock.
 */
static int socket_lock (lua_State *L)
{
  luaL_checkudata(L, 1, "nsock");
  lua_settop(L, 1);
  lua_rawgeti(L, LUA_ENVIRONINDEX, THREAD_PROXY);
  lua_pushthread(L);
  lua_gettable(L, -2);
  if (!lua_isnil(L, -1))
  {
    // Thread already has open sockets. Add the new socket to SOCKET_PROXY
    lua_rawgeti(L, LUA_ENVIRONINDEX, SOCKET_PROXY);
    lua_pushvalue(L, 1); // socket
    lua_pushvalue(L, -3); // proxy userdata
    lua_settable(L, -3);
    lua_pop(L, 1); // SOCKET_PROXY
    lua_pushboolean(L, true);
  } else if (table_length(L, 2) >= MAX(MAX_PARALLELISM, o.max_parallelism))
  {
    // Too many threads have sockets open. Add thread to waiting. The caller
    // is expected to yield. (see the connect function in luaopen_nsock)
    lua_rawgeti(L, LUA_ENVIRONINDEX, CONNECT_WAITING);
    lua_pushthread(L);
    lua_pushboolean(L, true);
    lua_settable(L, -3);
    lua_pop(L, 1); // CONNECT_WAITING
    lua_pushboolean(L, false);
  } else
  {
    // There is room for this thread to open sockets. Make a new proxy userdata
    // and add it to the THREAD_PROXY and SOCKET_PROXY tables.
    new_proxy(L);
    lua_rawgeti(L, LUA_ENVIRONINDEX, THREAD_PROXY);
    lua_pushthread(L);
    lua_pushvalue(L, -3); // proxy
    lua_settable(L, -3);
    lua_pop(L, 1); // THREAD_PROXY)
    lua_rawgeti(L, LUA_ENVIRONINDEX, SOCKET_PROXY);
    lua_pushvalue(L, 1); // Socket
    lua_pushvalue(L, -3); // proxy
    lua_settable(L, -3);
    lua_pop(L, 2); // proxy, SOCKET_PROXY
    lua_pushboolean(L, true);
  }
  return 1;
}

/* void socket_unlock (lua_State *L, int index)
 *
 * index is the location of the userdata on the stack.
 * A socket has been closed or collected, remove it from the SOCKET_PROXY
 * table.
 */
static void socket_unlock (lua_State *L, int index)
{
  lua_pushvalue(L, index); // socket
  lua_rawgeti(L, LUA_ENVIRONINDEX, SOCKET_PROXY);
  lua_pushvalue(L, -2); // socket
  lua_pushnil(L);
  lua_settable(L, -3);
  lua_pop(L, 2); // socket, SOCKET_PROXY
}

static nsock_pool nsp;

/*
 * Structure with nsock pcap descriptor.
 * shared between many lua threads
 */
struct ncap_socket{
	nsock_iod nsiod;	/* nsock pcap desc */
	int references;		/* how many lua threads use this */
	char *key;		/* (free) zero-terminated key used in map to 
				 * address this structure. */
};

/*
 *
 */ 
struct ncap_request{
	int suspended;		/* is the thread suspended? (lua_yield) */
	lua_State *L;		/* lua_State of current process
				 * or NULL if process isn't suspended */ 
	nsock_event_id nseid;	/* nse for this specific lua_State */
	struct timeval end_time;
	char *key;		/* (free) zero-terminated key used in map to 
				 * address this structure (hexified 'test') */
        
        bool	 	received;   /* are results ready? */
        
        bool	        r_success;  /* true-> okay,data ready to pass to user
        			     * flase-> this statusstring contains error description */
        char *          r_status;   /* errorstring */
        
        unsigned char  *r_layer2;
        size_t          r_layer2_len;
        unsigned char  *r_layer3;
        size_t          r_layer3_len;
        size_t          packetsz;
        
        int ncap_cback_ref; 	/* just copy of udata->ncap_cback_ref
        			 * because we don't have access to udata in place
        			 * we need to use this. */ 
};


struct l_nsock_udata {
	int timeout;
	nsock_iod nsiod;
	void *ssl_session;
	/*used for buffered reading */
	int bufidx; /*index inside lua's registry */
	int bufused;
	
	struct ncap_socket  *ncap_socket;
	struct ncap_request *ncap_request;
	int ncap_cback_ref;
};

void l_nsock_clear_buf(lua_State *L, l_nsock_udata* udata);

int luaopen_nsock (lua_State *L)
{
  /* nsock:connect(socket, ...)
   *
   * This Lua function is a wrapper around the actual l_nsock_connect.
   * The connect function must get a lock through socket_lock (C function
   * above). Once it has the lock, it can (tail call) return the actual
   * connect function.
   */
  static const char connect[] =
    "local yield = yield;\n"
    "local connect = connect;\n"
    "local socket_lock = socket_lock;\n"
    "return function(socket, ...)\n"
    "  while not socket_lock(socket) do\n"
    "    yield();\n"
    "  end\n"
    "  return connect(socket, ...);\n"
    "end";

  static const luaL_Reg l_nsock[] = {
    {"send", l_nsock_send},
    {"receive", l_nsock_receive},
    {"receive_lines", l_nsock_receive_lines},
    {"receive_bytes", l_nsock_receive_bytes},
    {"receive_buf", l_nsock_receive_buf},
    {"get_info", l_nsock_get_info},
    {"close", l_nsock_close},
    {"set_timeout", l_nsock_set_timeout},
    {"pcap_open", l_nsock_ncap_open},
    {"pcap_close", l_nsock_ncap_close},
    {"pcap_register", l_nsock_ncap_register},
    {"pcap_receive", l_nsock_pcap_receive},
    //{"callback_test", l_nsock_pcap_callback_test},
    {NULL, NULL}
  };

  /* Set up an environment for all nsock C functions to share.
   * This is especially important to make the THREAD_PROXY, SOCKET_PROXY,
   * and CONNECT_WAITING tables available. These values can be accessed
   * at the pseudo-index LUA_ENVIRONINDEX. These tables are documented
   * where the #defines are above.
   */
  lua_createtable(L, 5, 0);
  lua_setfenv(L, 1);

  lua_createtable(L, 0, 10); // THREAD_PROXY
  lua_createtable(L, 0, 1); // metatable
  lua_pushliteral(L, "kv"); // weak keys and values
  lua_setfield(L, -2, "__mode");
  lua_setmetatable(L, -2);
  lua_rawseti(L, LUA_ENVIRONINDEX, THREAD_PROXY);

  lua_createtable(L, 0, 193); // SOCKET_PROXY (large amount of room)
  lua_createtable(L, 0, 1); // metatable
  lua_pushliteral(L, "k"); // weak keys
  lua_setfield(L, -2, "__mode");
  lua_setmetatable(L, -2);
  lua_rawseti(L, LUA_ENVIRONINDEX, SOCKET_PROXY);

  lua_createtable(L, 0, 499); // CONNECT_WAITING (large amount of room)
  lua_rawseti(L, LUA_ENVIRONINDEX, CONNECT_WAITING);

  lua_createtable(L, 0, 1); // PROXY_META = metatable for proxies
  lua_pushcclosure(L, proxy_gc, 0);
  lua_setfield(L, -2, "__gc");
  lua_rawseti(L, LUA_ENVIRONINDEX, PROXY_META);

  /* Load the connect function */
  if (luaL_loadstring(L, connect) != 0)
    fatal("connect did not compile!");
  lua_createtable(L, 0, 3); // connect function's environment table
  lua_getglobal(L, "coroutine");
  lua_getfield(L, -1, "yield");
  lua_replace(L, -2); // remove coroutine table
  lua_setfield(L, -2, "yield");
  lua_pushcclosure(L, l_nsock_connect, 0);
  lua_setfield(L, -2, "connect");
  lua_pushcclosure(L, socket_lock, 0);
  lua_setfield(L, -2, "socket_lock");
  lua_setfenv(L, -2); // set the environment
  lua_call(L, 0, 1); // leave connect function on stack...
  lua_newtable(L);
  lua_setfenv(L, -2); // clean environment (Lua functions can't tamper with)

  /* Create the nsock metatable for sockets */
  luaL_newmetatable(L, "nsock");
  lua_createtable(L, 0, 23);
  luaL_register(L, NULL, l_nsock);
  lua_pushvalue(L, -3); // connect function
  lua_setfield(L, -2, "connect");
  lua_setfield(L, -2, "__index");
  lua_pushcclosure(L, l_nsock_gc, 0);
  lua_setfield(L, -2, "__gc");
  lua_newtable(L);
  lua_setfield(L, -2, "__metatable"); // protect metatable
  lua_pop(L, 1); // nsock metatable

  luaL_newmetatable(L, "nsock_proxy");

  nsp = nsp_new(NULL);
  //nsp_settrace(nsp, o.debugging, o.getStartTime());
  if (o.scriptTrace())
    nsp_settrace(nsp, 5, o.getStartTime());

  return 0;
}

int l_nsock_new(lua_State *L) {
	struct l_nsock_udata* udata;
	udata = (struct l_nsock_udata*) lua_newuserdata(L, sizeof(struct l_nsock_udata));
    luaL_getmetatable(L, "nsock");
    lua_setmetatable(L, -2);
	udata->nsiod = NULL;
	udata->ssl_session = NULL;
	udata->timeout = DEFAULT_TIMEOUT;
	udata->bufidx = LUA_NOREF;
	udata->bufused= 0;
	udata->ncap_socket	= NULL;
	udata->ncap_request	= NULL;
	udata->ncap_cback_ref	= 0;
	
	return 1;
}

int l_nsock_loop(int tout) {
	return nsock_loop(nsp, tout);
}

int l_nsock_checkstatus(lua_State *L, nsock_event nse) {
	enum nse_status status = nse_status(nse);

	switch (status) {
		case NSE_STATUS_SUCCESS:
			lua_pushboolean(L, true);
			return NSOCK_WRAPPER_SUCCESS;
			break;
		case NSE_STATUS_ERROR:
		case NSE_STATUS_TIMEOUT:
		case NSE_STATUS_CANCELLED:
		case NSE_STATUS_KILL:
		case NSE_STATUS_EOF:
			lua_pushnil(L);
			lua_pushstring(L, nse_status2str(status));
			return NSOCK_WRAPPER_ERROR;
			break;
		case NSE_STATUS_NONE:
		default:
			fatal("%s: In: %s:%i This should never happen.", 
					NSOCK_WRAPPER, __FILE__, __LINE__);
			break;
		
	}

	return -1;
}

static int l_nsock_connect(lua_State *L) {
	l_nsock_udata* udata = (l_nsock_udata*) luaL_checkudata(L, 1, "nsock");
	const char* addr = luaL_checkstring(L, 2);
	unsigned short port = (unsigned short) luaL_checkint(L, 3);
	const char *how = luaL_optstring(L, 4, "tcp");

	const char* error;
	struct addrinfo *dest;
	int error_id;
	
	l_nsock_clear_buf(L, udata);
	
	error_id = getaddrinfo(addr, NULL, NULL, &dest);
	if (error_id) {
		error = gai_strerror(error_id);
		lua_pushboolean(L, false);
		lua_pushstring(L, error);
		return 2;
	}

	udata->nsiod = nsi_new(nsp, NULL);
	if (o.spoofsource) {
		struct sockaddr_storage ss;
		size_t sslen;
		o.SourceSockAddr(&ss, &sslen);
		nsi_set_localaddr(udata->nsiod, &ss, sslen);
	}
	if (o.ipoptionslen)
		nsi_set_ipoptions(udata->nsiod, o.ipoptions, o.ipoptionslen);

	switch (how[0]) {
		case 't':
			if (strcmp(how, "tcp")) goto error;
			nsock_connect_tcp(nsp, udata->nsiod, l_nsock_connect_handler, 
					udata->timeout, L, dest->ai_addr, dest->ai_addrlen, port);
			break;
		case 'u':
			if (strcmp(how, "udp")) goto error;
			nsock_connect_udp(nsp, udata->nsiod, l_nsock_connect_handler, 
					L, dest->ai_addr, dest->ai_addrlen, port);
			break;
		case 's':
			if (strcmp(how, "ssl")) goto error;
#ifdef HAVE_OPENSSL
			nsock_connect_ssl(nsp, udata->nsiod, l_nsock_connect_handler, 
					udata->timeout, L, dest->ai_addr, dest->ai_addrlen, port, 
					udata->ssl_session);
			break;
#else
			lua_pushboolean(L, false);
			lua_pushstring(L, "Sorry, you don't have OpenSSL\n");
			return 2;
#endif
		default:
			goto error;
			break;
	}

	freeaddrinfo(dest);
	return lua_yield(L, 0);

error:
	freeaddrinfo(dest);
	luaL_argerror(L, 4, "invalid connection method");
	return 0;
}

void l_nsock_connect_handler(nsock_pool nsp, nsock_event nse, void *lua_state) {
	lua_State *L = (lua_State*) lua_state;

	if(o.scriptTrace()) {
		l_nsock_trace(nse_iod(nse), "CONNECT", TO);
	}

	if(l_nsock_checkstatus(L, nse) == NSOCK_WRAPPER_SUCCESS) {
		process_waiting2running((lua_State*) lua_state, 1);
	} else {
		process_waiting2running((lua_State*) lua_state, 2);
	}
}

static int l_nsock_send(lua_State *L) {
	l_nsock_udata* udata = (l_nsock_udata*) luaL_checkudata(L, 1, "nsock");
	const char* string = luaL_checkstring(L, 2);
	size_t string_len = lua_objlen (L, 2);
	
	l_nsock_clear_buf(L,udata); 

	if(udata->nsiod == NULL) {
		lua_pushboolean(L, false);
		lua_pushstring(L, "Trying to send through a closed socket\n");
		return 2;	
	}

	if(o.scriptTrace())
		l_nsock_trace(udata->nsiod, hexify(string, string_len).c_str(), TO);

	nsock_write(nsp, udata->nsiod, l_nsock_send_handler, udata->timeout, L, string, string_len);
	return lua_yield(L, 0);
}

void l_nsock_send_handler(nsock_pool nsp, nsock_event nse, void *lua_state) {
	lua_State *L = (lua_State*) lua_state;
	
	if(l_nsock_checkstatus(L, nse) == NSOCK_WRAPPER_SUCCESS) {
		process_waiting2running((lua_State*) lua_state, 1);
	} else {
		process_waiting2running((lua_State*) lua_state, 2);
	}
}

static int l_nsock_receive(lua_State *L) {
	l_nsock_udata* udata = (l_nsock_udata*) luaL_checkudata(L, 1, "nsock");
	l_nsock_clear_buf(L, udata);

	if(udata->nsiod == NULL) {
		lua_pushboolean(L, false);
		lua_pushstring(L, "Trying to receive through a closed socket\n");
		return 2;	
	}

	nsock_read(nsp, udata->nsiod, l_nsock_receive_handler, udata->timeout, L);

	return lua_yield(L, 0);
}

static int l_nsock_receive_lines(lua_State *L) {
	l_nsock_udata* udata = (l_nsock_udata*) luaL_checkudata(L, 1, "nsock");
	int nlines = (int) luaL_checknumber(L, 2);

	l_nsock_clear_buf(L, udata);
	
	if(udata->nsiod == NULL) {
		lua_pushboolean(L, false);
		lua_pushstring(L, "Trying to receive lines through a closed socket\n");
		return 2;	
	}

	nsock_readlines(nsp, udata->nsiod, l_nsock_receive_handler, udata->timeout, L, nlines);

	return lua_yield(L, 0);
}

static int l_nsock_receive_bytes(lua_State *L) {
	l_nsock_udata* udata = (l_nsock_udata*) luaL_checkudata(L, 1, "nsock");
	int nbytes = (int) luaL_checknumber(L, 2);
	
	l_nsock_clear_buf(L, udata);

	if(udata->nsiod == NULL) {
		lua_pushboolean(L, false);
		lua_pushstring(L, "Trying to receive bytes through a closed socket\n");
		return 2;	
	}

	nsock_readbytes(nsp, udata->nsiod, l_nsock_receive_handler, udata->timeout, L, nbytes);

	return lua_yield(L, 0);
}

void l_nsock_receive_handler(nsock_pool nsp, nsock_event nse, void *lua_state) {
	lua_State *L = (lua_State*) lua_state;
	char* rcvd_string;
	int rcvd_len = 0;

	if(l_nsock_checkstatus(L, nse) == NSOCK_WRAPPER_SUCCESS) {
		rcvd_string = nse_readbuf(nse, &rcvd_len);

		if(o.scriptTrace())
			l_nsock_trace(nse_iod(nse), hexify(rcvd_string, (size_t) rcvd_len).c_str(), FROM);

		lua_pushlstring(L, rcvd_string, rcvd_len);
		process_waiting2running((lua_State*) lua_state, 2);
	} else {
		process_waiting2running((lua_State*) lua_state, 2);
	}
}

void l_nsock_trace(nsock_iod nsiod, const char* message, int direction) { 
	int status; 
	int protocol; 
	int af; 
	struct sockaddr local; 
	struct sockaddr remote; 
	char* ipstring_local = (char*) safe_malloc(sizeof(char) * INET6_ADDRSTRLEN);
	char* ipstring_remote = (char*) safe_malloc(sizeof(char) * INET6_ADDRSTRLEN);

	if(!nsi_is_pcap(nsiod)){
		status =  nsi_getlastcommunicationinfo(nsiod, &protocol, &af,
			&local, &remote, sizeof(sockaddr)); 
		log_write(LOG_STDOUT, "%s: %s %s:%d %s %s:%d | %s\n", 
			SCRIPT_ENGINE,
			(protocol == IPPROTO_TCP)? "TCP" : "UDP",
			inet_ntop_both(af, &local, ipstring_local), 
			inet_port_both(af, &local), 
			(direction == TO)? ">" : "<", 
			inet_ntop_both(af, &remote, ipstring_remote), 
			inet_port_both(af, &remote), 
			message); 

		free(ipstring_local);
		free(ipstring_remote);
	}else{ // is pcap device
		log_write(LOG_STDOUT, "%s: %s | %s\n", 
			SCRIPT_ENGINE,
			(direction == TO)? ">" : "<", 
			message); 
	}
}

const char* inet_ntop_both(int af, const void* v_addr, char* ipstring) {
//	char* ipstring = (char*) safe_malloc(sizeof(char) * INET6_ADDRSTRLEN);

	if(af == AF_INET) {
		inet_ntop(AF_INET, &((struct sockaddr_in*) v_addr)->sin_addr, 
				ipstring, INET6_ADDRSTRLEN);

		return ipstring;
	} 
#ifdef HAVE_IPV6
	else if(af == AF_INET6) {
		inet_ntop(AF_INET6, &((struct sockaddr_in6*) v_addr)->sin6_addr, 
				ipstring, INET6_ADDRSTRLEN);
		return ipstring;
	} 
#endif
	else {
		return "unknown protocol";
	}

}

unsigned short inet_port_both(int af, const void* v_addr) {
	int port;
	if(af == AF_INET) {
		port = ((struct sockaddr_in*) v_addr)->sin_port;	
	}
#ifdef HAVE_IPV6
	else if(af == AF_INET6) {
		port = ((struct sockaddr_in6*) v_addr)->sin6_port;	
	}
#endif
	else {
		port = 0;
	}
	
	return ntohs(port);
}

static int l_nsock_get_info(lua_State *L) {
	l_nsock_udata* udata = (l_nsock_udata*) luaL_checkudata(L, 1, "nsock");
	int status;

	int protocol; // tcp or udp
	int af; // address family
	struct sockaddr local;
	struct sockaddr remote;
	char* ipstring_local = (char*) safe_malloc(sizeof(char) * INET6_ADDRSTRLEN);
	char* ipstring_remote = (char*) safe_malloc(sizeof(char) * INET6_ADDRSTRLEN);

	if(udata->nsiod == NULL) {
		lua_pushboolean(L, false);
		lua_pushstring(L, "Trying to get info from a closed socket\n");
		return 2;	
	}

	status =  nsi_getlastcommunicationinfo(udata->nsiod, &protocol, &af,
			&local, &remote, sizeof(sockaddr));

	lua_pushboolean(L, true);

	lua_pushstring(L, inet_ntop_both(af, &local, ipstring_local));
	lua_pushnumber(L, inet_port_both(af, &local));

	lua_pushstring(L, inet_ntop_both(af, &remote, ipstring_remote));
	lua_pushnumber(L, inet_port_both(af, &remote));

	free(ipstring_local);
	free(ipstring_remote);
	return 5;
}
static int l_nsock_gc(lua_State *L){
	l_nsock_udata* udata = (l_nsock_udata*) luaL_checkudata(L, 1, "nsock");
	if(udata->nsiod == NULL) { //socket obviously got closed already - so no finalization needed
		return 0;	
	}else{
	//FIXME - check wheter close returned true!!
		l_nsock_close(L);
	}
	return 0;
}

static int l_nsock_close(lua_State *L) {
	l_nsock_udata* udata = (l_nsock_udata*) luaL_checkudata(L, 1, "nsock");

    socket_unlock(L, 1); // Unlock the socket.

	/* Never ever collect nse-pcap connections. */
	if(udata->ncap_socket){
		return 0;
	}
	
	l_nsock_clear_buf(L, udata);

	if(udata->nsiod == NULL) {
		lua_pushboolean(L, false);
		lua_pushstring(L, "Trying to close a closed socket\n");
		return 2;	
	}

	if(o.scriptTrace()) {
		l_nsock_trace(udata->nsiod, "CLOSE", TO);
	}

#ifdef HAVE_OPENSSL
	if (udata->ssl_session)
		SSL_SESSION_free((SSL_SESSION*)udata->ssl_session);
	udata->ssl_session=NULL;
#endif

	nsi_delete(udata->nsiod, NSOCK_PENDING_NOTIFY);

	udata->nsiod = NULL;

	lua_pushboolean(L, true);
	return 1;
}

static int l_nsock_set_timeout(lua_State *L) {
	l_nsock_udata* udata = (l_nsock_udata*) luaL_checkudata(L, 1, "nsock");
	int timeout = (unsigned short) luaL_checkint(L, 2);

	udata->timeout = timeout;

	return 0;
}

/* buffered I/O */
static int l_nsock_receive_buf(lua_State *L) {
	l_nsock_udata* udata = (l_nsock_udata*) luaL_checkudata(L, 1, "nsock");
	if(lua_gettop(L)==2){ 
		/*we were called with 2 arguments only - push the default third one*/
		lua_pushboolean(L,true);
	}
	if(udata->nsiod == NULL) {
		lua_pushboolean(L, false);
		lua_pushstring(L, "Trying to receive through a closed socket\n");
		return 2;	
	}
	if(udata->bufused==0){
		lua_pushstring(L,"");
		udata->bufidx = luaL_ref(L, LUA_REGISTRYINDEX);
		udata->bufused=1;
		nsock_read(nsp, udata->nsiod, l_nsock_receive_buf_handler, udata->timeout, L);
	}else if(udata->bufused==-1){ /*error message is inside the buffer*/
		lua_pushboolean(L,false); 
		lua_rawgeti(L, LUA_REGISTRYINDEX, udata->bufidx);
		return 2;
	}else{ /*buffer contains already some data */
		/*we keep track here of how many calls to receive_buf are made */
		udata->bufused++; 
		if(l_nsock_check_buf(L)==NSOCK_WRAPPER_BUFFER_MOREREAD){
			/*if we didn't have enough data in the buffer another nsock_read()
			 * was scheduled - its callback will put us in running state again
			 */
			return lua_yield(L,3);
		}
		return 2;
	}
	/*yielding with 3 arguments since we need them when the callback arrives */
	return lua_yield(L, 3);
}

void l_nsock_receive_buf_handler(nsock_pool nsp, nsock_event nse, void *lua_state) {
	lua_State *L = (lua_State*) lua_state;
	char* rcvd_string;
	int rcvd_len = 0;
	int tmpidx;
	l_nsock_udata* udata = (l_nsock_udata*) luaL_checkudata(L, 1, "nsock");
	if(l_nsock_checkstatus(L, nse) == NSOCK_WRAPPER_SUCCESS) {
		
		//l_nsock_checkstatus pushes true on the stack in case of success
		// we do this on our own here
		lua_pop(L,1);

		rcvd_string = nse_readbuf(nse, &rcvd_len);
		
		if(o.scriptTrace())
			l_nsock_trace(nse_iod(nse), hexify(rcvd_string, (size_t) rcvd_len).c_str(), FROM);
		/* push the buffer and what we received from nsock on the stack and
		 * concatenate both*/
		lua_rawgeti(L, LUA_REGISTRYINDEX, udata->bufidx);
		lua_pushlstring(L, rcvd_string, rcvd_len);
		lua_concat (L, 2);
		luaL_unref(L, LUA_REGISTRYINDEX, udata->bufidx);
		udata->bufidx = luaL_ref(L, LUA_REGISTRYINDEX);
		if(l_nsock_check_buf(L)==NSOCK_WRAPPER_BUFFER_MOREREAD){
		/*if there wasn't enough data in the buffer and we've issued another
		 * nsock_read() the next callback will schedule the script for running
		 */
			return;
		}
		process_waiting2running((lua_State*) lua_state, 2);
	} else {
		if(udata->bufused>1){ 
		/*error occured after we read into some data into the buffer
		 * behave as if there was no error and push the rest of the buffer 
		 * and clean the buffer afterwards
		 */
			/*save the error message inside the buffer*/
			tmpidx=luaL_ref(L, LUA_REGISTRYINDEX); 
			/*pop the status (==false) of the stack*/
			lua_pop(L,1);
			lua_pushboolean(L, true);
			lua_rawgeti(L, LUA_REGISTRYINDEX, udata->bufidx);
			l_nsock_clear_buf(L, udata);
			udata->bufidx=tmpidx;
			udata->bufused=-1;
			process_waiting2running((lua_State*) lua_state, 2);
		}else{ /*buffer should be empty */
			process_waiting2running((lua_State*) lua_state, 2);
		}
	}
}

int l_nsock_check_buf(lua_State *L ){
	l_nsock_udata* udata;
	size_t startpos, endpos, bufsize;
	const char *tmpbuf;
	int tmpidx;
	int keeppattern;
	/*should we return the string including the pattern or without it */
	keeppattern= lua_toboolean(L,-1);
	lua_pop(L,1);
	udata = (l_nsock_udata*) luaL_checkudata(L, 1, "nsock");
	if(lua_isfunction(L,2)){
		lua_pushvalue(L,2);
		lua_rawgeti(L, LUA_REGISTRYINDEX, udata->bufidx); /* the buffer is the only argument to the function */
		if(lua_pcall(L,1,2,0)!=0){
			lua_pushboolean(L,false);
			lua_pushfstring(L,"Error inside splitting-function: %s\n", lua_tostring(L,-1));
			return NSOCK_WRAPPER_BUFFER_OK;
			//luaL_error(L,"Error inside splitting-function, given as argument to nsockobj:receive_buf: %s\n", lua_tostring(L,-1));
		}
	}else if(lua_isstring(L,2)){
		lua_getglobal(L,"string");
		lua_getfield(L,-1,"find");
		lua_remove(L, -2); /*drop the string-table, since we don't need it! */
		lua_rawgeti(L, LUA_REGISTRYINDEX, udata->bufidx); 
		lua_pushvalue(L,2); /*the pattern we are searching for */
		if(lua_pcall(L,2,2,0)!=0){
			lua_pushboolean(L,false);
			lua_pushstring(L,"Error in string.find (nsockobj:receive_buf)!");
			return NSOCK_WRAPPER_BUFFER_OK;
		}
	}else{
			lua_pushboolean(L,false);
			lua_pushstring(L,"Expected either a function or a string!");
			return NSOCK_WRAPPER_BUFFER_OK;
			//luaL_argerror(L,2,"expected either a function or a string!");
	}
	/*the stack contains on top the indices where we want to seperate */
	if(lua_isnil(L,-1)){ /*not found anything try to read more data*/
		lua_pop(L,2);
		nsock_read(nsp, udata->nsiod, l_nsock_receive_buf_handler, udata->timeout, L);
		lua_pushboolean(L,keeppattern);
		return NSOCK_WRAPPER_BUFFER_MOREREAD;
	}else{
		startpos = (size_t) lua_tointeger(L, -2);
		endpos = (size_t) lua_tointeger(L, -1);
		lua_settop(L,0); /* clear the stack for returning */
		if(startpos>endpos){
			lua_pushboolean(L,false);
			lua_pushstring(L,"Delimiter has negative size!");
			return NSOCK_WRAPPER_BUFFER_OK;
		}else if(startpos==endpos){
			/* if the delimter has a size of zero we keep it, since otherwise 
			 * retured string would be trucated
			 */
			keeppattern=1; 
		}
		lua_settop(L,0); /* clear the stack for returning */
		lua_rawgeti(L, LUA_REGISTRYINDEX, udata->bufidx); 
		tmpbuf = lua_tolstring(L, -1, &bufsize);
		lua_pop(L,1); /* pop the buffer off the stack, should be safe since it 
		it is still in the registry */
		if(tmpbuf==NULL){
		 fatal("%s: In: %s:%i The buffer is not a string?! - please report this to nmap-dev@insecure.org.", SCRIPT_ENGINE, __FILE__, __LINE__);
		}
		/*first push the remains of the buffer */
		lua_pushlstring(L,tmpbuf+endpos,(bufsize-endpos));
		tmpidx = luaL_ref(L,LUA_REGISTRYINDEX);
		lua_pushboolean(L,true);
		if(keeppattern){
			lua_pushlstring(L,tmpbuf,endpos);
		}else{
			lua_pushlstring(L,tmpbuf,startpos-1);
		}
		luaL_unref(L,LUA_REGISTRYINDEX,udata->bufidx);
		udata->bufidx=tmpidx;
		//l_dumpStack(L);
		return NSOCK_WRAPPER_BUFFER_OK;
	}
	assert(0);
	return 1;//unreachable
}

void l_nsock_clear_buf(lua_State *L, l_nsock_udata* udata){
	luaL_unref (L, LUA_REGISTRYINDEX, udata->bufidx); 
	udata->bufidx=LUA_NOREF;
	udata->bufused=0;
}

/****************** NCAP_SOCKET ***********************************************/ 
#ifdef WIN32
/* From tcpip.cc. Gets pcap device name from dnet name. */
bool DnetName2PcapName(const char *dnetdev, char *pcapdev, int pcapdevlen);
#endif

/* fuckin' C++ maps stuff */
/* here we store ncap_sockets */
std::map<std::string, struct ncap_socket*> ncap_socket_map;

/* receive sthing from socket_map */
struct ncap_socket *ncap_socket_map_get(char *key){
	std::string skey = key;
	return ncap_socket_map[skey];
}

/* set sthing on socket_map */
void ncap_socket_map_set(char *key, struct ncap_socket *ns){
	std::string skey = key;
	ncap_socket_map[skey] = ns;
	return;
}

/* receive sthing from socket_map */
void ncap_socket_map_del(char *key){
	std::string skey = key;
	ncap_socket_map.erase(skey);
	return;
}


/* (static) Dnet-like device name to Pcap-like name */
char *dnet_to_pcap_device_name(const char *device){
	static char pcapdev[128];
	if( strcmp(device, "any") == 0 )
		return strncpy(pcapdev, "any", sizeof(pcapdev));
		
	#ifdef WIN32
	/* Nmap normally uses device names obtained through dnet for interfaces, 
	 * but Pcap has its own naming system.  So the conversion is done here */
	if (!DnetName2PcapName(device, pcapdev, sizeof(pcapdev))) {
		/* Oh crap -- couldn't find the corresponding dev apparently.  
		 * Let's just go with what we have then ... */
		strncpy(pcapdev, device, sizeof(pcapdev));
	}
	#else
		strncpy(pcapdev, device, sizeof(pcapdev));
	#endif
	return pcapdev;
}

/* (LUA) Open nsock-pcap socket. 
 * 1)	device	- dnet-style network interface name, or "any"
 * 2)	snaplen	- maximum number of bytes to be captured for packet
 * 3)	promisc - should we set network car in promiscuous mode (0/1)
 * 4)	callback- callback function, that will create hash string from packet
 * 5)	bpf	- berkeley packet filter, see tcpdump(8)	
 * */  
static int l_nsock_ncap_open(lua_State *L){
	l_nsock_udata* udata  = (l_nsock_udata*) luaL_checkudata(L, 1, "nsock");
	const char* device    = luaL_checkstring(L, 2);
	int snaplen           = luaL_checkint(L, 3);
	int promisc           = luaL_checkint(L, 4);
	luaL_checktype(L, 5, LUA_TFUNCTION);		/* callback function that creates hash */
	const char* bpf       = luaL_checkstring(L, 6);

	if(udata->nsiod || udata->ncap_request || udata->ncap_socket) {
		luaL_argerror(L, 1, "Trying to open nsock-pcap, but this connection is already opened");
		return 0;
	}
	char *pcapdev = dnet_to_pcap_device_name(device);
	if(!strlen(device) || !strlen(pcapdev)) {
		luaL_argerror(L, 1, "Trying to open nsock-pcap, but you're passing empty or wrong device name.");
		return 0;
	}

	lua_pop(L, 1);	// pop bpf
	/* take func from top of stack and store it in the Registry */
	int hash_func_ref = luaL_ref(L, LUA_REGISTRYINDEX);
	/* push function on the registry-stack */
	lua_rawgeti(L, LUA_REGISTRYINDEX, hash_func_ref); 
	
	struct ncap_socket *ns;
	
	/* create key */
	char key[8192];
	Snprintf(key, sizeof(key), "%s|%i|%i|%u|%s",
					pcapdev,
					snaplen, promisc,
					(unsigned int)strlen(bpf),
					bpf);
	ns = ncap_socket_map_get(key);
	if(ns == NULL){
		ns = (struct ncap_socket*)safe_zalloc(sizeof(struct ncap_socket));
		ns->nsiod 	= nsi_new(nsp, ns);
		ns->key		= strdup(key);
		/* error messages are passed here */ 
		char *emsg = nsock_pcap_open(nsp, ns->nsiod, pcapdev, snaplen, promisc, bpf);
		if(emsg){
			luaL_argerror(L, 1, emsg);
			return 0;
		}
		ncap_socket_map_set(key, ns);
	}
	ns->references++;
	udata->nsiod		= ns->nsiod;
	udata->ncap_socket	= ns;
	udata->ncap_cback_ref	= hash_func_ref;
	return 0;
}

/* (LUA) Close nsock-pcap socket. 
 * */  
static int l_nsock_ncap_close(lua_State *L){
	l_nsock_udata* udata = (l_nsock_udata*) luaL_checkudata(L, 1, "nsock");
	struct ncap_socket *ns = udata->ncap_socket;

	if(!udata->nsiod || !udata->ncap_socket) {
		luaL_argerror(L, 1, "Trying to close nsock-pcap, but it was never opened.");
		return 0;	
	}
	if(udata->ncap_request) {
		luaL_argerror(L, 1, "Trying to close nsock-pcap, but it has active event.");
		return 0;	
	}

	assert(ns->references > 0);

	ns->references--;
	if(ns->references == 0){
		ncap_socket_map_del(ns->key);
		if(ns->key) free(ns->key);		
		nsi_delete(ns->nsiod, NSOCK_PENDING_NOTIFY);
		free(ns);
	}

	udata->nsiod 		= NULL;
	udata->ncap_socket	= NULL;
	lua_unref(L, udata->ncap_cback_ref);
	udata->ncap_cback_ref	= 0;

	lua_pushboolean(L, true);
	return 1;
}


/* (static) binary string to hex zero-terminated string */
char *hex(char *str, unsigned int strsz){
	static char x[] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
	static char buf[2048];
	unsigned int i;
	unsigned char *s;
	for(i=0, s=(unsigned char*)str; i<strsz && i<(sizeof(buf)/2-1); i++, s++){
		buf[i*2  ] = x[ *s/16 ];
		buf[i*2+1] = x[ *s%16 ];
	}
	buf[i*2] = '\0';
	return(buf);
}

/****************** NCAP_REQUEST **********************************************/ 

int ncap_restore_lua(ncap_request *nr);
void ncap_request_set_result(nsock_event nse, struct ncap_request *nr);
int ncap_request_set_results(nsock_event nse, const char *key);
void l_nsock_pcap_receive_handler(nsock_pool nsp, nsock_event nse, void *userdata);

/* next map, this time it's multimap "key"(from callback)->suspended_lua_threads */
std::multimap<std::string, struct ncap_request*> ncap_request_map;
typedef std::multimap<std::string, struct ncap_request*>::iterator ncap_request_map_iterator;
typedef std::pair<ncap_request_map_iterator, ncap_request_map_iterator> ncap_request_map_ii;

/* del from multimap */
void ncap_request_map_del(struct ncap_request *nr){
	ncap_request_map_iterator i;
	ncap_request_map_ii	  ii;
	std::string s = nr->key;
	ii = ncap_request_map.equal_range(s);
		
	for(i=ii.first ; i!=ii.second ;i++){
		if(i->second == nr){
			i->second = NULL;
			ncap_request_map.erase(i);
			return;
		}
	}
	assert(0);
}


/* add to multimap */
void ncap_request_map_add(char *key, struct ncap_request *nr){
	std::string skey = key;
	ncap_request_map.insert(std::pair<std::string, struct ncap_request *>(skey, nr));
	return;
}

/* (LUA) Register event that will wait for one packet matching hash. 
 * It's non-blocking method of capturing packets.
 * 1)	hash	- hash for packet that should be matched. or empty string if you 
 * 		  want to receive first packet   
 * */
static int l_nsock_ncap_register(lua_State *L){
	l_nsock_udata* udata = (l_nsock_udata*) luaL_checkudata(L, 1, "nsock");
	size_t testdatasz;
	const char* testdata = luaL_checklstring(L, 2, &testdatasz);

	struct timeval now = *nsock_gettimeofday();
	
	if(!udata->nsiod || !udata->ncap_socket) {
		luaL_argerror(L, 1, "You can't register to nsock-pcap if it wasn't opened.");
		return 0;
	}
	if(udata->ncap_request){
		luaL_argerror(L, 1, "You are already registered to this socket.");
		return 0;
	}
	
	struct ncap_request *nr = 
		(struct ncap_request*)safe_zalloc(sizeof(struct ncap_request));
		
	udata->ncap_request = nr;
	
	TIMEVAL_MSEC_ADD(nr->end_time, now, udata->timeout);
	nr->key   = strdup(hex((char*)testdata, testdatasz));
	nr->L     = L;
	nr->ncap_cback_ref = udata->ncap_cback_ref;
	/* always create new event. */
	nr->nseid = nsock_pcap_read_packet(nsp, 
					udata->nsiod, 
					l_nsock_pcap_receive_handler, 
					udata->timeout, nr);
	
	ncap_request_map_add(nr->key, nr);

	/* that's it. return to lua */
	return 0;
}

/* (LUA) After "register" use this function to block, and wait for packet. 
 * If packet is already captured, this function will return immidietly.
 * 
 * return values: status(true/false), capture_len/error_msg, layer2data, layer3data
 * */
int l_nsock_pcap_receive(lua_State *L){
	l_nsock_udata* udata = (l_nsock_udata*) luaL_checkudata(L, 1, "nsock");
	if(!udata->nsiod || !udata->ncap_socket) {
		luaL_argerror(L, 1, "You can't receive to nsock-pcap if it wasn't opened.");
		return 0;
	}
	if(!udata->ncap_request){
		luaL_argerror(L, 1, "You can't it's not registered");
		return 0;
	}

	/* and clear udata->ncap_request, we'll never,ever have access to current
	 * udata during this request */
	struct ncap_request *nr = udata->ncap_request;
	udata->ncap_request = NULL;
	
	/* ready to receive data? don't suspend thread*/
	if(nr->received) /*data already received*/
		return ncap_restore_lua(nr);
	
	/* no data yet? suspend thread */
	nr->suspended = 1;
	
	return lua_yield(L, 0);
}

/* (free) excute callback function from lua script */
char* ncap_request_do_callback(nsock_event nse, lua_State *L, int ncap_cback_ref){
	const unsigned char *l2_data, *l3_data;
	size_t l2_len, l3_len, packet_len;
	nse_readpcap(nse, &l2_data, &l2_len, &l3_data, &l3_len, &packet_len, NULL);
	
	lua_rawgeti(L, LUA_REGISTRYINDEX, ncap_cback_ref);
	lua_pushnumber(L,  packet_len);
	lua_pushlstring(L, (char*)l2_data, l2_len);
	lua_pushlstring(L, (char*)l3_data, l3_len);

	lua_call(L, 3, 1);
	
	/* get string from top of the stack*/
	size_t testdatasz;
	const char* testdata = lua_tolstring(L, -1, &testdatasz); 
	// lua_pop(L, 1);/* just in case [nope, it's not needed]*/
	
	char *key = strdup(hex((char*)testdata, testdatasz));
	return key;
}



/* callback from nsock */
void l_nsock_pcap_receive_handler(nsock_pool nsp, nsock_event nse, void *userdata){
	int this_event_restored=0;
	struct ncap_request *nr = (struct ncap_request *) userdata;

	
	switch(nse_status(nse)) {
	case NSE_STATUS_SUCCESS:{
		char *key = ncap_request_do_callback(nse, nr->L, nr->ncap_cback_ref);
		
		/* processes threads that receive every packet */
		this_event_restored += ncap_request_set_results(nse, "");
			
		/* process everything that matches test */
		this_event_restored += ncap_request_set_results(nse, key);
		free(key);


		if(!this_event_restored){
			/* okay, we received event but it wasn't handled by the process
			 * that requested this event. We must query for new event with
			 * smaller timeout */
			struct timeval now = *nsock_gettimeofday();
			
			/*event was successfull so I assert it occured before pr->end_time*/
			int timeout = TIMEVAL_MSEC_SUBTRACT(nr->end_time, now);
			if(timeout < 0) /* funny to receive event that should be timeouted in the past. But on windows it can happen*/
			    timeout = 0;
			nr->nseid = nsock_pcap_read_packet(nsp, 
							nse_iod(nse), 
							l_nsock_pcap_receive_handler, 
							timeout, nr);
			/* no need to cancel or delete current nse :) */
		}
		return;
		}
	default:
		/* event timeouted */
		ncap_request_map_del(nr);		/* delete from map */
		ncap_request_set_result(nse, nr);
		if(nr->suspended)			/* restore thread */
			ncap_restore_lua(nr);
		return;
	}
}


/* get data from nsock_event, and set result on ncap_requests which mach key */
int ncap_request_set_results(nsock_event nse, const char *key) {
	int this_event_restored = 0;
	
	std::string skey = key;
	
	ncap_request_map_iterator i;
	ncap_request_map_ii ii;
	
	ii = ncap_request_map.equal_range(skey);
	for(i = ii.first; i != ii.second; i++) {
		/* tests are successfull, so just restore process */
		ncap_request *nr = i->second;
		if(nr->nseid == nse_id(nse))
			this_event_restored = 1;
		
		ncap_request_set_result(nse, nr);
		if(nr->suspended)
			ncap_restore_lua(nr);
	}
        ncap_request_map.erase(ii.first, ii.second);
	
	return this_event_restored;
}

/* get data from nsock_event, and set result ncap_request */
void ncap_request_set_result(nsock_event nse, struct ncap_request *nr) {
	enum nse_status status = nse_status(nse);
	nr->received = true;

	switch (status) {
	case NSE_STATUS_SUCCESS:{
		nr->r_success = true;
		
		const unsigned char *l2_data, *l3_data;
		size_t l2_len, l3_len, packet_len;
		nse_readpcap(nse, &l2_data, &l2_len, &l3_data, &l3_len, 
					&packet_len, NULL);
		char *packet = (char*) safe_malloc(l2_len + l3_len);
		nr->r_layer2 = (unsigned char*)memcpy(&packet[0],      l2_data, l2_len);
		nr->r_layer3 = (unsigned char*)memcpy(&packet[l2_len], l3_data, l3_len);
		nr->r_layer2_len = l2_len;
		nr->r_layer3_len = l3_len;
		nr->packetsz 	 = packet_len;
		break;}
	case NSE_STATUS_ERROR:
	case NSE_STATUS_TIMEOUT:
	case NSE_STATUS_CANCELLED:
	case NSE_STATUS_KILL:
	case NSE_STATUS_EOF:
		nr->r_success = false;
		nr->r_status  = strdup( nse_status2str(status) );
		break;
	case NSE_STATUS_NONE:
	default:
		fatal("%s: In: %s:%i This should never happen.", 
				NSOCK_WRAPPER, __FILE__, __LINE__);
	}

	if(nr->nseid != nse_id(nse)){ /* different event, cancel*/
		nsock_event_cancel(nsp, nr->nseid, 0); /* Don't send CANCELED event, just cancel */
		nr->nseid = 0;
	}else{	/* this event -> do nothing */
	}
	
	return;
}


/* if lua thread was suspended, restore it. If it wasn't, just return results 
 * (push them on the stack and return) */
int ncap_restore_lua(ncap_request *nr){
	lua_State *L = nr->L;

	if(nr->r_success){
		lua_pushboolean(L, true);
		lua_pushnumber(L, nr->packetsz);
		lua_pushlstring(L, (char*)nr->r_layer2, nr->r_layer2_len);
		lua_pushlstring(L, (char*)nr->r_layer3, nr->r_layer3_len);
	}else{
		lua_pushnil(L);
		lua_pushstring(L, nr->r_status);
		lua_pushnil(L);
		lua_pushnil(L);
	}
	bool suspended  = nr->suspended;
	nr->L 		   = NULL;
	nr->ncap_cback_ref = 0;	/* this ref is freed in different place (on udata->ncap_cback_ref) */
	if(nr->key) free(nr->key);
	if(nr->r_status) free(nr->r_status);
	if(nr->r_layer2) free(nr->r_layer2);
	/* dont' free r_layer3, it's in the same block as r_layer2*/

	free(nr);
	
	if(suspended) 	/* lua process is  suspended */
		return process_waiting2running(L, 4);
	else			/* not suspended, just pass output */
		return 4;
}




/****************** DNET ******************************************************/ 
static int l_dnet_open_ethernet(lua_State *L);
static int l_dnet_close_ethernet(lua_State *L);
static int l_dnet_send_ethernet(lua_State *L);

static luaL_reg l_dnet [] = {
	{"ethernet_open",  l_dnet_open_ethernet},
	{"ethernet_close", l_dnet_close_ethernet},
	{"ethernet_send",  l_dnet_send_ethernet},
	{NULL, NULL}
};

int l_dnet_open(lua_State *L) {
    luaL_newmetatable(L, "dnet");
    lua_createtable(L, 0, 5);
    luaL_register(L, NULL, l_dnet);
    lua_setfield(L, -2, "__index");
    lua_pushliteral(L, "");
    lua_setfield(L, -2, "__metatable"); // protect metatable
    lua_pop(L, 1);
	return NSOCK_WRAPPER_SUCCESS;
}

struct l_dnet_udata {
	char *interface;
	eth_t *eth;
};

int l_dnet_new(lua_State *L) {
	struct l_dnet_udata* udata;
	udata = (struct l_dnet_udata*) lua_newuserdata(L, sizeof(struct l_dnet_udata));
    luaL_getmetatable(L, "dnet");
    lua_setmetatable(L, -2);
	udata->interface= NULL;
	udata->eth    	= NULL;

	return 1;
}

int l_dnet_get_interface_link(lua_State *L) {
	const char* interface_name = luaL_checkstring(L, 1);
	
	struct interface_info *ii = getInterfaceByName((char*)interface_name);
	if(!ii){	
		lua_pushnil(L);
		return 1;
	}
	const char *s= NULL;
	switch(ii->device_type){
	case devt_ethernet:
		s = "ethernet";
		break;
	case devt_loopback:
		s = "loopback";
		break;
	case devt_p2p:
		s = "p2p";
		break;
	case devt_other:
	default:
		s = NULL;
		break;
	}
	if(s)
		lua_pushstring(L, s);
	else
		lua_pushnil(L);
	
	return 1;
}

typedef struct{
	int references;
	eth_t *eth;
} dnet_eth_map;


std::map<std::string, dnet_eth_map *> dnet_eth_cache;

eth_t *ldnet_eth_open_cached(const char *device) {
	assert(device && *device);
	
	std::string key = device;
	dnet_eth_map *dem = dnet_eth_cache[key];
	if(dem != NULL){
		dem->references++;
		return dem->eth;
	} 
	
	dem = (dnet_eth_map *)safe_zalloc(sizeof(dnet_eth_map));
	dem->eth	= eth_open(device);
	if(!dem->eth)
		fatal("Unable to open dnet on ethernet interface %s",device);
	dem->references	= 1;
	dnet_eth_cache[key] = dem;
	return dem->eth;
}

/* See the description for eth_open_cached */
void ldnet_eth_close_cached(const char *device) {
	std::string key = device;
	dnet_eth_map *dem = dnet_eth_cache[key];
	assert(dem);
	dem->references--;
	if(dem->references==0){
		dnet_eth_cache.erase(key);
		eth_close(dem->eth);
		free(dem);
	}
	return;
}

static int l_dnet_open_ethernet(lua_State *L){
	l_dnet_udata* udata = (l_dnet_udata*) luaL_checkudata(L, 1, "dnet");
	const char* interface_name = luaL_checkstring(L, 2);

	struct interface_info *ii = getInterfaceByName((char*)interface_name);
	if(!ii || ii->device_type!=devt_ethernet){
		luaL_argerror(L, 2, "device is not valid ethernet interface");
		return 0;
	}
	udata->interface= strdup(interface_name);
	udata->eth	= ldnet_eth_open_cached(interface_name);	
	
	return 0;
}

static int l_dnet_close_ethernet(lua_State *L){
	l_dnet_udata* udata = (l_dnet_udata*) luaL_checkudata(L, 1, "dnet");
	if(!udata->interface || !udata->eth){
		luaL_argerror(L, 1, "dnet is not valid opened ethernet interface");
		return  0;
	}

	udata->eth = NULL;
	ldnet_eth_close_cached(udata->interface);
	free(udata->interface);
	udata->interface = NULL;
	return 0;
}

static int l_dnet_send_ethernet(lua_State *L){
	l_dnet_udata* udata = (l_dnet_udata*) luaL_checkudata(L, 1, "dnet");
	size_t packetsz = 0;
	const char* packet = luaL_checklstring(L, 2, &packetsz);

	if(!udata->interface || !udata->eth){
		luaL_argerror(L, 1, "dnet is not valid opened ethernet interface");
		return  0;
	}
	eth_send(udata->eth, packet, packetsz);
	return 0;
}

int l_clock_ms(lua_State *L){
	struct timeval tv;
	gettimeofday(&tv, NULL);
	// no rounding error 
	// unless the number is greater than 100,000,000,000,000
	double usec = 0.0; //MAX_INT*1000 =    4 294 967 296 000 <- miliseconds since epoch should fit
	usec = tv.tv_sec*1000; 
	usec += (int)(tv.tv_usec/1000);	// make sure it's integer.
	
	lua_pushnumber(L, usec);
	return 1;
}
