#include "nse_nsock.h"
#include "nse_auxiliar.h"
#include "nse_macros.h"
#include "nse_string.h"

#include "nsock.h"
#include "nmap_error.h"
#include "NmapOps.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#if HAVE_OPENSSL
#include <openssl/ssl.h>
#endif

#define SCRIPT_ENGINE			"SCRIPT ENGINE"
#define NSOCK_WRAPPER			"NSOCK WRAPPER"
#define NSOCK_WRAPPER_SUCCESS		0 
#define NSOCK_WRAPPER_ERROR		2 

#define FROM 	1
#define TO 	2

#define DEFAULT_TIMEOUT 30000

extern NmapOps o;

// defined in nse_main.cc but also declared here
// to keep the .h files clean
int process_waiting2running(lua_State* l, int resume_arguments);

static int l_nsock_connect(lua_State* l);
static int l_nsock_send(lua_State* l);
static int l_nsock_receive(lua_State* l);
static int l_nsock_receive_lines(lua_State* l);
static int l_nsock_receive_bytes(lua_State* l);
static int l_nsock_get_info(lua_State* l);
static int l_nsock_gc(lua_State* l);
static int l_nsock_close(lua_State* l);
static int l_nsock_set_timeout(lua_State* l);

void l_nsock_connect_handler(nsock_pool nsp, nsock_event nse, void *lua_state);
void l_nsock_send_handler(nsock_pool nsp, nsock_event nse, void *lua_state);
void l_nsock_receive_handler(nsock_pool nsp, nsock_event nse, void *lua_state);

int l_nsock_checkstatus(lua_State* l, nsock_event nse);

void l_nsock_trace(nsock_iod nsiod, char* message, int direction);
char* inet_ntop_both(int af, const void* v_addr, char* ipstring);
unsigned short inet_port_both(int af, const void* v_addr);

static luaL_reg l_nsock [] = {
	{"connect", l_nsock_connect},
	{"send", l_nsock_send},
	{"receive", l_nsock_receive},
	{"receive_lines", l_nsock_receive_lines},
	{"receive_bytes", l_nsock_receive_bytes},
	{"get_info", l_nsock_get_info},
	{"close", l_nsock_close},
	{"set_timeout", l_nsock_set_timeout},
	{"__gc",l_nsock_gc},
	{NULL, NULL}
};

static nsock_pool nsp;

struct l_nsock_udata {
	int timeout;
	nsock_iod nsiod;
	void *ssl_session;
};

int l_nsock_open(lua_State* l) {
	auxiliar_newclass(l, "nsock", l_nsock);

        nsp = nsp_new(NULL);
	nsp_settrace(nsp, o.debugging, o.getStartTime());

	return NSOCK_WRAPPER_SUCCESS;
}

int l_nsock_new(lua_State* l) {
	struct l_nsock_udata* udata;
	udata = (struct l_nsock_udata*) lua_newuserdata(l, sizeof(struct l_nsock_udata));
	auxiliar_setclass(l, "nsock", -1);
	udata->nsiod = NULL;
	udata->ssl_session = NULL;
	udata->timeout = DEFAULT_TIMEOUT;
	return 1;
}

int l_nsock_loop(int tout) {
	return nsock_loop(nsp, tout);
}

int l_nsock_checkstatus(lua_State* l, nsock_event nse) {
	enum nse_status status = nse_status(nse);

	switch (status) {
		case NSE_STATUS_SUCCESS:
			lua_pushboolean(l, true);
			return NSOCK_WRAPPER_SUCCESS;
			break;
		case NSE_STATUS_ERROR:
		case NSE_STATUS_TIMEOUT:
		case NSE_STATUS_CANCELLED:
		case NSE_STATUS_KILL:
		case NSE_STATUS_EOF:
			lua_pushnil(l);
			lua_pushstring(l, nse_status2str(status));
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

static int l_nsock_connect(lua_State* l) {
	l_nsock_udata* udata = (l_nsock_udata*) auxiliar_checkclass(l, "nsock", 1);
	const char* addr = luaL_checkstring(l, 2);
	unsigned short port = (unsigned short) luaL_checkint(l, 3);
	const char *how = luaL_optstring(l, 4, "tcp");

	const char* error;
	struct addrinfo *dest;
	int error_id;
	

	error_id = getaddrinfo(addr, NULL, NULL, &dest);
	if (error_id) {
		error = gai_strerror(error_id);
		lua_pushboolean(l, false);
		lua_pushstring(l, error);
		return 2;
	}

	udata->nsiod = nsi_new(nsp, NULL);

	switch (how[0]) {
		case 't':
			if (strcmp(how, "tcp")) goto error;
			nsock_connect_tcp(nsp, udata->nsiod, l_nsock_connect_handler, 
					udata->timeout, l, dest->ai_addr, dest->ai_addrlen, port);
			break;
		case 'u':
			if (strcmp(how, "udp")) goto error;
			nsock_connect_udp(nsp, udata->nsiod, l_nsock_connect_handler, 
					l, dest->ai_addr, dest->ai_addrlen, port);
			break;
		case 's':
			if (strcmp(how, "ssl")) goto error;
#ifdef HAVE_OPENSSL
			nsock_connect_ssl(nsp, udata->nsiod, l_nsock_connect_handler, 
					udata->timeout, l, dest->ai_addr, dest->ai_addrlen, port, 
					udata->ssl_session);
			break;
#else
			luaL_argerror(l, 4, "Sorry, you don't have openssl.");
			return 0;
#endif
		default:
			goto error;
			break;
	}

	freeaddrinfo(dest);
	return lua_yield(l, 0);

error:
	freeaddrinfo(dest);
	luaL_argerror(l, 4, "invalid connection method");
	return 0;
}

void l_nsock_connect_handler(nsock_pool nsp, nsock_event nse, void *lua_state) {
	lua_State* l = (lua_State*) lua_state;

	if(o.scripttrace) {
		l_nsock_trace(nse_iod(nse), "CONNECT", TO);
	}

	if(l_nsock_checkstatus(l, nse) == NSOCK_WRAPPER_SUCCESS) {
		process_waiting2running((lua_State*) lua_state, 1);
	} else {
		process_waiting2running((lua_State*) lua_state, 2);
	}
}

static int l_nsock_send(lua_State* l) {
	l_nsock_udata* udata = (l_nsock_udata*) auxiliar_checkclass(l, "nsock", 1);
	const char* string = luaL_checkstring(l, 2);
	size_t string_len = lua_objlen (l, 2);
	char* hexified;

	if(udata->nsiod == NULL) {
		lua_pushboolean(l, false);
		lua_pushstring(l, "Trying to send through a closed socket\n");
		return 2;	
	}

	if(o.scripttrace) {
		hexified = nse_hexify((const void*)string, string_len);
		l_nsock_trace(udata->nsiod, hexified, TO);
		free(hexified);
	}

	nsock_write(nsp, udata->nsiod, l_nsock_send_handler, udata->timeout, l, string, string_len);
	return lua_yield(l, 0);
}

void l_nsock_send_handler(nsock_pool nsp, nsock_event nse, void *lua_state) {
	lua_State* l = (lua_State*) lua_state;
	
	if(l_nsock_checkstatus(l, nse) == NSOCK_WRAPPER_SUCCESS) {
		process_waiting2running((lua_State*) lua_state, 1);
	} else {
		process_waiting2running((lua_State*) lua_state, 2);
	}
}

static int l_nsock_receive(lua_State* l) {
	l_nsock_udata* udata = (l_nsock_udata*) auxiliar_checkclass(l, "nsock", 1);

	if(udata->nsiod == NULL) {
		lua_pushboolean(l, false);
		lua_pushstring(l, "Trying to receive through a closed socket\n");
		return 2;	
	}

	nsock_read(nsp, udata->nsiod, l_nsock_receive_handler, udata->timeout, l);

	return lua_yield(l, 0);
}

static int l_nsock_receive_lines(lua_State* l) {
	l_nsock_udata* udata = (l_nsock_udata*) auxiliar_checkclass(l, "nsock", 1);
	int nlines = (int) luaL_checknumber(l, 2);

	if(udata->nsiod == NULL) {
		lua_pushboolean(l, false);
		lua_pushstring(l, "Trying to receive lines through a closed socket\n");
		return 2;	
	}

	nsock_readlines(nsp, udata->nsiod, l_nsock_receive_handler, udata->timeout, l, nlines);

	return lua_yield(l, 0);
}

static int l_nsock_receive_bytes(lua_State* l) {
	l_nsock_udata* udata = (l_nsock_udata*) auxiliar_checkclass(l, "nsock", 1);
	int nbytes = (int) luaL_checknumber(l, 2);

	if(udata->nsiod == NULL) {
		lua_pushboolean(l, false);
		lua_pushstring(l, "Trying to receive bytes through a closed socket\n");
		return 2;	
	}

	nsock_readbytes(nsp, udata->nsiod, l_nsock_receive_handler, udata->timeout, l, nbytes);

	return lua_yield(l, 0);
}

void l_nsock_receive_handler(nsock_pool nsp, nsock_event nse, void *lua_state) {
	lua_State* l = (lua_State*) lua_state;
	char* rcvd_string;
	int rcvd_len = 0;
	char* hexified;

	if(l_nsock_checkstatus(l, nse) == NSOCK_WRAPPER_SUCCESS) {
		rcvd_string = nse_readbuf(nse, &rcvd_len);

		if(o.scripttrace) {
			hexified = nse_hexify((const void*) rcvd_string, (size_t) rcvd_len);
			l_nsock_trace(nse_iod(nse), hexified, FROM);
			free(hexified);
		}

		lua_pushlstring(l, rcvd_string, rcvd_len);
		process_waiting2running((lua_State*) lua_state, 2);
	} else {
		process_waiting2running((lua_State*) lua_state, 2);
	}
}

void l_nsock_trace(nsock_iod nsiod, char* message, int direction) { 
	int status; 
	int protocol; 
	int af; 
	struct sockaddr local; 
	struct sockaddr remote; 
	char* ipstring_local = (char*) safe_malloc(sizeof(char) * INET6_ADDRSTRLEN);
	char* ipstring_remote = (char*) safe_malloc(sizeof(char) * INET6_ADDRSTRLEN);

	status =  nsi_getlastcommunicationinfo(nsiod, &protocol, &af,
			&local, &remote, sizeof(sockaddr)); 

	log_write(LOG_STDOUT, "SCRIPT ENGINE: %s %s:%d %s %s:%d | %s\n", 
			(protocol == IPPROTO_TCP)? "TCP" : "UDP",
			inet_ntop_both(af, &local, ipstring_local), 
			inet_port_both(af, &local), 
			(direction == TO)? ">" : "<", 
			inet_ntop_both(af, &remote, ipstring_remote), 
			inet_port_both(af, &remote), 
			message); 

	free(ipstring_local);
	free(ipstring_remote);
}

char* inet_ntop_both(int af, const void* v_addr, char* ipstring) {
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

static int l_nsock_get_info(lua_State* l) {
	l_nsock_udata* udata = (l_nsock_udata*) auxiliar_checkclass(l, "nsock", 1);
	int status;

	int protocol; // tcp or udp
	int af; // address family
	struct sockaddr local;
	struct sockaddr remote;
	char* ipstring_local = (char*) safe_malloc(sizeof(char) * INET6_ADDRSTRLEN);
	char* ipstring_remote = (char*) safe_malloc(sizeof(char) * INET6_ADDRSTRLEN);

	if(udata->nsiod == NULL) {
		lua_pushboolean(l, false);
		lua_pushstring(l, "Trying to get info from a closed socket\n");
		return 2;	
	}

	status =  nsi_getlastcommunicationinfo(udata->nsiod, &protocol, &af,
			&local, &remote, sizeof(sockaddr));

	lua_pushboolean(l, true);

	lua_pushstring(l, inet_ntop_both(af, &local, ipstring_local));
	lua_pushnumber(l, inet_port_both(af, &local));

	lua_pushstring(l, inet_ntop_both(af, &remote, ipstring_remote));
	lua_pushnumber(l, inet_port_both(af, &remote));

	free(ipstring_local);
	free(ipstring_remote);
	return 5;
}
static int l_nsock_gc(lua_State* l){
	l_nsock_udata* udata = (l_nsock_udata*) auxiliar_checkclass(l, "nsock", 1);
	if(udata->nsiod == NULL) { //socket obviously got closed already - so no finalization needed
		return 0;	
	}else{
	//FIXME - check wheter close returned true!!
		l_nsock_close(l);
	}
	return 0;
}
static int l_nsock_close(lua_State* l) {
	l_nsock_udata* udata = (l_nsock_udata*) auxiliar_checkclass(l, "nsock", 1);

	if(udata->nsiod == NULL) {
		lua_pushboolean(l, false);
		lua_pushstring(l, "Trying to close a closed socket\n");
		return 2;	
	}

	if(o.scripttrace) {
		l_nsock_trace(udata->nsiod, "CLOSE", TO);
	}

#ifdef HAVE_OPENSSL
	if (udata->ssl_session)
		SSL_SESSION_free((SSL_SESSION*)udata->ssl_session);
	udata->ssl_session=NULL;
#endif

	nsi_delete(udata->nsiod, NSOCK_PENDING_NOTIFY);

	udata->nsiod = NULL;

	lua_pushboolean(l, true);
	return 1;
}

static int l_nsock_set_timeout(lua_State* l) {
	l_nsock_udata* udata = (l_nsock_udata*) auxiliar_checkclass(l, "nsock", 1);
	int timeout = (unsigned short) luaL_checkint(l, 2);

	udata->timeout = timeout;

	return 0;
}

