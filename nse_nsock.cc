#include "nse_nsock.h"
#include "nse_auxiliar.h"
#include "nse_macros.h"
#include "nse_string.h"

#include "nse_debug.h"

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

#define NSOCK_WRAPPER_BUFFER_OK 1
#define NSOCK_WRAPPER_BUFFER_MOREREAD 2

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
static int l_nsock_receive_buf(lua_State* l);

void l_nsock_connect_handler(nsock_pool nsp, nsock_event nse, void *lua_state);
void l_nsock_send_handler(nsock_pool nsp, nsock_event nse, void *lua_state);
void l_nsock_receive_handler(nsock_pool nsp, nsock_event nse, void *lua_state);
void l_nsock_receive_buf_handler(nsock_pool nsp, nsock_event nse, void *lua_state);

int l_nsock_check_buf(lua_State* l);

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
	{"receive_buf", l_nsock_receive_buf},
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
	/*used for buffered reading */
	int bufidx; /*index inside lua's registry */
	int bufused;
};

void l_nsock_clear_buf(lua_State* l, l_nsock_udata* udata);

int l_nsock_open(lua_State* l) {
	auxiliar_newclass(l, "nsock", l_nsock);

        nsp = nsp_new(NULL);

	if (o.scriptTrace())
		nsp_settrace(nsp, 5, o.getStartTime());

	return NSOCK_WRAPPER_SUCCESS;
}

int l_nsock_new(lua_State* l) {
	struct l_nsock_udata* udata;
	udata = (struct l_nsock_udata*) lua_newuserdata(l, sizeof(struct l_nsock_udata));
	auxiliar_setclass(l, "nsock", -1);
	udata->nsiod = NULL;
	udata->ssl_session = NULL;
	udata->timeout = DEFAULT_TIMEOUT;
	udata->bufidx = LUA_NOREF;
	udata->bufused= 0;
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
	
	l_nsock_clear_buf(l, udata);

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

	if(o.scriptTrace()) {
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
	
	l_nsock_clear_buf(l,udata); 

	if(udata->nsiod == NULL) {
		lua_pushboolean(l, false);
		lua_pushstring(l, "Trying to send through a closed socket\n");
		return 2;	
	}

	if(o.scriptTrace()) {
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
	l_nsock_clear_buf(l, udata);

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

	l_nsock_clear_buf(l, udata);
	
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
	
	l_nsock_clear_buf(l, udata);

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

		if(o.scriptTrace()) {
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
	
	l_nsock_clear_buf(l, udata);

	if(udata->nsiod == NULL) {
		lua_pushboolean(l, false);
		lua_pushstring(l, "Trying to close a closed socket\n");
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

	lua_pushboolean(l, true);
	return 1;
}

static int l_nsock_set_timeout(lua_State* l) {
	l_nsock_udata* udata = (l_nsock_udata*) auxiliar_checkclass(l, "nsock", 1);
	int timeout = (unsigned short) luaL_checkint(l, 2);

	udata->timeout = timeout;

	return 0;
}

/* buffered I/O */
static int l_nsock_receive_buf(lua_State* l) {
	l_nsock_udata* udata = (l_nsock_udata*) auxiliar_checkclass(l, "nsock", 1);
	if(lua_gettop(l)==2){ 
		/*we were called with 2 arguments only - push the default third one*/
		lua_pushboolean(l,true);
	}
	if(udata->nsiod == NULL) {
		lua_pushboolean(l, false);
		lua_pushstring(l, "Trying to receive through a closed socket\n");
		return 2;	
	}
	if(udata->bufused==0){
		lua_pushstring(l,"");
		udata->bufidx = luaL_ref(l, LUA_REGISTRYINDEX);
		udata->bufused=1;
		nsock_read(nsp, udata->nsiod, l_nsock_receive_buf_handler, udata->timeout, l);
	}else if(udata->bufused==-1){ /*error message is inside the buffer*/
		lua_pushboolean(l,false); 
		lua_rawgeti(l, LUA_REGISTRYINDEX, udata->bufidx);
		return 2;
	}else{ /*buffer contains already some data */
		/*we keep track here of how many calls to receive_buf are made */
		udata->bufused++; 
		if(l_nsock_check_buf(l)==NSOCK_WRAPPER_BUFFER_MOREREAD){
			/*if we didn't have enough data in the buffer another nsock_read()
			 * was scheduled - its callback will put us in running state again
			 */
			return lua_yield(l,3);
		}
		return 2;
	}
	/*yielding with 3 arguments since we need them when the callback arrives */
	return lua_yield(l, 3);
}

void l_nsock_receive_buf_handler(nsock_pool nsp, nsock_event nse, void *lua_state) {
	lua_State* l = (lua_State*) lua_state;
	char* rcvd_string;
	int rcvd_len = 0;
	char* hexified;
	int tmpidx;
	l_nsock_udata* udata = (l_nsock_udata*) auxiliar_checkclass(l, "nsock", 1);
	if(l_nsock_checkstatus(l, nse) == NSOCK_WRAPPER_SUCCESS) {
		
		//l_nsock_checkstatus pushes true on the stack in case of success
		// we do this on our own here
		lua_pop(l,1);

		rcvd_string = nse_readbuf(nse, &rcvd_len);
		
		if(o.scriptTrace()) {
			hexified = nse_hexify((const void*) rcvd_string, (size_t) rcvd_len);
			l_nsock_trace(nse_iod(nse), hexified, FROM);
			free(hexified);
		}
		/* push the buffer and what we received from nsock on the stack and
		 * concatenate both*/
		lua_rawgeti(l, LUA_REGISTRYINDEX, udata->bufidx);
		lua_pushlstring(l, rcvd_string, rcvd_len);
		lua_concat (l, 2);
		luaL_unref(l, LUA_REGISTRYINDEX, udata->bufidx);
		udata->bufidx = luaL_ref(l, LUA_REGISTRYINDEX);
		if(l_nsock_check_buf(l)==NSOCK_WRAPPER_BUFFER_MOREREAD){
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
			tmpidx=luaL_ref(l, LUA_REGISTRYINDEX); 
			/*pop the status (==false) of the stack*/
			lua_pop(l,1);
			lua_pushboolean(l, true);
			lua_rawgeti(l, LUA_REGISTRYINDEX, udata->bufidx);
			l_nsock_clear_buf(l, udata);
			udata->bufidx=tmpidx;
			udata->bufused=-1;
			process_waiting2running((lua_State*) lua_state, 2);
		}else{ /*buffer should be empty */
			process_waiting2running((lua_State*) lua_state, 2);
		}
	}
}

int l_nsock_check_buf(lua_State* l ){
	l_nsock_udata* udata;
	size_t startpos, endpos, bufsize;
	const char *tmpbuf;
	int tmpidx;
	int keeppattern;
	/*should we return the string including the pattern or without it */
	keeppattern= lua_toboolean(l,-1);
	lua_pop(l,1);
	udata = (l_nsock_udata*) auxiliar_checkclass(l, "nsock", 1);
	if(lua_isfunction(l,2)){
		lua_pushvalue(l,2);
		lua_rawgeti(l, LUA_REGISTRYINDEX, udata->bufidx); /* the buffer is the only argument to the function */
		if(lua_pcall(l,1,2,0)!=0){
			lua_pushboolean(l,false);
			lua_pushfstring(l,"Error inside splitting-function: %s\n", lua_tostring(l,-1));
			return NSOCK_WRAPPER_BUFFER_OK;
			//luaL_error(l,"Error inside splitting-function, given as argument to nsockobj:receive_buf: %s\n", lua_tostring(l,-1));
		}
	}else if(lua_isstring(l,2)){
		lua_getglobal(l,"string");
		lua_getfield(l,-1,"find");
		lua_remove(l, -2); /*drop the string-table, since we don't need it! */
		lua_rawgeti(l, LUA_REGISTRYINDEX, udata->bufidx); 
		lua_pushvalue(l,2); /*the pattern we are searching for */
		if(lua_pcall(l,2,2,0)!=0){
			lua_pushboolean(l,false);
			lua_pushstring(l,"error in string.find (nsockobj:receive_buf)!");
			return NSOCK_WRAPPER_BUFFER_OK;
		}
	}else{
			lua_pushboolean(l,false);
			lua_pushstring(l,"expected either a function or a string!");
			return NSOCK_WRAPPER_BUFFER_OK;
			//luaL_argerror(l,2,"expected either a function or a string!");
	}
	/*the stack contains on top the indices where we want to seperate */
	if(lua_isnil(l,-1)){ /*not found anything try to read more data*/
		lua_pop(l,2);
		nsock_read(nsp, udata->nsiod, l_nsock_receive_buf_handler, udata->timeout, l);
		lua_pushboolean(l,keeppattern);
		return NSOCK_WRAPPER_BUFFER_MOREREAD;
	}else{
		startpos = (size_t) lua_tointeger(l, -2);
		endpos = (size_t) lua_tointeger(l, -1);
		lua_settop(l,0); /* clear the stack for returning */
		if(startpos>endpos){
			lua_pushboolean(l,false);
			lua_pushstring(l,"delimter has negative size!");
			return NSOCK_WRAPPER_BUFFER_OK;
		}else if(startpos==endpos){
			/* if the delimter has a size of zero we keep it, since otherwise 
			 * retured string would be trucated
			 */
			keeppattern=1; 
		}
		lua_settop(l,0); /* clear the stack for returning */
		lua_rawgeti(l, LUA_REGISTRYINDEX, udata->bufidx); 
		tmpbuf = lua_tolstring(l, -1, &bufsize);
		lua_pop(l,1); /* pop the buffer off the stack, should be safe since it 
		it is still in the registry */
		if(tmpbuf==NULL){
		 fatal("%s: In: %s:%i The buffer is not a string?! - please report this to nmap-dev@insecure.org.", SCRIPT_ENGINE, __FILE__, __LINE__);
		}
		/*first push the remains of the buffer */
		lua_pushlstring(l,tmpbuf+endpos,(bufsize-endpos));
		tmpidx = luaL_ref(l,LUA_REGISTRYINDEX);
		lua_pushboolean(l,true);
		if(keeppattern){
			lua_pushlstring(l,tmpbuf,endpos);
		}else{
			lua_pushlstring(l,tmpbuf,startpos-1);
		}
		luaL_unref(l,LUA_REGISTRYINDEX,udata->bufidx);
		udata->bufidx=tmpidx;
		l_dumpStack(l);
		return NSOCK_WRAPPER_BUFFER_OK;
	}
	assert(0);
	return 1;//unreachable
}

void l_nsock_clear_buf(lua_State* l, l_nsock_udata* udata){
	luaL_unref (l, LUA_REGISTRYINDEX, udata->bufidx); 
	udata->bufidx=LUA_NOREF;
	udata->bufused=0;
}
