#include "nsock.h"
#include "nmap_error.h"
#include "NmapOps.h"
#include "tcpip.h"
#include "protocols.h"

#ifdef WIN32
/* Need DnetName2PcapName */
#include "libnetutil/netutil.h"
#endif

#include "nse_nsock.h"
#include "nse_main.h"
#include "nse_utility.h"
#include "nse_ssl_cert.h"

#if HAVE_OPENSSL
/* See the comments in service_scan.cc for the reason for _WINSOCKAPI_. */
#  define _WINSOCKAPI_
#  include <openssl/ssl.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <sstream>
#include <iomanip>

#define DEFAULT_TIMEOUT 30000

/* Upvalues for library variables */
enum {
  NSOCK_POOL = lua_upvalueindex(1),
  NSOCK_SOCKET = lua_upvalueindex(2), /* nsock socket metatable */
  THREAD_SOCKETS = lua_upvalueindex(3), /* <Thread, Table of Sockets (keys)> */
  CONNECT_WAITING = lua_upvalueindex(4), /* Threads waiting to lock */
};

/* Integer keys in the Nsock userdata environments */
#define THREAD_I  1 /* The thread that yielded */
#define BUFFER_I  2 /* Location of Userdata Buffer */

/* Special value for af to mean a pcap socket */
#define NSE_AF_PCAP -1

extern NmapOps o;

typedef struct nse_nsock_udata
{
  nsock_iod nsiod;
  int timeout;

  lua_State *thread;

  int proto;
  int af;

  const char *direction;
  const char *action;

  void *ssl_session;

  struct sockaddr_storage source_addr;
  size_t source_addrlen;

} nse_nsock_udata;

static const char *NU_ACTION_IMMEDIATE = "returned immediately";

static int gc_pool (lua_State *L)
{
  nsock_pool *nsp = (nsock_pool *) lua_touserdata(L, 1);
  assert(*nsp != NULL);
  nsock_pool_delete(*nsp);
  *nsp = NULL;
  return 0;
}

static nsock_pool new_pool (lua_State *L)
{
  nsock_pool nsp = nsock_pool_new(NULL);
  nsock_pool *nspp;

  /* configure logging */
  nmap_set_nsock_logger();
  nmap_adjust_loglevel(o.scriptTrace());

  if (*o.device)
    nsock_pool_set_device(nsp, o.device);

  if (o.proxy_chain)
    nsock_pool_set_proxychain(nsp, o.proxy_chain);

  nsock_pool_set_broadcast(nsp, true);

  nspp = (nsock_pool *) lua_newuserdatauv(L, sizeof(nsock_pool), 0);
  *nspp = nsp;
  lua_newtable(L);
  lua_pushcfunction(L, gc_pool);
  lua_setfield(L, -2, "__gc");
  lua_setmetatable(L, -2);
  return nsp;
}

static nsock_pool get_pool (lua_State *L)
{
  nsock_pool *nspp;
  nspp = (nsock_pool *) lua_touserdata(L, NSOCK_POOL);
  assert(nspp != NULL);
  assert(*nspp != NULL);
  return *nspp;
}

static std::string hexify (const unsigned char *str, size_t len)
{
  size_t num = 0;

  std::ostringstream ret;

  // If more than 95% of the chars are printable, we escape unprintable chars
  for (size_t i = 0; i < len; i++)
    if (isprint((int) str[i]))
      num++;
  if ((double) num / (double) len >= 0.95)
  {
    for (size_t i = 0; i < len; i++)
    {
      if (isprint((int) str[i]) || isspace((int) str[i]))
        ret << str[i];
      else
        ret << std::setw(3) << "\\" << (unsigned int) (unsigned char) str[i];
    }
    return ret.str();
  }

  ret << std::setbase(16) << std::setfill('0');
  for (size_t i = 0; i < len; i += 16)
  {
    ret << std::setw(8) << i << ": ";
    for (size_t j = i; j < i + 16; j++)
      if (j < len)
        ret << std::setw(2) << (unsigned int) (unsigned char) str[j] << " ";
      else
        ret << "   ";
    for (size_t j = i; j < i + 16 && j < len; j++)
      ret.put(isgraph((int) str[j]) ? (unsigned char) str[j] : ' ');
    ret << std::endl;
  }
  return ret.str();
}

/* Some constants used for enforcing a limit on the number of open sockets
 * in use by threads. The maximum value between MAX_PARALLELISM and
 * o.max_parallelism is the max # of threads that can have connected sockets
 * (open).
 *
 * THREAD_SOCKETS is a weak keyed table of <Thread, Socket Table> pairs.
 * A socket table is a weak keyed table (socket keys with garbage values) of
 * sockets the Thread has allocated but not necessarily open). You may
 * test for an open socket by checking whether its nsiod field in the
 * socket userdata structure is not NULL.
 *
 * CONNECT_WAITING is a weak keyed table of <Thread, Garbage Value> pairs.
 * The table contains threads waiting to make a socket connection.
 */
#define MAX_PARALLELISM   20

/* int socket_lock (lua_State *L)
 *
 * This function is called by l_connect to get a "lock" on a socket.
 * When connect calls this function, it expects socket_lock to yield forcing
 * connect to be restarted when resumed or it succeeds returning normally.
 */
static int socket_lock (lua_State *L, int idx)
{
  unsigned p = o.max_parallelism == 0 ? MAX_PARALLELISM : o.max_parallelism;
  int top = lua_gettop(L);
  nse_base(L);
  lua_rawget(L, THREAD_SOCKETS);
  if (lua_istable(L, -1))
  {
    /* Thread already has a "lock" with open sockets. Place the new socket
     * in its sockets table */
    lua_pushvalue(L, idx);
    lua_pushboolean(L, true);
    lua_rawset(L, -3);
  } else if (nseU_tablen(L, THREAD_SOCKETS) <= p)
  {
    /* There is room for this thread to open sockets */
    nse_base(L);
    nseU_weaktable(L, 0, 0, "k"); /* weak socket references */
    lua_pushvalue(L, idx); /* socket */
    lua_pushboolean(L, true);
    lua_rawset(L, -3); /* add to sockets table */
    lua_rawset(L, THREAD_SOCKETS); /* add new <Thread, Sockets Table> Pair
                                    * to THREAD_SOCKETS */
  } else
  {
    nse_base(L);
    lua_pushboolean(L, true);
    lua_rawset(L, CONNECT_WAITING);
    lua_settop(L, top); /* restore stack to original condition for l_connect */
    return 0;
  }
  lua_settop(L, top); /* restore stack to original condition for l_connect */
  return 1;
}

static void socket_unlock (lua_State *L)
{
  int top = lua_gettop(L);

  lua_gc(L, LUA_GCSTOP, 0); /* don't collect threads during iteration */

  for (lua_pushnil(L); lua_next(L, THREAD_SOCKETS); lua_pop(L, 1))
  {
    unsigned open = 0;

    if (lua_status(lua_tothread(L, -2)) == LUA_YIELD)
    {
      for (lua_pushnil(L); lua_next(L, -2); lua_pop(L, 1)) /* for each socket */
      {
        if (((nse_nsock_udata *) lua_touserdata(L, -2))->nsiod != NULL)
          open++;
      }
    }

    if (open == 0) /* thread has no open sockets? */
    {
      /* close all of its sockets */
      for (lua_pushnil(L); lua_next(L, -2); lua_pop(L, 1)) /* for each socket */
      {
        lua_getfield(L, -2, "close");
        lua_pushvalue(L, -3);
        lua_call(L, 1, 0);
      }

      lua_pushvalue(L, -2); /* thread key */
      lua_pushnil(L);
      lua_rawset(L, THREAD_SOCKETS);

      for (lua_pushnil(L); lua_next(L, CONNECT_WAITING); lua_pop(L, 1))
      {
        nse_restore(lua_tothread(L, -2), 0);
        lua_pushvalue(L, -2);
        lua_pushnil(L);
        lua_rawset(L, CONNECT_WAITING);
      }
    }
  }

  lua_gc(L, LUA_GCRESTART, 0);

  lua_settop(L, top);
}

static const char *inet_ntop_both (int af, const void *v_addr, char *ipstring)
{
  if (af == AF_INET)
  {
    inet_ntop(AF_INET, &((struct sockaddr_in *) v_addr)->sin_addr,
        ipstring, INET6_ADDRSTRLEN);
    return ipstring;
  }
#ifdef HAVE_IPV6
  else if (af == AF_INET6)
  {
    inet_ntop(AF_INET6, &((struct sockaddr_in6 *) v_addr)->sin6_addr,
        ipstring, INET6_ADDRSTRLEN);
    return ipstring;
  }
#endif
  else
    return "unknown protocol";
}

static unsigned short inet_port_both (int af, const void *v_addr)
{
  int port;

  if (af == AF_INET)
    port = ((struct sockaddr_in *) v_addr)->sin_port;
#ifdef HAVE_IPV6
  else if (af == AF_INET6)
    port = ((struct sockaddr_in6 *) v_addr)->sin6_port;
#endif
  else
    port = 0;

  return ntohs(port);
}

#define TO      ">"
#define FROM    "<"

static void trace (nsock_iod nsiod, const char *message, const char *dir)
{
  if (o.scriptTrace())
  {
    if (!nsock_iod_is_pcap(nsiod))
    {
      int protocol;
      int af;
      char ipstring_local[INET6_ADDRSTRLEN];
      char ipstring_remote[INET6_ADDRSTRLEN];
      struct sockaddr_storage local;
      struct sockaddr_storage remote;

      nsock_iod_get_communication_info(nsiod, &protocol, &af,
          (sockaddr *) &local, (sockaddr *) &remote, sizeof(sockaddr_storage));
      log_write(LOG_STDOUT, "%s: %s %s:%d %s %s:%d | %s\n",
          SCRIPT_ENGINE,
          IPPROTO2STR_UC(protocol),
          inet_ntop_both(af, &local, ipstring_local),
          inet_port_both(af, &local),
          dir,
          inet_ntop_both(af, &remote, ipstring_remote),
          inet_port_both(af, &remote), message);
    } else {
      log_write(LOG_STDOUT, "%s: %s | %s\n", SCRIPT_ENGINE, dir, message);
    }
  }
}

static void status (lua_State *L, enum nse_status status)
{
  switch (status)
  {
    case NSE_STATUS_SUCCESS:
      assert(lua_status(L) == LUA_YIELD);
      lua_pushboolean(L, true);
      nse_restore(L, 1);
      break;
    case NSE_STATUS_KILL:
      return;
    case NSE_STATUS_CANCELLED:
    case NSE_STATUS_EOF:
    case NSE_STATUS_ERROR:
    case NSE_STATUS_TIMEOUT:
    case NSE_STATUS_PROXYERROR:
      assert(lua_status(L) == LUA_YIELD);
      lua_pushnil(L);
      lua_pushstring(L, nse_status2str(status));
      nse_restore(L, 2);
      break;
    case NSE_STATUS_NONE:
    default:
      assert(0);
      break;
  }
}

/* callback for connect and write events */
static void callback (nsock_pool nsp, nsock_event nse, void *ud)
{
  nse_nsock_udata *nu = (nse_nsock_udata *) ud;
  lua_State *L = nu->thread;
  if (nse_status(nse) == NSE_STATUS_KILL)
      return;
  assert(nse_type(nse) != NSE_TYPE_READ);
  if (lua_status(L) == LUA_OK && nse_status(nse) == NSE_STATUS_ERROR) {
    // Sometimes Nsock fails immediately and callback is called before
    // l_connect has a chance to yield. We'll use nu->action to signal
    // l_connect to return an error instead of yielding.
    // http://seclists.org/nmap-dev/2016/q1/201
    trace(nse_iod(nse), nu->action, nu->direction);
    nu->action = NU_ACTION_IMMEDIATE;
    return;
  }
  switch (nse_type(nse)) {
    case NSE_TYPE_CONNECT:
    case NSE_TYPE_CONNECT_SSL:
      /* After a connect or reconnect event, allow the socket to be reused by a
       * different thread. */
      nu->thread = NULL;
      break;
    default:
      break;
  }
  assert(lua_status(L) == LUA_YIELD);
  trace(nse_iod(nse), nu->action, nu->direction);
  status(L, nse_status(nse));
}

static int yield (lua_State *L, nse_nsock_udata *nu, const char *action,
    const char *direction, int ctx, lua_KFunction k)
{
  lua_getuservalue(L, 1);
  lua_pushthread(L);
  lua_rawseti(L, -2, THREAD_I);
  lua_pop(L, 1); /* nsock udata environment */
  if (nu->thread != NULL && nu->thread != L)
  {
    luaL_error(L, "Invalid reuse of a socket from one thread to another.");
  }
  nu->thread = L;
  nu->action = action;
  nu->direction = direction;
  return nse_yield(L, ctx, k);
}

/* In the case of unconnected UDP sockets, this function will call
   nsock_setup_udp on your behalf before returning true. */
static nse_nsock_udata *check_nsock_udata (lua_State *L, int idx, bool open)
{
  nse_nsock_udata *nu = (nse_nsock_udata *) nseU_checkudata(L, idx, NSOCK_SOCKET, "nsock");

  if (open && nu->nsiod == NULL) {
    /* The socket hasn't been connected or setup yet. Try doing a setup, or
       throw an error if that's not possible. */
    if (nu->proto == IPPROTO_UDP) {
      nsock_pool nsp;

      nsp = get_pool(L);
      nu->nsiod = nsock_iod_new(nsp, NULL);
      if (nu->source_addr.ss_family != AF_UNSPEC) {
        nsock_iod_set_localaddr(nu->nsiod, &nu->source_addr, nu->source_addrlen);
      } else if (o.spoofsource) {
        struct sockaddr_storage ss;
        size_t sslen;
        o.SourceSockAddr(&ss, &sslen);
        nsock_iod_set_localaddr(nu->nsiod, &ss, sslen);
      }
      if (o.ipoptionslen)
        nsock_iod_set_ipoptions(nu->nsiod, o.ipoptions, o.ipoptionslen);

      if (nsock_setup_udp(nsp, nu->nsiod, nu->af) == -1) {
        luaL_error(L, "Error in setup of iod with proto %d and af %d: %s (%d)",
          nu->proto, nu->af, socket_strerror(socket_errno()), socket_errno());
      }
    }
  }

  return nu;
}

/* If the socket udata nu is not open, return from the enclosing function with
   an error. */
#define NSOCK_UDATA_ENSURE_OPEN(L, nu) \
do { \
  if (nu->nsiod == NULL) \
    return luaL_error(L, "socket must be connected"); \
  if (nu->af == NSE_AF_PCAP) \
    return luaL_error(L, "invalid operation on pcap socket"); \
} while (0)

static int l_loop (lua_State *L)
{
  nsock_pool nsp = get_pool(L);
  int tout = luaL_checkinteger(L, 1);

  socket_unlock(L); /* clean up old socket locks */

  nmap_adjust_loglevel(o.scriptTrace());
  if (nsock_loop(nsp, tout) == NSOCK_LOOP_ERROR)
    return luaL_error(L, "a fatal error occurred in nsock_loop");
  return 0;
}

static int l_reconnect_ssl (lua_State *L)
{
  nsock_pool nsp = get_pool(L);
  nse_nsock_udata *nu = check_nsock_udata(L, 1, true);
  NSOCK_UDATA_ENSURE_OPEN(L, nu);

#ifndef HAVE_OPENSSL
  return nseU_safeerror(L, "sorry, you don't have OpenSSL");
#endif

  nsock_reconnect_ssl(nsp, nu->nsiod, callback, nu->timeout,
      nu, nu->ssl_session);

  return yield(L, nu, "SSL RECONNECT", TO, 0, NULL);
}

static void close_internal (lua_State *L, nse_nsock_udata *nu);

static int connect (lua_State *L, int status, lua_KContext ctx)
{
  enum type {TCP, UDP, SSL};
  static const char * const op[] = {"tcp", "udp", "ssl", NULL};

  nsock_pool nsp = get_pool(L);
  nse_nsock_udata *nu = check_nsock_udata(L, 1, false);
  const char *addr, *targetname; nseU_checktarget(L, 2, &addr, &targetname);
  const char *default_proto = NULL;
  unsigned short port = nseU_checkport(L, 3, &default_proto);
  if (default_proto == NULL) {
    switch (nu->proto) {
    case IPPROTO_TCP:
      default_proto = "tcp";
      break;
    case IPPROTO_UDP:
      default_proto = "udp";
      break;
    default:
      default_proto = "tcp";
      break;
    }
  }
  int what = luaL_checkoption(L, 4, default_proto, op);
#ifndef HAVE_OPENSSL
  if (what == SSL)
    return nseU_safeerror(L, "sorry, you don't have OpenSSL");
#endif

  struct addrinfo *dest;
  int error_id;

  if (!socket_lock(L, 1)) /* we cannot get a socket lock */
    return nse_yield(L, 0, connect); /* restart on continuation */

  /* If we're connecting by name, we should use the same AF as our scan */
  struct addrinfo hints = {0};
  /* First check if it's a numeric address */
  hints.ai_flags = AI_NUMERICHOST;
  error_id = getaddrinfo(addr, NULL, &hints, &dest);
  if (error_id == EAI_NONAME) {
    /* Nope, let's resolve it for the proper AF */
    hints.ai_flags = 0;
    hints.ai_family = o.af();
    error_id = getaddrinfo(addr, NULL, &hints, &dest);
  }

  if (error_id)
    return nseU_safeerror(L, gai_strerror(error_id));

  if (dest == NULL)
    return nseU_safeerror(L, "getaddrinfo returned success but no addresses");

  if (nu->nsiod != NULL)
    close_internal(L, nu);
  nu->nsiod = nsock_iod_new(nsp, NULL);
  if (nu->source_addr.ss_family != AF_UNSPEC) {
    nsock_iod_set_localaddr(nu->nsiod, &nu->source_addr, nu->source_addrlen);
  } else if (o.spoofsource) {
    struct sockaddr_storage ss;
    size_t sslen;

    o.SourceSockAddr(&ss, &sslen);
    nsock_iod_set_localaddr(nu->nsiod, &ss, sslen);
  }
  if (o.ipoptionslen)
    nsock_iod_set_ipoptions(nu->nsiod, o.ipoptions, o.ipoptionslen);
  if (targetname != NULL) {
    if (nsock_iod_set_hostname(nu->nsiod, targetname) == -1)
      fatal("nsock_iod_set_hostname(\"%s\" failed in %s()", targetname, __func__);
  }

  nu->af = dest->ai_addr->sa_family;
  nu->thread = L;
  nu->action = "PRECONNECT";
  nu->direction = TO;

  switch (what)
  {
    case TCP:
      nu->proto = IPPROTO_TCP;
      nsock_connect_tcp(nsp, nu->nsiod, callback, nu->timeout, nu,
          dest->ai_addr, dest->ai_addrlen, port);
      break;
    case UDP:
      nu->proto = IPPROTO_UDP;
      nsock_connect_udp(nsp, nu->nsiod, callback, nu, dest->ai_addr,
          dest->ai_addrlen, port);
      break;
    case SSL:
      if (nu->proto != IPPROTO_UDP) {
        // Assume TCP unless we're explicitly connecting to a UDP port
        nu->proto = IPPROTO_TCP;
      }
      nsock_connect_ssl(nsp, nu->nsiod, callback, nu->timeout, nu,
          dest->ai_addr, dest->ai_addrlen, nu->proto, port, nu->ssl_session);
      break;
  }

  if (dest != NULL)
    freeaddrinfo(dest);

  if (nu->action == NU_ACTION_IMMEDIATE) {
    // Immediate error
    return nseU_safeerror(L, nse_status2str(NSE_STATUS_ERROR));
  }
  return yield(L, nu, "CONNECT", TO, 0, NULL);
}

static int l_connect (lua_State *L)
{
  return connect(L, LUA_OK, 0);
}

static int l_send (lua_State *L)
{
  nsock_pool nsp = get_pool(L);
  nse_nsock_udata *nu = check_nsock_udata(L, 1, true);
  NSOCK_UDATA_ENSURE_OPEN(L, nu);
  size_t size;
  const char *string = luaL_checklstring(L, 2, &size);
  trace(nu->nsiod, hexify((unsigned char *) string, size).c_str(), TO);
  nsock_write(nsp, nu->nsiod, callback, nu->timeout, nu, string, size);
  if (nu->action == NU_ACTION_IMMEDIATE) {
    // Immediate error
    return nseU_safeerror(L, nse_status2str(NSE_STATUS_ERROR));
  }
  return yield(L, nu, "SEND", TO, 0, NULL);
}

static int l_sendto (lua_State *L)
{
  nsock_pool nsp = get_pool(L);
  nse_nsock_udata *nu = check_nsock_udata(L, 1, true);
  NSOCK_UDATA_ENSURE_OPEN(L, nu);
  size_t size;
  const char *addr, *targetname; nseU_checktarget(L, 2, &addr, &targetname);
  const char *default_proto = NULL;
  unsigned short port = nseU_checkport(L, 3, &default_proto);
  const char *string = luaL_checklstring(L, 4, &size);
  int error_id;
  struct addrinfo *dest;

  error_id = getaddrinfo(addr, NULL, NULL, &dest);
  if (error_id)
    return nseU_safeerror(L, gai_strerror(error_id));

  if (dest == NULL)
    return nseU_safeerror(L, "getaddrinfo returned success but no addresses");

  nsock_sendto(nsp, nu->nsiod, callback, nu->timeout, nu, dest->ai_addr, dest->ai_addrlen, port, string, size);
  trace(nu->nsiod, hexify((unsigned char *) string, size).c_str(), TO);
  freeaddrinfo(dest);
  return yield(L, nu, "SEND", TO, 0, NULL);

}

static void receive_callback (nsock_pool nsp, nsock_event nse, void *udata)
{
  nse_nsock_udata *nu = (nse_nsock_udata *) udata;
  lua_State *L = nu->thread;
  assert(nse_type(nse) == NSE_TYPE_READ);
  if (nse_status(nse) == NSE_STATUS_SUCCESS)
  {
    int len;
    const char *str = nse_readbuf(nse, &len);
    trace(nse_iod(nse), hexify((const unsigned char *) str, len).c_str(), FROM);
    lua_pushboolean(L, true);
    lua_pushlstring(L, str, len);
    // since r39036, read event can succeed immediately if there's pending SSL data
    if(lua_status(L) == LUA_YIELD)
      nse_restore(L, 2);
    else
      nu->action = NU_ACTION_IMMEDIATE;
    return;
  }
  else if (lua_status(L) == LUA_OK && nse_status(nse) == NSE_STATUS_EOF) {
    // since r39028, read event can fail immediately if the socket is EOF.
    trace(nse_iod(nse), nu->action, "EOF");
    lua_pushnil(L);
    lua_pushliteral(L, "EOF");
    nu->action = NU_ACTION_IMMEDIATE;
    return;
  }
  else
    status(L, nse_status(nse)); /* will also restore the thread */
}

static int l_receive (lua_State *L)
{
  nsock_pool nsp = get_pool(L);
  nse_nsock_udata *nu = check_nsock_udata(L, 1, true);
  NSOCK_UDATA_ENSURE_OPEN(L, nu);
  int oldtop = lua_gettop(L);
  nsock_read(nsp, nu->nsiod, receive_callback, nu->timeout, nu);
  if (nu->action == NU_ACTION_IMMEDIATE) {
    // Immediate return
    return lua_gettop(L) - oldtop;
  }
  return yield(L, nu, "RECEIVE", FROM, 0, NULL);
}

static int l_receive_lines (lua_State *L)
{
  nsock_pool nsp = get_pool(L);
  nse_nsock_udata *nu = check_nsock_udata(L, 1, true);
  NSOCK_UDATA_ENSURE_OPEN(L, nu);
  int oldtop = lua_gettop(L);
  nsock_readlines(nsp, nu->nsiod, receive_callback, nu->timeout, nu,
      luaL_checkinteger(L, 2));
  if (nu->action == NU_ACTION_IMMEDIATE) {
    // Immediate return
    return lua_gettop(L) - oldtop;
  }
  return yield(L, nu, "RECEIVE LINES", FROM, 0, NULL);
}

static int l_receive_bytes (lua_State *L)
{
  nsock_pool nsp = get_pool(L);
  nse_nsock_udata *nu = check_nsock_udata(L, 1, true);
  NSOCK_UDATA_ENSURE_OPEN(L, nu);
  int oldtop = lua_gettop(L);
  nsock_readbytes(nsp, nu->nsiod, receive_callback, nu->timeout, nu,
      luaL_checkinteger(L, 2));
  if (nu->action == NU_ACTION_IMMEDIATE) {
    // Immediate return
    return lua_gettop(L) - oldtop;
  }
  return yield(L, nu, "RECEIVE BYTES", FROM, 0, NULL);
}

static int receive_buf (lua_State *L, int status, lua_KContext ctx)
{
  nsock_pool nsp = get_pool(L);
  nse_nsock_udata *nu = check_nsock_udata(L, 1, true);
  NSOCK_UDATA_ENSURE_OPEN(L, nu);
  if (!(lua_type(L, 2) == LUA_TFUNCTION || lua_type(L, 2) == LUA_TSTRING))
    nseU_typeerror(L, 2, "function/string");
  luaL_checktype(L, 3, LUA_TBOOLEAN); /* 3 */

  if (status == LUA_OK) {
    lua_settop(L, 3); /* clear top */
    lua_getuservalue(L, 1); /* 4 */
    lua_rawgeti(L, 4, BUFFER_I); /* 5 */
  } else {
    /* Here we are returning from nsock_read below.
     * We have two extra values on the stack pushed by receive_callback.
     */
    assert(lua_gettop(L) == 7);
    if (lua_toboolean(L, 6)) /* success? */
    {
      lua_replace(L, 6); /* remove boolean */
      lua_concat(L, 2); /* concat BUFFER_I with received data */
    }
    else /* receive_callback encountered an error */
      return 2;
  }

  if (lua_isfunction(L, 2))
  {
    lua_pushvalue(L, 2);
    lua_pushvalue(L, 5);
    lua_call(L, 1, 2); /* we do not allow yields */
  }
  else /* string */
  {
    lua_getglobal(L, "string");
    lua_getfield(L, -1, "find");
    lua_replace(L, -2);
    lua_pushvalue(L, 5);
    lua_pushvalue(L, 2);
    lua_call(L, 2, 2); /* we do not allow yields */
  }

  if (lua_isnumber(L, -2) && lua_isnumber(L, -1)) /* found end? */
  {
    lua_Integer l = lua_tointeger(L, -2), r = lua_tointeger(L, -1);
    if (l > r || r > (lua_Integer) lua_rawlen(L, 5))
      return luaL_error(L, "invalid indices for match");
    lua_pushboolean(L, 1);
    if (lua_toboolean(L, 3))
      lua_pushlstring(L, lua_tostring(L, 5), r);
    else
      lua_pushlstring(L, lua_tostring(L, 5), l-1);
    lua_pushlstring(L, lua_tostring(L, 5)+r, lua_rawlen(L, 5)-r);
    lua_rawseti(L, 4, BUFFER_I);
    return 2;
  }
  else
  {
    lua_pop(L, 2); /* pop 2 results */
    int oldtop = lua_gettop(L);
    nsock_read(nsp, nu->nsiod, receive_callback, nu->timeout, nu);
    if (nu->action == NU_ACTION_IMMEDIATE) {
      // Immediate return
      return lua_gettop(L) - oldtop;
    }
    return yield(L, nu, "RECEIVE BUF", FROM, 0, receive_buf);
  }
}

static int l_receive_buf (lua_State *L)
{
  return receive_buf(L, LUA_OK, 0);
}

static int l_get_info (lua_State *L)
{
  nse_nsock_udata *nu = check_nsock_udata(L, 1, true);
  NSOCK_UDATA_ENSURE_OPEN(L, nu);
  int protocol;                                  // tcp or udp
  int af;                                        // address family
  struct sockaddr_storage local;
  struct sockaddr_storage remote;
  char *ipstring_local = (char *) lua_newuserdatauv(L, sizeof(char) * INET6_ADDRSTRLEN, 0);
  char *ipstring_remote = (char *) lua_newuserdatauv(L, sizeof(char) * INET6_ADDRSTRLEN, 0);

  nsock_iod_get_communication_info(nu->nsiod, &protocol, &af,
      (struct sockaddr*)&local, (struct sockaddr*)&remote,
      sizeof(struct sockaddr_storage));

  lua_pushboolean(L, true);
  lua_pushstring(L, inet_ntop_both(af, &local, ipstring_local));
  lua_pushinteger(L, inet_port_both(af, &local));
  lua_pushstring(L, inet_ntop_both(af, &remote, ipstring_remote));
  lua_pushinteger(L, inet_port_both(af, &remote));
  return 5;
}

static int l_set_timeout (lua_State *L)
{
  nse_nsock_udata *nu = check_nsock_udata(L, 1, false);
  int timeout = nseU_checkinteger(L, 2);
  if (timeout < -1) /* -1 is no timeout */
    return luaL_error(L, "Negative timeout: %f", timeout);
  nu->timeout = timeout;
  return nseU_success(L);
}

static int sleep_destructor (lua_State *L)
{
  nsock_pool nsp = get_pool(L);
  nsock_event_id *neidp = (nsock_event_id *) lua_touserdata(L, 2);
  if (o.debugging >= 2)
    log_write(LOG_STDERR, "Destroying sleep callback.\n");
  assert(neidp);
  int success = nsock_event_cancel(nsp, *neidp, 0);
  if (success)
    return nseU_success(L);
  else
    return nseU_safeerror(L, "could not cancel event");
}

static void sleep_callback (nsock_pool nsp, nsock_event nse, void *ud)
{
  lua_State *L = (lua_State *) ud;
  if (nse_status(nse) == NSE_STATUS_KILL)
      return;
  assert(lua_status(L) == LUA_YIELD);
  assert(nse_status(nse) == NSE_STATUS_SUCCESS);
  nse_restore(L, 0);
}

static int l_sleep (lua_State *L)
{
  nsock_pool nsp = get_pool(L);
  double secs = luaL_checknumber(L, 1);
  int msecs;

  if (secs < 0)
    luaL_error(L, "argument to sleep (%f) must not be negative\n", secs);

  /* Convert to milliseconds for nsock_timer_create. */
  msecs = (int) (secs * 1000 + 0.5);

  nsock_event_id *neidp = (nsock_event_id *) lua_newuserdatauv(L, sizeof(nsock_event_id *), 0);
  *neidp = nsock_timer_create(nsp, sleep_callback, msecs, L);
  lua_pushvalue(L, NSOCK_POOL);
  lua_pushcclosure(L, sleep_destructor, 1);
  nse_destructor(L, 'a');

  return nse_yield(L, 0, NULL);
}

#if HAVE_OPENSSL
SSL *nse_nsock_get_ssl (lua_State *L)
{
  nse_nsock_udata *nu = check_nsock_udata(L, 1, false);

  if (nu->nsiod == NULL || !nsock_iod_check_ssl(nu->nsiod))
    luaL_argerror(L, 1, "not a SSL socket");

  return (SSL *) nsock_iod_get_ssl(nu->nsiod);
}
#else
/* If HAVE_OPENSSL is defined, these come from nse_ssl_cert.cc. */
int l_get_ssl_certificate (lua_State *L)
{
  return luaL_error(L, "SSL is not available");
}

int l_parse_ssl_certificate(lua_State *L)
{
  return luaL_error(L, "SSL is not available");
}
#endif

/* Set the local address for socket operations. The two optional parameters
   after the first (which is the socket object) are a string representing a
   numeric address, and a port number. If either optional parameter is omitted
   or nil, that part of the address will be left unspecified. */
static int l_bind (lua_State *L)
{
  nse_nsock_udata *nu = check_nsock_udata(L, 1, false);
  struct addrinfo hints = { 0 };
  struct addrinfo *results;
  const char *addr_str = luaL_optstring(L, 2, NULL);
  luaL_checkinteger(L, 3);
  const char *port_str = lua_tostring(L, 3); /* automatic conversion */
  int rc;

  /* If we don't have a string to work with, set our configured address family
     to get the proper unspecified address (0.0.0.0 or ::). Otherwise infer the
     family from the string. */
  if (addr_str == NULL)
    hints.ai_family = o.af();
  else
    hints.ai_family = AF_UNSPEC;
  /* AI_NUMERICHOST: don't use DNS to resolve names.
     AI_PASSIVE: set an unspecified address if addr_str is NULL. */
  hints.ai_flags = AI_NUMERICHOST | AI_PASSIVE;

  rc = getaddrinfo(addr_str, port_str, &hints, &results);
  if (rc != 0)
    return nseU_safeerror(L, "getaddrinfo: %s", gai_strerror(rc));
  if (results == NULL)
    return nseU_safeerror(L, "getaddrinfo: no results found");
  if (results->ai_addrlen > sizeof(nu->source_addr)) {
    freeaddrinfo(results);
    return nseU_safeerror(L, "getaddrinfo: result is too big");
  }

  /* We ignore any results after the first. */
  /* We would just call nsock_iod_set_localaddr here, but nu->nsiod is not
   * created until connect. So store the address in the userdatum. */
  nu->source_addrlen = results->ai_addrlen;
  memcpy(&nu->source_addr, results->ai_addr, nu->source_addrlen);

  freeaddrinfo(results);
  return nseU_success(L);
}

static const char *default_af_string(int af)
{
  if (af == AF_INET)
    return "inet";
  else
    return "inet6";
}

static void initialize (lua_State *L, int idx, nse_nsock_udata *nu,
  int proto, int af)
{

  lua_createtable(L, 2, 0); /* room for thread in array */
  lua_pushliteral(L, "");
  lua_rawseti(L, -2, BUFFER_I);
  lua_setuservalue(L, idx);
  nu->nsiod = NULL;
  nu->proto = proto;
  nu->af = af;
  nu->ssl_session = NULL;
  nu->source_addr.ss_family = AF_UNSPEC;
  nu->source_addrlen = sizeof(nu->source_addr);
  nu->timeout = DEFAULT_TIMEOUT;
  nu->thread = NULL;
  nu->direction = nu->action = NULL;
}

static int l_new (lua_State *L)
{
  static const char *proto_strings[] = { "tcp", "udp", NULL };
  int proto_map[] = { IPPROTO_TCP, IPPROTO_UDP };
  static const char *af_strings[] = { "inet", "inet6", NULL };
  int af_map[] = { AF_INET, AF_INET6 };
  int proto, af;
  nse_nsock_udata *nu;

  proto = proto_map[luaL_checkoption(L, 1, "tcp", proto_strings)];
  af = af_map[luaL_checkoption(L, 2, default_af_string(o.af()), af_strings)];

  lua_settop(L, 0);

  nu = (nse_nsock_udata *) lua_newuserdatauv(L, sizeof(nse_nsock_udata), 1);
  lua_pushvalue(L, NSOCK_SOCKET);
  lua_setmetatable(L, -2);
  initialize(L, 1, nu, proto, af);

  return 1;
}

/* Common subfunction to l_close and l_connect. l_connect calls this when a
   second attempt is made to connect a socket that has already had a connection
   attempt. */
static void close_internal (lua_State *L, nse_nsock_udata *nu)
{
  trace(nu->nsiod, "CLOSE", TO);
#ifdef HAVE_OPENSSL
  if (nu->ssl_session)
    SSL_SESSION_free((SSL_SESSION *) nu->ssl_session);
#endif
  nsock_iod_delete(nu->nsiod, NSOCK_PENDING_NOTIFY);
  nu->nsiod = NULL;
}

static int l_close (lua_State *L)
{
  nse_nsock_udata *nu = check_nsock_udata(L, 1, false);
  if (nu->nsiod == NULL)
    return nseU_safeerror(L, "socket already closed");
  close_internal(L, nu);
  initialize(L, 1, nu, nu->proto, nu->af);
  return nseU_success(L);
}

static int nsock_gc (lua_State *L)
{
  nse_nsock_udata *nu = check_nsock_udata(L, 1, false);
  if (nu->nsiod)
    return l_close(L);
  return 0;
}


/****************** PCAP_SOCKET ***********************************************/

static void dnet_to_pcap_device_name (lua_State *L, const char *device)
{
  if (strcmp(device, "any") == 0)
    lua_pushliteral(L, "any");
  else
  {
#ifdef WIN32
    // Packet32.h: #define ADAPTER_NAME_LENGTH 256 + 12
    // We'll use a little extra to be safe.
    char pcapdev[384];
    /* Nmap normally uses device names obtained through dnet for interfaces,
       but Pcap has its own naming system.  So the conversion is done here */
    if (DnetName2PcapName(device, pcapdev, sizeof(pcapdev)))
      lua_pushstring(L, pcapdev);
    else
#endif
      lua_pushstring(L, device);
  }
}

static int l_pcap_open (lua_State *L)
{
  nsock_pool nsp = get_pool(L);
  nse_nsock_udata *nu = check_nsock_udata(L, 1, false);
  const char *device = luaL_checkstring(L, 2);
  int snaplen = luaL_checkinteger(L, 3);
  luaL_checktype(L, 4, LUA_TBOOLEAN); /* promiscuous */
  const char *bpf = luaL_checkstring(L, 5);

  if (nu->nsiod)
    luaL_argerror(L, 1, "socket is already open");

  lua_settop(L, 5);

  dnet_to_pcap_device_name(L, device); /* 6 */

  if (lua_rawlen(L, 6) == 0)
    luaL_argerror(L, 2, "bad device name");

  int rc;

  nu->nsiod = nsock_iod_new(nsp, nu);
  rc = nsock_pcap_open(nsp, nu->nsiod, lua_tostring(L, 6), snaplen,
      lua_toboolean(L, 4), bpf);
  if (rc) {
    nsock_iod_delete(nu->nsiod, NSOCK_PENDING_ERROR);
    nu->nsiod = NULL;
    luaL_error(L, "can't open pcap reader on %s", device);
  }
  nu->af = NSE_AF_PCAP;
  nu->proto = 0;
  return 0;
}

static void pcap_receive_handler (nsock_pool nsp, nsock_event nse, void *ud)
{
  nse_nsock_udata *nu = (nse_nsock_udata *) ud;
  lua_State *L = nu->thread;

  assert(lua_status(L) == LUA_YIELD);
  if (nse_status(nse) == NSE_STATUS_SUCCESS)
  {
    const unsigned char *l2_data, *l3_data;
    size_t l2_len, l3_len, packet_len;
    struct timeval tv;

    nse_readpcap(nse, &l2_data, &l2_len, &l3_data, &l3_len, &packet_len, &tv);

    lua_pushboolean(L, 1);
    lua_pushinteger(L, packet_len);
    lua_pushlstring(L, (const char *) l2_data, l2_len);
    lua_pushlstring(L, (const char *) l3_data, l3_len);
    lua_pushnumber(L, TIMEVAL_SECS(tv));
    nse_restore(L, 5);
  }
  else
    status(L, nse_status(nse)); /* will also restore the thread */
}

static int l_pcap_receive (lua_State *L)
{
  nsock_pool nsp = get_pool(L);
  nse_nsock_udata *nu = check_nsock_udata(L, 1, false);
  if (nu->nsiod == NULL || nu->af != NSE_AF_PCAP) {
    return luaL_error(L, "not a pcap socket");
  }
  nsock_pcap_read_packet(nsp, nu->nsiod, pcap_receive_handler,
      nu->timeout, nu);
  return yield(L, nu, "PCAP RECEIVE", FROM, 0, NULL);
}

/* This function also has a binding in stdnse.lua */
static int l_get_stats (lua_State *L) {
  lua_newtable(L);
  int idx = lua_gettop(L);

  /* the only field so far is
     connect_waiting - number of threads waiting for connection */
  lua_pushinteger(L, nseU_tablen(L, CONNECT_WAITING));
  lua_setfield(L, idx, "connect_waiting");

  return 1;
}

LUALIB_API int luaopen_nsock (lua_State *L)
{
  static const luaL_Reg metatable_index[] = {
    {"bind", l_bind},
    {"close", l_close},
    {"connect", l_connect},
    {"get_info", l_get_info},
    {"get_ssl_certificate", l_get_ssl_certificate},
    {"pcap_open", l_pcap_open},
    {"pcap_close", l_close},
    {"pcap_receive", l_pcap_receive},
    {"send", l_send},
    {"sendto", l_sendto},
    {"receive", l_receive},
    {"receive_buf", l_receive_buf},
    {"receive_bytes", l_receive_bytes},
    {"receive_lines", l_receive_lines},
    {"reconnect_ssl", l_reconnect_ssl},
    {"set_timeout", l_set_timeout},
    {NULL, NULL}
  };

  static const luaL_Reg l_nsock[] = {
    {"loop", l_loop},
    {"new", l_new},
    {"sleep", l_sleep},
    {"parse_ssl_certificate", l_parse_ssl_certificate},
    {"get_stats", l_get_stats},
    {NULL, NULL}
  };

  /* Set up an environment for all nsock C functions to share.
   * This table particularly contains the THREAD_SOCKETS and
   * CONNECT_WAITING tables.
   * These values are accessed at the Lua pseudo-index LUA_ENVIRONINDEX.
   */
  int i;
  int top = lua_gettop(L);

  /* library upvalues */
  nsock_pool nsp = new_pool(L); /* NSOCK_POOL */
  lua_newtable(L); /* NSOCK_SOCKET */
  nseU_weaktable(L, 0, MAX_PARALLELISM, "k"); /* THREAD_SOCKETS */
  nseU_weaktable(L, 0, 1000, "k"); /* CONNECT_WAITING */
  int nupvals = lua_gettop(L)-top;

  /* Create the nsock metatable for sockets */
  lua_pushvalue(L, top+2); /* NSOCK_SOCKET */
  luaL_newlibtable(L, metatable_index);
  for (i = top+1; i <= top+nupvals; i++) lua_pushvalue(L, i);
  luaL_setfuncs(L, metatable_index, nupvals);
  lua_setfield(L, -2, "__index");
  for (i = top+1; i <= top+nupvals; i++) lua_pushvalue(L, i);
  lua_pushcclosure(L, nsock_gc, nupvals);
  lua_setfield(L, -2, "__gc");
  lua_newtable(L);
  lua_setfield(L, -2, "__metatable");  /* protect metatable */
  lua_pop(L, 1); /* NSOCK_SOCKET */

#if HAVE_OPENSSL
  /* Set up the SSL certificate userdata code in nse_ssl_cert.cc. */
  nse_nsock_init_ssl_cert(L);
#endif

#if HAVE_OPENSSL
  /* Value speed over security in SSL connections. */
  nsock_pool_ssl_init(nsp, NSOCK_SSL_MAX_SPEED);
#else
  (void) nsp; //variable is unused, avoid warning.
#endif

  luaL_newlibtable(L, l_nsock);
  for (i = top+1; i <= top+nupvals; i++) lua_pushvalue(L, i);
  luaL_setfuncs(L, l_nsock, nupvals);

  return 1;
}
