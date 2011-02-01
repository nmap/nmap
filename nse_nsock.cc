#include "nsock.h"
#include "nmap_error.h"
#include "NmapOps.h"
#include "utils.h"
#include "tcpip.h"
#include "protocols.h"
#include "libnetutil/netutil.h"

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

#define NMAP_NSOCK_SOCKET  "NMAP_NSOCK_SOCKET"
#define NMAP_NSOCK_PCAP_SOCKET  "NMAP_NSOCK_PCAP_SOCKET"

#define DEFAULT_TIMEOUT 30000

/* Integer keys in Nsock function environments */
#define THREAD_SOCKETS     1           /* <Thread, Table of Sockets (keys)> */
#define CONNECT_WAITING    2           /* Threads waiting to lock */
#define KEY_PCAP           3           /* keys to pcap sockets */

/* Integer keys in the Nsock userdata environments */
#define THREAD_I  1 /* The thread that yielded */
#define BUFFER_I  2 /* Location of Userdata Buffer */

extern NmapOps o;

typedef struct nse_nsock_udata
{
  nsock_iod nsiod;
  unsigned timeout;

  lua_State *thread;

  int proto;
  int af;

  const char *direction;
  const char *action;

  void *ssl_session;

  struct sockaddr_storage source_addr;
  size_t source_addrlen;

  /* PCAP */
  int is_pcap;
  nsock_event_id nseid;
  struct timeval recvtime; /* Time packet was received, if r_success is true */

} nse_nsock_udata;

static int NSOCK_POOL = 0xac1dba11;

static int gc_pool (lua_State *L)
{
  nsock_pool *nsp = (nsock_pool *) lua_touserdata(L, 1);
  assert(*nsp != NULL);
  nsp_delete(*nsp);
  *nsp = NULL;
  return 0;
}

static nsock_pool new_pool (lua_State *L)
{
  nsock_pool nsp = nsp_new(NULL);
  nsock_pool *nspp;
  nsp_setbroadcast(nsp, true);
  lua_pushlightuserdata(L, &NSOCK_POOL);
  nspp = (nsock_pool *) lua_newuserdata(L, sizeof(nsock_pool));
  *nspp = nsp;
  lua_newtable(L);
  lua_pushcfunction(L, gc_pool);
  lua_setfield(L, -2, "__gc");
  lua_setmetatable(L, -2);
  lua_rawset(L, LUA_REGISTRYINDEX);
  return nsp;
}

static nsock_pool get_pool (lua_State *L)
{
  nsock_pool *nsp;
  lua_pushlightuserdata(L, &NSOCK_POOL);
  lua_rawget(L, LUA_REGISTRYINDEX);
  nsp = (nsock_pool *) lua_touserdata(L, -1);
  assert(*nsp != NULL);
  lua_pop(L, 1);
  return *nsp;
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
 * o.maxparallelism is the max # of threads that can have connected sockets
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

/* The Lua 5.2 socket_lock function */
#if 0
/* int socket_lock (lua_State *L)
 *
 * This function is called by l_connect to get a "lock" on a socket.
 * When connect calls this function, it expects socket_lock to yield forcing
 * connect to be restarted when resumed or it succeeds returning normally.
 */
static void socket_lock (lua_State *L, int idx)
{
  unsigned p = o.max_parallelism == 0 ? MAX_PARALLELISM : o.max_parallelism;
  int top = lua_gettop(L);
  lua_rawgeti(L, LUA_ENVIRONINDEX, THREAD_SOCKETS);
  nse_base(L);
  lua_rawget(L, -2);
  if (lua_istable(L, -1))
  {
    /* Thread already has a "lock" with open sockets. Place the new socket
     * in its sockets table */
    lua_pushvalue(L, idx);
    lua_pushboolean(L, true);
    lua_rawset(L, -3);
  } else if (table_length(L, top+2) <= p)
  {
    /* There is room for this thread to open sockets */
    nse_base(L);
    weak_table(L, 0, 0, "k"); /* weak socket references */
    lua_pushvalue(L, idx); /* socket */
    lua_pushboolean(L, true);
    lua_rawset(L, -3); /* add to sockets table */
    lua_rawset(L, top+2); /* add new <Thread, Sockets Table> Pair
                       * to THREAD_SOCKETS */
  } else
  {
    /* Too many threads have sockets open. Add thread to waiting. The caller
     * is expected to yield. (see the connect function in luaopen_nsock) */
    lua_rawgeti(L, LUA_ENVIRONINDEX, CONNECT_WAITING);
    nse_base(L);
    lua_pushboolean(L, true);
    lua_settable(L, -3);
    lua_settop(L, top); /* restore stack to original condition for l_connect */
    return nse_yield(L, 0, NULL);
  }
  lua_settop(L, top); /* restore stack to original condition for l_connect */
}
#endif

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
  unsigned p = o.max_parallelism == 0 ? MAX_PARALLELISM : o.max_parallelism;
  lua_settop(L, 1);
  lua_rawgeti(L, LUA_ENVIRONINDEX, THREAD_SOCKETS);
  nse_base(L);
  lua_rawget(L, -2);
  if (lua_istable(L, -1))
  {
    /* Thread already has a "lock" with open sockets. Place the new socket
     * in its sockets table */
    lua_pushvalue(L, 1);
    lua_pushboolean(L, true);
    lua_rawset(L, -3);
  } else if (table_length(L, 2) <= p)
  {
    /* There is room for this thread to open sockets */
    nse_base(L);
    weak_table(L, 0, 0, "k"); /* weak socket references */
    lua_pushvalue(L, 1); /* socket */
    lua_pushboolean(L, true);
    lua_rawset(L, -3); /* add to sockets table */
    lua_rawset(L, 2); /* add new <Thread, Sockets Table> Pair
                       * to THREAD_SOCKETS */
  } else
  {
    /* Too many threads have sockets open. Add thread to waiting. The caller
     * is expected to yield. (see the connect function in luaopen_nsock) */
    lua_rawgeti(L, LUA_ENVIRONINDEX, CONNECT_WAITING);
    nse_base(L);
    lua_pushboolean(L, true);
    lua_settable(L, -3);
    return nse_yield(L, 0, NULL);
  }
  lua_pushboolean(L, true);
  return 1;
}

static void socket_unlock (lua_State *L)
{
  int top = lua_gettop(L);

  lua_gc(L, LUA_GCSTOP, 0); /* don't collect threads during iteration */

  lua_rawgeti(L, LUA_ENVIRONINDEX, THREAD_SOCKETS);
  lua_pushnil(L);
  while (lua_next(L, -2) != 0)
  {
    unsigned open = 0;

    if (lua_status(lua_tothread(L, -2)) == LUA_YIELD)
    {
      lua_pushnil(L);
      while (lua_next(L, -2) != 0) /* for each socket */
      {
        lua_pop(L, 1); /* pop garbage boolean */
        if (((nse_nsock_udata *) lua_touserdata(L, -1))->nsiod != NULL)
          open++;
      }
    }

    if (open == 0) /* thread has no open sockets? */
    {
      /* close all of its sockets */
      lua_pushnil(L);
      while (lua_next(L, -2) != 0) /* for each socket */
      {
        lua_pop(L, 1); /* pop garbage boolean */
        lua_getfield(L, -1, "close");
        lua_pushvalue(L, -2);
        lua_call(L, 1, 0);
      }

      lua_pushvalue(L, -2); /* thread key */
      lua_pushnil(L);
      lua_rawset(L, top+1); /* THREADS_SOCKETS */

      lua_rawgeti(L, LUA_ENVIRONINDEX, CONNECT_WAITING);
      lua_pushnil(L);
      while (lua_next(L, -2) != 0)
      {
        lua_pop(L, 1); /* pop garbage boolean */
        nse_restore(lua_tothread(L, -1), 0);
        lua_pushvalue(L, -1);
        lua_pushnil(L);
        lua_rawset(L, -4); /* remove thread from waiting */
      }
      lua_pop(L, 1); /* CONNECT_WAITING */
    }

    lua_pop(L, 1); /* pop sockets table */
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
    if (!nsi_is_pcap(nsiod))
    {
      int status;
      int protocol;
      int af;
      char ipstring_local[INET6_ADDRSTRLEN];
      char ipstring_remote[INET6_ADDRSTRLEN];
      struct sockaddr_storage local;
      struct sockaddr_storage remote;

      status = nsi_getlastcommunicationinfo(nsiod, &protocol, &af,
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
      lua_pushboolean(L, true);
      nse_restore(L, 1);
      break;
    case NSE_STATUS_KILL:
    case NSE_STATUS_CANCELLED:
      return; /* do nothing! */
    case NSE_STATUS_EOF:
    case NSE_STATUS_ERROR:
    case NSE_STATUS_TIMEOUT:
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

static void callback (nsock_pool nsp, nsock_event nse, void *ud)
{
  nse_nsock_udata *nu = (nse_nsock_udata *) ud;
  lua_State *L = nu->thread;
  assert(lua_status(L) == LUA_YIELD);
  trace(nse_iod(nse), nu->action, nu->direction);
  status(L, nse_status(nse));
}

static int yield (lua_State *L, nse_nsock_udata *nu, const char *action,
    const char *direction, int ctx, lua_CFunction k)
{
  lua_getfenv(L, 1);
  lua_pushthread(L);
  lua_rawseti(L, -2, THREAD_I);
  lua_pop(L, 1); /* nsock udata environment */
  nu->thread = L;
  nu->action = action;
  nu->direction = direction;
  return nse_yield(L, ctx, k);
}

static nse_nsock_udata *check_nsock_udata (lua_State *L, int idx, int open)
{
  nse_nsock_udata *nu =
      (nse_nsock_udata *) luaL_checkudata(L, idx, NMAP_NSOCK_SOCKET);

  if (open && nu->nsiod == NULL) {
    /* The socket hasn't been connected or setup yet. Try doing a setup, or
       throw and error if that's not possible. */
    if (nu->proto == IPPROTO_UDP) {
      nsock_pool nsp;

      nsp = get_pool(L);
      nu->nsiod = nsi_new(nsp, NULL);
      if (nu->source_addr.ss_family != AF_UNSPEC) {
        nsi_set_localaddr(nu->nsiod, &nu->source_addr, nu->source_addrlen);
      } else if (o.spoofsource) {
        struct sockaddr_storage ss;
        size_t sslen;
        o.SourceSockAddr(&ss, &sslen);
        nsi_set_localaddr(nu->nsiod, &ss, sslen);
      }
      if (o.ipoptionslen)
        nsi_set_ipoptions(nu->nsiod, o.ipoptions, o.ipoptionslen);

      if (nsock_setup_udp(nsp, nu->nsiod, nu->af) == -1) {
        luaL_error(L, "Error in setup of iod with proto %d and af %d: %s (%d)",
          nu->proto, nu->af, socket_strerror(socket_errno()), socket_errno());
      }
    } else {
      luaL_error(L, "socket must be connected\n");
    }
  }

  return nu;
}

static int loop (lua_State *L)
{
  nsock_pool nsp = get_pool(L);
  int tout = luaL_checkint(L, 1);

  /* clean up old socket locks */
  socket_unlock(L);

  if (nsock_loop(nsp, tout) == NSOCK_LOOP_ERROR)
    luaL_error(L, "a fatal error occurred in nsock_loop");
  return 0;
}

static int l_reconnect_ssl (lua_State *L)
{
  nsock_pool nsp = get_pool(L);
  nse_nsock_udata *nu = check_nsock_udata(L, 1, 1);

#ifndef HAVE_OPENSSL
  if (1)
    return safe_error(L, "sorry, you don't have OpenSSL");
#endif

  nsock_reconnect_ssl(nsp, nu->nsiod, callback, nu->timeout,
      nu, nu->ssl_session);

  return yield(L, nu, "SSL RECONNECT", TO, 0, NULL);
}

static int l_connect (lua_State *L)
{
  enum type {TCP, UDP, SSL};
  static const char * const op[] = {"tcp", "udp", "ssl", NULL};

  nsock_pool nsp = get_pool(L);
  nse_nsock_udata *nu = check_nsock_udata(L, 1, 0);
  const char *addr, *targetname; check_target(L, 2, &addr, &targetname);
  const char *default_proto = NULL;
  unsigned short port = check_port(L, 3, &default_proto);
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
  struct addrinfo *dest;
  int error_id;

  /* Lua 5.2 */
#if 0
  /* either socket_lock yields and this function is resumed (and restarted)
   * or it succeeds and we continue.
   */
  socket_lock(L);
#endif

#ifndef HAVE_OPENSSL
  if (what == SSL)
    return safe_error(L, "sorry, you don't have OpenSSL");
#endif

  error_id = getaddrinfo(addr, NULL, NULL, &dest);
  if (error_id)
    return safe_error(L, gai_strerror(error_id));

  if (dest == NULL)
    return safe_error(L, "getaddrinfo returned success but no addresses");

  nu->nsiod = nsi_new(nsp, NULL);
  if (nu->source_addr.ss_family != AF_UNSPEC) {
    nsi_set_localaddr(nu->nsiod, &nu->source_addr, nu->source_addrlen);
  } else if (o.spoofsource) {
    struct sockaddr_storage ss;
    size_t sslen;

    o.SourceSockAddr(&ss, &sslen);
    nsi_set_localaddr(nu->nsiod, &ss, sslen);
  }
  if (o.ipoptionslen)
    nsi_set_ipoptions(nu->nsiod, o.ipoptions, o.ipoptionslen);
  if (targetname != NULL) {
    if (nsi_set_hostname(nu->nsiod, targetname) == -1)
      fatal("nsi_set_hostname(\"%s\" failed in %s()", targetname, __func__);
  }

  nu->af = dest->ai_addr->sa_family;

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
      nu->proto = IPPROTO_TCP;
      nsock_connect_ssl(nsp, nu->nsiod, callback, nu->timeout, nu,
          dest->ai_addr, dest->ai_addrlen, IPPROTO_TCP, port, nu->ssl_session);
      break;
  }

  freeaddrinfo(dest);
  return yield(L, nu, "CONNECT", TO, 0, NULL);
}

static int l_send (lua_State *L)
{
  nsock_pool nsp = get_pool(L);
  nse_nsock_udata *nu = check_nsock_udata(L, 1, 1);
  size_t size;
  const char *string = luaL_checklstring(L, 2, &size);
  trace(nu->nsiod, hexify((unsigned char *) string, size).c_str(), TO);
  nsock_write(nsp, nu->nsiod, callback, nu->timeout, nu, string, size);
  return yield(L, nu, "SEND", TO, 0, NULL);
}

static int l_sendto (lua_State *L)
{
  nsock_pool nsp = get_pool(L);
  nse_nsock_udata *nu = check_nsock_udata(L, 1, 1);
  size_t size;
  const char *addr, *targetname; check_target(L, 2, &addr, &targetname);
  const char *default_proto = NULL;
  unsigned short port = check_port(L, 3, &default_proto);
  const char *string = luaL_checklstring(L, 4, &size);
  int error_id;
  struct addrinfo *dest;

  error_id = getaddrinfo(addr, NULL, NULL, &dest);
  if (error_id)
    return safe_error(L, gai_strerror(error_id));

  if (dest == NULL)
    return safe_error(L, "getaddrinfo returned success but no addresses");

  nsock_sendto(nsp, nu->nsiod, callback, nu->timeout, nu, dest->ai_addr, dest->ai_addrlen, port, string, size);
  trace(nu->nsiod, hexify((unsigned char *) string, size).c_str(), TO);
  return yield(L, nu, "SEND", TO, 0, NULL);
	
}

static void receive_callback (nsock_pool nsp, nsock_event nse, void *udata)
{
  nse_nsock_udata *nu = (nse_nsock_udata *) udata;
  lua_State *L = nu->thread;
  assert(lua_status(L) == LUA_YIELD);
  if (nse_status(nse) == NSE_STATUS_SUCCESS)
  {
    int len;
    const char *str = nse_readbuf(nse, &len);
    trace(nse_iod(nse), hexify((const unsigned char *) str, len).c_str(), FROM);
    lua_pushboolean(L, true);
    lua_pushlstring(L, str, len);
    nse_restore(L, 2);
  }
  else
    status(L, nse_status(nse)); /* will also restore the thread */
}

static int l_receive (lua_State *L)
{
  nsock_pool nsp = get_pool(L);
  nse_nsock_udata *nu = check_nsock_udata(L, 1, 1);
  nsock_read(nsp, nu->nsiod, receive_callback, nu->timeout, nu);
  return yield(L, nu, "RECEIVE", FROM, 0, NULL);
}

static int l_receive_lines (lua_State *L)
{
  nsock_pool nsp = get_pool(L);
  nse_nsock_udata *nu = check_nsock_udata(L, 1, 1);
  nsock_readlines(nsp, nu->nsiod, receive_callback, nu->timeout, nu,
      luaL_checkint(L, 2));
  return yield(L, nu, "RECEIVE LINES", FROM, 0, NULL);
}

static int l_receive_bytes (lua_State *L)
{
  nsock_pool nsp = get_pool(L);
  nse_nsock_udata *nu = check_nsock_udata(L, 1, 1);
  nsock_readbytes(nsp, nu->nsiod, receive_callback, nu->timeout, nu,
      luaL_checkint(L, 2));
  return yield(L, nu, "RECEIVE BYTES", FROM, 0, NULL);
}

#if 0
/* Lua 5.2 */
static int l_receive_buf (lua_State *L)
{
  nsock_pool nsp = get_pool(L);
  nse_nsock_udata *nu = check_nsock_udata(L, 1, 1); /* 1 */
  if (!(lua_type(L, 2) == LUA_TFUNCTION || lua_type(L, 2) == LUA_TSTRING))
    luaL_typeerror(L, 2, "function/string");
  luaL_checktype(L, 3, LUA_TBOOLEAN); /* 3 */

  if (lua_getctx(L, NULL) == LUA_OK)
  {
    lua_settop(L, 3); /* clear top */
    lua_getuservalue(L, 1); /* 4 */
    lua_rawgeti(L, 4, BUFFER_I); /* 5 */
  }
  else
  {
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
    if (l > r || r > (lua_Integer) lua_objlen(L, 5))
      return luaL_error(L, "invalid indices for match");
    lua_pushboolean(L, 1);
    if (lua_toboolean(L, 3))
      lua_pushlstring(L, lua_tostring(L, 5), r);
    else
      lua_pushlstring(L, lua_tostring(L, 5), l-1);
    lua_pushlstring(L, lua_tostring(L, 5)+r, lua_objlen(L, 5)-r);
    lua_rawseti(L, 4, BUFFER_I);
    return 2;
  }
  else
  {
    lua_pop(L, 2); /* pop 2 results */
    nsock_read(nsp, nu->nsiod, receive_callback, nu->timeout, nu);
    return yield(L, nu, "RECEIVE BUF", FROM, 0, l_receive_buf);
  }
}
#endif

static int l_get_info (lua_State *L)
{
  nse_nsock_udata *nu = check_nsock_udata(L, 1, 1);
  int status;
  int protocol;                                  // tcp or udp
  int af;                                        // address family
  struct sockaddr local;
  struct sockaddr remote;
  char *ipstring_local = (char *) lua_newuserdata(L, sizeof(char) * INET6_ADDRSTRLEN);
  char *ipstring_remote = (char *) lua_newuserdata(L, sizeof(char) * INET6_ADDRSTRLEN);

  status = nsi_getlastcommunicationinfo(nu->nsiod, &protocol, &af,
      &local, &remote, sizeof(sockaddr));

  lua_pushboolean(L, true);
  lua_pushstring(L, inet_ntop_both(af, &local, ipstring_local));
  lua_pushnumber(L, inet_port_both(af, &local));
  lua_pushstring(L, inet_ntop_both(af, &remote, ipstring_remote));
  lua_pushnumber(L, inet_port_both(af, &remote));
  return 5;
}

static int l_set_timeout (lua_State *L)
{
  nse_nsock_udata *nu = check_nsock_udata(L, 1, 0);
  nu->timeout = luaL_checkint(L, 2);
  if ((int) nu->timeout < -1)
    return luaL_error(L, "Negative timeout: %d", nu->timeout);
  return success(L);
}

static void sleep_callback (nsock_pool nsp, nsock_event nse, void *ud)
{
  lua_State *L = (lua_State *) ud;
  assert(lua_status(L) == LUA_YIELD);
  assert(nse_status(nse) == NSE_STATUS_SUCCESS);
  nse_restore(L, 0);
}

LUALIB_API int l_nsock_sleep (lua_State *L)
{
  nsock_pool nsp = get_pool(L);
  double secs = luaL_checknumber(L, 1);
  int msecs;

  if (secs < 0)
    luaL_error(L, "argument to sleep (%f) must not be negative\n", secs);
  /* Convert to milliseconds for nsock_timer_create. */
  msecs = (int) (secs * 1000 + 0.5);
  nsock_timer_create(nsp, sleep_callback, msecs, L);

  return nse_yield(L, 0, NULL);
}

#if HAVE_OPENSSL
SSL *nse_nsock_get_ssl (lua_State *L)
{
  nse_nsock_udata *nu = check_nsock_udata(L, 1, 0);

  if (!nsi_checkssl(nu->nsiod))
    luaL_argerror(L, 1, "not a SSL socket");

  return (SSL *) nsi_getssl(nu->nsiod);
}
#else
/* If HAVE_OPENSSL is defined, this comes from nse_ssl_cert.cc. */
int l_get_ssl_certificate (lua_State *L)
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
  nse_nsock_udata *nu = check_nsock_udata(L, 1, 0);
  struct addrinfo hints = { 0 };
  struct addrinfo *results;
  const char *addr_str = luaL_optstring(L, 2, NULL);
  luaL_checkint(L, 3);
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
    return safe_error(L, gai_strerror(rc));
  if (results == NULL)
    return safe_error(L, "getaddrinfo: no results found");
  if (results->ai_addrlen > sizeof(nu->source_addr)) {
    freeaddrinfo(results);
    return safe_error(L, "getaddrinfo: result is too big");
  }

  /* We ignore any results after the first. */
  /* We would just call nsi_set_localaddr here, but nu->nsiod is not created
     until connect. So store the address in the userdatum. */
  nu->source_addrlen = results->ai_addrlen;
  memcpy(&nu->source_addr, results->ai_addr, nu->source_addrlen);

  return success(L);
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
  lua_setfenv(L, idx);
  nu->nsiod = NULL;
  nu->proto = proto;
  nu->af = af;
  nu->ssl_session = NULL;
  nu->source_addr.ss_family = AF_UNSPEC;
  nu->source_addrlen = sizeof(nu->source_addr);
  nu->timeout = DEFAULT_TIMEOUT;
  nu->is_pcap = 0;
  nu->thread = NULL;
  nu->direction = nu->action = NULL;
}

LUALIB_API int l_nsock_new (lua_State *L)
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

  nu = (nse_nsock_udata *) lua_newuserdata(L, sizeof(nse_nsock_udata));
  luaL_getmetatable(L, NMAP_NSOCK_SOCKET);
  lua_setmetatable(L, -2);
  initialize(L, 1, nu, proto, af);

  return 1;
}

static int l_close (lua_State *L)
{
  nse_nsock_udata *nu = check_nsock_udata(L, 1, 0);
  if (nu->nsiod == NULL)
    return safe_error(L, "socket already closed");
  trace(nu->nsiod, "CLOSE", TO);
#ifdef HAVE_OPENSSL
  if (nu->ssl_session)
    SSL_SESSION_free((SSL_SESSION *) nu->ssl_session);
#endif
  if (!nu->is_pcap) /* pcap sockets are closed by pcap_gc */
    nsi_delete(nu->nsiod, NSOCK_PENDING_NOTIFY);
  initialize(L, 1, nu, nu->proto, nu->af);
  return success(L);
}

static int nsock_gc (lua_State *L)
{
  nse_nsock_udata *nu = check_nsock_udata(L, 1, 0);
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
#ifdef WIN32
  {
    char pcapdev[4096];
    /* Nmap normally uses device names obtained through dnet for interfaces,
       but Pcap has its own naming system.  So the conversion is done here */
    if (!DnetName2PcapName(device, pcapdev, sizeof(pcapdev)))
      lua_pushstring(L, device);
    else
      lua_pushstring(L, pcapdev);
  }
#else
    lua_pushstring(L, device);
#endif
}

static int pcap_gc (lua_State *L)
{
  nsock_iod *nsiod = (nsock_iod *) lua_touserdata(L, 1);
  nsi_delete(*nsiod, NSOCK_PENDING_NOTIFY);
  *nsiod = NULL;
  return 0;
}

static int l_pcap_open (lua_State *L)
{
  nsock_pool nsp = get_pool(L);
  nse_nsock_udata *nu = check_nsock_udata(L, 1, 0);
  const char *device = luaL_checkstring(L, 2);
  int snaplen = luaL_checkint(L, 3);
  luaL_checktype(L, 4, LUA_TBOOLEAN); /* promiscuous */
  const char *bpf = luaL_checkstring(L, 5);

  lua_settop(L, 5);

  dnet_to_pcap_device_name(L, device); /* 6 */
  lua_pushfstring(L, "%s|%d|%d|%s", lua_tostring(L, 6), snaplen,
      lua_toboolean(L, 4), lua_tostring(L, 5)); /* 7, the pcap socket key */

  if (nu->nsiod)
    luaL_argerror(L, 1, "socket is already open");

  if (lua_objlen(L, 6) == 0)
    luaL_argerror(L, 2, "bad device name");

  lua_rawgeti(L, LUA_ENVIRONINDEX, KEY_PCAP);
  lua_pushvalue(L, 7);
  lua_rawget(L, -2);
  nsock_iod *nsiod = (nsock_iod *) lua_touserdata(L, -1);
  if (nsiod == NULL) /* does not exist */
  {
    nsiod = (nsock_iod *) lua_newuserdata(L, sizeof(nsock_iod));
    luaL_getmetatable(L, NMAP_NSOCK_PCAP_SOCKET);
    lua_setmetatable(L, -2);
    *nsiod = nsi_new(nsp, nu);
    lua_rawgeti(L, LUA_ENVIRONINDEX, KEY_PCAP);
    lua_pushvalue(L, 7); /* the pcap socket key */
    lua_pushvalue(L, -2); /* the pcap socket nsiod */
    lua_rawset(L, -3); /* _ENV[KEY_PCAP]["dev|snap|promis|bpf"] = pcap_nsiod */
    lua_pop(L, 1); /* KEY_PCAP */
    lua_getfenv(L, 1); /* the socket user value */
    lua_pushvalue(L, -2); /* the pcap socket nsiod */
    lua_pushboolean(L, 1); /* dummy variable */
    lua_rawset(L, -3);
    lua_pop(L, 1); /* the socket user value */
    char *e = nsock_pcap_open(nsp, *nsiod, lua_tostring(L, 6), snaplen,
        lua_toboolean(L, 4), bpf);
    if (e)
      luaL_error(L, "%s", e);
  }
  nu->nsiod = *nsiod;
  nu->is_pcap = 1;
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
  nse_nsock_udata *nu = check_nsock_udata(L, 1, 1);
  nu->nseid = nsock_pcap_read_packet(nsp, nu->nsiod, pcap_receive_handler,
      nu->timeout, nu);
  return yield(L, nu, "PCAP RECEIVE", FROM, 0, NULL);
}

LUALIB_API int luaopen_nsock (lua_State *L)
{
/* These two functions can be implemented in C in Lua 5.2 */

  /* nsock:connect(socket, ...)
   * This Lua function is a wrapper around the actual l_nsock_connect. The
   * connect function must get a lock through socket_lock (C function above).
   * Once it has the lock, it can (tail call) return the actual connect
   * function.
   */
  static const char connect[] =
"local connect, socket_lock = ...;\n"
"return function(socket, ...)\n"
"  repeat until socket_lock(socket) == true;\n"
"  return connect(socket, ...);\n"
"end\n";
  static const char receive_buf[] =
"local function receive_buf (socket, fstr, keep)\n"
"  local i, j;\n"
"  local socket_uservalue = debug.getfenv(socket);\n"
"  local buf = socket_uservalue[2];\n"
"  if type(fstr) == 'function' then\n"
"    i, j = fstr(buf);\n"
"  elseif type(fstr) == 'string' then\n"
"    i, j = string.find(buf, fstr)\n"
"  end\n"
"  if type(i) == 'number' and type(j) == 'number' then\n"
"    if i > j or j > #buf then\n"
"      error('invalid indices for match');\n"
"    else\n"
"      socket_uservalue[2] = string.sub(buf, j+1);\n"
"      if keep then\n"
"        return true, string.sub(buf, 1, j);\n"
"      else\n"
"        return true, string.sub(buf, 1, i-1);\n"
"      end\n"
"    end\n"
"  else\n"
"    local status, result = socket:receive();\n"
"    if not status then return status, result end\n"
"    socket_uservalue[2] = socket_uservalue[2]..result;\n"
"    return receive_buf(socket, fstr, keep);\n"
"  end\n"
"end\n"
"return receive_buf;\n";

  static const luaL_Reg l_nsock[] = {
    {"bind", l_bind},
    {"send", l_send},
    {"sendto", l_sendto},
    {"receive", l_receive},
    {"receive_lines", l_receive_lines},
    {"receive_bytes", l_receive_bytes},
    /* {"receive_buf", l_receive_buf}, Lua 5.2 */
    {"get_info", l_get_info},
    {"close", l_close},
    {"set_timeout", l_set_timeout},
    {"reconnect_ssl", l_reconnect_ssl},
    {"get_ssl_certificate", l_get_ssl_certificate},
    {"pcap_open", l_pcap_open},
    {"pcap_close", l_close},
    {"pcap_receive", l_pcap_receive},
    {NULL, NULL}
  };

  /* Set up an environment for all nsock C functions to share.
   * This table particularly contains the THREAD_SOCKETS and
   * CONNECT_WAITING tables.
   * These values are accessed at the Lua pseudo-index LUA_ENVIRONINDEX.
   */
  lua_createtable(L, 3, 0);
  lua_replace(L, LUA_ENVIRONINDEX);

  weak_table(L, 0, MAX_PARALLELISM, "k");
  lua_rawseti(L, LUA_ENVIRONINDEX, THREAD_SOCKETS);

  weak_table(L, 0, 1000, "k");
  lua_rawseti(L, LUA_ENVIRONINDEX, CONNECT_WAITING);

  weak_table(L, 0, 0, "v");
  lua_rawseti(L, LUA_ENVIRONINDEX, KEY_PCAP);

  lua_pushcfunction(L, loop);
  lua_setfield(L, LUA_REGISTRYINDEX, NSE_NSOCK_LOOP);

  /* Load the connect function */
  if (luaL_loadstring(L, connect) != 0)
    assert(0);
  lua_pushcfunction(L, l_connect);
  lua_pushcfunction(L, socket_lock);
  lua_call(L, 2, 1);                   // leave connect function on stack...

  /* Create the nsock metatable for sockets */
  luaL_newmetatable(L, NMAP_NSOCK_SOCKET);
  lua_createtable(L, 0, 23);
  luaL_register(L, NULL, l_nsock);
  lua_pushvalue(L, -3);                // connect function
  lua_setfield(L, -2, "connect");
  if (luaL_dostring(L, receive_buf))
    assert(0);
  lua_pushvalue(L, LUA_GLOBALSINDEX);
  lua_setfenv(L, -2);
  lua_setfield(L, -2, "receive_buf");
  lua_setfield(L, -2, "__index");
  lua_pushcfunction(L, nsock_gc);
  lua_setfield(L, -2, "__gc");
  lua_newtable(L);
  lua_setfield(L, -2, "__metatable");  // protect metatable
  lua_pop(L, 1);                       // nsock metatable

  /* Create the nsock pcap metatable */
  luaL_newmetatable(L, NMAP_NSOCK_PCAP_SOCKET);
  lua_pushcfunction(L, pcap_gc);
  lua_setfield(L, -2, "__gc");
  lua_pop(L, 1);

#if HAVE_OPENSSL
  /* Set up the SSL certificate userdata code in nse_ssl_cert.cc. */
  nse_nsock_init_ssl_cert(L);
#endif

  nsock_pool nsp = new_pool(L);
  if (o.scriptTrace())
    nsp_settrace(nsp, NULL, NSOCK_TRACE_LEVEL, o.getStartTime());
#if HAVE_OPENSSL
  /* Value speed over security in SSL connections. */
  nsp_ssl_init_max_speed(nsp);
#endif

  return 0;
}
