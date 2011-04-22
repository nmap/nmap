#include "nsock.h"
#include "nmap_error.h"
#include "NmapOps.h"
#include "utils.h"
#include "tcpip.h"
#include "protocols.h"
#include "libnetutil/netutil.h"

#include "nse_main.h"
#include "nse_utility.h"

extern "C" {
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
}

#include <assert.h>

extern NmapOps o;

/* Map of dnet userdata to ethernet device userdata */
#define ETH_CACHE_DNET_ETH  0
/* Map of ethernet device string identifier to ethernet device userdata */
#define ETH_CACHE_DEVICE_ETH 1

/* metatable entries in the registry */
#define DNET_METATABLE  "DNET_METATABLE"
#define DNET_ETH_METATABLE  "DNET_ETH_METATABLE"

typedef struct nse_dnet_udata
{
  eth_t *eth;
  int sock; /* raw ip socket */
} nse_dnet_udata;

LUALIB_API int l_dnet_new (lua_State *L)
{
  nse_dnet_udata *udata;

  udata = (nse_dnet_udata *) lua_newuserdata(L, sizeof(nse_dnet_udata));
  luaL_getmetatable(L, DNET_METATABLE);
  lua_setmetatable(L, -2);
  udata->eth = NULL;
  udata->sock = -1;

  return 1;
}

LUALIB_API int l_dnet_get_interface_info (lua_State *L)
{
  char ipstr[INET6_ADDRSTRLEN];
  struct addr src, bcast;
  struct interface_info *ii = getInterfaceByName(luaL_checkstring(L, 1));

  if (ii == NULL) {
    lua_pushnil(L);
    lua_pushstring(L, "failed to find interface");
    return 2;
  }

  memset(ipstr, 0, INET6_ADDRSTRLEN);
  memset(&src, 0, sizeof(src));
  memset(&bcast, 0, sizeof(bcast));
  lua_newtable(L);

  setsfield(L, -1, "device", ii->devfullname);
  setsfield(L, -1, "shortname", ii->devname);
  setnfield(L, -1, "netmask", ii->netmask_bits);

  if (ii->addr.ss_family == AF_INET)
    inet_ntop(AF_INET, &((struct sockaddr_in *)&ii->addr)->sin_addr,
              ipstr, INET6_ADDRSTRLEN);
  else if (ii->addr.ss_family == AF_INET6)
    inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&ii->addr)->sin6_addr,
              ipstr, INET6_ADDRSTRLEN);
  else
    luaL_error(L, "unknown protocol");

  setsfield(L, -1, "address", ipstr);

  switch (ii->device_type) {
    case devt_ethernet:
      setsfield(L, -1, "link", "ethernet");
      lua_pushlstring(L, (const char *) ii->mac, 6);
      lua_setfield(L, -2, "mac");

      /* calculate the broadcast address */
      if (ii->addr.ss_family == AF_INET) {
        src.addr_type = ADDR_TYPE_IP;
        src.addr_bits = ii->netmask_bits;
        src.addr_ip = ((struct sockaddr_in *)&ii->addr)->sin_addr.s_addr;
        addr_bcast(&src, &bcast);
        memset(ipstr, 0, INET6_ADDRSTRLEN);
        if (addr_ntop(&bcast, ipstr, INET6_ADDRSTRLEN) != NULL)
          setsfield(L, -1, "broadcast", ipstr);
      }
      break;
    case devt_loopback:
      setsfield(L, -1, "link", "loopback");
      break;
    case devt_p2p:
      setsfield(L, -1, "link", "p2p");
      break;
    case devt_other:
    default:
      setsfield(L, -1, "link", "other");
  }

  setsfield(L, -1, "up", (ii->device_up ? "up" : "down"));
  setnfield(L, -1, "mtu", ii->mtu);

  return 1;
}

static int close_eth (lua_State *L)
{
  eth_t **eth = (eth_t **) luaL_checkudata(L, 1, DNET_ETH_METATABLE);
  assert(*eth != NULL);
  eth_close(*eth);
  *eth = NULL;
  return success(L);
}

static eth_t *open_eth_cached (lua_State *L, int dnet_index, const char *device)
{
  eth_t **eth;

  lua_rawgeti(L, LUA_ENVIRONINDEX, ETH_CACHE_DNET_ETH);
  lua_rawgeti(L, LUA_ENVIRONINDEX, ETH_CACHE_DEVICE_ETH);
  lua_getfield(L, -1, device);
  if (!lua_isuserdata(L, -1))
  {
    eth = (eth_t **) lua_newuserdata(L, sizeof(eth_t *));
    *eth = eth_open(device);
    if (*eth == NULL)
      luaL_error(L, "unable to open dnet on ethernet interface %s", device);
    luaL_getmetatable(L, DNET_ETH_METATABLE);
    lua_setmetatable(L, -2);
    lua_pushvalue(L, -1);
    lua_setfield(L, -4, device);
    lua_replace(L, -2); /* replace nil */
  }
  eth = (eth_t **) lua_touserdata(L, -1);

  lua_pushvalue(L, dnet_index);
  lua_pushvalue(L, -2); /* eth_t userdata */
  lua_rawset(L, -5); /* add to ETH_CACHE_DNET_ETH */
  lua_pop(L, 3); /* ETH_CACHE_DNET_ETH, ETH_CACHE_DEVICE_ETH, eth_t userdata */

  return *eth;
}

static int ethernet_open (lua_State *L)
{
  nse_dnet_udata *udata = (nse_dnet_udata *) luaL_checkudata(L, 1, DNET_METATABLE);
  const char *interface_name = luaL_checkstring(L, 2);
  struct interface_info *ii = getInterfaceByName(interface_name);

  if (ii == NULL || ii->device_type != devt_ethernet)
    return luaL_argerror(L, 2, "device is not valid ethernet interface");

  udata->eth = open_eth_cached(L, 1, interface_name);

  return success(L);
}

static int ethernet_close (lua_State *L)
{
  nse_dnet_udata *udata = (nse_dnet_udata *) luaL_checkudata(L, 1, DNET_METATABLE);

  udata->eth = NULL;

  lua_rawgeti(L, LUA_ENVIRONINDEX, ETH_CACHE_DNET_ETH);
  lua_pushvalue(L, 1);
  lua_pushnil(L);
  lua_rawset(L, -3);

  return success(L);
}

static int ethernet_send (lua_State *L)
{
  nse_dnet_udata *udata = (nse_dnet_udata *) luaL_checkudata(L, 1, DNET_METATABLE);
  if (udata->eth == NULL)
    return luaL_error(L, "dnet ethernet interface is not open");
  eth_send(udata->eth, luaL_checkstring(L, 2), lua_objlen(L, 2));
  return success(L);
}

static int ip_open (lua_State *L)
{
  nse_dnet_udata *udata = (nse_dnet_udata *) luaL_checkudata(L, 1, DNET_METATABLE);
  udata->sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (udata->sock == -1)
    return luaL_error(L, "failed to open raw socket: %s (errno %d)",
        socket_strerror(socket_errno()), socket_errno());
  broadcast_socket(udata->sock);
#ifndef WIN32
  sethdrinclude(udata->sock);
#endif
  return success(L);
}

static int ip_close (lua_State *L)
{
  nse_dnet_udata *udata = (nse_dnet_udata *) luaL_checkudata(L, 1, DNET_METATABLE);
  if (udata->sock == -1)
    return safe_error(L, "raw socket already closed");
  close(udata->sock);
  udata->sock = -1;
  return success(L);
}

static int ip_send (lua_State *L)
{
  nse_dnet_udata *udata = (nse_dnet_udata *) luaL_checkudata(L, 1, DNET_METATABLE);
  const char *packet = luaL_checkstring(L, 2);
  char dev[16];
  int ret;

  if (udata->sock == -1)
    return luaL_error(L, "raw socket not open to send");

  if (lua_objlen(L, 2) < sizeof(struct ip))
    return luaL_error(L, "ip packet too short");

  *dev = '\0';

  if (o.sendpref & PACKET_SEND_ETH)
  {
    struct route_nfo route;
    struct sockaddr_storage srcss, dstss, *nexthop;
    struct sockaddr_in *srcsin = (struct sockaddr_in *) &srcss;
    struct sockaddr_in *dstsin = (struct sockaddr_in *) &dstss;
    struct ip *ip = (struct ip *) packet;
    u8 dstmac[6];
    eth_nfo eth;

    /* build sockaddr for target from user packet and determine route */
    memset(&dstss, 0, sizeof(dstss));
    dstsin->sin_family = AF_INET;
    dstsin->sin_addr.s_addr = ip->ip_dst.s_addr;

    if (!nmap_route_dst(&dstss, &route))
      goto usesock;

    Strncpy(dev, route.ii.devname, sizeof(dev));

    if (route.ii.device_type != devt_ethernet)
      goto usesock;

    /* above we fallback to using the raw socket if we can't find an (ethernet)
     * route to the host.  From here on out it's ethernet all the way.
     */

    /* build sockaddr for source from user packet to determine next hop mac */
    memset(&srcss, 0, sizeof(srcss));
    srcsin->sin_family = AF_INET;
    srcsin->sin_addr.s_addr = ip->ip_src.s_addr;

    if (route.direct_connect)
      nexthop = &dstss;
    else
      nexthop = &route.nexthop;

    if (!getNextHopMAC(route.ii.devfullname, route.ii.mac, &srcss, nexthop, dstmac))
      return luaL_error(L, "failed to determine next hop MAC address");

    /* Use cached ethernet device, and use udata's eth and interface to keep
     * track of if we're reusing the same device from the previous packet, and
     * close the cached device if not.
     */
    memset(&eth, 0, sizeof(eth));
    memcpy(eth.srcmac, route.ii.mac, sizeof(eth.srcmac));
    memcpy(eth.dstmac, dstmac, sizeof(eth.dstmac));

    /* close any current ethernet associated with this userdata */
    lua_pushcfunction(L, ethernet_close);
    lua_pushvalue(L, 1);
    lua_call(L, 1, 0);

    udata->eth = eth.ethsd = open_eth_cached(L, 1, route.ii.devname);

    ret = send_ip_packet(udata->sock, &eth, (u8 *) packet, lua_objlen(L, 2));
  } else {
usesock:
#ifdef WIN32
    if (strlen(dev) > 0)
      win32_warn_raw_sockets(dev);
#endif
    ret = send_ip_packet(udata->sock, NULL, (u8 *) packet, lua_objlen(L, 2));
  }
  if (ret == -1)
    return safe_error(L, "error while sending: %s (errno %d)",
        socket_strerror(socket_errno()), socket_errno());

  return success(L);
}

static int gc (lua_State *L)
{
  luaL_checkudata(L, 1, DNET_METATABLE);

  lua_pushcfunction(L, ip_close);
  lua_pushvalue(L, 1);
  lua_call(L, 1, 0);
  lua_pushcfunction(L, ethernet_close);
  lua_pushvalue(L, 1);
  lua_call(L, 1, 0);

  return 0;
}

LUALIB_API int luaopen_dnet (lua_State *L)
{
  static const luaL_reg l_dnet[] = {
    {"ethernet_open", ethernet_open},
    {"ethernet_close", ethernet_close},
    {"ethernet_send", ethernet_send},
    {"ip_open", ip_open},
    {"ip_close", ip_close},
    {"ip_send", ip_send},
    {NULL, NULL}
  };

  lua_createtable(L, 2, 0);
  lua_replace(L, LUA_ENVIRONINDEX);
  weak_table(L, 0, 0, "k"); /* dnet udata weak, eth device strong */
  lua_rawseti(L, LUA_ENVIRONINDEX, ETH_CACHE_DNET_ETH);
  weak_table(L, 0, 0, "v"); /* eth_device weak */
  lua_rawseti(L, LUA_ENVIRONINDEX, ETH_CACHE_DEVICE_ETH);

  luaL_newmetatable(L, DNET_METATABLE);
  lua_createtable(L, 0, 5);
  luaL_register(L, NULL, l_dnet);
  lua_setfield(L, -2, "__index");
  lua_newtable(L);
  lua_setfield(L, -2, "__metatable");
  lua_pushcfunction(L, gc);
  lua_setfield(L, -2, "__gc");

  luaL_newmetatable(L, DNET_ETH_METATABLE);
  lua_pushcfunction(L, close_eth);
  lua_setfield(L, -2, "__gc");

  return 0;
}
