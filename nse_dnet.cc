#include "nsock.h"
#include "nmap_error.h"
#include "NmapOps.h"
#include "tcpip.h"
#include "libnetutil/netutil.h"

#include "nse_main.h"
#include "nse_utility.h"

#include "struct_ip.h"

#include "nse_lua.h"

#include <assert.h>

extern NmapOps o;

enum {
  DNET_METATABLE = lua_upvalueindex(1),
  DNET_ETHERNET_METATABLE = lua_upvalueindex(2),
  CACHE_DNET_ETHERNET = lua_upvalueindex(3), /* Map of dnet userdata to ethernet device userdata */
  CACHE_DEVICE_ETHERNET = lua_upvalueindex(4), /* Map of ethernet device string identifier to ethernet device userdata */
};

typedef struct nse_dnet_udata
{
  netutil_eth_t *eth;
  int sock; /* raw ip socket */
  char devname[32]; /* libnetutil uses this len; dnet generally uses 16 */
} nse_dnet_udata;

static int l_dnet_new (lua_State *L)
{
  nse_dnet_udata *udata;

  udata = (nse_dnet_udata *) lua_newuserdatauv(L, sizeof(nse_dnet_udata), 0);
  lua_pushvalue(L, DNET_METATABLE);
  lua_setmetatable(L, -2);
  udata->eth = NULL;
  udata->sock = -1;
  udata->devname[0] = '\0';

  return 1;
}

static struct interface_info *checkdevname (lua_State *L, int idx)
{
  size_t len = 0;
  const char *interface_name = luaL_checklstring(L, idx, &len);
  if (len >= 32) {
    luaL_argerror(L, idx, "device name too long");
    return NULL;
  }
  struct interface_info *ii = getInterfaceByName(interface_name, o.af());
  if (ii == NULL)
    luaL_argerror(L, idx, "device %s not found or no address configured");

  return ii;
}

static int l_dnet_get_interface_info (lua_State *L)
{
  char ipstr[INET6_ADDRSTRLEN];
  struct addr src, bcast;
  struct interface_info *ii = checkdevname(L, 1);

  if (ii == NULL)
    return nseU_safeerror(L, "failed to find interface");

  memset(ipstr, 0, INET6_ADDRSTRLEN);
  memset(&src, 0, sizeof(src));
  memset(&bcast, 0, sizeof(bcast));
  lua_newtable(L);

  nseU_setsfield(L, -1, "device", ii->devfullname);
  nseU_setsfield(L, -1, "shortname", ii->devname);
  nseU_setifield(L, -1, "netmask", ii->netmask_bits);

  if (ii->addr.ss_family == AF_INET)
    inet_ntop(AF_INET, &((struct sockaddr_in *)&ii->addr)->sin_addr,
              ipstr, INET6_ADDRSTRLEN);
  else if (ii->addr.ss_family == AF_INET6)
    inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&ii->addr)->sin6_addr,
              ipstr, INET6_ADDRSTRLEN);
  else
    luaL_error(L, "unknown protocol");

  nseU_setsfield(L, -1, "address", ipstr);

  switch (ii->device_type) {
    case devt_ethernet:
      nseU_setsfield(L, -1, "link", "ethernet");
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

  nseU_setsfield(L, -1, "up", (ii->device_up ? "up" : "down"));
  nseU_setifield(L, -1, "mtu", ii->mtu);

  return 1;
}

static int close_eth (lua_State *L)
{
  netutil_eth_t **eth = (netutil_eth_t **) nseU_checkudata(L, 1, DNET_ETHERNET_METATABLE, "ethernet");
  assert(*eth != NULL);
  netutil_eth_close(*eth);
  *eth = NULL;
  return nseU_success(L);
}

static netutil_eth_t *open_eth_cached (lua_State *L, int dnet_index, const char *device)
{
  netutil_eth_t **eth;

  lua_getfield(L, CACHE_DEVICE_ETHERNET, device);
  if (!lua_isuserdata(L, -1))
  {
    lua_pop(L, 1);
    eth = (netutil_eth_t **) lua_newuserdatauv(L, sizeof(netutil_eth_t *), 0);
    *eth = netutil_eth_open(device);
    if (*eth == NULL)
      luaL_error(L, "unable to open dnet on ethernet interface %s", device);
    lua_pushvalue(L, DNET_ETHERNET_METATABLE);
    lua_setmetatable(L, -2);
    lua_pushvalue(L, -1);
    lua_setfield(L, CACHE_DEVICE_ETHERNET, device);
  }
  eth = (netutil_eth_t **) lua_touserdata(L, -1);

  lua_pushvalue(L, dnet_index);
  lua_pushvalue(L, -2); /* netutil_eth_t userdata */
  lua_rawset(L, CACHE_DNET_ETHERNET);

  lua_pop(L, 1); /* netutil_eth_t userdata */

  return *eth;
}

static int ethernet_open (lua_State *L)
{
  nse_dnet_udata *udata = (nse_dnet_udata *) nseU_checkudata(L, 1, DNET_METATABLE, "dnet");
  const char *devname = luaL_checkstring(L, 2);

  udata->eth = open_eth_cached(L, 1, devname);
  strncpy(udata->devname, devname, 16);
  udata->devname[16] = '\0';
  if (o.scriptTrace())
  {
      log_write(LOG_STDOUT, "%s: Ethernet open %s\n",
          SCRIPT_ENGINE, udata->devname);
  }

  return nseU_success(L);
}

static void ethernet_close_main (lua_State *L, int dnet_index)
{
  nse_dnet_udata *udata = (nse_dnet_udata *) lua_touserdata(L, dnet_index);

  if (o.scriptTrace())
  {
      log_write(LOG_STDOUT, "%s: Ethernet close %s\n",
          SCRIPT_ENGINE, udata->devname);
  }
  udata->devname[0] = '\0';
  udata->eth = NULL;

  lua_pushvalue(L, dnet_index);
  lua_pushnil(L);
  lua_rawset(L, CACHE_DNET_ETHERNET);
}

static int ethernet_close (lua_State *L)
{
  nseU_checkudata(L, 1, DNET_METATABLE, "dnet");
  ethernet_close_main(L, 1);
  return nseU_success(L);
}

static int ethernet_send (lua_State *L)
{
  nse_dnet_udata *udata = (nse_dnet_udata *) nseU_checkudata(L, 1, DNET_METATABLE, "dnet");
  if (udata->eth == NULL)
    return luaL_error(L, "dnet ethernet interface is not open");
  size_t len = 0;
  const char *frame = luaL_checklstring(L, 2, &len);
  if (o.scriptTrace())
  {
      log_write(LOG_STDOUT, "%s: Ethernet frame (%lu bytes) > %s\n",
          SCRIPT_ENGINE, len, udata->devname);
  }
  size_t sent = netutil_eth_send(udata->eth, frame, len);
  if (sent == len)
    return nseU_success(L);
  else
    return nseU_safeerror(L, "netutil_eth_send error: %lu", sent);
}

static int ip_open (lua_State *L)
{
  nse_dnet_udata *udata = (nse_dnet_udata *) nseU_checkudata(L, 1, DNET_METATABLE, "dnet");
  udata->sock = netutil_raw_socket(NULL);
  if (udata->sock == -1) {
    if (o.scriptTrace())
    {
      log_write(LOG_STDOUT, "%s: failed to open raw socket: %s (errno %d)", SCRIPT_ENGINE,
          socket_strerror(socket_errno()), socket_errno());
    }
    // If possible, we'll try to use Ethernet headers to send packets, but not
    // if the user specified --send-ip
    if (o.sendpref == PACKET_SEND_IP_STRONG) {
      return luaL_error(L, "Unable to open raw IP socket.");
    }
  }
  if (o.scriptTrace())
  {
      log_write(LOG_STDOUT, "%s: raw IP socket open\n", SCRIPT_ENGINE);
  }
  return nseU_success(L);
}

static void ip_close_main (lua_State *L, int dnet_index)
{
  nse_dnet_udata *udata = (nse_dnet_udata *) lua_touserdata(L, dnet_index);
  if (udata->sock >= 0) {
    close(udata->sock);
    udata->sock = -1;
    if (o.scriptTrace())
    {
      log_write(LOG_STDOUT, "%s: raw IP socket close\n", SCRIPT_ENGINE);
    }
  }
}

static int ip_close (lua_State *L)
{
  nse_dnet_udata *udata = (nse_dnet_udata *) nseU_checkudata(L, 1, DNET_METATABLE, "dnet");
  if (udata->eth) {
    ethernet_close_main(L, 1);
  }
  ip_close_main(L, 1);
  return nseU_success(L);
}

static int ip_send (lua_State *L)
{
  struct abstract_ip_hdr hdr;
  struct sockaddr_storage dst;
  nse_dnet_udata *udata = (nse_dnet_udata *) nseU_checkudata(L, 1, DNET_METATABLE, "dnet");
  const char *packet;
  const char *addr, *targetname;
  size_t packetlen;
  unsigned int payloadlen;
  int ret;

  // If possible, we'll try to use Ethernet headers to send packets, but not
  // if the user specified --send-ip
  if (udata->sock == -1 && o.sendpref == PACKET_SEND_IP_STRONG)
    return luaL_error(L, "raw socket not open to send");

  packet = luaL_checklstring(L, 2, &packetlen);
  nseU_opttarget(L, 3, &addr, &targetname);

  payloadlen = packetlen;
  if (ip_get_data_any(packet, &payloadlen, &hdr) == NULL)
    return luaL_error(L, "can't parse ip packet");

  if (addr == NULL) {
    /* Extract dst from packet contents. This is deprecated because it doesn't
       work for link-local IPv6 addresses; there's no way to recover the
       scope_id from the packet contents. */
    dst = hdr.dst;
  } else {
    /* Resolve hostname or numeric IP. */
    size_t dstlen;
    int rc = resolve(addr, 0, &dst, &dstlen, AF_UNSPEC);
    if (rc != 0)
      return nseU_safeerror(L, gai_strerror(rc));
  }

  if (udata->sock >= 0) {
    ret = send_ip_packet(udata->sock, NULL, &dst, (u8 *) packet, packetlen);
  }
  else {
    // Already checked for PACKET_SEND_IP_STRONG above, so okay to try eth instead.
    struct sockaddr_storage *nexthop;
    struct route_nfo route;
    u8 dstmac[6];
    eth_nfo eth = {0};

    if (!nmap_route_dst(&dst, &route))
      return nseU_safeerror(L, "Can't find route to %s", addr);

    /* above we fallback to using the raw socket if we can't find an (ethernet)
     * route to the host.  From here on out it's ethernet all the way.
     */

    if (route.direct_connect)
      nexthop = &dst;
    else
      nexthop = &route.nexthop;

    /* Use cached ethernet device, and use udata's eth and interface to keep
     * track of if we're reusing the same device from the previous packet, and
     * close the cached device if not.
     */
    if (0 != strncmp(udata->devname, route.ii.devfullname, 16)) {
      if (udata->eth) {
        /* close any current ethernet associated with this userdata */
        ethernet_close_main(L, 1);
      }

      udata->eth = open_eth_cached(L, 1, route.ii.devname);
      strncpy(udata->devname, route.ii.devname, 16);
      udata->devname[16] = '\0';
    }
    eth.ethsd = udata->eth;

    if (DLT_EN10MB == netutil_eth_datalink(udata->eth)
#ifdef WIN32
        // Some Npcap installs will report DLT_EN10MB for the loopback adapter, but
        // it ignores the Ethernet header, and getNextHopMAC will crash.
        && route.ii.device_type != devt_loopback
#endif
       ) {
      if (!getNextHopMAC(route.ii.devfullname, route.ii.mac, &hdr.src, nexthop, dstmac))
        return luaL_error(L, "failed to determine next hop MAC address");
      memcpy(eth.srcmac, route.ii.mac, sizeof(eth.srcmac));
      memcpy(eth.dstmac, dstmac, sizeof(eth.dstmac));
    }

    ret = send_ip_packet(udata->sock, &eth, &dst, (u8 *) packet, packetlen);
  }
  if (ret == -1)
    return nseU_safeerror(L, "error while sending: %s (errno %d)",
        socket_strerror(socket_errno()), socket_errno());
  if (o.scriptTrace())
  {
      log_write(LOG_STDOUT, "%s: RAW SEND %s\n",
          SCRIPT_ENGINE, ippackethdrinfo((const u8 *)packet, packetlen, LOW_DETAIL));
  }

  return nseU_success(L);
}

LUALIB_API int luaopen_dnet (lua_State *L)
{
  static const luaL_Reg l_dnet_metatable[] = {
    {"ethernet_open", ethernet_open},
    {"ethernet_close", ethernet_close},
    {"ethernet_send", ethernet_send},
    {"ip_open", ip_open},
    {"ip_close", ip_close},
    {"ip_send", ip_send},
    {NULL, NULL}
  };

  static const luaL_Reg l_dnet[] = {
    {"new", l_dnet_new},
    {"get_interface_info", l_dnet_get_interface_info},
    {NULL, NULL}
  };
  int i;
  int top = lua_gettop(L);

  /* Create the library upvalues:
    DNET_METATABLE = lua_upvalueindex(1),
    DNET_ETHERNET_METATABLE = lua_upvalueindex(2),
    CACHE_DNET_ETHERNET = lua_upvalueindex(3),
    CACHE_DEVICE_ETHERNET = lua_upvalueindex(4),
  */
  lua_newtable(L);
  lua_newtable(L);
  nseU_weaktable(L, 0, 0, "k"); /* dnet udata weak, eth device strong */
  nseU_weaktable(L, 0, 0, "v"); /* eth_device weak */

  luaL_newlibtable(L, l_dnet_metatable);
  for (i = top+1; i < top+1+4; i++) lua_pushvalue(L, i);
  luaL_setfuncs(L, l_dnet_metatable, 4);
  lua_setfield(L, top+1, "__index");
  lua_newtable(L);
  lua_setfield(L, top+1, "__metatable");
  for (i = top+1; i < top+1+4; i++) lua_pushvalue(L, i);
  lua_pushcclosure(L, ip_close, 4);
  lua_setfield(L, top+1, "__gc");

  lua_newtable(L);
  lua_setfield(L, top+2, "__metatable");
  for (i = top+1; i < top+1+4; i++) lua_pushvalue(L, i);
  lua_pushcclosure(L, close_eth, 4);
  lua_setfield(L, top+2, "__gc");

  luaL_newlibtable(L, l_dnet); /* external interface */
  for (i = top+1; i < top+1+4; i++) lua_pushvalue(L, i);
  luaL_setfuncs(L, l_dnet, 4);

  return 1;
}
