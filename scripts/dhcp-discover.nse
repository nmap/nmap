local dhcp = require "dhcp"
local rand = require "rand"
local nmap = require "nmap"
local outlib = require "outlib"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local ipOps = require "ipOps"

description = [[
Sends a DHCPINFORM request to a host on UDP port 67 to obtain all the local configuration parameters
without allocating a new address.

DHCPINFORM is a DHCP request that returns useful information from a DHCP server, without allocating an IP
address. The request sends a list of which fields it wants to know (a handful by default, every field if
verbosity is turned on), and the server responds with the fields that were requested. It should be noted
that the server doesn't have to return every field, nor does it have to return them in the same order,
or honour the request at all. A Linksys WRT54g, for example, completely ignores the list of requested
fields and returns a few standard ones. This script displays every field it receives.

With script arguments, the type of DHCP request can be changed, which can lead to interesting results.
Additionally, the MAC address can be randomized, which in should override the cache on the DHCP server and
assign a new IP address. Extra requests can also be sent to exhaust the IP address range more quickly.

Some of the more useful fields:
* DHCP Server (the address of the server that responded)
* Subnet Mask
* Router
* DNS Servers
* Hostname
]]

---
-- @see broadcast-dhcp6-discover.nse
-- @see broadcast-dhcp-discover.nse
--
-- @args dhcp-discover.dhcptype  The type of DHCP request to make. By default,
--         DHCPINFORM is sent, but this argument can change it to DHCPOFFER,
--         DHCPREQUEST, DHCPDECLINE, DHCPACK, DHCPNAK, DHCPRELEASE or
--         DHCPINFORM. Not all types will evoke a response from all servers,
--         and many require different fields to contain specific values.
-- @args dhcp-discover.mac  Set to <code>native</code> (default) or
--         <code>random</code> or a specific client MAC address in the DHCP
--         request. Keep in mind that you may not see the response if
--         a non-native address is used. Setting it to <code>random</code> will
--         possibly cause the DHCP server to reserve a new IP address each time.
-- @args dhcp-discover.requests Set to an integer to make up to that many
--         requests (and display the results).
--
-- @usage
-- nmap -sU -p 67 --script=dhcp-discover <target>
-- @output
-- Interesting ports on 192.168.1.1:
-- PORT   STATE SERVICE
-- 67/udp open  dhcps
-- | dhcp-discover:
-- |   DHCP Message Type: DHCPACK
-- |   Server Identifier: 192.168.1.1
-- |   IP Address Lease Time: 1 day, 0:00:00
-- |   Subnet Mask: 255.255.255.0
-- |   Router: 192.168.1.1
-- |_  Domain Name Server: 208.81.7.10, 208.81.7.14
--
-- @xmloutput
-- <elem key="DHCP Message Type">DHCPACK</elem>
-- <elem key="Server Identifier">192.168.1.1</elem>
-- <elem key="IP Address Lease Time">1 day, 0:00:00</elem>
-- <elem key="Subnet Mask">255.255.255.0</elem>
-- <elem key="Router">192.168.1.1</elem>
-- <table key="Domain Name Server">
--   <elem>208.81.7.10</elem>
--   <elem>208.81.7.14</elem>
-- </table>
--

--
-- 2020-01-14 - Revised by nnposter
--   o Added script argument  "mac" to prescribe a specific MAC address
--   o Deprecated argument "randomize_mac" in favor of "mac=random"
--
-- 2011-12-28 - Revised by Patrik Karlsson <patrik@cqure.net>
--   o Removed DoS code and placed script into discovery and safe categories
--
-- 2011-12-27 - Revised by Patrik Karlsson <patrik@cqure.net>
--   o Changed script to use DHCPINFORM instead of DHCPDISCOVER
--


author = "Ron Bowes"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}


-- We want to run against a specific host if UDP/67 is open
function portrule(host, port)
  if nmap.address_family() ~= 'inet' then
    stdnse.debug1("is IPv4 compatible only.")
    return false
  end

  return shortport.portnumber(67, "udp")(host, port)
end

action = function(host, port)
  local dhcptype = (stdnse.get_script_args(SCRIPT_NAME .. ".dhcptype") or "DHCPINFORM"):upper()
  local dhcptypeid = dhcp.request_types[dhcptype]
  if not dhcptypeid then
    return stdnse.format_output(false, "Invalid request type (use "
                                       .. table.concat(dhcp.request_types_str, " / ")
                                       .. ")")
  end

  local reqcount = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".requests") or 1)
  if not reqcount then
    return stdnse.format_output(false, "Invalid request count")
  end

  local iface, err = nmap.get_interface_info(host.interface)
  if not (iface and iface.address) then
    return stdnse.format_output(false, "Couldn't determine local IP for interface: " .. host.interface)
  end

  local overrides = {}

  local macaddr = (stdnse.get_script_args(SCRIPT_NAME .. ".mac") or "native"):lower()
  -- Support for legacy argument "randomize_mac"
  local randomize = (stdnse.get_script_args(SCRIPT_NAME .. ".randomize_mac") or "false"):lower()
  if randomize == "true" or randomize == "1" then
    stdnse.debug1("Use %s.mac=random instead of %s.randomize_mac=%s", SCRIPT_NAME, SCRIPT_NAME, randomize)
    macaddr = "random"
  end
  if macaddr ~= "native" then
    -- Set the scanner as a relay agent
    overrides.giaddr = string.unpack("<I4", ipOps.ip_to_str(iface.address))
  end
  local macaddr_iter
  if macaddr:find("^ra?nd") then
    macaddr_iter = function () return rand.random_string(6) end
  else
    if macaddr == "native" then
      macaddr = host.mac_addr_src
    else
      macaddr = macaddr:gsub(":", "")
      if not (#macaddr == 12 and macaddr:find("^%x+$")) then
        return stdnse.format_output(false, "Invalid MAC address")
      end
      macaddr = stdnse.fromhex(macaddr)
    end
    macaddr_iter = function () return macaddr end
  end

  local results = {}
  for i = 1, reqcount do
    local macaddr = macaddr_iter()
    stdnse.debug1("Client MAC address: %s", stdnse.tohex(macaddr, {separator = ":"}))
    local status, result = dhcp.make_request(host.ip, dhcptypeid, iface.address, macaddr, nil, nil, overrides)
    if not status then
      return stdnse.format_output(false, "Couldn't send DHCP request: " .. result)
    end
    table.insert(results, result)
  end

  if #results == 0 then
    return nil
  end

  nmap.set_port_state(host, port, "open")

  local response = stdnse.output_table()

  -- Display the results
  for i, result in ipairs(results) do
    local result_table = stdnse.output_table()

    if dhcptype ~= "DHCPINFORM" then
      result_table["IP Offered"] = result.yiaddr_str
    end
    for _, v in ipairs(result.options) do
      if type(v.value) == 'table' then
        outlib.list_sep(v.value)
      end
      result_table[ v.name ] = v.value
    end

    if(#results == 1) then
      response = result_table
    else
      response[string.format("Response %d of %d", i, #results)] = result_table
    end
  end

  return response
end
