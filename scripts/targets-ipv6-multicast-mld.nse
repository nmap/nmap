local ipOps = require "ipOps"
local coroutine = require "coroutine"
local nmap = require "nmap"
local stdnse = require "stdnse"
local tab = require "tab"
local table = require "table"
local target = require "target"
local multicast = require "multicast"

description = [[
Attempts to discover available IPv6 hosts on the LAN by sending an MLD
(multicast listener discovery) query to the link-local multicast address
(ff02::1) and listening for any responses.  The query's maximum response delay
set to 1 to provoke hosts to respond immediately rather than waiting for other
responses from their multicast group.
]]

---
-- @usage
-- nmap -6 --script=targets-ipv6-multicast-mld.nse --script-args 'newtargets,interface=eth0'
--
-- @output
-- Pre-scan script results:
-- | targets-ipv6-multicast-mld:
-- |   IP: fe80::5a55:abcd:ef01:2345  MAC: 58:55:ab:cd:ef:01  IFACE: en0
-- |   IP: fe80::9284:0123:4567:89ab  MAC: 90:84:01:23:45:67  IFACE: en0
-- |
-- |_  Use --script-args=newtargets to add the results as targets
--
-- @args targets-ipv6-multicast-mld.timeout timeout to wait for
--       responses (default: 10s)
-- @args targets-ipv6-multicast-mld.interface Interface to send on (default:
--       the interface specified with -e or every available Ethernet interface
--       with an IPv6 address.)
--
-- @xmloutput
-- <table>
--   <table>
--     <elem key="address">fe80::5a55:abcd:ef01:2345</elem>
--     <elem key="mac">58:55:ab:cd:ef:01</elem>
--     <elem key="iface">en0</elem>
--   </table>
--   <table>
--     <elem key="address">fe80::9284:0123:4567:89ab</elem>
--     <elem key="mac">90:84:01:23:45:67</elem>
--     <elem key="iface">en0</elem>
--   </table>
-- </table>

author = "niteesh, alegen"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery","broadcast"}


local arg_timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. '.timeout'))

prerule = function()
  if ( not(nmap.is_privileged()) ) then
    stdnse.verbose1("not running for lack of privileges.")
    return false
  end
  return true
end


local function get_interfaces()
  local interface_name = stdnse.get_script_args(SCRIPT_NAME .. ".interface")
    or nmap.get_interface()

  -- interfaces list (decide which interfaces to broadcast on)
  local interfaces = {}
  for _, if_table in pairs(nmap.list_interfaces()) do
    if (interface_name == nil or if_table.device == interface_name) -- check for correct interface
      and ipOps.ip_in_range(if_table.address, "fe80::/10") -- link local address
      and if_table.link == "ethernet" then                 -- not the loopback interface
      table.insert(interfaces, if_table)
    end
  end

  return interfaces
end

local function single_interface_broadcast(if_nfo, results)
  stdnse.debug2("Starting " .. SCRIPT_NAME .. " on " .. if_nfo.device)
  local condvar = nmap.condvar(results)

  local reports = multicast.mld_query(if_nfo, arg_timeout or 10)
  for _, r in pairs(reports) do
    local l2reply = r[2]
    local l3reply = r[3]
    local target_str = l3reply.ip_src
    if not results[target_str] then
      if target.ALLOW_NEW_TARGETS then
        target.add(target_str)
      end
      results[target_str] = { address = target_str, mac = stdnse.format_mac(l2reply.mac_src), iface = if_nfo.device }
    end
  end

  condvar("signal")
end

local function format_output(results)
  local output = tab.new()
  local xmlout = {}
  local ips = stdnse.keys(results)
  table.sort(ips)

  for i, ip in ipairs(ips) do
    local record = results[ip]
    xmlout[i] = record
    tab.addrow(output, "  IP: " .. record.address, "MAC: " .. record.mac, "IFACE: " .. record.iface)
  end

  if ( #output > 0 ) then
    output = {"", tab.dump(output) }
    if not target.ALLOW_NEW_TARGETS then
      table.insert(output, "  Use --script-args=newtargets to add the results as targets")
    end
    return xmlout, table.concat(output, "\n")
  end
end

action = function()
  local threads = {}
  local results = {}
  local condvar = nmap.condvar(results)

  for _, if_nfo in ipairs(get_interfaces()) do
    -- create a thread for each interface
    local co = stdnse.new_thread(single_interface_broadcast, if_nfo, results)
    threads[co] = true
  end

  repeat
    for thread in pairs(threads) do
      if coroutine.status(thread) == "dead" then threads[thread] = nil end
    end
    if ( next(threads) ) then
      condvar "wait"
    end
  until next(threads) == nil

  return format_output(results)
end

