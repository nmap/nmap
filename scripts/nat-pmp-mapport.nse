local natpmp = require "natpmp"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Maps a WAN port on the router to a local port on the client using the NAT Port Mapping Protocol (NAT-PMP).  It supports the following operations:
* map - maps a new external port on the router to an internal port of the requesting IP
* unmap - unmaps a previously mapped port for the requesting IP
* unmapall - unmaps all previously mapped ports for the requesting IP
]]

---
-- @usage
-- nmap -sU -p 5351 <ip> --script nat-pmp-mapport --script-args='op=map,pubport=8080,privport=8080,protocol=tcp'
-- nmap -sU -p 5351 <ip> --script nat-pmp-mapport --script-args='op=unmap,pubport=8080,privport=8080,protocol=tcp'
-- nmap -sU -p 5351 <ip> --script nat-pmp-mapport --script-args='op=unmapall,protocol=tcp'
--
-- @output
-- PORT     STATE SERVICE
-- 5351/udp open  nat-pmp
-- | nat-pmp-mapport:
-- |_  Successfully mapped tcp 1.2.3.4:8080 -> 192.168.0.100:80
--
-- @args nat-pmp-mapport.op operation, can be either map, unmap or unmap all
--       o map allows you to map an external port to an internal port of the calling IP
--       o unmap removes the external port mapping for the specified ports and protocol
--       o unmapall removes all mappings for the specified protocol and calling IP
--
-- @args nat-pmp-mapport.pubport the external port to map on the router. The
--       specified port is treated as the requested port. If the port is available
--       it will be allocated to the caller, otherwise the router will simply
--       choose another port, create the mapping and return the resulting port.
--
-- @args nat-pmp-mapport.privport the internal port of the calling IP to map requests
--       to. This port will receive all requests coming in to the external port on the
--       router.
--
-- @args nat-pmp-mapport.protocol the protocol to map, can be either tcp or udp.
--
-- @args nat-pmp-mapport.lifetime the lifetime of the mapping in seconds (default: 3600)
--
-- @see nat-pmp-info.nse

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


portrule = shortport.port_or_service(5351, "nat-pmp", {"udp"} )

local arg_pubport = stdnse.get_script_args(SCRIPT_NAME .. ".pubport")
local arg_privport= stdnse.get_script_args(SCRIPT_NAME .. ".privport")
local arg_protocol= stdnse.get_script_args(SCRIPT_NAME .. ".protocol")
local arg_lifetime= stdnse.get_script_args(SCRIPT_NAME .. ".lifetime") or 3600
local arg_op      = stdnse.get_script_args(SCRIPT_NAME .. ".op") or "map"

local function fail(str) return stdnse.format_output(false, str) end

action = function(host, port)

  local op = arg_op:lower()

  if ( "map" ~= op and "unmap" ~= op and "unmapall" ~= op ) then
    return fail("Operation must be either \"map\", \"unmap\" or \"unmapall\"")
  end

  if ( ("map" == op or "unmap" == op ) and
    ( not(arg_pubport) or not(arg_privport) or not(arg_protocol) ) ) then
    return fail("The arguments pubport, privport and protocol are required")
  elseif ( "unmapall" == op and not(arg_protocol) ) then
    return fail("The argument protocol is required")
  end

  local helper = natpmp.Helper:new(host, port)

  if ( "unmap" == op or "unmapall" == op ) then
    arg_lifetime = 0
  end
  if ( "unmapall" == op ) then
    arg_pubport, arg_privport = 0, 0
  end

  local status, response = helper:getWANIP()
  if ( not(status) ) then
    return fail("Failed to retrieve WAN IP")
  end

  local wan_ip = response.ip
  local lan_ip = (nmap.get_interface_info(host.interface)).address

  local status, response = helper:mapPort(arg_pubport, arg_privport, arg_protocol, arg_lifetime)

  if ( not(status) ) then
    return fail(response)
  end

  local output
  if ( "unmap" == op ) then
    output = ("Successfully unmapped %s %s:%d -> %s:%d"):format(
      arg_protocol, wan_ip, response.pubport, lan_ip, response.privport )
  elseif ( "unmapall" == op ) then
    output = ("Sucessfully unmapped all %s NAT mappings for %s"):format(arg_protocol, lan_ip)
  else
    output = ("Successfully mapped %s %s:%d -> %s:%d"):format(
      arg_protocol, wan_ip, response.pubport, lan_ip, response.privport )

    if ( tonumber(arg_pubport) ~= tonumber(response.pubport) ) then
      output = { output }
      table.insert(output, "WARNING: Requested public port could not be allocated")
    end
  end

  return stdnse.format_output(true, output)

end
