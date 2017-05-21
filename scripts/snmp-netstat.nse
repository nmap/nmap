local nmap = require "nmap"
local shortport = require "shortport"
local snmp = require "snmp"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local target = require "target"

description = [[
Attempts to query SNMP for a netstat like output. The script can be used to
identify and automatically add new targets to the scan by supplying the
newtargets script argument.
]]

---
-- @usage
-- nmap -sU -p 161 --script=snmp-netstat <target>
-- @output
-- | snmp-netstat:
-- |   TCP  0.0.0.0:21           0.0.0.0:2256
-- |   TCP  0.0.0.0:80           0.0.0.0:8218
-- |   TCP  0.0.0.0:135          0.0.0.0:53285
-- |   TCP  0.0.0.0:389          0.0.0.0:38990
-- |   TCP  0.0.0.0:445          0.0.0.0:49158
-- |   TCP  127.0.0.1:389        127.0.0.1:1045
-- |   TCP  127.0.0.1:389        127.0.0.1:1048
-- |   UDP  192.168.56.3:137     *:*
-- |   UDP  192.168.56.3:138     *:*
-- |   UDP  192.168.56.3:389     *:*
-- |_  UDP  192.168.56.3:464     *:*

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}
dependencies = {"snmp-brute"}

-- Version 0.3
-- Created 01/19/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 04/11/2010 - v0.2 - moved snmp_walk to snmp library <patrik@cqure.net>
-- Revised 07/26/2012 - v0.3 - added newtargets support


portrule = shortport.portnumber(161, "udp", {"open", "open|filtered"})

--- Processes the table and creates the script output
--
-- @param tbl table containing <code>oid</code> and <code>value</code>
-- @param base_oid string containing the value of the base_oid of the walk
-- @return table
local function process_answer( tbl, base_oid )
  local result = {}
  for _, v in ipairs( tbl ) do
    local lip = v.oid:match( "^" .. base_oid .. "%.(%d+%.%d+%.%d+%.%d+)") or ""
    local lport = v.oid:match( "^" .. base_oid .. "%.%d+%.%d+%.%d+%.%d+%.(%d+)")
    local fip = v.oid:match( "^" .. base_oid .. "%.%d+%.%d+%.%d+%.%d+%.%d+%.(%d+%.%d+%.%d+%.%d+)") or "*:*"
    local fport = v.oid:match( "^" .. base_oid .. "%.%d+%.%d+%.%d+%.%d+%.%d+%.%d+%.%d+%.%d+%.%d+%.(%d+)")
    local left = (lport and (lip .. ":" .. lport) or lip)
    local right= (fport and (fip .. ":" .. fport) or fip)
    if ( right or left ) then
      table.insert(result, { left = left, right = right })
    end
  end
  return result
end

local function format_output(tbl, prefix)
  local result = {}
  for _, v in ipairs(tbl) do
    local value = string.format("%-20s %s", v.left, v.right )
    table.insert( result, string.format( "%-4s %s", prefix, value ) )
  end
  return result
end

local function table_merge( t1, t2 )
  for _, v in ipairs(t2) do
    table.insert(t1, v)
  end
  return t1
end

local function add_targets(tbl)
  if ( not(target.ALLOW_NEW_TARGETS) ) then
    return
  end

  -- get a list of local IPs
  local local_ips = {}
  for _, v in ipairs(tbl) do
    local ip = ((v.left and v.left:match("^(.-):")) and v.left:match("^(.-):") or v.left)
    local_ips[ip] = true
  end

  -- identify remote IPs
  local remote_ips = {}
  for _, v in ipairs(tbl) do
    local ip = ((v.right and v.right:match("^(.-):")) and v.right:match("^(.-):") or v.right)
    if ( not(remote_ips[ip]) and not(local_ips[ip]) and ip ~= "*" ) then
      target.add(ip)
    end
  end
end

action = function(host, port)

  local tcp_oid = "1.3.6.1.2.1.6.13.1.1"
  local udp_oid = "1.3.6.1.2.1.7.5.1.1"
  local netstat = {}
  local status, tcp, udp

  local snmpHelper = snmp.Helper:new(host, port)
  snmpHelper:connect()

  status, tcp = snmpHelper:walk( tcp_oid )
  if ( not(status) ) then return end

  status, udp = snmpHelper:walk( udp_oid )
  if ( not(status) ) then return end

  if ( tcp == nil ) or ( #tcp == 0 ) or ( udp==nil ) or ( #udp == 0 ) then
    return
  end

  tcp = process_answer(tcp, tcp_oid)
  add_targets(tcp)
  tcp = format_output(tcp, "TCP")

  udp = process_answer(udp, udp_oid)
  add_targets(udp)
  udp = format_output(udp, "UDP")

  netstat = table_merge( tcp, udp )

  nmap.set_port_state(host, port, "open")

  return stdnse.format_output( true, netstat )
end

