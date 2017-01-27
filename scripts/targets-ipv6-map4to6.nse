local ipOps = require "ipOps"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local target = require "target"

description = [[
This script runs in the pre-scanning phase to map IPv4 addresses onto IPv6
networks and add them to the scan queue.

The technique is more general than what is technically termed "IPv4-mapped IPv6
addresses." The lower 4 bytes of the IPv6 network address are replaced with the
4 bytes of IPv4 address. When the IPv6 network is ::ffff:0:0/96, then the
script generates IPv4-mapped IPv6 addresses. When the network is ::/96, then it
generates IPv4-compatible IPv6 addresses.
]]

---
-- @usage
-- nmap -6 --script targets-ipv6-map4to6 --script-args newtargets,targets-ipv6-map4to6.IPv4Hosts={192.168.1.0/24},targets-ipv6-subnet={2001:db8:c0ca::/64}
--
-- @output
-- Pre-scan script results:
-- | targets-ipv6-map4to6:
-- |   node count: 256
-- |   addresses:
-- |_    2001:db8:c0ca:0:0:0:c0a8:100/120
--
-- @args targets-ipv6-map4to6.IPv4Hosts  This must have at least one IPv4
--                                   Host for the script be able to work
--                                   (Ex. 192.168.1.1 or
--                                   { 192.168.1.1, 192.168.2.2 } ) or Subnet
--                                   Addresses ( 192.168.1.0/24 or
--                                   { 192.168.1.0/24, 192.168.2.0/24 } )
--
-- @args targets-ipv6-subnet  Table/single IPv6 address with prefix
--                                  (Ex. 2001:db8:c0ca::/48 or
--                                  { 2001:db8:c0ca::/48, 2001:db8:FEA::/48 })
--
-- @xmloutput
-- <elem key="node count">256</elem>
-- <table key="addresses">
--   <elem>2001:db8:c0ca:0:0:0:c0a8:100/120</elem>
-- </table>

--
-- Version 1.4
-- Update  01/12/2014 - V 1.4 Update for inclusion in Nmap by Daniel Miller
-- Update  05/05/2014 - V 1.3 Eliminate the Host phase.
-- Update  05/05/2014 - V 1.2 Minor corrections and standardization.
-- Update  18/10/2013 - V 1.1 Added     SaveMemory option
-- Update  29/03/2013 - V 1.0 Functional script
-- Created 28/03/2013 - v0.1  Created by Raúl Fuentes <ra.fuentess.sam+nmap@gmail.com>
--

author = "Raúl Armando Fuentes Samaniego"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {
  "discovery",
}

local function split_prefix (net)
  local split = stdnse.strsplit("/", net)
  return split[1], tonumber(split[2])
end
---
-- This function will add all the list of IPv4 host to IPv6
--
-- The most normal is returning X:X:X:X::Y.Y.Y.Y/128
-- The conversion is going to be totally IPv6 syntax (we are going to
-- concatenate strings).
-- @param  IPv6_Network A IPv6 Address  ( X:X:X:X::/YY )
-- @param  IPv4SHosts   A IPv4 String can be: X.X.X.X or X.X.X.X/YY
-- @param  addr_table   A table to hold the generated addresses.
-- @return  Number   Total succesfuly nodes added to the scan.
-- @return  Error    A warning if something happened. (Nil otherwise)
local From_4_to_6 = function (IPv6_Network, IPv4SHosts, addr_table)

  --We check if the PRefix are OK, anything less than 96 is fine
  local v6_base, IPv6_Prefix = split_prefix(IPv6_Network)
  if IPv6_Prefix > 96 then
    return 0, string.format("The IPv6 subnet %s can't support a direct Mapping 4 to 6.", IPv6_Network)
  end

  local sBin6, sError = ipOps.ip_to_bin(v6_base)
  if sBin6 == nil then
    return 0, sError
  end

  -- two options: String or Table,  the bes thing to do:  make string Table
  local tTabla
  if type(IPv4SHosts) == "table" then
    tTabla = IPv4SHosts
  else
    tTabla = { IPv4SHosts }
  end

  stdnse.debug1("Total IPv4 objects to analyze: %d for IPv6 subnet %s",
    #tTabla, IPv6_Network)

  local iTotal = 0
  for _, Host in ipairs(tTabla) do


    stdnse.debug2("IPv4 Object: %s", Host)

    local v4base, prefix = split_prefix(Host)

    local sBin4
    sBin4, sError = ipOps.ip_to_bin(v4base)
    if sBin4 == nil then
      return 0, sError
    end

    local IPAux
    IPAux, sError = ipOps.bin_to_ip(sBin6:sub(1, 96) .. sBin4)
    if prefix then
      prefix = prefix + (128 - 32) -- adjust for different address lengths
      IPAux = string.format("%s/%d", IPAux, prefix)
    else
      prefix = 128
    end

    stdnse.debug2("IPv6 address: %s", IPAux)

    addr_table[#addr_table+1] = IPAux
    if target.ALLOW_NEW_TARGETS then
      local bool
      bool, sError = target.add(IPAux)
      if bool then
        iTotal = iTotal + 2^(128 - prefix)
      else
        stdnse.debug1("Error adding node %s: %s", IPAux, sError)
      end
    else
      iTotal = iTotal + 2^(128 - prefix)
    end

  end

  return iTotal
end

local IPv4Sub = stdnse.get_script_args(SCRIPT_NAME .. ".IPv4Hosts")
local IPv6User = stdnse.get_script_args("targets-ipv6-subnet")
---
-- We populated the host discovery list.
local Prescanning = function ()

  local errors = {}
  local tSalida = {
    Nodos = 0,
    addrs = {},
  }
  local Grantotal = 0

  stdnse.debug2("Beginning the work.")

  if type(IPv6User) == "string" then
    IPv6User = { IPv6User }
  end

  -- TODO: Gather IPv6 subnets from other sources.
  -- This was implemented in the original version of the script, but stripped
  -- for now until the other scripts are integrated.
  -- http://seclists.org/nmap-dev/2013/q4/285
  for _, IPv6_Subnet in ipairs(IPv6User) do
    stdnse.debug1("Processing %s", IPv6_Subnet)
    local IPv6Host, sError = From_4_to_6(IPv6_Subnet, IPv4Sub, tSalida.addrs)
    if sError ~= nil then
      stdnse.debug1( "ERROR: One IPv6 subnet wasn't translated")
      errors[#errors+1] = sError
    end
    if IPv6Host then
      -- We need to concatenate the new nodes
      Grantotal = Grantotal + IPv6Host
    end
  end

  tSalida.Nodos = Grantotal
  if #errors > 0 then
    tSalida.Error = table.concat(errors, "\n")
  end
  return true, tSalida
end

---
-- The script need to be working with IPv6
--
--(To bad can't do it with both at same time )
function prerule ()

  if not (nmap.address_family() == "inet6") then
    stdnse.verbose1("This script is IPv6 only.")
    return false
  end

  -- Because Nmap current limitation of working ONE single IP family we must
  -- be sure to have everything for work the Mapped IPv4 to IPv6
  if IPv4Sub == nil then
    stdnse.verbose1( "There are no IPv4 addresses to map!\z
    You must provide it using the %s.IPv4Hosts script-arg.", SCRIPT_NAME)
    return false
  end

  -- Now we need to have based IPv6 Prefix, the most important is the previous
  -- known but we have a last-option too .
  if IPv6User == nil then
    stdnse.verbose1("There are no IPv6 subnets to scan!\z
    You must provide it using the targets-ipv6-subnet script-arg.")
    return false
  end

  return true
end

function action ()
  --Vars for created the final report
  local tOutput = stdnse.output_table()
  local bExito = false
  local tSalida

  bExito, tSalida = Prescanning()

  -- Now we adapt the exit to tOutput and add the hosts to the target!
  tOutput.warning = tSalida.Error

  if bExito then
    --Final report of the Debug Lvl of Prescanning
    stdnse.debug1("Successful Mapped IPv4 to IPv6 added to the scan: %d",
      tSalida.Nodos)

    tOutput["node count"] = tSalida.Nodos
    tOutput["addresses"] = tSalida.addrs

    if tSalida.Error then
      stdnse.debug1("Warnings: %s", tSalida.Error)
    end
  else
    stdnse.debug1("Was unable to add nodes to the scan list due this error: %s",
      tSalida.Error)
  end

  return tOutput
end
