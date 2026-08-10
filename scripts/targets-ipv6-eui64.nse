local ipOps = require "ipOps"
local io = require "io"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local target = require "target"

description = [[
This script runs in the pre-scanning phase to convert 48-bit MAC addresses to
EUI-64 IPv6 addresses, which are often used for auto-configuration. Generated
addresses may be added to the scan queue.

The MAC addresses used as input are read from the file named by the
<code>targets-ipv6-eui64.input</code> script-arg. A good source of these
addresses would be an IPv4 host discovery Nmap scan.
]]

---
-- @usage
-- nmap -6 --script targets-ipv6-eui64 --script-args newtargets,targets-ipv6-eui64.input=macs.txt,targets-ipv6-subnet={2001:db8:c0ca::/64}
--
-- @output
-- Pre-scan script results:
-- | targets-ipv6-eui64:
-- |_  2001:db8:c0ca:0:1322:33ff:fe44:5566
--
-- @args targets-ipv6-eui64.input  The input file containing 1 MAC address per line
--
-- @args targets-ipv6-subnet  Table/single IPv6 address with prefix
--                                  (Ex. 2001:db8:c0ca::/48 or
--                                  { 2001:db8:c0ca::/48, 2001:db8:FEA::/48 })
--                            Default: fe80::/64
--
-- @xmloutput
-- <elem>2001:db8:c0ca:0:1322:33ff:fe44:5566</elem>


author = "Daniel Miller"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {
  "discovery",
}

local infile = stdnse.get_script_args(SCRIPT_NAME .. ".input")
local subnets = stdnse.get_script_args("targets-ipv6-subnet") or "fe80::/64"

prerule = function ()

  if nmap.address_family() ~= "inet6" then
    stdnse.verbose1("This script is IPv6 only.")
    return false
  end

  if infile == nil then
    stdnse.verbose1( "Missing script-arg %s.input", SCRIPT_NAME)
    return false
  end

  return true
end

action = function ()

  local file, err = io.open(infile, "r")
  if not file then
    stdnse.verbose1("Unable to open %s for reading: %s", infile, err)
    return nil
  end

  local eui64 = {}
  for mac in file:lines() do
    local raw, err = stdnse.fromhex(mac:gsub("[:-]", ""))
    if not raw or #raw ~= 6 then
      stdnse.debug1("Invalid MAC: %s", mac)
    else
      local bytes = {raw:byte(1,-1)}
      bytes[1] = bytes[1] ~ 0x2
      local eui = string.pack("BBBBBBBB",
        bytes[1], bytes[2], bytes[3],
        0xff, 0xfe,
        bytes[4], bytes[5], bytes[6]
        )
      eui64[#eui64+1] = eui
    end
  end

  if type(subnets) == "string" then
    subnets = { subnets }
  end

  local results = {}
  for _, subnet in ipairs(subnets) do
    local addr, maskbits = subnet:match("^%s*([:%x]+)/(%d+)%s*$")
    if not addr then
      stdnse.verbose1("Invalid IPv6 subnet: %s", subnet)
    else
      if tonumber(maskbits) > 64 then
        stdnse.verbose1("Subnet too small for EUI-64 addresses.")
      else
        local v6bin, err = ipOps.ip_to_str(addr, "inet6")
        if not v6bin then
          stdnse.verbose1("Error parsing %s as IPv6 address: %s", addr, err)
        else
          v6bin = v6bin:sub(1, 8)
          for _, eui in ipairs(eui64) do
            local ip6addr, err = ipOps.str_to_ip(v6bin .. eui, "inet6")
            if not ip6addr then
              stdnse.debug1("Failed to convert addr to IPv6")
            else
              results[#results+1] = ip6addr
              target.add(ip6addr)
            end
          end
        end
      end
    end
  end
  if next(results) then
    return results
  end
end
