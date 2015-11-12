local datafiles = require "datafiles"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Compares the detected service on a port against the expected service for that
port number (e.g. ssh on 22, http on 80) and reports deviations. The script
requires that a version scan has been run in order to be able to discover what
service is actually running on each port.
]]

---
-- @usage
-- nmap --script unusual-port <ip>
--
-- @output
-- 23/tcp open   ssh     OpenSSH 5.8p1 Debian 7ubuntu1 (protocol 2.0)
-- |_unusual-port: ssh unexpected on port tcp/23
-- 25/tcp open   smtp    Postfix smtpd
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "safe" }


local svc_table

portrule = function()
  local status
  status, svc_table = datafiles.parse_services()
  if not status then
    return false --Can't check if we don't have a table!
  end
  return true
end

hostrule = function() return true end

-- the hostrule is only needed to warn
hostaction = function(host)
  local port, state = nil, "open"
  local is_version_scan = false

  -- iterate over ports and check whether name_confidence > 3 this would
  -- suggest that a version scan has been run
  for _, proto in ipairs({"tcp", "udp"}) do
    repeat
      port = nmap.get_ports(host, port, proto, state)
      if ( port and port.version.name_confidence > 3 ) then
        is_version_scan = true
        break
      end
    until( not(port) )
  end

  -- if no version scan has been run, warn the user as the script requires a
  -- version scan in order to work.
  if ( not(is_version_scan) ) then
    return stdnse.format_output(true, "WARNING: this script depends on Nmap's service/version detection (-sV)")
  end

end

portchecks = {

  ['tcp'] = {
    [113] = function(host, port) return ( port.service == "ident" ) end,
    [445] = function(host, port) return ( port.service == "netbios-ssn" ) end,
    [587] = function(host, port) return ( port.service == "smtp" ) end,
    [593] = function(host, port) return ( port.service == "ncacn_http" ) end,
    [636] = function(host, port) return ( port.service == "ldapssl" ) end,
    [3268] = function(host, port) return ( port.service == "ldap" ) end,
  },

  ['udp'] = {
    [5353] = function(host, port) return ( port.service == "mdns" ) end,
  }

}

servicechecks = {
  ['http'] = function(host, port)
    local service = port.service
    port.service = "unknown"
    local status = shortport.http(host, port)
    port.service = service
    return status
  end,

  -- accept msrpc on any port for now, we might want to limit it to certain
  -- port ranges in the future.
  ['msrpc'] = function(host, port) return true end,

  -- accept ncacn_http on any port for now, we might want to limit it to
  -- certain port ranges in the future.
  ['ncacn_http'] = function(host, port) return true end,
}

portaction = function(host, port)
  local ok = false

  if ( port.version.name_confidence <= 3 ) then
    return
  end
  if ( portchecks[port.protocol][port.number] ) then
    ok = portchecks[port.protocol][port.number](host, port)
  end
  if ( not(ok) and servicechecks[port.service] ) then
    ok = servicechecks[port.service](host, port)
  end
  if ( not(ok) and port.service and
      ( port.service == svc_table[port.protocol][port.number] or
      "unknown" == svc_table[port.protocol][port.number] or
      not(svc_table[port.protocol][port.number]) ) ) then
    ok = true
  end
  if ( not(ok) ) then
    return ("%s unexpected on port %s/%d"):format(port.service, port.protocol, port.number)
  end
end

local Actions = {
  hostrule = hostaction,
  portrule = portaction
}

-- execute the action function corresponding to the current rule
action = function(...) return Actions[SCRIPT_TYPE](...) end
