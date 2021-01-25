---
-- Functions for building short portrules.
--
-- Since portrules are mostly the same for many scripts, this
-- module provides functions for the most common tests.
--
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

local nmap = require "nmap"
local stdnse = require "stdnse"
local tableaux = require "tableaux"
local comm
_ENV = stdnse.module("shortport", stdnse.seeall)

-- Just like tableaux.contains, but can match simple port ranges
local function port_includes(t, value)
  for _, elem in ipairs(t) do
    if elem == value then
      return true
    elseif type(elem) == "string" then
      local pstart, pend = elem:match("^(%d+)%-(%d+)$")
      if not pstart then
        pstart = elem:match("^(%d+)$")
        pend = pstart
      end
      pstart, pend = tonumber(pstart), tonumber(pend)
      assert(pstart,"Incorrect port range specification.")
      assert(pstart<=pend,"Incorrect port range specification, the starting port should have a smaller value than the ending port.")
      assert(pstart>-1 and pend<65536, "Port range number out of range (0-65535).")
      if value >= pstart and value <= pend then
        return true
      end
    end
  end
  return false
end

--- Check if the port and its protocol are in the exclude directive.
--
-- @param port A port number.
-- @param proto The protocol to match against, default <code>"tcp"</code>.
-- @return True if the <code>port</code> and <code>protocol</code> are
-- in the exclude directive.
port_is_excluded = function(port, proto)
  proto = proto or "tcp"
  return nmap.port_is_excluded(port, proto)
end

--- Return a portrule that returns true when given an open port matching a
-- single port number or a list of port numbers.
-- @param ports A single port number or a list of port numbers.
-- @param protos The protocol or list of protocols to match against, default
-- <code>"tcp"</code>.
-- @param states A state or list of states to match against, default
-- {<code>"open"</code>, <code>"open|filtered"</code>}.
-- @return Function for the portrule.
-- @usage portrule = shortport.portnumber({80, 443})
portnumber = function(ports, protos, states)
  protos = protos or "tcp"
  states = states or {"open", "open|filtered"}

  if type(ports) ~= "table" then
    ports = {ports}
  end
  if type(protos) ~= "table" then
    protos = {protos}
  end
  if type(states) ~= "table" then
    states = {states}
  end

  return function(host, port)
    return port_includes(ports, port.number)
      and tableaux.contains(protos, port.protocol, true)
      and tableaux.contains(states, port.state, true)
  end
end

--- Return a portrule that returns true when given an open port with a
-- service name matching a single service name or a list of service
-- names.
--
-- A service name is something like <code>"http"</code>, <code>"https"</code>,
-- <code>"smtp"</code>, or <code>"ftp"</code>. These service names are
-- determined by Nmap's version scan or (if no version scan information is
-- available) the service assigned to the port in <code>nmap-services</code>
-- (e.g. <code>"http"</code> for TCP port 80).
-- @param services Service name or a list of names to run against.
-- @param protos The protocol or list of protocols to match against, default
-- <code>"tcp"</code>.
-- @param states A state or list of states to match against, default
-- {<code>"open"</code>, <code>"open|filtered"</code>}.
-- @return Function for the portrule.
-- @usage portrule = shortport.service("ftp")
service = function(services, protos, states)
  protos = protos or "tcp"
  states = states or {"open", "open|filtered"}

  if type(services) ~= "table" then
    services = {services}
  end
  if type(protos) ~= "table" then
    protos = {protos}
  end
  if type(states) ~= "table" then
    states = {states}
  end

  return function(host, port)
    return tableaux.contains(services, port.service, true)
    and tableaux.contains(protos, port.protocol, true)
    and tableaux.contains(states, port.state, true)
  end
end

--- Return a portrule that returns true when given an open port matching
-- either a port number or service name.
--
-- This function is a combination of the <code>portnumber</code> and
-- <code>service</code> functions. The port and service may be single values or
-- a list of values as in those functions. This function exists because many
-- scripts explicitly try to run against the well-known ports, but want also to
-- run against any other port which was discovered to run the named service.
-- @usage portrule = shortport.port_or_service(22,"ssh").
-- @param ports A single port number or a list of port numbers.
-- @param services Service name or a list of names to run against.
-- @param protos The protocol or list of protocols to match against, default
-- <code>"tcp"</code>.
-- @param states A state or list of states to match against, default
-- {<code>"open"</code>, <code>"open|filtered"</code>}.
-- @return Function for the portrule.
port_or_service = function(ports, services, protos, states)
  return function(host, port)
    local port_checker = portnumber(ports, protos, states)
    local service_checker = service(services, protos, states)
    return port_checker(host, port) or service_checker(host, port)
  end
end

--- Return a portrule that returns true when given an open port matching
-- either a port number or service name and has not been listed in the
-- exclude port directive of the nmap-service-probes file. If version
-- intensity is lesser than rarity value, portrule always returns false.
--
-- This function is a combination of the <code>port_is_excluded</code>
-- and <code>port_or_service</code> functions. The port, service, proto may
-- be single values or a list of values as in those functions.
-- This function can be used by version category scripts to check if a
-- given port and its protocol are in the exclude directive and that version
-- intensity is greater than or equal to the rarity value of the script.
-- @usage portrule = shortport.version_port_or_service(22)
-- @usage portrule = shortport.version_port_or_service(nil, "ssh", "tcp")
-- @usage portrule = shortport.version_port_or_service(nil, nil, "tcp", nil, 8)
-- @param services Service name or a list of names to run against.
-- @param protos The protocol or list of protocols to match against, default
-- <code>"tcp"</code>.
-- @param states A state or list of states to match against, default
-- {<code>"open"</code>, <code>"open|filtered"</code>}.
-- @param rarity A minimum value of version script intensity, below
-- which the function always returns false, default 7.
-- @return Function for the portrule.
version_port_or_service = function(ports, services, protos, states, rarity)
  return function(host, port)
    local p_s_check = port_or_service(ports, services, protos, states)
    return p_s_check(host, port)
      and not(port_is_excluded(port.number, port.protocol))
      and (nmap.version_intensity() >= (rarity or 7))
  end
end

--[[
Apache Tomcat HTTP server default ports: 8180 and 8000
Litespeed webserver default ports: 8088 and 7080
--]]
LIKELY_HTTP_PORTS = {
  80, 443, 631, 7080, 8080, 8443, 8088, 5800, 3872, 8180, 8000
}

LIKELY_HTTP_SERVICES = {
  "http", "https", "ipp", "http-alt", "https-alt", "vnc-http", "oem-agent",
  "soap", "http-proxy", "caldav", "carddav", "webdav",
}

---
-- A portrule that matches likely HTTP services.
--
-- @name http
-- @class function
-- @param host The host table to match against.
-- @param port The port table to match against.
-- @return <code>true</code> if the port is likely to be HTTP,
-- <code>false</code> otherwise.
-- @usage
-- portrule = shortport.http

http = port_or_service(LIKELY_HTTP_PORTS, LIKELY_HTTP_SERVICES)

local LIKELY_SSL_PORTS = {
  261, -- nsiiops
  271, -- pt-tls
  324, -- rpki-rtr-tls
  443, -- https
  465, -- smtps
  563, -- snews/nntps
  585, -- imap4-ssl
  636, -- ldapssl
  853, -- domain-s
  989, -- ftps-data
  990, -- ftps-control
  992, -- telnets
  993, -- imaps
  994, -- ircs
  995, -- pop3s
  2221, -- ethernet-ip-s
  2252, -- njenet-ssl
  2376, -- docker-s
  3269, -- globalcatLDAPssl
  3389, -- ms-wbt-server
  4433, -- openssl s_server
  4911, -- ssl/niagara-fox
  5061, -- sip-tls
  5986, -- wsmans
  6679,
  6697,
  8443, -- https-alt
  9001, -- tor-orport
  8883, -- secure-mqtt
}
local LIKELY_SSL_SERVICES = {
  "ftps", "ftps-data", "ftps-control", "https", "https-alt", "imaps", "ircs",
  "ldapssl", "ms-wbt-server", "pop3s", "sip-tls", "smtps", "telnets", "tor-orport",
}

---
-- A portrule that matches likely SSL services.
--
-- @param host The host table to match against.
-- @param port The port table to match against.
-- @return <code>true</code> if the port is likely to be SSL,
-- <code>false</code> otherwise.
-- @usage
-- portrule = shortport.ssl
function ssl(host, port)
  if (port.version and port.version.service_tunnel == "ssl") or
    port_or_service(LIKELY_SSL_PORTS, LIKELY_SSL_SERVICES, {"tcp", "sctp"})(host, port) then
    return true
  end
  -- If we're just looking up port info, stop here.
  if not host then return false end
  -- if we didn't detect something *not* SSL, check it ourselves
  -- but don't check if it's an excluded port
  if port.version and port.version.name_confidence <= 3 and host.registry
    and not nmap.port_is_excluded(port.number, port.protocol) then
    comm = comm or require "comm"
    host.registry.ssl = host.registry.ssl or {}
    local mtx = nmap.mutex(host.registry.ssl)
    mtx "lock"
    local v = host.registry.ssl[port.number .. port.protocol]
    if v == nil then
      -- probes from nmap-service-probes
      for _, probe in ipairs({
          --TLSSessionReq
          "\x16\x03\0\0\x69\x01\0\0\x65\x03\x03U\x1c\xa7\xe4random1random2random3\z
          random4\0\0\x0c\0/\0\x0a\0\x13\x009\0\x04\0\xff\x01\0\0\x30\0\x0d\0,\0*\0\z
          \x01\0\x03\0\x02\x06\x01\x06\x03\x06\x02\x02\x01\x02\x03\x02\x02\x03\x01\z
          \x03\x03\x03\x02\x04\x01\x04\x03\x04\x02\x01\x01\x01\x03\x01\x02\x05\x01\z
          \x05\x03\x05\x02",
          -- SSLSessionReq
          "\x16\x03\0\0S\x01\0\0O\x03\0?G\xd7\xf7\xba,\xee\xea\xb2`~\xf3\0\xfd\z
          \x82{\xb9\xd5\x96\xc8w\x9b\xe6\xc4\xdb<=\xdbo\xef\x10n\0\0(\0\x16\0\x13\z
          \0\x0a\0f\0\x05\0\x04\0e\0d\0c\0b\0a\0`\0\x15\0\x12\0\x09\0\x14\0\x11\0\z
          \x08\0\x06\0\x03\x01\0",
        }) do
        local status, resp = comm.exchange(host, port, probe)
        if status and resp then
          if resp:match("^\x16\x03[\0-\x03]..\x02...\x03[\0-\x03]")
            or resp:match("^\x15\x03[\0-\x03]\0\x02\x02[F\x28]") then
            -- Definitely SSL
            v = true
            break
          elseif not resp:match("^[\x16\x15]\x03") then
            -- Something definitely not SSL
            v = false
            break
          end
          -- Something else? better try the other probes
        end
      end
      host.registry.ssl[port.number .. port.protocol] = v or false
    end
    mtx "done"
    return v
  end
  return false
end

local LIKELY_SSH_PORTS = {
  -- Top ssh ports on shodanhq.com
  22,
  2222,
  55554,
  --666, -- 86% SSH, but we'd like to be more certain.
  22222,
  2382,
  -- And others reported by users
  830, -- netconf-ssh
}

-- This part isn't really necessary, since -sV will reliably detect SSH
local LIKELY_SSH_SERVICES = {
  'ssh', 'netconf-ssh'
}

-- A portrule that matches likely SSH services.
--
-- @name ssh
-- @class function
-- @param host The host table to match against.
-- @param port The port table to match against.
-- @return <code>true</code> if the port is likely to be SSH,
-- <code>false</code> otherwise.
-- @usage
-- portrule = shortport.ssh

ssh = port_or_service(LIKELY_SSH_PORTS, LIKELY_SSH_SERVICES)

--- Return a portrule that returns true when given an open port matching a port range
--
--@param range A port range string in Nmap standard format (ex. "T:80,1-30,U:31337,21-25")
--@return Function for the portrule.
function port_range(range)
  assert(type(range)=="string" and range~="","Incorrect port range specification.")

  local ports = {
    tcp = {},
    udp = {},
  }
  local proto = "both"
  local pos = 1
  repeat
    local i, j, protspec = range:find("^%s*([TU:]+)", pos)
    if i then
      pos = j + 1
      if protspec == "U:" then
        proto = "udp"
      elseif protspec == "T:" then
        proto = "tcp"
      else
        assert(protspec == "", "Incorrect port range specification.")
      end
    end
    repeat
      local i, j, portspec = range:find("^%s*([%d%-]+),?", pos)
      if not i then break end
      pos = j + 1
      portspec = tonumber(portspec) or portspec
      if proto == "both" then
        local ttab = ports.tcp
        ttab[#ttab+1] = portspec
        local utab = ports.udp
        utab[#utab+1] = portspec
      else
        local ptab = ports[proto]
        ptab[#ptab+1] = portspec
      end
    until pos >= #range
  until pos >= #range

  local tcp_rule = portnumber(ports.tcp, "tcp")
  local udp_rule = portnumber(ports.udp, "udp")
  return function(host, port)
    return tcp_rule(host, port) or udp_rule(host, port)
  end
end

return _ENV;
