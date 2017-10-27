---
-- Functions for building short portrules.
--
-- Since portrules are mostly the same for many scripts, this
-- module provides functions for the most common tests.
--
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

local nmap = require "nmap"
local stdnse = require "stdnse"
_ENV = stdnse.module("shortport", stdnse.seeall)

---
-- See if a table contains a value.
-- @param t A table representing a set.
-- @param value The value to check for.
-- @return True if <code>t</code> contains <code>value</code>, false otherwise.
local function includes(t, value)
  for _, elem in ipairs(t) do
    if elem == value then
      return true
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
    return includes(ports, port.number)
      and includes(protos, port.protocol)
      and includes(states, port.state)
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
    return includes(services, port.service)
    and includes(protos, port.protocol)
    and includes(states, port.state)
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
  return (port.version and port.version.service_tunnel == "ssl") or
    port_or_service(LIKELY_SSL_PORTS, LIKELY_SSL_SERVICES, {"tcp", "sctp"})(host, port)
end

return _ENV;
