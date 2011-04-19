---
-- Functions for building short portrules.
--
-- Since portrules are mostly the same for many scripts, this
-- module provides functions for the most common tests.
--
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html

module(... or "shortport", package.seeall)

local nmap = require "nmap"

---
-- See if a table contains a value.
-- @param t A table repesenting a set.
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

--- Check if the port and it's protocol are in the exclude directive.
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
-- exclude port directive of the nmap-service-probes file.
--
-- This function is a combination of the <code>port_is_excluded</code>
-- and <code>port_or_service</code> functions. The port, service, proto may
-- be single values or a list of values as in those functions.
-- This function can be used by version category scripts to check if a
-- given port and it's protocol are in the exclude directive.
-- @usage portrule = shortport.version_port_or_service(22)
-- @usage portrule = shortport.version_port_or_service(nil, "ssh", "tcp")
-- @param services Service name or a list of names to run against.
-- @param protos The protocol or list of protocols to match against, default
-- <code>"tcp"</code>.
-- @param states A state or list of states to match against, default
-- {<code>"open"</code>, <code>"open|filtered"</code>}.
-- @return Function for the portrule.
version_port_or_service = function(ports, services, protos, states)
        return function(host, port)
                local p_s_check = port_or_service(ports, services, protos, states)
                return p_s_check(host, port)
                       and not(port_is_excluded(port.number, port.protocol))
        end
end

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
http = shortport.port_or_service({80, 443, 631, 8080, 5800, 3872},
	{"http", "https", "ipp", "http-alt", "vnc-http", "oem-agent"})

local LIKELY_SSL_PORTS = {
    443, 465, 587, 636, 989, 990, 992, 993, 994, 995, 5061, 6679, 6697, 8443,
    9001,
}
local LIKELY_SSL_SERVICES = {
    "ftps", "ftps-data", "https", "https-alt", "imaps", "ircs",
    "ldapssl", "pop3s", "sip-tls", "smtps", "telnets", "tor-orport",
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
    return port.version.service_tunnel == "ssl" or
        port_or_service(LIKELY_SSL_PORTS, LIKELY_SSL_SERVICES, {"tcp", "sctp"})(host, port)
end
