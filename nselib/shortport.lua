--- Functions for building short portrules.
--
-- Since portrules are mostly the same for many scripts, this
-- module provides functions for the most common tests.
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html

module(... or "shortport", package.seeall)

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
