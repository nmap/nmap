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
-- @param port A single port number or a list of port numbers.
-- @param _proto The protocol or list of protocols to match against, default
-- <code>"tcp"</code>.
-- @param _state A state or list of states to match against, default
-- {<code>"open"</code>, <code>"open|filtered"</code>}.
-- @return Function for the portrule.
-- @usage portrule = shortport.portnumber({80, 443})
portnumber = function(port, _proto, _state)
	local port_table, state_table, proto_table
	local proto = _proto or "tcp"
	local state = _state or {"open", "open|filtered"}

	if(type(port) == "number") then
		port_table = {port}
	elseif(type(port) == "table") then
		port_table = port
	end	

	if(type(state) == "string") then
		state_table = {state}
	elseif(type(state) == "table") then
		state_table = state
	end	

	if(type(proto) == "string") then
		proto_table = {proto}
	elseif(type(proto) == "table") then
		proto_table = proto
	end	

	return function(host, port)
		return includes(state_table, port.state)
			and includes(port_table, port.number)
			and includes(proto_table, port.protocol)
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
-- @param service Service name or a list of names to run against.
-- @param _proto The protocol or list of protocols to match against, default
-- <code>"tcp"</code>.
-- @param _state A state or list of states to match against, default
-- {<code>"open"</code>, <code>"open|filtered"</code>}.
-- @return Function for the portrule.
-- @usage portrule = shortport.service("ftp")
service = function(service, _proto, _state)
	local service_table, state_table, proto_table
	local state = _state or {"open", "open|filtered"}
	local proto = _proto or "tcp"

	if(type(service) == "string") then
		service_table = {service}
	elseif(type(service) == "table") then
		service_table = service
	end	

	if(type(state) == "string") then
		state_table = {state}
	elseif(type(state) == "table") then
		state_table = state
	end	

	if(type(proto) == "string") then
		proto_table = {proto}
	elseif(type(proto) == "table") then
		proto_table = proto
	end	

	return function(host, port)
		return includes(state_table, port.state)
			and includes(service_table, port.service)
			and includes(proto_table, port.protocol)
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
-- @param _port A single port number or a list of port numbers.
-- @param _service Service name or a list of names to run against.
-- @param proto The protocol or list of protocols to match against, default
-- <code>"tcp"</code>.
-- @param _state A state or list of states to match against, default
-- {<code>"open"</code>, <code>"open|filtered"</code>}.
-- @return Function for the portrule.
port_or_service = function(_port, _service, proto, _state)
	local state = _state or {"open", "open|filtered"}
	local state_table

	if(type(state) == "string") then
		state_table = {state}
	elseif(type(state) == "table") then
		state_table = state
	end	

	return function(host, port)
		local port_checker = portnumber(_port, proto, state_table)
		local service_checker = service(_service, proto, state_table)
		return port_checker(host, port) or service_checker(host, port)
	end
end
