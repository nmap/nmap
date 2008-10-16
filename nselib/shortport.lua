--- Functions for building short portrules.
-- \n\n
-- Since portrules are mostly the same for many scripts, this
-- module provides functions for the most common tests.
--@copyright See nmaps COPYING for licence

module(... or "shortport", package.seeall)

--- Return a portrule that returns true when given an open port matching a
-- single port number or a list of port numbers.
-- @param port A single port number or a list of port numbers.
-- @param _proto The protocol to match against, default "tcp".
-- @param _state A state or list of states to match against, default {"open", "open|filtered"}.
-- @return Function for the portrule.
-- @usage portrule = shortport.portnumber({80, 443})
portnumber = function(port, _proto, _state)
	local port_table, state_table
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

	return function(host, port)
		for _, state in pairs(state_table) do
			if(port.protocol == proto and port.state == state) then
				for _, _port in ipairs(port_table) do
					if(port.number == _port) then
						return true
					end
				end
			end
		end

		return false
	end
end

--- Return a portrule that returns true when given an open port with a
--service name matching a single service name or a list of service
--names.
-- \n\n
-- A service name is something like "http", "https", "smtp", or "ftp".
-- These service names are determined by Nmap's version scan or (if no
-- version scan information is available) the service assigned to the
-- port in nmap-services  (e.g. "http" for TCP port 80). 
-- @param service Service name or a list of names to run against.
-- @param _proto The protocol to match against, default "tcp".
-- @param _state A state or list of states to match against, default {"open", "open|filtered"}.
-- @return Function for the portrule.
-- @usage portrule = shortport.service("ftp")
service = function(service, _proto, _state)
	local service_table, state_table
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

	return function(host, port)
		for _, state in pairs(state_table) do
			if(port.protocol == proto and port.state == state) then
				for _, service in ipairs(service_table) do
					if(port.service == service) then
						return true
					end
				end
			end
		end

		return false
	end
end

--- Return a portrule that returns true when given an open port matching
-- either a port number or service name.
-- \n\n
-- This function is a combination of the portnumber and service
-- functions. The port and service may be single values or a list of
-- values as in those functions. Many scripts explicitly try to run
-- against the well-known ports, but want also to run against any other
-- port which was discovered to run the named service.
-- @usage portrule = shortport.port_or_service(22,"ssh"). 
-- @param _port A single port number or a list of port numbers.
-- @param _service Service name or a list of names to run against.
-- @param proto The protocol to match against, default "tcp".
-- @param _state A state or list of states to match against, default {"open", "open|filtered"}.
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
		for _, state in pairs(state_table) do
			local port_checker = portnumber(_port, proto, state)
			local service_checker = service(_service, proto, state)
			if (port_checker(host, port) or service_checker(host, port)) then
				return true
			end
		end

		return false
	end
end
