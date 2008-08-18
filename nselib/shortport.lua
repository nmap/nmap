--- Functions for common port tests.\n\n
-- Takes a number as its argument and returns that many bytes.
-- It can be used to get a buffered version of sockobj:receive_bytes(n) in
-- case a script requires more than one fixed-size chunk, as the unbuffered
-- version may return more bytes than requested and thus would require you
-- to do the parsing on your own. 
--@copyright See nmaps COPYING for licence

module(... or "shortport", package.seeall)

--- The port argument is either a number or a table of numbers which are
-- interpreted as port numbers, against which the script should run. See
-- module description for other arguments.
-- @param port The port or list of ports to run against
-- @return Function for the portrule.
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

--- The service argument is either a string or a table of strings which are
-- interpreted as service names (e.g. "http", "https", "smtp" or "ftp")
-- against which the script should run. These service names are determined
-- by Nmap's version scan or (if no version scan information is available)
-- the service assigned to the port in nmap-services  (e.g. "http" for TCP
-- port 80). 
-- @param service Service name or a list of names to run against.
-- @return Function for the portrule.
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

--- Run the script if either the port or service is available. This is
-- a combination of shortport.portnumber and shortport.service, since
-- many scripts explicitly try to run against the well-known ports,
-- but want also to run against any other port which was discovered to
-- run the named service.
-- @usage portrule = shortport.port_or_service(22,"ssh"). 
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
