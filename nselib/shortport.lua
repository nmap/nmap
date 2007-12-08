-- See nmaps COPYING for licence
module(..., package.seeall)

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

service = function(service, _proto, _state)
	local service_table;
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

port_or_service = function(port, _service, proto, _state)
	local state = _state or {"open", "open|filtered"}
	local state_table

	if(type(state) == "string") then
		state_table = {state}
	elseif(type(state) == "table") then
		state_table = state
	end	

	return function(host, port)
		for _, state in pairs(state_table) do
			local port_checker = portnumber(port, proto, state)
			local service_checker = service(_service, proto, state)
			if (port_checker(host, port) or service_checker(host, port)) then
				return true
			end
		end

		return false
	end
end
