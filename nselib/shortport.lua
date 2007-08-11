module(..., package.seeall)

portnumber = function(port, _proto, _state)
	local port_table;
	local state = _state or "open"
	local proto = _proto or "tcp"

	if(type(port) == "number") then
		port_table = {port}
	elseif(type(port) == "table") then
		port_table = port
	end	

	return function(host, port)
		if(port.protocol == proto and port.state == state) then
			for _, _port in ipairs(port_table) do
				if(port.number == _port) then
					return true
				end
			end
		end

		return false
	end
end

service = function(service, _proto, _state)
	local service_table;
	local state = _state or "open"
	local proto = _proto or "tcp"

	if(type(service) == "string") then
		service_table = {service}
	elseif(type(service) == "table") then
		service_table = service
	end	

	return function(host, port)
		if(port.protocol == proto and port.state == state) then
			for _, service in ipairs(service_table) do
				if(port.service == service) then
					return true
				end
			end
		end

		return false
	end
end

port_or_service = function(port, _service, proto, state)
	local port_checker = portnumber(port, proto, state)
	local service_checker = service(_service, proto, state)

	return function(host, port)
		return port_checker(host, port) or service_checker(host, port)
	end
end
