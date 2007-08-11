module(...)

protorule = function(service, proto, state)
	return function(host,port)
		state = state or "open"
		proto = proto or "tcp"
		if port.service==service
			and port.protocol == proto
			and port.state == state
		then
			return true;
		else
			return false;
		end
	end
end

portnumber = function(number, proto, state)
	return function(host,port)
		state = state or "open"
		proto = proto or "tcp"
		if port.number==number
			and port.protocol == proto
			and port.state ==state
		then
			return true;
		else
			return false;
		end
	end
end

port_in_list = function(proto, ...)
	local list={...}
	return function(host,port)
		if not port.protocol==proto
		then
			return false
		end
		for _, v in ipairs(list) do
			if port.number == v then
				return true
			end
		end
		return false
	end
end

port_or_service = function(number, service, proto, state)
	return function(host, port)
		state = state or "open"
		proto = proto or "tcp"
		if 	(port.number==number or port.service==service) 
			and port.protocol==proto
			and port.state == state
		then
			return true
		else 
			return false
		end
	end
end
