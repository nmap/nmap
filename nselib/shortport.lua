module(...)

protorule = function(porttab, service, proto, state)
	state = state or "open"
	proto = proto or "tcp"
	if porttab.service==service
		and porttab.protocol == proto
		and porttab.state == state
	then
		return true;
	else
		return false;
	end
end

portnumber = function(porttab, number, proto, state)
	state = state or "open"
	proto = proto or "tcp"
	if porttab.number==number
		and porttab.protocol == proto
		and porttab.state ==state
	then
		return true;
	else
		return false;
	end
	
end

port_in_list = function(porttab, proto, ...)
	if not porttab.protocol==proto
	then
		return false
	end
	for i, v in ipairs{...} do
		if porttab.number == v then
			return true
		end
	end
	return false
end

port_or_service = function(porttab, number, service, proto, state)
	state= state or "open"
	proto = proto or "tcp"
	if 	(porttab.number==number or porttab.service==service) 
		and porttab.protocol==proto
		and porttab.state == state
	then
		return true
	else 
		return false
	end
end
