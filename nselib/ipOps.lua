module(...,package.seeall)


isPrivate = function(ip)
	-- check to see if ip is part of RFC 1918 address space
	-- if so, don't bother with the RIPE lookup
	local a, b
	a, b = get_parts_as_number(ip)  
	if a == 10 then
		return true
	elseif a == 172 and (b>15 and b<32) then
			return true
	elseif a == 192 and b == 168 then
		return true
	end
	return false
end

todword = function(ip)
	local a, b, c, d
	a,b,c,d = get_parts_as_number(ip) 
	return (((a*256+b))*256+c)*256+d
end

get_parts_as_number = function(ip)
	local a,b,c,d = string.match(ip, "(%d+)%.(%d+)%.(%d+)%.(%d+)")
	a = tonumber(a);
	b = tonumber(b);
	c = tonumber(c);
	d = tonumber(d);
	return a,b,c,d
end
