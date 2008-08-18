--- General IP Operations.
-- @copyright See nmaps COPYING for licence

module(... or "ipOps",package.seeall)

--- Checks whether an IP address, provided as a string in dotted-quad
-- notation, is part of the non-routed private IP address space,
-- as described in RFC 1918. These addresses are the well-known
-- 10.0.0.0/8, 192.168.0.0/16 and 172.16.0.0/12 networks. 
-- @param ip Dotted-Quad IP address.
-- @return boolean Is private IP
isPrivate = function(ip)
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

--- Returns the IP address as DWORD value (i.e. the IP <a.b.c.d> becomes
-- (((a*256+b)*256+c)*256+d) ) 
-- @param ip Dotted-Quad IP address.
-- @return IP Address as a DWORD value.
todword = function(ip)
	local a, b, c, d
	a,b,c,d = get_parts_as_number(ip) 
	return (((a*256+b))*256+c)*256+d
end

--- Returns 4 numbers corresponding to the fields in dotted-quad notation.
-- For example, ipOps.get_parts_as_number("192.168.1.1")  returns 192,168,1,1. 
-- @param ip Dotted-Quad IP address.
-- @return Four numbers in the IP address.
get_parts_as_number = function(ip)
	local a,b,c,d = string.match(ip, "(%d+)%.(%d+)%.(%d+)%.(%d+)")
	a = tonumber(a);
	b = tonumber(b);
	c = tonumber(c);
	d = tonumber(d);
	return a,b,c,d
end
