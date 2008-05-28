-- Arturo 'Buanzo' Busleiman <buanzo@buanzo.com.ar> / www.buanzo.com.ar / linux-consulting.buanzo.com.ar
-- See Nmap'ss COPYING file for licence details
-- This is version 20070413 aka "13th Friday" :)
-- Changelog: Added explode() function. Header-only matching now works.
--		* Fixed set_timeout
--		* Fixed some \r\n's

id="Open Proxy Test"
description="Test if a discovered proxy is open to us by connecting to www.google.com and checking for the 'Server: GWS/' header response."
categories = {"default", "intrusive"}

-- I found a nice explode() function in lua-users' wiki. I had to fix it, though.
-- http://lua-users.org/wiki/LuaRecipes
function explode(d,p)
	local t,ll,l
	t={}
	ll=0
	while true do
		l=string.find(p,d,ll+1,true) -- find the next d in the string
		if l~=nil then -- if "not not" found then..
			table.insert(t, string.sub(p,ll,l-1)) -- Save it in our array.
			ll=l+1 -- save just after where we found it for searching next time.
		else
			table.insert(t, string.sub(p,ll)) -- Save what's left in our array.
			break -- Break at end, as it should be, according to the lua manual.
		end
	end
	return t
end

portrule = function(host, port)
	if 	(port.number == 3128 or port.number == 8080 or port.service == "http-proxy" or port.service == "squid-proxy" or port.service == "squid-proxy?")
		and port.protocol == "tcp"
	then
		return true
	else
		return false
	end
end

action = function(host, port)
	local socket = nmap.new_socket()
	local result
	local status = true
	local response
	local i
-- We will return this if we don't find "^Server: GWS" in response headers
	local retval

	socket:set_timeout(10000);
	socket:connect(host.ip, port.number, port.protocol)
	
-- Ask proxy to open www.google.com
	socket:send("GET http://www.google.com HTTP/1.0\r\nHost: www.google.com\r\n\r\n")

-- read the response, if any
	status, result = socket:receive_lines(1)
	
-- Explode result into the response table
	if (status == false) or (result == "TIMEOUT") then
	else
		response = explode("\n",result)
	end

-- Now, search for Server: GWS until headers (or table) end.
	i = 0
	while true do
		i = i+1
		if i > table.getn(response) then break end
		if response[i]=="\r" then break end
		if string.match(response[i],"^Server: GWS/") then
			retval = "Potentially OPEN proxy. Check for Google\'s \"Server: GWS/\" header FOUND."
			break
		end
	end

-- close the socket and exit, returning the retval string.
	socket:close()
	return retval
end
