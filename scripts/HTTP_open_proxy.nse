id="Open Proxy Test"
description=[[
Checks if an HTTP proxy is open.
\n\n
The script attempts to connect to www.google.com through the proxy and checks
for a 'Server: gws' header field in the response.
\n\n
If the target is an open proxy, this script will cause the target to retrieve a
web page from www.google.com.
]]

-- Arturo 'Buanzo' Busleiman <buanzo@buanzo.com.ar> / www.buanzo.com.ar / linux-consulting.buanzo.com.ar
-- Changelog: Added explode() function. Header-only matching now works.
--   * Fixed set_timeout
--   * Fixed some \r\n's
-- 2008-10-02 Vlatko Kosturjak <kost@linux.hr>
--   * Match case-insensitively against "^Server: gws" rather than
--     case-sensitively against "^Server: GWS/".

author = "Arturo 'Buanzo' Busleiman <buanzo@buanzo.com.ar>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "external", "intrusive"}
require "comm"
require "shortport"

--- An explode() function for NSE/LUA. Taken (and fixed) from http://lua-users.org/wiki/LuaRecipes
--@param d Delimiter
--@param p Buffer to explode
--@return A LUA Table
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

portrule = shortport.port_or_service({3128,8000,8080},{'squid-http','http-proxy'})

action = function(host, port)
	local response
	local i
-- We will return this if we don't find "^Server: gws" in response headers
	local retval

-- Ask proxy to open www.google.com
	local req = "GET http://www.google.com HTTP/1.0\r\nHost: www.google.com\r\n\r\n"
	local status, result = comm.exchange(host, port, req, {lines=1,proto=port.protocol, timeout=10000})
	
	if not status then
		return
	end

-- Explode result into the response table
	response = explode("\n",result)

-- Now, search for "Server: gws" until headers (or table) end.
	i = 0
	while true do
		i = i+1
		if i > table.getn(response) then break end
		if response[i]=="\r" then break end
		if string.match(response[i]:lower(),"^server: gws") then
			retval = "Potentially OPEN proxy. Google\'s \"Server: gws\" header FOUND."
			break
		end
	end

	return retval
end
