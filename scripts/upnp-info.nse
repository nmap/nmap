description = [[
Attempts to extract system information from the UPnP service.
]]

---
-- @output
-- |  upnp-info:  System/1.0 UPnP/1.0 IGD/1.0
-- |_ Location: http://192.168.1.1:80/UPnP/IGD.xml

-- 2010-10-05 - add prerule support <patrik@cqure.net>
-- 2010-10-10 - add newtarget support <patrik@cqure.net>

author = "Thomas Buchanan"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}

require("stdnse")
require("shortport")
require("strbuf")
require("target")

prerule = function() return true end

---
-- Runs on UDP port 1900
portrule = shortport.portnumber(1900, "udp", {"open", "open|filtered"})

local function process_response( response )
	
	local catch = function() socket:close()	end
	local try = nmap.new_try(catch)
	local output = {}
	
	if response ~= nil then
		-- We should get a response back that has contains one line for the server, and one line for the xml file location
		-- these match any combination of upper and lower case responses
		local server, location
		server = string.match(response, "[Ss][Ee][Rr][Vv][Ee][Rr]:%s*(.-)\010")
		if server ~= nil then table.insert(output, server ) end
		location = string.match(response, "[Ll][Oo][Cc][Aa][Tt][Ii][Oo][Nn]:(.-)\010")
		if location ~= nil then
			table.insert(output, "Location: " .. location )
			
			local v = nmap.verbosity()
			
			-- the following check can output quite a lot of information, so we require at least one -v flag
			if v > 0 then
				-- split the location into an IP address, port, and path name for the xml file
				local xhost, xport, xfile
				xhost = string.match(location, "http://(.-)/")
				-- check to see if the host portionof the location specifies a port
				-- if not, use port 80 as a standard web server port
				if xhost ~= nil and string.match(xhost, ":") then
					xport = string.match(xhost, ":(.*)")
					xhost = string.match(xhost, "(.*):")
				end

				if xport == nil then
					xport = 80
				end

				local peer = {}
				local _
				
				-- extract the path name from the location field, but strip off the \r that HTTP servers return
				xfile = string.match(location, "http://.-/(.-)\013")
				if xfile ~= nil then
					local payload = strbuf.new()
					
					strbuf.clear(payload)
					-- create an HTTP request for the file, using the host and port we extracted earlier
					payload = payload .. "GET /" .. xfile .. " HTTP/1.1\r\n"
					payload = payload .. "Accept: text/xml, application/xml, text/html\r\n"
					payload = payload .. "User-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine; http://nmap.org/book/nse.html)\r\n"
					payload = payload .. "Host: " .. xhost .. ":" .. xport .. "\r\n"
					payload = payload .. "Connection: Keep-Alive\r\n"
					payload = payload .. "Cache-Control: no-cache\r\n"
					payload = payload .. "Pragma: no-cache\r\n\r\n"

					local socket = nmap.new_socket()
					socket:set_timeout(5000)

					try(socket:connect(xhost, xport, "tcp"))
					try(socket:send(strbuf.dump(payload)))
					-- we're expecting an xml file, and for UPnP purposes it should end in </root>
					status, response = socket:receive_buf("</root>", true)

					if (status) and (response ~= "TIMEOUT") then
						if string.match(response, "HTTP/1.%d 200") then
							local webserver
							-- extract information about the webserver that is handling responses for the UPnP system
							webserver = string.match(response, "[Ss][Ee][Rr][Vv][Ee][Rr]:(.-)\010")
							if webserver ~= nil then table.insert(output, "Webserver: " .. webserver) end

							-- the schema for UPnP includes a number of <device> entries, which can a number of interesting fields
							for device in string.gmatch(response, "<deviceType>(.-)</UDN>") do
								local fn, mnf, mdl, nm, ver

								fn = string.match(device, "<friendlyName>(.-)</friendlyName>")
								mnf = string.match(device, "<manufacturer>(.-)</manufacturer>")
								mdl = string.match(device, "<modelDescription>(.-)</modelDescription>")
								nm = string.match(device, "<modelName>(.-)</modelName>")
								ver = string.match(device, "<modelNumber>(.-)</modelNumber>")

								if fn ~= nil then table.insert(output, "Name: " .. fn) end
								if mnf ~= nil then table.insert(output,"Manufacturer: " .. mnf) end
								if mdl ~= nil then table.insert(output,"Model Descr: " .. mdl) end
								if nm ~= nil then table.insert(output,"Model Name: " .. nm) end
								if ver ~= nil then table.insert(output,"Model Version: " .. ver) end
							end
						end
					end

					socket:close()
				end
			end	
		end
		return output
	end
end

--- Converts a string ip to a numeric value suitable for comparing
--
-- @param ip string containing the ip to convert
-- @return number containing the converted ip
local function ipToNumber(ip)
	local o1, o2, o3, o4 = ip:match("^(%d*)%.(%d*)%.(%d*)%.(%d*)$")
	return (256^3) * o1 + (256^2) * o2 + (256^1) * o3 + (256^0) * o4
end

--- Compare function used for sorting IP-addresses
--
-- @param a table containing first item
-- @param b table containing second item
-- @return true if the port of a is less than the port of b
local function ipCompare(a, b)
	local ip_a = ipToNumber(a.name)
	local ip_b = ipToNumber(b.name)
	if ( tonumber(ip_a) < tonumber(ip_b) ) then
		return true
	end
	return false
end


---
-- Sends UPnP discovery packet to host, 
-- and extracts service information from results
preaction = function(host, port)
	
	-- create the socket used for our connection
	local socket = nmap.new_socket("udp")
	
	-- set a reasonable timeout value
	socket:set_timeout(5000)
	
	local payload = strbuf.new()
	
	-- for details about the UPnP message format, see http://upnp.org/resources/documents.asp
	payload = payload .. "M-SEARCH * HTTP/1.1\r\n"
	payload = payload .. "Host:239.255.255.250:1900\r\n"
	payload = payload .. "ST:upnp:rootdevice\r\n"
	payload = payload .. "Man:\"ssdp:discover\"\r\n"
	payload = payload .. "MX:3\r\n\r\n"

	local status, err = socket:sendto("239.255.255.250", 1900, strbuf.dump(payload))
	if (not(status)) then return err end
	
	local response, output
	local result = {}
	
	while(true) do
		-- read in any response we might get
		status, response = socket:receive()
		if (not status) then break end

		local status, _, _, peer_ip, _ = socket:get_info()

		if target.ALLOW_NEW_TARGETS then
			target.add(peer_ip)
		end
		
		output = process_response( response )
		output = { output }
		output.name = peer_ip
		table.insert( result, output )				
	end
	socket:close()

	table.sort(result, ipCompare)
	return stdnse.format_output(true, result)
end

scanaction = function( host, port )

	-- create the socket used for our connection
	local socket = nmap.new_socket()
	
	-- set a reasonable timeout value
	socket:set_timeout(5000)
	
	local payload = strbuf.new()
	
	-- for details about the UPnP message format, see http://upnp.org/resources/documents.asp
	payload = payload .. "M-SEARCH * HTTP/1.1\r\n"
	payload = payload .. "Host:239.255.255.250:1900\r\n"
	payload = payload .. "ST:upnp:rootdevice\r\n"
	payload = payload .. "Man:\"ssdp:discover\"\r\n"
	payload = payload .. "MX:3\r\n\r\n"

	local status, err = socket:connect(host, port, "udp" )
	if ( not(status) ) then return err end
	
	status, err = socket:send( strbuf.dump(payload) )
	if ( not(status) ) then return err end
	
	local response
	status, response = socket:receive()

	if (not status) then
		socket:close()
		return response
	end

	-- since we got something back, the port is definitely open
	nmap.set_port_state(host, port, "open")
		
	return stdnse.format_output(true, process_response( response ))
end

-- Function dispatch table
local actions = {
	prerule = preaction,
	hostrule = scanaction,
	portrule = scanaction,
}

function action (...) return actions[SCRIPT_TYPE](...) end

