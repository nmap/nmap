description = [[
Attempts to extract system information from the UPnP service.
]]

---
-- @output
-- |  upnp-info:  System/1.0 UPnP/1.0 IGD/1.0
-- |_ Location: http://192.168.1.1:80/UPnP/IGD.xml

author = "Thomas Buchanan"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "safe"}

require("stdnse")
require("shortport")
require("strbuf")

---
-- Runs on UDP port 1900
portrule = shortport.portnumber(1900, "udp", {"open", "open|filtered"})

---
-- Sends UPnP discovery packet to host, 
-- and extracts service information from results
action = function(host, port)
	
	-- create the socket used for our connection
	local socket = nmap.new_socket()
	
	-- set a reasonable timeout value
	socket:set_timeout(5000)
	
	-- do some exception handling / cleanup
	local catch = function()
		socket:close()
	end
	
	local try = nmap.new_try(catch)
	
	-- connect to the potential UPnP system
	try(socket:connect(host.ip, port.number, "udp"))
	
	local payload = strbuf.new()
	
	-- for details about the UPnP message format, see http://upnp.org/resources/documents.asp
	payload = payload .. "M-SEARCH * HTTP/1.1\r\n"
	payload = payload .. "Host:239.255.255.250:1900\r\n"
	payload = payload .. "ST:upnp:rootdevice\r\n"
	payload = payload .. "Man:\"ssdp:discover\"\r\n"
	payload = payload .. "MX:3\r\n\r\n"
	
	try(socket:send(strbuf.dump(payload)))
	
	local status
	local response
	
	-- read in any response we might get
	status, response = socket:receive_bytes(1)

	if (not status) or (response == "TIMEOUT") then
		socket:close()
		return
	end

	-- since we got something back, the port is definitely open
	nmap.set_port_state(host, port, "open")
	
	-- buffer to hold script output
	local output
	
	if response ~= nil then
		-- We should get a response back that has contains one line for the server, and one line for the xml file location
		-- these match any combination of upper and lower case responses
		local server, location
		server = string.match(response, "[Ss][Ee][Rr][Vv][Ee][Rr]:(.-)\010")
		if server ~= nil then output = server .. "\n" end
		location = string.match(response, "[Ll][Oo][Cc][Aa][Tt][Ii][Oo][Nn]:(.-)\010")
		if location ~= nil then
			output = output .. "Location: " .. location 
			
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

				-- check if the IP address in the location matches the IP address we're scanning
				-- if not, alert the user, but continue to scan the IP address we're interested in
				if xhost ~= host.ip then 
					output = output .. "\n !! Location did not match target IP address !! "
				--	return output 
					xhost = host.ip
				end

				-- extract the path name from the location field, but strip off the \r that HTTP servers return
				xfile = string.match(location, "http://.-/(.-)\013")
				if xfile ~= nil then
					strbuf.clear(payload)
					-- create an HTTP request for the file, using the host and port we extracted earlier
					payload = payload .. "GET /" .. xfile .. " HTTP/1.1\r\n"
					payload = payload .. "Accept: text/xml, application/xml, text/html\r\n"
					payload = payload .. "User-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine; http://nmap.org/book/nse.html)\r\n"
					payload = payload .. "Host: " .. xhost .. ":" .. xport .. "\r\n"
					payload = payload .. "Connection: Keep-Alive\r\n"
					payload = payload .. "Cache-Control: no-cache\r\n"
					payload = payload .. "Pragma: no-cache\r\n\r\n"

					socket = nmap.new_socket()
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
							if webserver ~= nil then output = output .. "\nWebserver: " .. webserver end

							-- the schema for UPnP includes a number of <device> entries, which can a number of interesting fields
							for device in string.gmatch(response, "<deviceType>(.-)</UDN>") do
								local fn, mnf, mdl, nm, ver

								fn = string.match(device, "<friendlyName>(.-)</friendlyName>")
								mnf = string.match(device, "<manufacturer>(.-)</manufacturer>")
								mdl = string.match(device, "<modelDescription>(.-)</modelDescription>")
								nm = string.match(device, "<modelName>(.-)</modelName>")
								ver = string.match(device, "<modelNumber>(.-)</modelNumber>")

								if fn ~= nil then output = output .. "\n Name: " .. fn end
								if mnf ~= nil then output = output .. "\n  Manufacturer: " .. mnf end
								if mdl ~= nil then output = output .. "\n  Model Descr: " .. mdl end
								if nm ~= nil then output = output .. "\n  Model Name: " .. nm end
								if ver ~= nil then output = output .. "\n  Model Version: " .. ver end
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
