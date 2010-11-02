--- A UPNP library based on code from upnp-info initially written by 
-- Thomas Buchanan. The code was factored out from upnp-info and partly
-- re-written by Patrik Karlsson <patrik@cqure.net> in order to support
-- multicast requests.
--
-- The library supports sending UPnP requests and decoding the responses
--
-- The library contains the following classes
-- * <code>Comm</code>
-- ** A class that handles communication with the UPnP service
-- * <code>Helper</code>
-- ** The helper class wraps the <code>Comm</code> class using functions with a more descriptive name.
-- * <code>Util</code>
-- ** The <code>Util</code> class contains a number of static functions mainly used to convert and sort data.
--
-- The following code snipplet queries all UPnP services on the network:
-- <code>
--   local helper = upnp.Helper:new()
--   helper:setMulticast(true)
--   return stdnse.format_output(helper:queryServices())
-- </code>
-- 
-- This next snipplet queries a specific host for the same information:
-- <code>
--   local helper = upnp.Helper:new(host, port)
--   return stdnse.format_output(helper:queryServices())
-- </code>
--
--
-- @author "Thomas Buchanan, Patrik Karlsson <patrik@cqure.net>"

--
-- Version 0.1
--

module(... or "upnp", package.seeall)

require("strbuf")
require("target")

Util = {
	
	--- Converts a string ip to a numeric value suitable for comparing
	--
	-- @param ip string containing the ip to convert
	-- @return number containing the converted ip
	ipToNumber = function(ip)
		local o1, o2, o3, o4 = ip:match("^(%d*)%.(%d*)%.(%d*)%.(%d*)$")
		return (256^3) * o1 + (256^2) * o2 + (256^1) * o3 + (256^0) * o4
	end,

	--- Compare function used for sorting IP-addresses
	--
	-- @param a table containing first item
	-- @param b table containing second item
	-- @return true if the port of a is less than the port of b
	ipCompare = function(a, b)
		local ip_a = Util.ipToNumber(a.name)
		local ip_b = Util.ipToNumber(b.name)
		if ( tonumber(ip_a) < tonumber(ip_b) ) then
			return true
		end
		return false
	end
	
}

Comm = {
	
	--- Creates a new Comm instance
	--
	-- @param host string containing the host name or ip
	-- @param port number containing the port to connect to
	-- @return o a new instance of Comm
	new = function( self, host, port )
		local o = {}
	   	setmetatable(o, self)
        self.__index = self
		o.host = host
		o.port = port
		o.mcast = false
		return o
	end,
	
	--- Connect to the server
	--
	-- @return status true on success, false on failure
	connect = function( self )
		if ( self.mcast ) then
			self.socket = nmap.new_socket("udp")
			self.socket:set_timeout(5000)
		else
			self.socket = nmap.new_socket()
			self.socket:set_timeout(5000)
			local status, err = self.socket:connect(self.host, self.port, "udp" )
			if ( not(status) ) then return false, err end
		end
		
		return true
	end,
	
	--- Send the UPNP discovery request to the server
	--
	-- @return status true on success, false on failure	
	sendRequest = function( self )
		local payload = strbuf.new()

		-- for details about the UPnP message format, see http://upnp.org/resources/documents.asp
		payload = payload .. "M-SEARCH * HTTP/1.1\r\n"
		payload = payload .. "Host:239.255.255.250:1900\r\n"
		payload = payload .. "ST:upnp:rootdevice\r\n"
		payload = payload .. "Man:\"ssdp:discover\"\r\n"
		payload = payload .. "MX:3\r\n\r\n"
		
		local status, err 
		
		if ( self.mcast ) then
			status, err = self.socket:sendto( self.host, self.port, strbuf.dump(payload) )
		else
			status, err = self.socket:send( strbuf.dump(payload) )
		end
		
		if ( not(status) ) then return false, err end
	
		return true
	end,

	--- Receives one or multiple UPNP responses depending on whether 
	-- <code>setBroadcast</code> was enabled or not. The function returns the
	-- status and a response containing:
	-- * an array (table) of responses if broadcast is used
	-- * a single response if broadcast is not in use
	-- * an error message if status was false
	--
	-- @return status true on success, false on failure
	-- @return result table or string containing results or error message
	--         on failure.
	receiveResponse = function( self )
		local status, response
		local result = {}
		
		repeat
		 	status, response = self.socket:receive()
			if ( not(status) and #response == 0 ) then
				return false, response
			elseif( not(status) ) then 
				break 
			end

			local status, _, _, ip, _ = self.socket:get_info()
			if target.ALLOW_NEW_TARGETS then target.add(ip) end

			local status, output = self.decodeResponse( response )
			if ( not(status) ) then
				return false, "Failed to decode UPNP response"
			end
			output = { output }
			output.name = ip
			table.insert( result, output )				
		until ( not( self.mcast ) )
	
		if ( self.mcast ) then 
			table.sort(result, Util.ipCompare) 
			return true, result
		end
	
		if ( #response > 0 ) then
			return true, result[1]
		else
			return false, "Received no responses"
		end
	end,
	
	--- Processes a response from a upnp device
	--
	-- @param response as received over the socket
	-- @return status true on success, false on failure
	-- @return response suitable for output or error message if status is false
	decodeResponse = function( response )
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

						local status = socket:connect(xhost, xport, "tcp")
						if ( not(status) ) then return false, ("Failed to connect to: %s"):format(xhost) end

						status = socket:send(strbuf.dump(payload))
						if ( not(status) ) then return false, ("Failed to send data to: %s"):format(xhost) end

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
					end
				end	
			end
			return true, output
		end
	end,
	
	--- Enables or disables multicast support
	--
	-- @param mcast boolean true if multicast is to be used, false otherwise
	setMulticast = function( self, mcast )
		assert( type(mcast)=="boolean", "mcast has to be either true or false")
		self.mcast = mcast
		self.host = "239.255.255.250"
		self.port = 1900
	end,

	--- Closes the socket
	close = function( self ) self.socket:close() end
		
}


Helper = {
	
	--- Creates a new helper instance
	--
	-- @param host string containing the host name or ip
	-- @param port number containing the port to connect to
	-- @return o a new instance of Helper
	new = function( self, host, port )
		local o = {}
	   	setmetatable(o, self)
        self.__index = self
		o.comm = Comm:new( host, port )
		return o
	end,
    
	--- Enables or disables multicast support
	--
	-- @param mcast boolean true if multicast is to be used, false otherwise
	setMulticast = function( self, mcast ) self.comm:setMulticast(mcast) end,
	
	--- Sends a UPnP queries and collects a single or multiple responses
	--
	-- @return status true on success, false on failure
	-- @return result table or string containing results or error message
	--         on failure.
	queryServices = function( self )
		local status, err = self.comm:connect()
		local response
		
		if ( not(status) ) then return false, err end
		
		status, err = self.comm:sendRequest()
		if ( not(status) ) then return false, err end

		status, response = self.comm:receiveResponse()
		self.comm:close()
		
		return status, response
	end,
	
}