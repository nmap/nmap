local base64 = require "base64"
local bin = require "bin"
local http = require "http"
local match = require "match"
local nmap = require "nmap"
local package = require "package"
local stdnse = require "stdnse"
local table = require "table"
local url = require "url"
_ENV = stdnse.module("ajp", stdnse.seeall)

---
-- A basic AJP 1.3 implementation based on documentation available from Apache
-- mod_proxy_ajp; http://httpd.apache.org/docs/2.2/mod/mod_proxy_ajp.html
--
-- @author "Patrik Karlsson <patrik@cqure.net>"
--

AJP = {
	
	-- The magic prefix that has to be present in all requests
	Magic = 0x1234,
	
	-- Methods encoded as numeric values
	Method = {
		['OPTIONS'] = 1,
		['GET'] = 2,
		['HEAD'] = 3,
		['POST'] = 4,
		['PUT']  = 5,
		['DELETE'] = 6,
		['TRACE'] = 7,
		['PROPFIND'] = 8,
		['PROPPATCH'] = 9,
		['MKCOL'] = 10,
		['COPY'] = 11,
		['MOVE'] = 12,
		['LOCK'] = 13,
		['UNLOCK'] = 14,
		['ACL'] = 15,
		['REPORT'] = 16,
		['VERSION-CONTROL'] = 17,
		['CHECKIN'] = 18,
		['CHECKOUT'] = 19,
		['UNCHECKOUT'] = 20,
		['SEARCH'] = 21,
		['MKWORKSPACE'] = 22,
		['UPDATE'] = 23,
		['LABEL'] = 24,
		['MERGE'] = 25,
		['BASELINE_CONTROL'] = 26,
		['MKACTIVITY'] = 27,
	},
	
	-- Request codes
	Code = {
		FORWARD_REQUEST = 2,
		SEND_BODY       = 3,
		SEND_HEADERS    = 4,
		END_RESPONSE    = 5,
		SHUTDOWN        = 7,
		PING            = 8,
		CPING           = 10,
	},
	
	-- Request attributes
	Attribute = {
		CONTEXT      = 0x01,
		SERVLET_PATH = 0x02,
		REMOTE_USER  = 0x03,
		AUTH_TYPE    = 0x04,
		QUERY_STRING = 0x05,
		JVM_ROUTE    = 0x06,
		SSL_CERT     = 0x07,
		SSL_CIPHER   = 0x08,
		SSL_SESSION  = 0x09,
		REQ_ATTRIBUTE= 0x0A,
		SSL_KEY_SIZE = 0x0B,
		ARE_DONE     = 0xFF,
	},
	
	ForwardRequest = {
		
		-- Common headers encoded as numeric values
		Header = {
			['accept']           = 0xA001,
			['accept-charset']   = 0xA002,
			['accept-encoding']  = 0xA003,
			['accept-language']  = 0xA004,
			['authorization']    = 0xA005,
			['connection']       = 0xA006,
			['content-type']     = 0xA007,
			['content-length']   = 0xA008,
			['cookie']           = 0xA009,
			['cookie2']          = 0xA00A,
			['host']             = 0xA00B,
			['pragma']           = 0xA00C,
			['referer']          = 0xA00D,
			['user-agent']       = 0xA00E,
		},		

		new = function(self, host, port, method, uri, headers, attributes, options)
			local o = {
				host = host,
				magic = 0x1234,
				length = 0,
				code = AJP.Code.FORWARD_REQUEST,
				method = AJP.Method[method],
				version = "HTTP/1.1",
				uri = uri,
				raddr = options.raddr or "127.0.0.1",
				rhost = options.rhost or "",
				srv = host.ip,
				port = port.number,
				is_ssl = (port.service == "https"),
				headers = headers or {},
				attributes = attributes or {},
			}
			setmetatable(o, self)
			self.__index = self
	       	return o		
		end,
		
		__tostring = function(self)
			
			-- encodes a string, prefixing it with a 2-byte length
			-- and suffixing it with a zero. P-encoding can't be used
			-- as the zero terminator should not be counted in the length
			local function encstr(str)
				if ( not(str) or #str == 0 ) then
					return bin.pack(">S", 0xFFFF)
				end
				return bin.pack(">Sz", #str, str)
			end

			-- count the number of headers
			local function headerCount()
				local i = 0
				for _, _ in pairs(self.headers) do i = i + 1 end
				return i
			end

			-- add host header if it's missing
			if ( not(self.headers['host']) ) then
				self.headers['host'] = stdnse.get_hostname(self.host)
			end
			
			-- add keep-alive connection header if missing
			if ( not(self.headers['connection']) ) then
				self.headers['connection'] = "keep-alive"
			end

			local p_url = url.parse(self.uri)

			-- save the magic and data for last
			local data = bin.pack(">CCAAAAASCS", self.code, self.method, 
				encstr(self.version), encstr(p_url.path), encstr(self.raddr),
				encstr(self.rhost), encstr(self.srv),
				self.port, (self.is_ssl and 1 or 0),
				headerCount())
			
			-- encode headers
			for k, v in pairs(self.headers) do
				local header = AJP.ForwardRequest.Header[k:lower()] or k
				if ( "string" == type(header) ) then
					data = data .. bin.pack(">Sz", #header, header)
				else
					data = data .. bin.pack(">S", header)
				end
				
				data = data .. encstr(v)
			end
			
			-- encode attributes
			if ( p_url.query ) then
			 	data = data .. bin.pack("C", AJP.Attribute.QUERY_STRING)
			 	data = data .. encstr(p_url.query)
			end
			
			-- terminate the attribute list
			data = data .. bin.pack("C", AJP.Attribute.ARE_DONE)
			
			-- returns the AJP request as a string
			return bin.pack(">SSA", AJP.Magic, #data, data)
		end,
		
	},
	
	Response = {
		
		Header = {
			['Content-Type']      = 0xA001,
			['Content-Language']  = 0xA002,
			['Content-Length']    = 0xA003,
			['Date']              = 0xA004,
			['Last-Modified']     = 0xA005,
			['Location']          = 0xA006,
			['Set-Cookie']        = 0xA007,
			['Set-Cookie2']       = 0xA008,
			['Servlet-Engine']    = 0xA009,
			['Status']            = 0xA00A,
			['WWW-Authenticate']  = 0xA00B,
		},
	
		SendHeaders = {
		
			new = function(self)
				local o = { headers = {}, rawheaders = {} }
				setmetatable(o, self)
				self.__index = self
				return o
			end,
			
			parse = function(data)
				local sh = AJP.Response.SendHeaders:new()
				local pos = 6
				local status_msg, hdr_count
				
				pos, sh.status = bin.unpack(">S", data, pos)
				pos, status_msg  = bin.unpack(">P", data, pos)
				pos = pos + 1
				sh['status-line'] = ("AJP/1.3 %d %s"):format(sh.status, status_msg)
								
				pos, hdr_count = bin.unpack(">S", data, pos)
								
				local function headerById(id)
					for k, v in pairs(AJP.Response.Header) do
						if ( v == id ) then	return k end
					end
				end
				
				
				for i=1, hdr_count do
					local key, val, len
					pos, len = bin.unpack(">S", data, pos)
					
					if ( len < 0xA000 ) then
						pos, key = bin.unpack("A"..len, data, pos)
						pos = pos + 1
					else
						key = headerById(len)
					end
					
					pos, val = bin.unpack(">P", data, pos)
					pos = pos + 1
					
					sh.headers[key:lower()] = val
					
					-- to keep the order, in which the headers were received,
					-- add them to the rawheader table as well. This is based
					-- on the same principle as the http library, however the
					-- difference being that we have to "construct"	the "raw"
					-- format of the header, as we're receiving kvp's.
					table.insert(sh.rawheaders, ("%s: %s"):format(key,val))
				end
				return sh
			end,
			
		},
						
	},
		
}

-- The Comm class handles sending and receiving AJP requests/responses
Comm = {
	
	-- Creates a new Comm instance
	new = function(self, host, port, options)
		local o = { host = host, port = port, options = options or {}}
		setmetatable(o, self)
		self.__index = self
		return o
	end,
	
	-- Connects to the AJP server
	--
	-- @return status true on success, false on failure
	-- @return err string containing error message on failure
	connect = function(self)
		self.socket = nmap.new_socket()
		self.socket:set_timeout(self.options.timeout or 5000)
		return self.socket:connect(self.host, self.port)
	end,
	
	-- Sends a request to the server
	--
	-- @param req instance of object that can be serialized with tostring
	-- @return status true on succes, false on failure
	-- @return err string containing error message on failure
	send = function(self, req)
		return self.socket:send(tostring(req))
	end,
	
	-- Receives an AJP response from the server
	--
	-- @return status true on succes, false on failure
	-- @return response table containing the following fields, or string
	--         containing error message on failure
	--         <code>status</code> - status of response (see HTTP status codes)
	--         <code>status-line</code> - the complete status line (eg. 200 OK)
	--         <code>body</code> - the response body as string
	--         <code>headers</code> - table of response headers
	--
	receive = function(self)
		local response = {}
		while(true) do
			local status, buf = self.socket:receive_buf(match.numbytes(4), true)
			if ( not(status) ) then
				return false, "Failed to receive response from server"
			end
			local pos, magic, length = bin.unpack(">A2S", buf)
			if ( magic ~= "AB" ) then
				return false, ("Invalid magic received from server (%s)"):format(magic)
			end
			local status, data = self.socket:receive_buf(match.numbytes(length), true)
			if ( not(status) ) then
				return false, "Failed to receive response from server"
			end
		
			local pos, code = bin.unpack("C", data)
			if ( AJP.Code.SEND_HEADERS == code ) then
				local sh = AJP.Response.SendHeaders.parse(buf .. data)
				response = sh
			elseif( AJP.Code.SEND_BODY == code ) then
				response.body = select(2, bin.unpack(">P", data, pos))
			elseif( AJP.Code.END_RESPONSE == code ) then
				break
			end
		end
		return true, response
	end,
	
	-- Closes the socket
	close = function(self)
		return self.socket:close()
	end,
	
}


Helper = {
	
	--- Creates a new AJP Helper instance
	--
	-- @param host table
	-- @param port table
	-- @param opt 
	-- @return o new Helper instance
	new = function(self, host, port, opt)
		local o = { host = host, port = port, opt = opt or {} }
		setmetatable(o, self)
        self.__index = self
       	return o
	end,

	--- Connects to the AJP server
	--
	-- @return status true on success, false on failure
	-- @return err string containing error message on failure
	connect = function(self)
		self.comm = Comm:new(self.host, self.port, self.opt)
		return self.comm:connect()
	end,
	
	getOption = function(self, options, key)
	
		-- first check options, then global self.opt
		if ( options and options[key] ) then
			return options[key]
		elseif ( self.opt and self.opt[key] ) then
			return self.opt[key]
		end
	
	end,
	
	--- Sends an AJP request to the server
	--
	-- @param url string containing the URL to query
	-- @param headers table containing optional headers
	-- @param attributes table containing optional attributes
	-- @param options table with request specific options
	-- @return status true on succes, false on failure
	-- @return response table (@see Comm.receive), or string containing error
	--         message on failure
	request = function(self, method, url, headers, attributes, options)
		local status, lhost, lport, rhost, rport = self.comm.socket:get_info()
		if ( not(status) ) then
			return false, "Failed to get socket information"
		end
				
		local request = AJP.ForwardRequest:new(self.host, self.port, method, url, headers, attributes, { raddr = rhost })
		if ( not(self.comm:send(request)) ) then
			return false, "Failed to send request to server"
		end
		local status, result = self.comm:receive()
	
		-- support Basic authentication
		if ( status and result.status == 401 and result.headers['www-authenticate'] ) then
			
			local auth = self:getOption(options, "auth")
			if ( not(auth) or not(auth.username) and not(auth.password) ) then
				stdnse.print_debug(2, "No authentication information")
				return status, result
			end
			
			local challenges = http.parse_www_authenticate(result.headers['www-authenticate'])
			local scheme
			for _, challenge in ipairs(challenges or {}) do
				if ( challenge and challenge.scheme and challenge.scheme:lower() == "basic") then
					scheme = challenge.scheme:lower()
					break
				end
			end
						
			if ( not(scheme) ) then
				stdnse.print_debug(2, "Could not find a supported authentication scheme")
			elseif ( "basic" ~= scheme ) then
				stdnse.print_debug(2, "Unsupported authentication scheme: %s", scheme)
			else
				headers = headers or {}
				headers["Authorization"] = ("Basic %s"):format(base64.enc(auth.username .. ":" .. auth.password))
				request = AJP.ForwardRequest:new(self.host, self.port, method, url, headers, attributes, { raddr = rhost })
				if ( not(self.comm:send(request)) ) then
					return false, "Failed to send request to server"
				end
				status, result = self.comm:receive()
			end
			
		end
		return status, result
	end,

	--- Sends an AJP GET request to the server
	--
	-- @param url string containing the URL to query
	-- @param headers table containing optional headers
	-- @param attributes table containing optional attributes
	-- @param options table with request specific options
	-- @return status true on succes, false on failure
	-- @return response table (@see Comm.receive), or string containing error
	--         message on failure
	get = function(self, url, headers, attributes, options)
		return self:request("GET", url, headers, attributes, options)
	end,
	
	--- Sends an AJP HEAD request to the server
	--
	-- @param url string containing the URL to query
	-- @param headers table containing optional headers
	-- @param attributes table containing optional attributes
	-- @param options table with request specific options
	-- @return status true on succes, false on failure
	-- @return response table (@see Comm.receive), or string containing error
	--         message on failure
	head = function(self, url, headers, attributes, options)
		return self:request("HEAD", url, headers, attributes, options)
	end,
	
	--- Sends an AJP TRACE request to the server
	--
	-- @param url string containing the URL to query
	-- @param headers table containing optional headers
	-- @param attributes table containing optional attributes
	-- @param options table with request specific options
	-- @return status true on succes, false on failure
	-- @return response table (@see Comm.receive), or string containing error
	--         message on failure
	trace = function(self, url, headers, attributes, options)
		return self:request("TRACE", url, headers, attributes, options)
	end,
	
	--- Sends an AJP PUT request to the server
	--
	-- @param url string containing the URL to query
	-- @param headers table containing optional headers
	-- @param attributes table containing optional attributes
	-- @param options table with request specific options
	-- @return status true on succes, false on failure
	-- @return response table (@see Comm.receive), or string containing error
	--         message on failure
	put = function(self, url, headers, attributes, options)
		return self:request("PUT", url, headers, attributes, options)
	end,

	--- Sends an AJP DELETE request to the server
	--
	-- @param url string containing the URL to query
	-- @param headers table containing optional headers
	-- @param attributes table containing optional attributes
	-- @param options table with request specific options
	-- @return status true on succes, false on failure
	-- @return response table (@see Comm.receive), or string containing error
	--         message on failure
	delete = function(self, url, headers, attributes, options)
		return self:request("DELETE", url, headers, attributes, options)
	end,
	
	--- Sends an AJP OPTIONS request to the server
	--
	-- @param url string containing the URL to query
	-- @param headers table containing optional headers
	-- @param attributes table containing optional attributes
	-- @param options table with request specific options
	-- @return status true on succes, false on failure
	-- @return response table (@see Comm.receive), or string containing error
	--         message on failure
	options = function(self, url, headers, attributes, options)
		return self:request("OPTIONS", url, headers, attributes, options)
	end,
	
	-- should only work against 127.0.0.1
	shutdownContainer = function(self)
		self.comm:send(bin.pack("H", "1234000107"))
		self.comm:receive()
	end,
	
	--- Disconnects from the server
	close = function(self)
		return self.comm:close()
	end,
	
}

return _ENV;