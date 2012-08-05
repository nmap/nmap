--- A SIP library supporting a limited subset of SIP commands and methods
--
-- The library currently supports the following methods:
--	* REGISTER, INVITE & OPTIONS
--
-- Overview
-- --------
-- The library consists of the following classes:
-- 
-- o SessionData
--		- Holds session data for the SIP session
--
-- o Session
--		- Contains application functionality related to the implemented
-- 		  SIP methods.
--
-- o Connection
--		- A class containing code related to socket communication.
--
-- o Response
--		- A class containing code for handling SIP responses
--
-- o Request
--		- A class containing code for handling SIP requests
--
-- o Util
--		- A class containing static utility functions
--
-- o SIPAuth
--		- A class containing code related to SIP Authentication
--
-- o Helper
--		- A class containing code used as a primary interface by scripts
-- 
--
-- @author "Patrik Karlsson <patrik@cqure.net>"
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html
--
-- @args sip.timeout - specifies the session (socket) timeout in seconds

-- Version 0.1
-- Created 2011/03/30 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>

local bin = require "bin"
local math = require "math"
local nmap = require "nmap"
local os = require "os"
local stdnse = require "stdnse"
local openssl = stdnse.silent_require "openssl"
local string = require "string"
local table = require "table"
_ENV = stdnse.module("sip", stdnse.seeall)

-- Method constants
Method = {
	ACK = "ACK",
	INVITE = "INVITE",
	OPTIONS = "OPTIONS",
	REGISTER = "REGISTER",
}

-- Error constants
Error = {
	TRYING = 100,
	RING = 180,
	TIMEOUT = 408,
	BUSY = 486,
	DECLINE = 603,
	OK = 200,
	UNAUTHORIZED = 401,
	FORBIDDEN = 403,
	NOTFOUND = 404,
	PROXY_AUTH_REQUIRED = 407,
}

-- The SessionData class
SessionData = {
	
	--- Creates a new instance of sessiondata
	-- @return o an instance of SessionData
	new = function(self, o)
		local o = o or {}
		setmetatable(o, self)
        self.__index = self
		o.user = "user"
		return o
	end,
	
	--- Sets the session username
	-- @param user string containing the username
	setUsername = function(self, user) self.user = user end,

	--- Sets the session password
	-- @param pass string containing the password
	setPassword = function(self, pass) self.pass = pass end,

	--- Sets the SIP domain
	-- @param domain string containing the SIP domain
	setDomain = function(self, domain) self.domain = domain end,

	--- Sets the ip and port of the remote server
	-- @param host string containing the ip of the remote server
	-- @param port number containing the port of the remote server
	setServer = function(self, host, port) self.server = { host = host, port = port } end,

	--- Sets the ip and port of the client
	-- @param host string containing the ip of the client
	-- @param port number containing the port of the client
	setClient = function(self, host, port) self.client = { host = host, port = port } end,

	--- Sets the SIP users Full Name
	-- @param name string containing the full name of the user
	setName = function(self, name) self.name = name end,
	
	--- Retrieves the username
	-- @return user string containing the sessions username
	getUsername = function(self) return self.user end,
	
	--- Retrieves the session password
	-- @return pass string containing the session password
	getPassword = function(self) return self.pass end,
	
	--- Retrieves the SIP domain
	-- @return domain string containing the SIP domain
	getDomain = function(self) return self.domain end,
	
	--- Retrieves the client IP and port
	-- @return host string containing the client IP
	-- @return port number containing the client port
	getClient = function(self) return self.client.host, self.client.port end,

	--- Retrieves the server IP and port
	-- @return host string containing the server IP
	-- @return port number containing the server port
	getServer = function(self) return self.server.host, self.server.port end,

	--- Retrieves the SIP users full name
	-- @return name string containing the users full name
	getName = function(self) return self.name or "Nmap NSE" end,
}

-- The session class holds the code necessary to register a SIP session
Session = {

	--- Creates a new session instance
	-- @param host table containing the remote host to connect to
	-- @param port table containing the remote port to connect to
	-- @param sessdata instance of SessionData
	-- @param options table containing zero or more of the following options
	--		<code>expires</code> - the expire value in seconds
	--		<code>timeout</code> - the socket timeout in seconds
	-- @return o containing a new instance of the Session class
	new = function(self, host, port, sessdata, options)
		local o = {}
		setmetatable(o, self)
        self.__index = self
		o.protocol = port.protocol:upper()
		o.expires = (options and options.expires) or 300
		o.conn = Connection:new(host,port)
		o.cseq = (options and options.cseq) or 1234
		local timeout = ( ( options and options.timeout ) and 
							options.timeout * 1000 ) or 5000
		o.conn.socket:set_timeout( timeout )
		o.sessdata = sessdata or SessionData:new()
		return o
	end,
			
	--- Connect the session
	-- @return true on success, false on failure
	-- @return err string containing error message
	connect = function(self)
		local status, err = self.conn:connect()
		if (not(status)) then
			return false, "ERROR: Failed to connect to server"
		end
		local status, lhost, lport, rhost, rport = self.conn.socket:get_info()
		if ( not(status) ) then
			return false, "Failed to retreive socket information"
		end
		self.sessdata:setClient(lhost, lport)
		self.sessdata:setServer(rhost, rport)
		return true
	end,
	
	--- Closes the session
	-- TODO: We should probably send some "closing" packets here
	-- @return true on success, false on failure
	close = function(self) return self.conn:close()	end,
	
	--- Sends and SIP invite
	-- @param uri
	invite = function(self, uri)
		local request = Request:new(Method.INVITE, self.protocol)

		local lhost, _ = self.sessdata:getClient()
		local tm = os.time()
		
		local uri = (uri and uri:match("^sip:.*@.*")) or 
					("sip:%s@%s"):format(uri, self.sessdata:getDomain())
		
		request:setUri(uri)
		request:setSessionData(self.sessdata)

		local data = {}
		table.insert(data, "v=0")
		table.insert(data, ("o=- %s %s IN IP4 %s"):format(tm, tm, lhost))
		table.insert(data, "s=-")
		table.insert(data, ("c=IN IP4 %s"):format(lhost))
		table.insert(data, "t=0 0")
		table.insert(data, "m=audio 49174 RTP/AVP 0")
		table.insert(data, "a=rtpmap:0 PCMU/8000")

		request:setContent(stdnse.strjoin("\r\n", data))
		request:setContentType("application/sdp")
		
		local status, response = self:exch(request)
		if ( not(status) ) then return false, response end

		local errcode = response:getErrorCode()

		if ( Error.PROXY_AUTH_REQUIRED == errcode or 
					Error.UNAUTHORIZED == errcode ) then

			-- Send an ACK to the server
			request:setMethod(Method.ACK)
			local status, err = self.conn:send( tostring(request) )
			if ( not(status) ) then	return status, "ERROR: Failed to send request" end

			-- Send an authenticated INVITE to the server
			request:setMethod(Method.INVITE)
			self.cseq = self.cseq + 1
			status, data = self:authenticate(request, response)
			if ( not(status) ) then	return false, "SIP Authentication failed" end
			response = Response:new(data)
	
			-- read a bunch of 180 Ringing and 100 Trying requests, until we get a 200 OK
			while ( response:getErrorCode() ~= Error.OK ) do
				status, data = self.conn:recv()
				if ( not(status) ) then return status, "ERROR: Failed to receive response" end
				response = Response:new(data)
			end
				
		end
		
		return true
	end,
	
	--- Prepares and sends the challenge response authentication to the server
	-- @param request instance of the request object requiring authentication
	-- @param authdata string containing authentication data
	-- @return status true on success false on failure
	-- @return err string containing an error message if status is false
	authenticate = function(self, request, response)
		local rhost, _ = self.sessdata:getServer()
		local auth_header, auth_data = response:getAuthData() 
		local auth = SipAuth:new(auth_data)
		auth:setUsername(self.sessdata:getUsername())
		auth:setPassword(self.sessdata:getPassword())
		auth:setMethod(request.method)
		auth:setUri(("sip:%s"):format(rhost))

		if ( auth_header == "WWW-Authenticate" ) then
			request:setWWWAuth(auth:createResponse())
		else
			request:setProxyAuth(auth:createResponse())
		end
		request:setCseq(self.cseq)

		local status, err = self.conn:send( tostring(request) )
		if ( not(status) ) then	return status, "ERROR: Failed to send request" end

		local data
		status, data = self.conn:recv()
		if ( not(status) and data ~= "TIMEOUT" ) then
			return status, "ERROR: Failed to receive response"
		end
		return status, data
	end,
	
	--- Sends a SIP Request and receives the Response
	-- @param request instance of Request
	-- @return status true on success, false on failure
	-- @return resp containing a new Response instance
	--			err containing error message if status is false
	exch = function(self, request)
		request:setCseq(self.cseq)
		
		local status, err = self.conn:send( tostring(request) )
		if ( not(status) ) then	return status, "ERROR: Failed to send request" end

		local status, data = self.conn:recv()
		if ( not(status) ) then return status, "ERROR: Failed to receive response" end
		
		return true, Response:new(data)
	end,
	
	--- Sends a register request to the server
	-- @return status true on success, false on failure
	-- @return msg string containing the error message (if status is false)
	register = function(self)
		local request = Request:new(Method.REGISTER, self.protocol)
		
		request:setUri("sip:" .. self.sessdata:getServer())
		request:setSessionData(self.sessdata)
		request:setExpires(self.expires)
				
		local status, response = self:exch(request)
		if (not(status)) then return false, response end

		local errcode = response:getErrorCode()
		
		if ( status and errcode == Error.OK ) then
			return true, response
		elseif ( Error.PROXY_AUTH_REQUIRED == errcode or Error.UNAUTHORIZED == errcode ) then
			local data
			self.cseq = self.cseq + 1
			status, data = self:authenticate(request, response)
			response = Response:new(data)
			errcode = response:getErrorCode() 
			if ( not(status) or ( errcode and errcode ~= Error.OK ) ) then
				return false, "ERROR: Failed to authenticate"
			end
		elseif ( Error.FORBIDDEN == errcode ) then
			return false, "Authentication forbidden"
		else
			return false, ("Unhandled error: %d"):format(errcode)
		end
		return true
	end,
	
	--- Sends an option request to the server and handles the response
	-- @return status true on success, false on failure
	-- @return response if status is true, nil else.
	options = function(self)
		local req = Request:new(Method.OPTIONS, self.protocol)
		req:setUri("sip:" .. self.sessdata:getServer())
		req:setSessionData(self.sessdata)
		req:setExpires(self.expires)
		req:addHeader("Accept", "application/sdp")

		local status, response = self:exch(req)
		if status then return true, response end

		return false, nil
	end,

}

-- The connection class contains basic communication code
Connection = {
	
	--- Creates a new SIP Connection
	-- @param host table containing the host to connect to
	-- @param port table containing the port to connect to
	-- @return o containing a new Connection instance
	new = function(self, host, port)
		local o = {}
		setmetatable(o, self)
        self.__index = self
		o.host = host
		o.port = port
		o.socket = nmap.new_socket()
		return o
	end,
	
	--- Connects to the server
	-- @return status containing true on success and false on failure
	-- @return err containing the error message (if status is false)
	connect = function(self)
		local status, err = self.socket:connect(self.host, self.port)
		if ( status ) then
			local status, lhost, lport, _, _ = self.socket:get_info()
			if ( status ) then
				self.lhost = lhost
				self.lport = lport
			end
		end
		return status, err
	end,
	
	--- Sends the data over the socket
	-- @return status true on success, false on failure
	send = function(self, data)
		return self.socket:send(data)
	end,

	--- Receives data from the socket
	-- @return status true on success, false on failure
	recv = function(self)
		return self.socket:receive()
	end,

	--- Closes the communication channel (socket)
	-- @return true on success false on failure
	close = function(self)
		return self.socket:close()
	end,
	
	--- Retrieves the client ip and port
	-- @return lhost string containing the local ip
	-- @return lport number containing the local port
	getClient = function(self) return self.lhost, self.lport end,

	--- Retrieves the server ip and port
	-- @return rhost string containing the server ip
	-- @return rport number containing the server port
	getServer = function(self) return ( self.host.ip or self.host ), ( self.port.number or self.port ) end,
	
	
}

-- The response class holds the necessary methods and parameters to parse a response
Response = {
	
	--- Creates a new Response instance
	-- @param str containing the data as received over the socket
	-- @return o table containing a new Response instance
	new = function(self, str)
		local o = {}
		setmetatable(o, self)
        self.__index = self
		o.tbl = stdnse.strsplit("\r\n", str)
		return o
	end,
	
	--- Retrieves a given header value from the response
	-- @param name string containing the name of the header
	-- @return value string containing the header value
	getHeader = function(self,name)
		for _, line in ipairs(self.tbl) do
			local header, value = line:match("^(.-): (.*)$")
			if ( header and header:lower() == name:lower() ) then
			    return value 
			end
		end
	end,
	
	--- Returns the error code from the SIP response
	-- @return err number containing the error code
	getErrorCode = function(self)
		return tonumber(self.tbl[1]:match("SIP/%d%.%d (%d+)"))
	end,
	
	--- Returns the error message returned by the server
	-- @return errmsg string containing the error message
	getErrorMessage = function(self)
		return self.tbl[1]:match("^SIP/%d%.%d %d+ (.+)$")
	end,
	
	--- Returns the message method
	-- @return method string containing the method
	getMethod = function(self)
		return self.tbl[1]:match("^(.-)%s.*SIP/2%.0$")
	end,
	
	--- Returns the authentication data from the SIP response
	-- @return auth string containing the raw authentication data
	getAuthData = function(self)
		local auth = self:getHeader("WWW-Authenticate") or self:getHeader("Proxy-Authenticate")
		if ( auth ) then
			return ( self:getHeader("WWW-Authenticate") and 
					"WWW-Authenticate" or 
					"Proxy-Authenticate"), auth
		end
	end,
	
	--- Retrieves the current sequence number
	-- @return cseq number containing the current sequence number
	getCSeq = function(self)
		local cseq = self:getHeader("CSeq")
		cseq = (cseq and cseq:match("^(%d+)"))
		return (cseq and tonumber(cseq))
	end,
	
}

-- The request class holds the necessary functions and parameters for a basic SIP request
Request = {
	
	--- Creates a new Request instance
	-- @param method string containing the request method to use
	-- @param proto Used protocol, could be "UDP" or "TCP"
	-- @return o containing a new Request instance
	new = function(self, method, proto)
		local o = {}
		setmetatable(o, self)
        self.__index = self
      	
		o.ua = "Nmap NSE"
		o.protocol = proto or "UDP"
		o.expires = 0
		o.allow = "PRACK, INVITE ,ACK, BYE, CANCEL, UPDATE, SUBSCRIBE"
			  .. ",NOTIFY, REFER, MESSAGE, OPTIONS"

		o.maxfwd = 70
		o.method = method
		o.length = 0
		o.cid = Util.get_random_string(60)
		return o
	end,
	
	--- Sets the sessiondata so that session information may be fetched
	-- @param data instance of SessionData
	setSessionData = function(self, data) self.sessdata = data end,
	
	--- Adds a custom header to the request
	-- @param name string containing the header name
	-- @param value string containing the header value
	addHeader = function(self, name, value)
		self.headers = self.headers or {}
		table.insert(self.headers, ("%s: %s"):format(name, value))
	end,
		
	--- Sets the SIP uri
	-- @param uri string containing the SIP uri
	setUri = function(self, uri) self.uri = uri end,
	
	--- Sets an error
	-- @param code number containing the error code
	-- @param msg string containing the error message
	setError = function(self, code, msg) self.error = { code = code, msg = msg } end,
	
	--- Sets the request method
	-- @param method string containing a valid SIP method (@see Method constant)
	setMethod = function(self, method) self.method = method end,
	
	--- Sets the sequence number
	-- @param seq number containing the sequence number to set
	setCseq = function(self, seq) self.cseq = seq end,
	
	--- Sets the allow header
	-- @param allow table containing all of the allowed SIP methods
	setAllow = function(self, allow) self.allow = stdnse.strjoin(", ", allow) end,
	
	--- Sets the request content data
	-- @param string containing the content data
	setContent = function(self, content) self.content = content end,

	--- Sets the requests' content type
	-- @param t string containing the content type
	setContentType = function(self, t) self.content_type = t end,

	--- Sets the supported SIP methods
	-- @param supported string containing the supported methods
	setSupported = function(self, supported) self.supported = supported end,
	
	--- Sets the content-length of the SIP request
	-- @param len number containing the length of the actual request
	setContentLength = function(self, len) self.length = len end,
	
	--- Sets the expires header of the SIP request
	-- @param expires number containing the expire value
	setExpires = function(self, expires) self.expires = expires end,
	
	--- Sets the User Agent being used to connect to the SIP server
	-- @param ua string containing the User-Agent name (defaults to Nmap NSE)
	setUA = function(self, ua) self.ua = ua end,

	--- Sets the caller ID information of the SIP request
	-- @param cid string containing the callers id
	setCallId = function(self, cid) self.cid = cid end,
	
	--- Sets the maximum forwards allowed of this request
	-- @param maxfwd number containing the maximum allowed forwards
	setForwards = function(self, maxfwd) self.maxfwd = maxfwd end,
	
	--- Sets the proxy authentication data
	-- @param auth string containing properly formatted proxy authentication data
	setProxyAuth = function(self, auth) self.proxyauth = auth end,
	
	--- Sets the www authentication data
	-- @param auth string containing properly formatted proxy authentication data
	setWWWAuth = function(self, auth) self.wwwauth = auth end,
			
	--- Specifies the network protocol being used
	-- @param proto should be either "UDP" or "TCP"
	setProtocol = function(self, proto)
		assert( proto == "UDP" or proto == "TCP", ("Unsupported protocol %s"):format(proto))
		self.protocol = proto
	end,

			
	--- Converts the request to a String suitable to be sent over the socket
	-- @return ret string containing the complete request for sending over the socket
	__tostring = function(self)
		local data = {}
		local branch = "z9hG4bK" .. Util.get_random_string(25)
		-- must be at least 32-bit unique
		self.from_tag = self.from_tag or Util.get_random_string(20)
		local sessdata = self.sessdata
		local lhost, lport = sessdata:getClient()
		local rhost, rport = sessdata:getServer()
		
		local name, user, domain = sessdata:getName(), sessdata:getUsername(), sessdata:getDomain()
		
		assert(self.method, "No method specified")
		assert(self.maxfwd, "Max forward not set")
		
		-- if no domain was specified use the remote host instead
		domain = domain or rhost
		
		if ( self.error ) then
			table.insert(data, ("SIP/2.0 %s %d"):format(self.error.msg, self.error.code))
		else
			if ( self.method == Method.ACK ) then
				table.insert(data, ("%s %s:%d SIP/2.0"):format(self.method, self.uri, rport))
			else
				table.insert(data, ("%s %s SIP/2.0"):format(self.method, self.uri))
			end
		end
		table.insert(data, ("Via: SIP/2.0/%s %s:%d;rport;branch=%s"):format(self.protocol, lhost, lport, branch))
		table.insert(data, ("Max-Forwards: %d"):format(self.maxfwd))
		table.insert(data, ("From: \"%s\" <sip:%s@%s>;tag=%s"):format(name, user, domain, self.from_tag))
		
		if ( self.method == Method.INVITE ) then
			table.insert(data, ("To: <sip:%s@%s>"):format(user, domain))
		else
			table.insert(data, ("To: \"%s\" <sip:%s@%s>"):format(name, user, domain))
		end
		
		table.insert(data, ("Call-ID: %s"):format(self.cid))
		
		if ( self.error and self.error.code == Error.OK ) then
			table.insert(data, ("CSeq: %d OPTIONS"):format(self.cseq))
		else
			table.insert(data, ("CSeq: %d %s"):format(self.cseq, self.method))
		end

		if ( self.method ~= Method.ACK ) then
			table.insert(data, ("User-Agent: %s"):format(self.ua))
			table.insert(data, ("Contact: \"%s\" <sip:%s@%s:%d>"):format(name, user, lhost, lport))
			if ( self.expires ) then
				table.insert(data, ("Expires: %d"):format(self.expires))
			end
			if ( self.allow ) then
				table.insert(data, ("Allow: %s"):format(self.allow))
			end
			if ( self.supported ) then
				table.insert(data, ("Supported: %s"):format(self.supported))
			end
			
			if ( not(self.error) ) then
				if ( self.proxyauth ) then 
					table.insert(data, ("Proxy-Authorization: %s"):format(self.proxyauth))
				end
				if ( self.wwwauth ) then
					table.insert(data, ("Authorization: %s"):format(self.wwwauth))
				end
			end

			self.length = (self.content and #self.content +2 or 0)
			if ( self.headers ) then
				for _, val in ipairs(self.headers) do
					table.insert(data, val)
				end
			end
			if ( self.content_type ) then
				table.insert(data, ("Content-Type: %s"):format(self.content_type))
			end
			table.insert(data, ("Content-Length:  %d"):format(self.length))
			table.insert(data, "")

			if ( self.content ) then table.insert(data, self.content) end
			table.insert(data, "")
		else
			self.length = (self.content and #self.content +2 or 0)
			
			table.insert(data, ("Content-Length:  %d"):format(self.length))
			table.insert(data, "")
		end
		return stdnse.strjoin("\r\n", data)
	end,
	
}

-- A minimal Util class with supporting functions
Util = {
	
	--- Generates a random string of the requested length. 
	-- @param length (optional) The length of the string to return. Default: 8. 
	-- @param set    (optional) The set of letters to choose from. Default: upper, lower, numbers, and underscore. 
	-- @return The random string. 
	get_random_string = function(length, set)
		if(length == nil) then
			length = 8
		end

		if(set == nil) then
			set = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"
		end

		local str = ""

		for i = 1, length, 1 do
			local random = math.random(#set)
			str = str .. string.sub(set, random, random)
		end

		return str
	end
	
}

-- The SIP authentication class, supporting MD5 digest authentication
SipAuth = {
	
	--- Creates a new SipAuth instance
	-- @param auth string containing the auth data as received from the server
	new = function(self, auth)
		local o = {}
		setmetatable(o, self)
        self.__index = self
		o.auth = auth
		return o
	end,
	
	--- Sets the username used for authentication
	-- @param username string containing the name of the user
	setUsername = function(self, username) self.username = username end,
	
	--- Sets the password used for authentication
	-- @param password string containing the password of the user
	setPassword = function(self, password) self.password = password end,
	
	--- Sets the method used for authentication
	-- @param method string containing the method (Usually REGISTER)
	setMethod = function(self, method) self.method = method end,
	
	--- Sets the uri used for authentication
	-- @param uri string containing the uri (Usually sip:<ip>)
	setUri = function(self, uri) self.uri = uri end,
	
	--- Processes and parses a challenge as received from the server
	parseChallenge = function(self)
		if ( not(self.auth) ) then return end
		self.nonce = self.auth:match("nonce=[\"]([^,]-)[\"]")
		self.algorithm = self.auth:match("algorithm=[\"]*(.-)[\"]*,")
		self.realm = self.auth:match("realm=[\"]([^,]-)[\"]")
		assert(self.algorithm:upper() == "MD5", 
			("Unsupported algorithm detected in authentication challenge (%s)"):format(self.algorithm:upper()))
	end,
	
	--- Calculates the authentication response
	-- @return reponse string containing the authentication response
	calculateResponse = function(self)
	
		if ( not(self.nonce) or not(self.algorithm) or not(self.realm) ) then
			self:parseChallenge()
		end
		
		assert(self.username, "SipAuth: No username specified")
		assert(self.password, "SipAuth: No password specified")
		assert(self.method, "SipAuth: No method specified")
		assert(self.uri, "SipAuth: No uri specified")
	
		local result
		if ( self.algorithm == "MD5" ) then
			local HA1 = select(2, bin.unpack("H16", openssl.md5(self.username .. ":" .. self.realm .. ":" .. self.password)))
			local HA2 = select(2, bin.unpack("H16", openssl.md5(self.method .. ":" .. self.uri)))
			result = openssl.md5(HA1:lower() .. ":" .. self.nonce ..":" .. HA2:lower())
		end
		return select(2, bin.unpack("H16", result)):lower()
	end,
	
	--- Creates the complete authentication response
	-- @return auth string containing the complete authentication digest
	createResponse = function(self)
		local response = self:calculateResponse()
		return ("Digest username=\"%s\", realm=\"%s\", nonce=\"%s\"," ..
				" uri=\"%s\", response=\"%s\", algorithm=%s"):format(self.username, self.realm,
					self.nonce, self.uri, response, self.algorithm)
	end,
	
}

-- The Helper class used as main script interface
Helper = {
	
	--- Creates a new instance of the Helper class
	-- @param host table containing the remote host
	-- @param port table containing the remote port
	-- @param options table containing any options to pass along to the
	-- 		session	(@see Session:new for more details)
	-- @return o containing a new instance of the Helper class
	new = function(self, host, port, options)
		local o = {}
		setmetatable(o, self)
        self.__index = self
		local timeout = stdnse.get_script_args("sip.timeout")
		if ( timeout ) then	options.timeout = timeout end
		o.sessdata = SessionData:new()
		o.session = Session:new(host, port, o.sessdata, options)		
		return o
	end,

	--- Connects the helper instance
	connect = function(self) return self.session:connect() end,

	--- Disconnects and closes the helper instance
	close = function(self) return self.session:close() end,	

	--- Sets the credentials used when performing authentication
	-- @param username string containing the username to use for authentication
	-- @param password string containing the password to use for authentication
	setCredentials = function(self, username, password)
		self.sessdata:setUsername(username)
		self.sessdata:setPassword(password)
	end,

	--- Sets the SIP domain
	-- @param domain string containing the domain name
	setDomain = function(self, domain) self.sessdata:setDomain(domain) end,

	--- Register the UAC with the server
	-- @param options table containing zero or more options 
	-- 		(@see Session:register for more details)
	-- @return status true on success, false on failure
	-- @return msg containing the error message if status is false
	register = function(self, options)
		local status, response = self.session:register(options)
		if ( not(status) ) then	return false, response end
		return true
	end,

	options = function(self) return self.session:options() end,
	
	--- Attempts to INVITE the user at uri to a call
	-- @param uri string containing the sip uri
	-- @return status true on success, false on failure
	invite = function(self, uri)
		return self.session:invite(uri)
	end,
	
}

return _ENV;
