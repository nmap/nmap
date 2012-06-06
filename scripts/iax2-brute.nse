local brute = require "brute"
local creds = require "creds"
local iax2 = require "iax2"
local shortport = require "shortport"

description = [[
Performs brute force password auditing against the Asterisk IAX2 protocol.
Guessing fails when a large number of attempts is made due to the maxcallnumber limit (default 2048).
In case your getting "ERROR: Too many retries, aborted ..." after a while, this is most likely what's happening.
In order to avoid this problem try:
  - reducing the size of your dictionary 
  - use the brute delay option to introduce a delay between guesses
  - split the guessing up in chunks and wait for a while between them
]]

---
-- @usage
-- nmap -sU -p 4569 <ip> --script iax2-brute
--
-- @output
-- PORT     STATE         SERVICE
-- 4569/udp open|filtered unknown
-- | iax2-brute: 
-- |   Accounts
-- |     1002:password12 - Valid credentials
-- |   Statistics
-- |_    Performed 1850 guesses in 2 seconds, average tps: 925
--
--

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}


portrule = shortport.port_or_service(4569, "iax2", {"udp", "tcp"})

Driver = {
	
	new = function(self, host, port)
		local o = { host = host, port = port }
       	setmetatable(o, self)
        self.__index = self
		return o
	end,
	
	connect = function(self)
		self.helper = iax2.Helper:new(self.host, self.port)
		return self.helper:connect()
	end,
	
	login = function(self, username, password)
		local status, resp = self.helper:regRelease(username, password)
		if ( status ) then
			return true, brute.Account:new( username, password, creds.State.VALID )
		elseif ( resp == "Release failed" ) then
			return false, brute.Error:new( "Incorrect password" )
		else
			local err = brute.Error:new(resp)
			err:setRetry(true)
			return false, err
		end
	end,
	
	disconnect = function(self) return self.helper:close() end,
}




action = function(host, port)
	local engine = brute.Engine:new(Driver, host, port)
	engine.options.script_name = SCRIPT_NAME
	local status, result = engine:start()
	return result
end
