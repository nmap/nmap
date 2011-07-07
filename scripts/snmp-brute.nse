description = [[
Attempts to find an SNMP community string by brute force guessing.
]]
-- 2008-07-03

---
-- @args snmpcommunity The SNMP community string to use. If it's supplied, this
-- script will not run.
-- @args snmplist The filename of a list of community strings to try.
--
-- @output
-- PORT    STATE SERVICE
-- 161/udp open  snmp
-- |_snmp-brute: public

author = "Philip Pickering, Gorjan Petrovski"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "auth"}

-- Revised 07/07/2011 - v 0.2 - ported to the brute library (Gorjan Petrovski)  

require "shortport"
require "snmp"
require "brute"
require "creds"

portrule = shortport.portnumber(161, "udp", {"open", "open|filtered"})

local port_set_open = false

local Driver =
{
	new = function(self, host, port)
		local o = {}
		setmetatable(o,self)
		self.__index = self
		o.host = host
		o.port = port
		return o
	end,
	connect = function(self)
		self.socket = nmap.new_socket()
		if not self.socket then return false end
		-- set some reasonable timeouts :)
		if self.host.times.timeout < 1 then
			self.socket:set_timeout(1000)
		else
			self.socket:set_timeout(self.host.times.timeout * 1000)
		end
		local status, err = self.socket:connect(self.host, self.port)
		if not status then
			self.socket:close()
			return false
		end
		self.request = snmp.buildGetRequest({}, "1.3.6.1.2.1.1.3.0") 
		return true
	end,
	disconnect = function(self)
		self.socket:close()
	end,
	login = function( self, username, password)
		local payload = snmp.encode(snmp.buildPacket(self.request, 0, password))

		local status, response = self.socket:send(payload)
		if not status then
			self.socket:close()
			local brute_err = brute.Error:new(response)
			brute_err:setAbort(true)
			return false, brute_err
		end

		status, response = self.socket:receive_bytes(1)
		if (not status) or (response == "TIMEOUT") then
			local brute_err = brute.Error:new(response)
			brute_err:setRetry(false)
			return false, brute_err
		end

		if not port_set_open then
			port_set_open = true
			nmap.set_port_state(self.host, self.port, "open")
		end

		local result 
		_, result = snmp.decode(response)

		-- response contains valid community string
		if type(result) == "table" then
			-- keep only the first password as snmpcommunity, like the old script did
			if not nmap.registry.snmpcommunity then
				nmap.registry.snmpcommunity = result[2]
			end
			
			-- adding the credentials
			local c = creds.Credentials:new( SCRIPT_NAME, self.host, self.port )
			c:add(nil, result[2], creds.State.VALID)
			
			local brute_acc = brute.Account.new("", result[2], creds.State.VALID)
			return true, brute_acc
		end

		local err = brute.Error:new("Incorrect password")
		err:setRetry(false)
		return false, err

	end
}

action = function(host, port)
	if nmap.registry.snmpcommunity or nmap.registry.args.snmpcommunity then return end
	
	local engine = brute.Engine:new(Driver,host,port)
	
	--we want to search for both readonly and readwrite community strings
	-- engine.options.firstonly = false
	engine.options.passonly = true
	engine.options.script_name = SCRIPT_NAME
	
	status, result = engine:start()
	
	return result
end

