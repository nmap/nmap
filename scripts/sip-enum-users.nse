description = [[
Attempts to enumerate valid user account using SIP. Currently only the SIP
server Asterisk is supported. 

* Asterisk
	- The script enumerates valid accounts by checking the SIP servers response
	  to the REGISTER request. If TRYING is returned, the account does not
	  exist. If REGISTER is returned the account is valid.
]]

---
-- @usage
-- nmap -sU -p 5060 <target> --script=sip-brute
--
-- PORT     STATE         SERVICE
-- 5060/udp open|filtered sip
-- | sip-enum-users: 
-- |   Valid SIP accounts
-- |     1000
-- |_    1001

-- Version 0.1
-- Created 04/03/2011 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "auth"}

require "shortport"
require "sip"
require "unpwdb"

portrule = shortport.port_or_service(5060, "sip", "udp")

-- Send a register request to the server and returned the unparsed response
-- @param session instance of Session class
-- @param username string containing the name of the user
-- @return status true on success false on failure
-- @return response instance of sip.Response (on success)
-- @return err string containing the error message (on failure)
local function register(session, username)
	local request = sip.Request:new(sip.Method.REGISTER)
	local callid = sip.Util.get_random_string(20)

	session.sessdata:setUsername(username)
	request:setUri("sip:" .. session.sessdata:getServer() )
	request:setSessionData(session.sessdata)
	request:setCallId(callid)
	request:setExpires(0)
	request:setAllow({"PRACK","INVITE","ACK","BYE","CANCEL","UPDATE",
						"SUBSCRIBE","NOTIFY","REFER","MESSAGE","OPTIONS"})
	request:setContentLength(0)
	
	local status, response = session:exch(request)
	if (not(status)) then return false, response end
	
	return true, response
end


-- Confirm the server is a valid and supported one
-- @param host table as passed to the action method
-- @param port table as passed to the action method
-- @return status true on success, false on failure
-- @return header string containing the server name
local function confirmServer(host, port)
	local user = "nmap_banner_check"
	local session = sip.Session:new( host, port )

	local status = session:connect()
	if ( not(status) ) then
		return "ERROR: Failed to connect to the SIP server"
	end

	local response
	status, response = register(session, user)
	if ( status ) then
		return true, ( 
				response:getHeader("User-Agent") or 
				response:getHeader("Server") 
				)
	end

	return false
end

-- Asterisk specific function used to check for valid usernames
-- @param session instance of SIP Session
-- @param username string containing the SIP username
-- @return status true on success, false on failure
-- @return err on failure
local function checkAsteriskUsername(session, username)
	local status, response = register(session, username)
	if ( status and response:getErrorCode() == 401 ) then
		return true, "SUCCESS"
	end
	return false, "FAILURE"
end

-- Table containing a server match and corresponding check function
local detectiontbl = {
	{ name="^Asterisk PBX", func=checkAsteriskUsername }
}

action = function(host, port)
	local accounts = {}
	local status, usernames = unpwdb.usernames()
	if ( not(status) ) then return false, "Failed to load usernames" end

	local server
	status, server = confirmServer( host, port )
	if ( not(status) ) then
		return "ERROR: Failed to determine server version"
	end

	local checkUsername
	for _, item in ipairs( detectiontbl ) do
		if ( server and server:match( item.name ) ) then
			checkUsername = item.func
			break
		end
	end
	
	if ( not(checkUsername) ) then return ("ERROR: Unsupported server (%s)"):format((server or "")) end

	for username in usernames do
		local session = sip.Session:new( host, port )

		local status = session:connect()
		if ( not(status) ) then
			return "ERROR: Failed to connect to the SIP server"
		end
	
		local status, err = checkUsername( session, username )
		if ( status ) then table.insert( accounts, username ) end
		
		session:close()
	end
	
	accounts.name = "Valid SIP accounts"
	return stdnse.format_output(true, { accounts } )
	
end