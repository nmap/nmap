local nmap = require "nmap"
local shortport = require "shortport"
local sip = require "sip"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Enumerates a SIP Server's allowed methods (INVITE, OPTIONS, SUBSCRIBE, etc.)

The script works by sending an OPTION request to the server and checking for
the value of the Allow header in the response.
]]

---
-- @usage
-- nmap --script=sip-methods -sU -p 5060 <targets>
--
--@output
-- 5060/udp open  sip
-- | sip-methods: 
-- |_  INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO


author = "Hani Benhabiles"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "safe", "discovery"}


portrule = shortport.port_or_service(5060, "sip", {"tcp", "udp"})

action = function(host, port)
    local status, session, response
    session = sip.Session:new(host, port)
    status = session:connect()
    if not status then
	return "ERROR: Failed to connect to the SIP server."
    end

    status, response = session:options()
    if status then
	-- If port state not set to open, set it to open.
	if nmap.get_port_state(host, port) ~= "open" then
	    nmap.set_port_state(host, port, "open")
	end

	-- Check if allow header exists in response
	local allow = response:getHeader("allow")
	if allow then
	    return stdnse.format_output(true, allow)
	end
    end
end
