description = [[
Detects the UDP IAX2 service.

The script sends an Inter-Asterisk eXchange (IAX) Revision 2 Control Frame POKE request and checks for a proper response.  This protocol is used to enable VoIP connections between servers as well as client-server communication.
]]

---
-- @output
-- PORT     STATE  SERVICE VERSION
-- 4569/udp closed iax2

author = "Ferdy Riphagen"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"version"}

require "comm"
require "shortport"

portrule = shortport.version_port_or_service(4569, nil, "udp")

action = function(host, port)
 	-- see http://www.cornfed.com/iax.pdf for all options.
	local poke = string.char(0x80, 0x00, 0x00, 0x00)
	poke = poke .. string.char(0x00, 0x00, 0x00, 0x00)  
	poke = poke .. string.char(0x00, 0x00, 0x06, 0x1e)

	local status, recv = comm.exchange(host, port, poke, {proto=port.protocol,timeout=10000})

	if not status then
		return
	end

	if (#recv) == 12 then
		local byte11 = string.format("%02X", string.byte(recv, 11))
		local byte12 = string.format("%02X", string.byte(recv, 12))

		-- byte11 must be \x06 IAX Control Frame
		-- and byte12 must be \x03 or \x04
		if ((byte11 == "06") and
		   (byte12 == ("03" or "04"))) 
		then
		    nmap.set_port_state(host, port, "open")
		    port.version.name = "iax2"
		    nmap.set_port_version(host, port, "hardmatched")
		end

	end
end
