id= "IAX2 Service Detection"

description = "Detects an listening UDP IAX2 service by using a \
				IAX Control Frame POKE request." 

author = "Ferdy Riphagen <f.riphagen@nsec.nl>"

license = "Same as Nmap--See http://nmap.org/man/man-legal.html"

categories = {"version"}

require "shortport"

portrule = shortport.portnumber(4569, "udp")

action = function(host, port)
	local soc = nmap.new_socket()
	soc:set_timeout(10000)
	local conn = soc:connect(host.ip, port.number, port.protocol)

	if (conn) then
	 	-- see http://www.cornfed.com/iax.pdf for all options.
		local poke = string.char(0x80, 0x00, 0x00, 0x00)
		poke = poke .. string.char(0x00, 0x00, 0x00, 0x00)  
		poke = poke .. string.char(0x00, 0x00, 0x06, 0x1e)
		soc:send(poke)

		local status, recv
		status, recv = soc:receive_bytes(1)
        
		if (string.len(recv)) == 12 then
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

		soc:close()

	end

end
