description = [[
Checks if an SMTP server is an open relay.
]]

-- Arturo 'Buanzo' Busleiman <buanzo@buanzo.com.ar> / www.buanzo.com.ar / linux-consulting.buanzo.com.ar
-- Same as Nmap--See http://nmap.org/book/man-legal.html file for licence details
-- This is version 20070516.
-- Changelog: 
--   * I changed it to the "demo" category until we figure out what
--     to do about using real hostnames. -Fyodor
--   + Added some strings to return in different places.
--   * Changed "HELO www.[ourdomain]" to "EHLO [ourdomain]".
--   * Fixed some API differences
--   * The "ourdomain" variable's contents are used instead of hardcoded "insecure.org". Settable by the user.
--   * Fixed tags -> categories (reported by Jason DePriest to nmap-dev)

categories = {"demo"}

require "shortport"
require "comm"

ourdomain="scanme.org"

portrule = shortport.port_or_service({25, 465, 587}, {"smtp", "smtps"})

action = function(host, port)
	local socket = nmap.new_socket()
	local result
	local status = true

	local mailservername
	local tor = {}
	local i

	opt = {timeout=10000, recv_before=true}
	socket, result = comm.tryssl(host, port, "EHLO " ..ourdomain.."\r\n", opt)
	if not socket then
		return "Unable to establish connection"
	end

	if (result == "TIMEOUT") then
		socket:close()
		return "Timeout. Try incresing settimeout, or enhance this."
	end

-- close socket and return if there's an smtp status code != 250
	if not string.match(result, "^250") then
		socket:close()
		return "EHLO with errors or timeout. Enable --script-trace to see what is happening."
	end

	mailservername = string.sub(result, string.find(result, '([.%w]+)',4))

-- read the rest of the response, if any

	while true do
		status, result = socket:receive_lines(1)
		if not status  then
			break
		end
	end

-- Now that we have the mailservername, fill in the tor table
	tor[0] = {f = "MAIL FROM:<spamtest@"..ourdomain..">",t="RCPT TO:<relaytest@"..ourdomain..">"}
	tor[1] = {f = "MAIL FROM:<>",t="RCPT TO:<relaytest@"..ourdomain..">"}
	tor[2] = {f = "MAIL FROM:<spamtest@[" .. host.ip .. "]>",t="RCPT TO:<relaytest@"..ourdomain..">"}
	tor[3] = {f = "MAIL FROM:<spamtest@" .. mailservername .. ">",t="RCPT TO:<relaytest@"..ourdomain..">"}
	tor[4] = {f = "MAIL FROM:<spamtest@[" .. host.ip .. "]>",t="RCPT TO:<relaytest%"..ourdomain.."@[" .. host.ip .. "]>"}
	tor[5] = {f = "MAIL FROM:<spamtest@[" .. host.ip .. "]>",t="RCPT TO:<relaytest%"..ourdomain.."@" .. mailservername .. ">"}
	tor[6] = {f = "MAIL FROM:<spamtest@[" .. host.ip .. "]>",t="RCPT TO:<\"relaytest@"..ourdomain.."\">"}
	tor[7] = {f = "MAIL FROM:<spamtest@[" .. host.ip .. "]>",t="RCPT TO:<\"relaytest%"..ourdomain.."\">"}
	tor[8] = {f = "MAIL FROM:<spamtest@[" .. host.ip .. "]>",t="RCPT TO:<relaytest@"..ourdomain.."@[" .. host.ip .. "]>"}
	tor[9] = {f = "MAIL FROM:<spamtest@[" .. host.ip .. "]>",t="RCPT TO:<\"relaytest@"..ourdomain.."\"@[" .. host.ip .. "]>"}
	tor[10] = {f = "MAIL FROM:<spamtest@[" .. host.ip .. "]>",t="RCPT TO:<relaytest@"..ourdomain.."@" .. mailservername .. ">"}
	tor[11] = {f = "MAIL FROM:<spamtest@[" .. host.ip .. "]>",t="RCPT TO:<@[" .. host.ip .. "]:relaytest@"..ourdomain..">"}
	tor[12] = {f = "MAIL FROM:<spamtest@[" .. host.ip .. "]>",t="RCPT TO:<@" .. mailservername .. ":relaytest@"..ourdomain..">"}
	tor[13] = {f = "MAIL FROM:<spamtest@[" .. host.ip .. "]>",t="RCPT TO:<"..ourdomain.."!relaytest>"}
	tor[14] = {f = "MAIL FROM:<spamtest@[" .. host.ip .. "]>",t="RCPT TO:<"..ourdomain.."!relaytest@[" .. host.ip .. "]>"}
	tor[15] = {f = "MAIL FROM:<spamtest@[" .. host.ip .. "]>",t="RCPT TO:<"..ourdomain.."!relaytest@" .. mailservername .. ">"}
	

	i = -1
	while true do
		i = i+1
		if i > table.getn(tor) then break end

-- for debugging, uncomment next line
--		print (tor[i]["f"] .. " -> " .. tor[i]["t"])

-- first, issue a RSET
		socket:send("RSET\r\n")
		status, result = socket:receive_lines(1)
		if not string.match(result, "^250") then
			socket:close()
			return
		end

-- send MAIL FROM....
		socket:send(tor[i]["f"].."\r\n")
		status, result = socket:receive_lines(1)
		if string.match(result, "^250") then
-- if we get a 250, then continue with RCPT TO:
			socket:send(tor[i]["t"].."\r\n")
			status, result = socket:receive_lines(1)
			if string.match(result, "^250") then
				socket:close()
				return "OPEN RELAY found."
			end
		end
	end

	socket:close()
	return
end
