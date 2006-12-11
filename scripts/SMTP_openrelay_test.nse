-- Arturo 'Buanzo' Busleiman <buanzo@buanzo.com.ar> / www.buanzo.com.ar / linux-consulting.buanzo.com.ar
-- See Nmap'ss COPYING file for licence details
-- This is version 20060927.
-- Changelog: + Added some strings to return in different places.
--            * Changed "HELO www.insecure.org" to "EHLO insecure.org".

id="Open Relay SMTP"
description="Checks to see if a SMTP server is an open relay"
tags = {"intrusive"}

portrule = function(host, port)
	if 	(port.number == 25
		or port.service == "smtp")
		and port.state == "open"
		and port.protocol == "tcp"
	then
		return true
	else
		return false
	end
end

action = function(host, port)
	local socket = nmap.new_socket()
	local result
	local status = true

	local mailservername
	local tor = {}
	local i

	local catch = function()
		socket:close()
	end

	local try = nmap.new_try(catch)

	try(socket:connect(host.ip, port.number, port.protocol))
	
	result = try(socket:receive_lines(1))

-- Introduce ourselves...
	try(socket:send("EHLO insecure.org\n"))
	result = try(socket:receive_lines(1))

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
	tor[0] = {f = "MAIL FROM:<spamtest@insecure.org>",t="RCPT TO:<relaytest@insecure.org>"}
	tor[1] = {f = "MAIL FROM:<>",t="RCPT TO:<relaytest@insecure.org>"}
	tor[2] = {f = "MAIL FROM:<spamtest@[" .. host.ip .. "]>",t="RCPT TO:<relaytest@insecure.org>"}
	tor[3] = {f = "MAIL FROM:<spamtest@" .. mailservername .. ">",t="RCPT TO:<relaytest@insecure.org>"}
	tor[4] = {f = "MAIL FROM:<spamtest@[" .. host.ip .. "]>",t="RCPT TO:<relaytest%insecure.org@[" .. host.ip .. "]>"}
	tor[5] = {f = "MAIL FROM:<spamtest@[" .. host.ip .. "]>",t="RCPT TO:<relaytest%insecure.org@" .. mailservername .. ">"}
	tor[6] = {f = "MAIL FROM:<spamtest@[" .. host.ip .. "]>",t="RCPT TO:<\"relaytest@insecure.org\">"}
	tor[7] = {f = "MAIL FROM:<spamtest@[" .. host.ip .. "]>",t="RCPT TO:<\"relaytest%insecure.org\">"}
	tor[8] = {f = "MAIL FROM:<spamtest@[" .. host.ip .. "]>",t="RCPT TO:<relaytest@insecure.org@[" .. host.ip .. "]>"}
	tor[9] = {f = "MAIL FROM:<spamtest@[" .. host.ip .. "]>",t="RCPT TO:<\"relaytest@insecure.org\"@[" .. host.ip .. "]>"}
	tor[10] = {f = "MAIL FROM:<spamtest@[" .. host.ip .. "]>",t="RCPT TO:<relaytest@insecure.org@" .. mailservername .. ">"}
	tor[11] = {f = "MAIL FROM:<spamtest@[" .. host.ip .. "]>",t="RCPT TO:<@[" .. host.ip .. "]:relaytest@insecure.org>"}
	tor[12] = {f = "MAIL FROM:<spamtest@[" .. host.ip .. "]>",t="RCPT TO:<@" .. mailservername .. ":relaytest@insecure.org>"}
	tor[13] = {f = "MAIL FROM:<spamtest@[" .. host.ip .. "]>",t="RCPT TO:<insecure.org!relaytest>"}
	tor[14] = {f = "MAIL FROM:<spamtest@[" .. host.ip .. "]>",t="RCPT TO:<insecure.org!relaytest@[" .. host.ip .. "]>"}
	tor[15] = {f = "MAIL FROM:<spamtest@[" .. host.ip .. "]>",t="RCPT TO:<insecure.org!relaytest@" .. mailservername .. ">"}
	

	i = -1
	while true do
		i = i+1
		if i > table.getn(tor) then break end

-- for debugging, uncomment next line
--		print (tor[i]["f"] .. " -> " .. tor[i]["t"])

-- first, issue a RSET
		try(socket:send("RSET\n"))
		result = try(socket:receive_lines(1))
		if not string.match(result, "^250") then
			socket:close()
			return "RSET with errors. Enable --script-trace to see what is happening."
		end

-- send MAIL FROM....
		try(socket:send(tor[i]["f"].."\n"))
		result = try(socket:receive_lines(1))
		if string.match(result, "^250") then
-- if we get a 250, then continue with RCPT TO:
			try(socket:send(tor[i]["t"].."\n"))
			result = try(socket:receive_lines(1))
			if string.match(result, "^250") then
				socket:close()
				return "OPEN RELAY found."
			end
		end
	end

	socket:close()
	return "Relaying denied."
end
