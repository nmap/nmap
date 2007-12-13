require('shortport')
require('strbuf')
require('listop')

id = "robots.txt"
author = "Eddie Bell <ejlbell@gmail.com>"
description = "Download a http servers robots.txt file and display all disallowed entries"
license = "See nmaps COPYING for licence"
categories = {"safe"}
runlevel = 1.0

portrule = shortport.port_or_service(80, "http")
local last_len = 0

-- split the output in 40 character lines 
local function buildOutput(output, w)
	local len = string.len(w)

	for i,v in ipairs(output) do
		if w == v then return nil end
	end
	
	if last_len == 0 or last_len + len <= 40 then
		last_len = last_len + len
	else
		output = output .. '\n'
		last_len = 0
	end

	output = output .. w 
	output = output .. ' '
end

action = function(host, port)
	local soc, lines, status

	local catch = function() soc.close() end
	local try = nmap.new_try(catch)

	-- connect to webserver 
	soc = nmap.new_socket()
	soc:set_timeout(4000)
	try(soc:connect(host.ip, port.number))

	local query = strbuf.new()
	query = query .. "GET /robots.txt HTTP/1.1"
	query = query .. "Accept: */*"
	query = query .. "Accept-Language: en"
	query = query .. "User-Agent: Nmap NSE"
	query = query .. "Host: " .. host.ip .. ":" .. port.number
	query = query .. '\r\n\r\n';
	try(soc:send(strbuf.dump(query, '\r\n')))

	local response = strbuf.new()
	while true do
		status, lines = soc:receive_lines(1)
		if not status then break end
		response = response .. lines
	end

	if not string.find(strbuf.dump(response), "HTTP/1.1 200 OK") then
		return nil
	end

	-- parse all disallowed entries and remove comments
	local output = strbuf.new()
	for w in string.gmatch(strbuf.dump(response, '\n'), "Disallow:%s*([^\n]*)\n") do
			w = w:gsub("%s*#.*", "")
			buildOutput(output, w)
	end

	if not listop.is_empty(output) then
		return strbuf.dump(output)
	end

	return nil
end
