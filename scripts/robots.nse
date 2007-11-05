require('shortport')
require('strbuf')
require('stdnse')
require('listop')

id = "robots.txt"
author = "Eddie Bell <ejlbell@gmail.com>"
description = "Probes for a http servers robots.txt file and returns a summary of it"
license = "See nmaps COPYING for licence"
categories = {"intrusive"}
runlevel = 1.0

portrule = shortport.port_or_service(80, "http")

-- validates a robots.txt according to IETF conventions. Note
-- there is no standard governing robots.txt files but the
-- IETF document is the closes thing
local function validate(robot_txt)
	local function valid(line)
		return string.find(line, '^#.*') or
		string.find(line, '^user%-agent:.*') or
		string.find(line, '^disallow:.*') or
		string.find(line, '^allow:.') or
		string.len(line) == 0
	end

	-- test if the robots.txt data is valid
	local results = listop.map(valid, robot_txt)
	local invalid_lines = listop.filter(function(x) return not x end, results)
	return listop.is_empty(invalid_lines)
end

local function analyse_robots(r_data, output)
	local function is_present(line)
		if string.find(line, '^#.*') then return 1 
		elseif string.find(line, '^user%-agent:.*') then return 2
		elseif string.find(line, '^disallow:.*') then return 3
		else return 0
		end
	end

	local function gen_match(match_id, present)
		return listop.filter(function(x) return x == match_id end, present)
	end

	-- parse robots file and check for its elements
	local robot_txt = stdnse.strsplit("\n", r_data)
	local present = listop.map(is_present, robot_txt)
	
	if not listop.is_empty(gen_match(1, present)) then
		output = output .. "! contains disallowed entries\n"
	end

	if not listop.is_empty(gen_match(2, present)) then
		output = output .. "! mentions specific user-agents\n"
	end

	if not listop.is_empty(gen_match(3, present)) then
		output = output .. "! contains comments, which may be interesting\n"
	end

	if not validate(robot_txt) then
		output = output .. "! does not adhere to IETF conventions\n"
	end
end

action = function(host, port)
	local lines, status, soc, query, s, e
	local catch = function() soc.close() end
	local try = nmap.new_try(catch)

	-- connect to webserver 
	soc = nmap.new_socket()
	soc:set_timeout(4000)
	try(soc:connect(host.ip, port.number))
	
	-- test if robots.txt is present
	query = strbuf.new()
	query = query .. "GET /robots.txt HTTP/1.1"
	query = query .. "Accept: */*"
	query = query .. "Accept-Language: en"
	query = query .. "User-Agent: Nmap NSE"
	query = query .. "Host: " .. host.ip .. ":" .. port.number
	query = query .. '\r\n\r\n';
	try(soc:send(strbuf.dump(query, '\r\n')))

	local response = strbuf.new()
	local output = strbuf.new()

	while true do
		status, lines = soc:receive_lines(1)
		if not status then break end
		response = response .. lines
	end

	local hdata = strbuf.dump(response, '\n')

	if string.find(hdata, "HTTP/1.1 200 OK") then
		for w in string.gmatch(hdata, "Content%-Type:%s*([^\r\n]*)\r\n") do
			output = output .. w .. '\n'
		end

		-- remove http protocol stuff and analyse robots.txt file
		s, e = string.find(hdata, "\r\n\r\n")
		hdata = string.lower(hdata)
		if e then analyse_robots(string.sub(hdata, e), output) end
	end

	soc:close()
	try(soc:connect(host.ip, port.number))
	strbuf.clear(query)
	strbuf.clear(response)

	-- test to see if info.txt is present
	query = query .. "GET /info.txt HTTP/1.1"
	query = query .. "Accept: */*"
	query = query .. "Accept-Language: en"
	query = query .. "User-Agent: Nmap NSE"
	query = query .. "Host: " .. host.ip .. ":" .. port.number
	query = query .. '\r\n\r\n';
	try(soc:send(strbuf.dump(query, '\r\n')))

	while true do
		status, lines = soc:receive_lines(1)
		if not status then break end
		response = response .. lines
	end

	if string.find(strbuf.dump(response), "HTTP/1.1 200 OK") then
		output = output .. "\n! info.txt is present\n"
	end

	soc:close()

	if listop.is_empty(output) then 
		return nil 
	else 
		return strbuf.dump(output)
	end
end
