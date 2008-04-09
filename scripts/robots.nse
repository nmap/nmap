require('shortport')
require('strbuf')
require('listop')
require('http')

id = "robots.txt"
author = "Eddie Bell <ejlbell@gmail.com>"
description = "Download a http servers robots.txt file and display all disallowed entries"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"safe"}
runlevel = 1.0

portrule = shortport.port_or_service({80,443}, {"http","https"})
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
	local answer = http.get( host, port, "/robots.txt" )

	if answer.status ~= 200 then
		return nil
	end

	-- parse all disallowed entries and remove comments
	local output = strbuf.new()
	for w in string.gmatch(answer.body, "Disallow:%s*([^\n]*)\n") do
			w = w:gsub("%s*#.*", "")
			buildOutput(output, w)
	end

	if not listop.is_empty(output) then
		return strbuf.dump(output)
	end

	return nil
end
