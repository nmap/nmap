description = [[
Checks if SMTP is running on a non-standard port.

This may indicate that crackers or script kiddies have set up a backdoor on the
system to send spam or control the machine.
]]

---
-- @output
-- 22/tcp  open   smtp
-- |_ smtp-strangeport: Mail server on unusual port: possible malware

author = "Diman Todorov"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"malware", "safe"}

portrule = function(host, port) 
	return port.service == "smtp" and
		port.number ~= 25 and port.number ~= 465 and port.number ~= 587
		and port.protocol == "tcp" 
		and port.state == "open"
end

action = function()
	return "Mail server on unusual port: possible malware"
end

