description = [[
Checks if SMTP is running on a non-standard port.

This may indicate that crackers or script kiddies have set up a backdoor on the
system to send spam or control the machine.
]]

---
-- @output
-- 22/tcp  open   smtp
-- |_ smtp-strangeport: Mail server on unusual port: possible malware

author = "Diman Todorov <diman.todorov@gmail.com>"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"malware"}

portrule = function(host, port) 
	if 
		(	port.number ~= 25
			and
			port.number ~= 465
			and
			port.number ~= 587
			and 
			port.service == "smtp" )
		and port.protocol == "tcp" 
		and port.state == "open"
	then
		return true
	else
		return false
	end
end

action = function()
	return "Mail server on unusual port: possible malware"
end

