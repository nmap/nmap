id = "Unexpected SMTP"
description = [[
Checks if SMTP is running on a non-standard port.

This usually indicates crackers or script kiddies have set up a backdoor on the
system to send spam or control your machine.
]]

---
-- @output
-- 22/tcp  open   ssh
-- |_ Unexpected SMTP: Warning: smtp is running on a strange port

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
	return "Warning: smtp is running on a strange port"
end

