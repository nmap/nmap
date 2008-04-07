id = "Unexpected SMTP"

description = "\
If smtp is running on a strange port\
there be a backdoor set up by crackers to send spam\
or even control your machine."

author = "Diman Todorov <diman.todorov@gmail.com>"

license = "Same as Nmap--See http://nmap.org/man/man-legal.html"

categories = {"backdoor"}

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

