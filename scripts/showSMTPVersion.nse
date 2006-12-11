id = "SMTP version"

description = "Simple script which queries and prints the version of an SMTP server."

author = "Diman Todorov <diman.todorov@gmail.com>"

license = "See nmaps COPYING for licence"

categories = {"demo"}

portrule = function(host, port) 
	local decision
	
	if 
		(	port.number == 25
			or port.service == "smtp")
		and port.protocol == "tcp" 
		and port.state == "open"
	then
		decision = true
	else
		decision = false
	end

	return decision
end

action = function(host, port)
	
	local client = nmap.new_socket()

	client:connect(host.ip, port.number)
	
	local status, result = client:receive_lines(1);

	client:close()	

	if result ~= nil then
		result = string.gsub(result, "\n", "")
	end

	return result
end

