id = "SMTP version"

description = "Simple script which queries and prints the version of an SMTP server."

author = "Diman Todorov <diman.todorov@gmail.com>"

license = "Same as Nmap--See http://nmap.org/man/man-legal.html"

categories = {"demo"}

require "shortport"

portrule = shortport.port_or_service(25, "smtp")

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

