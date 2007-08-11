id="Finger Results"

description="attempts to get a list of usernames via the finger service"

author = "Eddie Bell <ejlbell@gmail.com>"

license = "See nmaps COPYING for licence"

categories = {"discovery"}

portrule = function(host, port)
	if 	(port.number == 79 
		or port.service == "finger")
		and port.protocol == "tcp"
		and port.state == "open"
	then
		return true
	else
		return false
	end
end

action = function(host, port)
	local socket = nmap.new_socket()
	local results = ""
	local status = true

	local err_catch = function()
		socket:close()
	end

	local try = nmap.new_try(err_catch())

	socket:set_timeout(5000)
	try(socket:connect(host.ip, port.number, port.protocol))
       	try(socket:send("\n\r"))

	status, results = socket:receive_lines(100)
	socket:close()

	if not(status) then
		return results
	end
end
