--- Queries the version from an SSH Server. This typically does not result
-- in any logs of the connection being made.
--@output
-- 22/tcp  open   ssh\n
-- |_ Stealth SSH version: SSH-2.0-OpenSSH_3.9p1\n

id = "Stealth SSH version"

description = "Connects to an SSH server, queries the version string and echos it back. This tends to result\
in the scanning attempt not being logged by the ssh daemon on the target."

author = "Diman Todorov <diman.todorov@gmail.com>"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"demo"}

require "shortport"

portrule = shortport.service("ssh")

action = function(host, port)
	local result, socket

	local catch = function()
		socket:close()
	end

	local try = nmap.new_try(catch)

	result = ""
	socket = nmap.new_socket()

	try(socket:connect(host.ip, port.number))

	result = try(socket:receive_lines(1));
	try(socket:send(result))
	try(socket:close())

	return (string.gsub(result, "\n", ""))
end

