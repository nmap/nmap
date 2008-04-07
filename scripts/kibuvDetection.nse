id = "Kibuv worm"

description = "\
A fake FTP server was installed by the KIBUV.B worm \
on this port. This worm uses known security flaws to \
infect the system. \
\
This machine may already be a 'zombi' used by crackers  \
to perform distributed denial of service. \
\
http://www.trendmicro.com/vinfo/virusencyclo/default5.asp?VName=WORM_KIBUV.B&VSect=T"

author = "Diman Todorov <diman.todorov@gmail.com>"

license = "Same as Nmap--See http://nmap.org/man/man-legal.html"

categories = {"malware"}

require "shortport"

portrule = shortport.port_or_service({7955, 14920, 42260}, "ftp")

action = function(host, port)
	local socket = nmap.new_socket()

	socket:connect(host.ip, port.number)
	local status, s = socket:receive_lines(1)

	if	string.match(s, "220 StnyFtpd 0wns j0")
		or
		string.match(s, "220 fuckFtpd 0wns j0")
	then 
		return "Suspecting that the host is KIBUV.B infected"
	end

	return 
end
