id = "Nameserver open recursive querys (CVE-1999-0024) (BID 136, 678)"

description = "Checks whether a Nameserver on udp/53 allows querys for third-party names. If is expected that recursion will be enabled on your own internal nameserver."

author = "Felix Groebert <felix@groebert.org>"

license = "See nmaps COPYING for licence"

categories = {"intrusive"}

require "bit"

portrule = function(host, port)
	if 	port.number == 53
		and port.protocol == "udp"
	then
		return true
	else
		return false
	end
end

action = function(host, port)

    -- generate dns query, Transaction-ID 0xdead, isc.sans.org (type A, class IN)
	local request = string.char(0xde, 0xad, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03) ..  "isc" .. string.char(0x04) .. "sans" .. string.char(0x03) ..  "org" .. string.char(0x00, 0x00, 0x01, 0x00, 0x01)

	local socket = nmap.new_socket()
	socket:connect(host.ip, port.number, "udp")
	socket:send(request)

	local status, result = socket:receive();
	socket:close()

    -- parse response for dns flags
    if (bit.band(string.byte(result,3), 0x80) == 0x80
    and bit.band(string.byte(result,4), 0x85) == 0x80)
    then
		return "Recursion seems enabled"
    else
		return "Recursion not enabled"
	end

	return
end
