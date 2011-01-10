description = [[
Detects Minecraft username spoofing vulnerability.

Logging into a Minecraft multiplayer server requires online
authentication at minecraft.net. Some Minecraft servers
however are configured to run in an insecure mode making
it possible to play multiplayer games in the absence of Internet
connectivity. A server running in the insecure mode skips the
authentication letting anyone log in with any username.
A determined individual can use modified client software to log
into such insecure servers with a username registered to another
player.
]]

---
-- @output
-- 25565/tcp open  minecraft
-- |_minecraft-auth: vulnerable to username spoofing

author = "Toni Ruottu"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "vuln", "safe"}

require("bin")
require("nmap")
require("shortport")

portrule = shortport.port_or_service (25565, "minecraft", {"tcp"})

action = function( host, port )
	local HANDSHAKE_REQUEST = 2
	local HANDSHAKE_RESPONSE = 2

	local socket = nmap.new_socket()
	local status, _ = socket:connect(host.ip, port.number)
	if not status then
		return
	end

	--login name for the handshake
	--(we never actually try logging into the server)
	local login = "minecraft"

	socket:send(bin.pack("C>P", HANDSHAKE_REQUEST, login))
	status, data = socket:receive_bytes(4)
	socket:close()
	if not status then
		return
	end

	local _, packet_id, connection_hash = bin.unpack("C>P", data)
	if packet_id ~= HANDSHAKE_RESPONSE then
		return
	end
	if connection_hash ~= "-" then
		return
	end

	return "vulnerable to username spoofing"
end

