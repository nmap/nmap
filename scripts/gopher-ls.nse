description = [[
Lists files and directories at the root of a gopher service.
]]

---
-- @output
-- 70/tcp open  gopher
-- | gopher-ls:
-- | [txt] Gopher, the next big thing?
-- |_[dir] Tax Forms

author = "Toni Ruottu"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

require("nmap")
require("stdnse")
require("shortport")

portrule = shortport.port_or_service (70, "gopher", {"tcp"})

local function typelabel(type)
	if type == "0" then
		return "[txt]"
	end
	if type == "1" then
		return "[dir]"
	end
	return string.format("[%s]", type)

end

action = function( host, port )

	local socket = nmap.new_socket()
	local status, err = socket:connect(host.ip, port.number)
	if not status then
		return
	end
	
	socket:send("\r\n")

	local buffer, _ = stdnse.make_buffer(socket, "\r\n")
	local line = buffer()
	local files = {}

	while line ~= nil do
		local fields = stdnse.strsplit("\t", line)
		local first = fields[1]
		if #first > 1 then
			local type = string.sub(first, 1, 1)
			if type ~= "i" then
				local label = string.sub(first, 2)
				table.insert(files, string.format("%s %s", typelabel(type), label))
			end
		end
		line = buffer()
	end
	return "\n" .. stdnse.strjoin("\n", files)
end

