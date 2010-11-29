description = [[
Reads hard disk information from hddtemp service.
]]

---
-- @output
-- 7634/tcp open  hddtemp
-- |_hddtemp-info: /dev/sda: WDC WD2500JS-60MHB1: 38 C

author = "Toni Ruottu"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

require("comm")
require("shortport")

portrule = shortport.port_or_service (7634, "hddtemp", {"tcp"})

action = function( host, port )
	local status, data = comm.get_banner(host, port)
	if not status then
		return
	end
	local fields = stdnse.strsplit("|", data)
	local info = {}
	local disks = math.floor((# fields) / 5)
	for i = 0, (disks - 1) do
		local start = i * 5
		local device = fields[start + 2]
		local label = fields[start + 3]
		local temperature = fields[start + 4]
		local unit = fields[start + 5]
		local formatted = string.format("%s: %s: %s %s", device, label, temperature, unit)
		table.insert(info, formatted)
	end
	return stdnse.format_output(true, info)
end
