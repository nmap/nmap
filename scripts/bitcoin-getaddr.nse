description = [[
Queries a BitCoin server for a list of known BitCoin nodes
]]

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

require 'shortport'
require 'bitcoin'
require 'tab'

portrule = shortport.port_or_service(8333, "bitcoin", "tcp" )

action = function(host, port)
	
	local bcoin = bitcoin.Helper:new(host, port, { timeout = 10000 })
	local status = bcoin:connect()
	
	if ( not(status) ) then
		return "\n  ERROR: Failed to connect to server"
	end
	
	local status, ver = bcoin:exchVersion()
	if ( not(status) ) then
		return "\n  ERROR: Failed to extract version information"
	end
	
	local status, nodes = bcoin:getNodes()
	if ( not(status) ) then
		return "\n  ERROR: Failed to extract version information"
	end
	bcoin:close()

	local response = tab.new(2)
	tab.addrow(response, "ip", "timestamp")

	for _, node in ipairs(nodes.addresses) do
		tab.addrow(response, ("%s:%d"):format(node.address.host, node.address.port), os.date("%x %X", node.ts))
	end

	return stdnse.format_output(true, tab.dump(response) )
end