description = [[
Retrieves disk space statistics from the remote NFS share
]]

---
-- @output
-- PORT    STATE SERVICE
-- | nfs-statfs:  
-- |   /home/storage/backup
-- |     Block size: 512
-- |     Total blocks: 1901338728
-- |     Free blocks: 729769328
-- |     Available blocks: 633186880
-- |   /home
-- |     Block size: 512
-- |     Total blocks: 1901338728
-- |     Free blocks: 729769328
-- |_    Available blocks: 633186880
--

-- Version 0.3

-- Created 01/25/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 02/22/2010 - v0.2 - adapted to support new RPC library
-- Revised 03/13/2010 - v0.3 - converted host to port rule


author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

require("shortport")
require("rpc")

portrule = shortport.port_or_service(111, "rpcbind", {"tcp", "udp"} )

action = function(host, port)

	local result, entry = {}, {}
	local status, mounts = rpc.Helper.ShowMounts( host, port )

	if ( not(status) ) then
		return "  \n\n  Failed to list mount points"
	end

	for _, v in ipairs( mounts ) do
		local entry = {}
		local status, stats = rpc.Helper.ExportStats(host, port, v.name)

		if ( not(status) and stats:match("Version %d not supported") ) then
			return "  \n\n  " .. stats
		end
				
		entry.name = v.name
		
		if status and stats then
			table.insert( entry, string.format("Block size: %d", stats.block_size) )
			table.insert( entry, string.format("Total blocks: %d", stats.total_blocks) )
			table.insert( entry, string.format("Free blocks: %d", stats.free_blocks) )
			table.insert( entry, string.format("Available blocks: %d", stats.available_blocks) )
		else
			table.insert( entry, "ERROR: Mount failed")
		end
		table.insert( result, entry )
	end	

	return stdnse.format_output( true, result )
	
end
