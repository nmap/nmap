description = [[
Does a directory listing of a remote NFS share
]]

---
-- @output
-- PORT    STATE SERVICE
-- 111/tcp open  rpcbind
-- | nfs-dirlist:  
-- |   /home/storage/backup
-- |     www.cqure.net
-- |   /home
-- |     admin
-- |     lost+found
-- |     patrik
-- |     storage
-- |_    web
--
-- @args nfs-dirlist.maxfiles If set limits the amount of files returned by the
--       script for each export. If set to zero or less all files are shown.
--       (default 10)


-- Version 0.3
--
-- Created 01/25/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 02/22/2010 - v0.2 - adapted to support new RPC library
-- Revised 03/13/2010 - v0.3 - converted host to port rule
-- Revised 03/28/2010 - v0.4 - changed and documented maxfiles argument

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

require("shortport")
require("rpc")

portrule = shortport.port_or_service(111, "rpcbind", {"tcp", "udp"} )

action = function(host, port)

	local status, mounts
	local result, files = {}, {}
	local hasmore = false
    local proto

	status, mounts = rpc.Helper.ShowMounts( host, port )

	if ( not(status) ) then
		return "  \n\n  Failed to list mount points"
	end

	for _, v in ipairs( mounts ) do
		local files = {}
		local status, dirlist = rpc.Helper.Dir(host, port, v.name)
			
		if status and dirlist then
			local max_files = tonumber(nmap.registry.args['nfs-dirlist.maxfiles']) or 10
			
			hasmore = false
			for _, v in ipairs( dirlist.entries ) do
				if ( ( 0 < max_files ) and ( #files >= max_files ) ) then
					hasmore = true
					break
				end

				if v.name ~= ".." and v.name ~= "." then
					table.insert(files, v.name)
				end				
			end

			table.sort(files)
			
			if hasmore then
				files.name = v.name .. string.format(" (Output limited to %d files)", max_files )
			else
				files.name = v.name
			end

			table.insert( result, files )
		else
			files.name = v.name
			table.insert(files, "ERROR: Mount failed")
			table.insert( result, files )
		end
		
	end	

	return stdnse.format_output( true, result )
	
end
