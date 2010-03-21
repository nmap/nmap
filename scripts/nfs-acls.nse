description = [[
Shows NFS exports and access controls.
]]

---
-- @output
-- PORT    STATE SERVICE
-- 111/tcp open  rpcbind
-- | nfs-acls:  
-- |   /tmp
-- |     uid: 0; gid: 0; mode: drwxrwxrwx (1777)
-- |   /home/storage/backup
-- |     uid: 0; gid: 0; mode: drwxr-xr-x (755)
-- |   /home
-- |_    uid: 0; gid: 0; mode: drwxr-xr-x (755)
--

-- Version 0.6

-- Created 11/23/2009 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 11/24/2009 - v0.2 - added RPC query to find mountd ports
-- Revised 11/24/2009 - v0.3 - added a hostrule instead of portrule
-- Revised 11/26/2009 - v0.4 - reduced packet sizes and documented them
-- Revised 01/24/2009 - v0.5 - complete rewrite, moved all NFS related code into nselib/nfs.lua
-- Revised 02/22/2009 - v0.6 - adapted to support new RPC library


author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

require("shortport")
require("rpc")

portrule = shortport.port_or_service(111, "rpcbind", {"tcp", "udp"} )

action = function(host, port)

	local status, mounts, attribs
	local result = {}
	
	status, mounts = rpc.Helper.ShowMounts( host, port )

	if ( not(status) or mounts == nil ) then
		return "  \n\n  Failed to list mount points"
	end

	for _, mount in ipairs( mounts ) do
		local item = {}
		status, attribs = rpc.Helper.GetAttributes( host, port, mount.name )

		item.name = mount.name

		if ( status ) then
			table.insert(item, ("uid: %d; gid: %d; mode: %s (%d)"):format(attribs.uid, attribs.gid, rpc.Util.ToAclText( attribs.mode ), rpc.Util.ToAclMode( attribs.mode )) )
		else
			table.insert(item, "ERROR: Mount failed")
		end
		
		table.insert(result, item)
	end	
	
	return stdnse.format_output( true, result )
	
end
