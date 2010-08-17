description = [[
Shows NFS exports, like the <code>showmount -e</code> command.
]]

---
-- @output
-- PORT    STATE SERVICE
-- 111/tcp open  rpcbind
-- | nfs-showmount:  
-- |   /home/storage/backup 10.46.200.0/255.255.255.0
-- |_  /home 1.2.3.4/255.255.255.255 10.46.200.0/255.255.255.0
--

-- Version 0.7

-- Created 11/23/2009 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 11/24/2009 - v0.2 - added RPC query to find mountd ports
-- Revised 11/24/2009 - v0.3 - added a hostrule instead of portrule
-- Revised 11/26/2009 - v0.4 - reduced packet sizes and documented them
-- Revised 01/24/2009 - v0.5 - complete rewrite, moved all NFS related code into nselib/nfs.lua
-- Revised 02/22/2009 - v0.6 - adapted to support new RPC library
-- Revised 03/13/2010 - v0.7 - converted host to port rule


author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

require("stdnse")
require("shortport")
require("rpc")

portrule = shortport.port_or_service(111, "rpcbind", {"tcp", "udp"} )

action = function(host, port)

    local status, mounts, proto 
    local result = {}
    
    status, mounts = rpc.Helper.ShowMounts( host, port )

    if not status or mounts == nil then
        return stdnse.format_output(false, mounts)
    end

    for _, v in ipairs( mounts ) do
        local entry = v.name
        entry = entry .. " " .. stdnse.strjoin(" ", v)
        table.insert( result, entry )
    end
    
    return stdnse.format_output( true, result )
    
end
