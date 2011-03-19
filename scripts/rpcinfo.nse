description = [[
Connects to portmapper and fetches a list of all registered programs.  It then prints out a table including (for each program) the RPC program number, supported version numbers, port number and protocol, and program name.
]]

---
-- @output
-- PORT    STATE SERVICE
-- 111/tcp open  rpcbind
-- | rpcinfo:  
-- |   100000  2        111/tcp  rpcbind
-- |   100000  2        111/udp  rpcbind
-- |   100003  2       2049/tcp  nfs
-- |   100003  2       2049/udp  nfs
-- |   100005  1,2      953/udp  mountd
-- |   100005  1,2      956/tcp  mountd
-- |   100024  1      55145/tcp  status
-- |_  100024  1      59421/udp  status

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "default", "safe"}

require 'stdnse'
require 'shortport'
require 'rpc'

portrule = shortport.port_or_service(111, "rpcbind", {"tcp", "udp"} )

action = function(host, port)

    local result = {}
    local status, rpcinfo = rpc.Helper.RpcInfo( host, port )    
    
    if ( not(status) ) then
        return stdnse.format_output(false, rpcinfo)
    end
    
    for progid, v in pairs(rpcinfo) do
        for proto, v2 in pairs(v) do
            table.insert( result, ("%-7d %-10s %5d/%s  %s"):format(progid, stdnse.strjoin(",", v2.version), v2.port, proto, rpc.Util.ProgNumberToName(progid) or "") )
        end
    end
    
    table.sort(result)
    return stdnse.format_output( true, result )
    
end
