description = [[
Connects to portmapper and fetches a list of all registered programs.  It then prints out a table including (for each program) the RPC program number, supported version numbers, port number and protocol, and program name.
]]

---
-- @output
-- PORT    STATE SERVICE
-- 111/tcp open  rpcbind
-- | rpcinfo: 
-- |   program version   port/proto  service
-- |   100000  2,3,4        111/tcp  rpcbind
-- |   100000  2,3,4        111/udp  rpcbind
-- |   100001  2,3,4      32774/udp  rstatd
-- |   100002  2,3        32776/udp  rusersd
-- |   100002  2,3        32780/tcp  rusersd
-- |   100011  1          32777/udp  rquotad
-- |   100021  1,2,3,4     4045/tcp  nlockmgr
-- |   100021  1,2,3,4     4045/udp  nlockmgr
-- |   100024  1          32771/tcp  status
-- |   100024  1          32773/udp  status
-- |   100068  2,3,4,5    32775/udp  cmsd
-- |   100083  1          32779/tcp  ttdbserverd
-- |   100133  1          32771/tcp  nsm_addrand
-- |   100133  1          32773/udp  nsm_addrand
-- |   100229  1,2        32775/tcp  metad
-- |   100230  1          32778/tcp  metamhd
-- |   100242  1          32777/tcp  rpc.metamedd
-- |   100249  1          32780/udp  snmpXdmid
-- |   100249  1          32781/tcp  snmpXdmid
-- |   100422  1          32776/tcp  mdcommd
-- |   1073741824 1          32772/tcp  fmproduct
-- |   300598  1          32782/tcp  dmispd
-- |   300598  1          32783/udp  dmispd
-- |   805306368 1          32782/tcp  dmispd
-- |_  805306368 1          32783/udp  dmispd

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

    if (#result > 0) then
        table.insert(result, 1, "program version   port/proto  service")
    end

    return stdnse.format_output( true, result )
    
end
