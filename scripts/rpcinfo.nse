local nmap = require "nmap"
local rpc = require "rpc"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Connects to portmapper and fetches a list of all registered programs.  It then
prints out a table including (for each program) the RPC program number,
supported version numbers, port number and protocol, and program name.
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
--@xmloutput
--<table>
--  <table key="100003">
--    <table key="tcp">
--      <elem key="port">2049</elem>
--      <table key="version">
--        <elem>2</elem> <elem>3</elem> <elem>4</elem>
--      </table>
--    </table>
--    <table key="udp">
--      <elem key="port">2049</elem>
--      <table key="version">
--        <elem>2</elem> <elem>3</elem> <elem>4</elem>
--      </table>
--    </table>
--  </table>
--  <table key="100000">
--    <table key="tcp">
--      <elem key="port">111</elem>
--      <table key="version">
--        <elem>2</elem> <elem>3</elem> <elem>4</elem>
--      </table>
--    </table>
--    <table key="udp">
--      <elem key="port">111</elem>
--      <table key="version">
--        <elem>2</elem> <elem>3</elem> <elem>4</elem>
--      </table>
--    </table>
--  </table>
--</table>

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "default", "safe", "version"}


-- don't match "rpcbind" because that's what version scan labels any RPC service
portrule = shortport.portnumber(111, {"tcp", "udp"} )

action = function(host, port)

  local result = {}
  local status, rpcinfo = rpc.Helper.RpcInfo( host, port )
  local xmlout = {}

  if ( not(status) ) then
    return stdnse.format_output(false, rpcinfo)
  end

  for progid, v in pairs(rpcinfo) do
    xmlout[tostring(progid)] = v
    for proto, v2 in pairs(v) do
      if proto == "tcp" or proto == "udp" then
        local nmapport = nmap.get_port_state(host, {number=v2.port, protocol=proto})
        if nmapport and (nmapport.state == "open" or nmapport.state == "open|filtered") then
          nmapport.version = nmapport.version or {}
          -- If we don't already know it, or we only know that it's "rpcbind"
          if nmapport.service == nil or nmapport.version.service_dtype == "table" or port.service == "rpcbind" then
            nmapport.version.name = rpc.Util.ProgNumberToName(progid)
            nmapport.version.extrainfo = "RPC #" .. progid
            if #v2.version > 1 then
              nmapport.version.version = ("%d-%d"):format(v2.version[1], v2.version[#v2.version])
            else
              nmapport.version.version = tostring(v2.version[1])
            end
            nmap.set_port_version(host, nmapport, "softmatched")
          end
        end
      end

      table.insert( result, ("%-7d %-10s %5d/%s  %s"):format(progid, stdnse.strjoin(",", v2.version), v2.port, proto, rpc.Util.ProgNumberToName(progid) or "") )
    end
  end

  table.sort(result)

  if (#result > 0) then
    table.insert(result, 1, "program version   port/proto  service")
  end

  return xmlout, stdnse.format_output( true, result )
end
