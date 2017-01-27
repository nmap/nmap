local anyconnect = require('anyconnect')
local stdnse = require('stdnse')
local shortport = require('shortport')
local nmap = require('nmap')

description = [[
Connect as Cisco AnyConnect client to a Cisco SSL VPN and retrieves version
and tunnel information.
]]

---
-- @usage
-- nmap -p 443 --script http-cisco-anyconnect <target>
--
-- @output
-- PORT    STATE SERVICE REASON
-- 443/tcp open  https   syn-ack
-- | http-cisco-anyconnect:
-- |   version: 9.1(5)
-- |   tunnel-group: VPN
-- |   group-alias: vpn
-- |   config-hash: 7328433471719
-- |_  host: vpn.example.com
--
-- @xmloutput
-- <elem key="version">9.1(5)</elem>
-- <elem key="tunnel-group">VPN</elem>
-- <elem key="group-alias">vpn</elem>
-- <elem key="config-hash">7328433471719</elem>
-- <elem key="host">vpn.example.com</elem>
--

author = "Patrik Karlsson <patrik@cqure.net>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

portrule = function(host, port)
  return shortport.ssl(host, port) and shortport.http(host, port)
end

action = function(host, port)
  local ac = anyconnect.Cisco.AnyConnect:new(host, port)
  local status, err = ac:connect()
  if not status then
    return stdnse.format_output(false, err)
  else
    local o = stdnse.output_table()
    local xmltags = { 'version', 'tunnel-group', 'group-alias',
      'config-hash', 'host-scan-ticket', 'host-scan-token',
      'host-scan-base-uri', 'host-scan-wait-uri', 'host' }

    -- add login banner if running in debug mode
    if nmap.verbosity() > 2 then xmltags[#xmltags] = 'banner' end

    for _, tag in ipairs(xmltags) do
      o[tag] = ac.conn_attr[tag]
    end
    return o
  end
end
