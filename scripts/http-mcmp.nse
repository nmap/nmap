description = [[
Checks if the webserver allows mod_cluster management protocol (MCMP) methods.

The script sends a MCMP PING message to determine protocol support, then issues
the DUMP command to dump the current configuration seen by mod_cluster_manager.

References:

* https://developer.jboss.org/wiki/Mod-ClusterManagementProtocol
]]

---
-- @output
-- | http-mcmp:
-- |   status: Mod_cluster Management Protocol enabled
-- |   version: 1.2.0.Final
-- |   dump:
-- | balancer: [1] Name: mycluster Sticky: 1 [JSESSIONID]/[jsessionid] remove: 0 force: 0 Timeout: 0 maxAttempts: 1
-- | node: [1:1],Balancer: mycluster,JVMRoute: 2ca5eb39-053e-336f-8708-85f753a3adf2,LBGroup: [],Host: 155.250.130.22,Port: 11000,Type: http,flushpackets: 0,flushwait: 10,ping: 10,smax: 1,ttl: 60,timeout: 0
-- | node: [2:2],Balancer: mycluster,JVMRoute: 3fef9557-32f8-309f-9b9a-af1e6951ee17,LBGroup: [],Host: 155.250.130.21,Port: 11000,Type: http,flushpackets: 0,flushwait: 10,ping: 10,smax: 1,ttl: 60,timeout: 0
-- | host: 1 [localhost] vhost: 1 node: 1
-- | host: 2 [localhost] vhost: 1 node: 2
-- | context: 1 [/stisvc] vhost: 1 node: 1 status: 1
-- |_context: 2 [/stisvc] vhost: 1 node: 2 status: 1
--
--
--<elem key="status">Mod_cluster Management Protocol enabled</elem>
--<elem key="version">1.3.1.Final</elem>
--<elem key="dump">&#xa;balancer: [1] Name: seta-cluster-jboss Sticky: 1 [JSESSIONID]/[jsessionid] remove: 0 force: 0 Timeout: 0 maxAttempts: 1&#xa;node: [1:1],Balancer: seta-cluster-jboss,JVMRoute: sv-seta-sas-jb1,LBGroup: [],Host: 10.20.98.38,Port: 8009,Type: ajp,flushpackets: 0,flushwait: 10,ping: 10,smax: 2,ttl: 60,timeout: 0&#xa;node: [2:2],Balancer: seta-cluster-jboss,JVMRoute: sv-seta-sas-jb2,LBGroup: [],Host: 10.20.98.39,Port: 8009,Type: ajp,flushpackets: 0,flushwait: 10,ping: 10,smax: 2,ttl: 60,timeout: 0&#xa;host: 1 [example.com] vhost: 1 node: 1&#xa;host: 2 [localhost] vhost: 1 node: 1&#xa;host: 3 [default-host] vhost: 1 node: 1&#xa;host: 4 [example.com] vhost: 1 node: 2&#xa;host: 5 [localhost] vhost: 1 node: 2&#xa;host: 6 [default-host] vhost: 1 node: 2&#xa;context: 1 [/cgs] vhost: 1 node: 1 status: 1&#xa;context: 2 [/RequisicaoSeta] vhost: 1 node: 1 status: 1&#xa;context: 3 [/prodex-ensaio] vhost: 1 node: 1 status: 1&#xa;context: 4 [/gestordeacessos] vhost: 1 node: 1 status: 1&#xa;</elem>

author = "Frank Spierings"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

local stdnse = require "stdnse"
local shortport = require "shortport"
local http = require "http"
local nmap = require "nmap"
local table = require "table"

portrule = shortport.http

action = function(host, port)
  local output = stdnse.output_table()
  local response = http.generic_request(host, port, 'PING', '/')
  if (response.status == 200 and http.response_contains(response, "Type=PING%-RSP")) then
    output.status = 'Mod_cluster Management Protocol enabled'
    if response.header.server then
      local version = response.header.server:match('mod_cluster/(%d[%w%._%-]*)')
      if version then
        output.version = version
        local cpe_found = false
        port.version.cpe = port.version.cpe or {}
        for _, cpe in ipairs(port.version.cpe) do
          cpe_found = cpe:match('mod_cluster')
          if cpe_found then break end
        end
        if not cpe_found then
          table.insert(port.version.cpe, ("cpe:/a:redhat:mod_cluster:%s"):format(version))
          nmap.set_port_version(host, port, "hardmatched")
        end
      end
    end
    response = http.generic_request(host, port, 'DUMP', '/')
    if (response.status == 200) then
      output.dump = "\n" .. response.body
    end
    return output
  end
end
