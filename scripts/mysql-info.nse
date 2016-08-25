local bit = require "bit"
local mysql = require "mysql"
local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Connects to a MySQL server and prints information such as the protocol and
version numbers, thread ID, status, capabilities, and the password salt.

If service detection is performed and the server appears to be blocking
our host or is blocked because of too many connections, then this script
isn't run (see the portrule).
]]

---
-- @output
-- 3306/tcp open  mysql
-- |  mysql-info:
-- |    Protocol: 10
-- |    Version: 5.0.51a-3ubuntu5.1
-- |    Thread ID: 7
-- |    Capabilities flags: 40968
-- |    Some Capabilities: ConnectWithDatabase, SupportsTransactions, Support41Auth
-- |    Status: Autocommit
-- |_   Salt: bYyt\NQ/4V6IN+*3`imj
--
--@xmloutput
-- <elem key="Protocol">10</elem>
-- <elem key="Version">5.0.51a-3ubuntu5.1</elem>
-- <elem key="Thread ID">7</elem>
-- <elem key="Capabilities flags">40968</elem>
-- <table key="Some Capabilities">
--   <elem>ConnectWithDatabase</elem>
--   <elem>SupportsTransactions</elem>
--   <elem>Support41Auth</elem>
-- </table>
-- <elem key="Status">Autocommit</elem>
-- <elem key="Salt">bYyt\NQ/4V6IN+*3`imj</elem>

-- Many thanks to jah (jah@zadkiel.plus.com) for testing and enhancements

author = "Kris Katterjohn"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = { "default", "discovery", "safe" }

--- Converts a number to a string description of the capabilities
--@param num Start of the capabilities data
--@return table containing the names of the capabilities offered
local bitset = function(num, lookup)
  local caps = {}

  for k, v in pairs(lookup) do
    if bit.band(num, v) > 0 then
      caps[#caps+1] = k
    end
  end

  return caps
end

portrule = function(host, port)
  local extra = port.version.extrainfo

  return (port.number == 3306 or port.service == "mysql")
    and port.protocol == "tcp"
    and port.state == "open"
    and not (extra ~= nil
      and (extra:match("[Uu]nauthorized")
      or extra:match("[Tt]oo many connection")))
end

action = function(host, port)
  local output = stdnse.output_table()
  local socket = nmap.new_socket()
  socket:set_timeout(5000)

  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("error connecting: %s", err)
    return nil
  end

  local status, info = mysql.receiveGreeting(socket)

  if not status then
    stdnse.debug1("MySQL error: %s", info)
    output["MySQL Error"] = info
    if nmap.verbosity() > 1 then
      return output
    else
      return nil
    end
  end

  output["Protocol"] = info.proto
  output["Version"] = info.version
  output["Thread ID"] = info.threadid

  if info.proto == 10 then
    output["Capabilities flags"] = info.capabilities
    local caps = bitset(info.capabilities, mysql.Capabilities)
    if info.extcapabilities then
      local extcaps = bitset(info.extcapabilities, mysql.ExtCapabilities)
      for i, c in ipairs(extcaps) do
        caps[#caps+1] = c
      end
    end
    if #caps > 0 then
      setmetatable(caps, {
          __tostring = function (self)
            return table.concat(self, ", ")
          end
        })
      output["Some Capabilities"] = caps
    end

    if info.status == 2 then
      output["Status"] = "Autocommit"
    else
      output["Status"] = info.status
    end

    output["Salt"] = info.salt

    output["Auth Plugin Name"] = info.auth_plugin_name
  end

  return output
end

