local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Connects to Erlang Port Mapper Daemon (epmd) and retrieves a list of nodes with their respective port numbers.
]]

---
-- @usage
-- nmap -p 4369 --script epmd-info <target>
--
-- @output
-- PORT     STATE SERVICE
-- 4369/tcp open  epmd
-- | epmd-info.nse:
-- |   epmd_port: 4369
-- |   nodes:
-- |     rabbit: 36804
-- |_    ejabberd: 46540
-- @xmloutput
-- <elem key="epmd_port">4369</elem>
-- <table key="nodes">
--   <elem key="rabbit">36804</elem>
--   <elem key="ejabberd">46540</elem>
-- </table>

author = "Toni Ruottu"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

portrule = shortport.port_or_service (4369, "epmd")

action = function(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(stdnse.get_timeout(host))
  local try = nmap.new_try(function () socket:close() end)
  try(socket:connect(host, port))

  try(socket:send("\x00\x01n")) -- NAMESREQ = 110

  local getline = stdnse.make_buffer(socket, "\n")

  local data, err = getline()
  if data == nil then
    stdnse.debug2("Error on receive: %s", err)
    socket:close()
    return nil
  end

  local realport, pos = string.unpack(">I4", data)
  data = string.sub(data, pos)

  local nodes = stdnse.output_table()
  local name, port
  while data and data ~= "" do
    name, port = data:match("^name (.*) at port (%d+)")
    if name then
      nodes[name] = port
    end
    data = getline()
  end

  local response = stdnse.output_table()
  response.epmd_port = realport
  response.nodes = nodes
  return response
end
