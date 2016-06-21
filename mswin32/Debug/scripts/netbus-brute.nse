local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local unpwdb = require "unpwdb"

description = [[
Performs brute force password auditing against the Netbus backdoor ("remote administration") service.
]]

---
-- @usage
-- nmap -p 12345 --script netbus-brute <target>
--
-- @output
-- 12345/tcp open  netbus
-- |_netbus-brute: password123

author = "Toni Ruottu"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"brute", "intrusive"}


dependencies = {"netbus-version"}

portrule = shortport.port_or_service (12345, "netbus", {"tcp"})

action = function( host, port )
  local try = nmap.new_try()
  local passwords = try(unpwdb.passwords())
  local socket = nmap.new_socket()
  local status, err = socket:connect(host, port)
  if not status then
    return
  end
  local buffer, err = stdnse.make_buffer(socket, "\r")
  local _ = buffer() --skip the banner
  if not (_ and _:match("^NetBus")) then
    stdnse.debug1("Not NetBus")
    return nil
  end
  for password in passwords do
    local foo = string.format("Password;0;%s\r", password)
    socket:send(foo)
    local login = buffer()
    if login == "Access;1" then
      -- Store the password for other netbus scripts
      local key = string.format("%s:%d", host.ip, port.number)
      if not nmap.registry.netbuspasswords then
        nmap.registry.netbuspasswords = {}
      end
      nmap.registry.netbuspasswords[key] = password
      if password == "" then
        return "<empty>"
      end
      return string.format("%s", password)
    end
  end
  socket:close()
end


