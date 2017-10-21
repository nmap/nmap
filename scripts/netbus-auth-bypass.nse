local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks if a NetBus server is vulnerable to an authentication bypass
vulnerability which allows full access without knowing the password.

For example a server running on TCP port 12345 on localhost with
this vulnerability is accessible to anyone. An attacker could
simply form a connection to the server ( ncat -C 127.0.0.1 12345 )
and login to the service by typing Password;1; into the console.
]]

---
-- @see netbus-brute.nse
-- @usage
-- nmap -p 12345 --script netbus-auth-bypass <target>
--
-- @output
-- 12345/tcp open  netbus
-- |_netbus-auth-bypass: Vulnerable

author = "Toni Ruottu"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"auth", "safe", "vuln"}


dependencies = {"netbus-version", "netbus-brute", "netbus-info"}

portrule = shortport.port_or_service (12345, "netbus", {"tcp"})

action = function( host, port )

  local socket = nmap.new_socket()
  local status, err = socket:connect(host, port)
  if not status then
    return
  end
  local buffer, _ = stdnse.make_buffer(socket, "\r")
  _ = buffer()
  if not (_ and _:match("^NetBus")) then
    stdnse.debug1("Not NetBus")
    return nil
  end

  -- The first argument of Password is the super-login bit.
  -- On vulnerable servers any password will do as long as
  -- we send the super-login bit. Regular NetBus has only
  -- one password. Thus, if we can login with two different
  -- passwords using super-login, the server is vulnerable.

  socket:send("Password;1;\r") --password: empty
  if buffer() ~= "Access;1" then
    return
  end
  socket:send("Password;1; \r") --password: space
  if buffer() == "Access;1" then
    return "Vulnerable"
  end
  return "Not vulnerable, but password is empty"
end

