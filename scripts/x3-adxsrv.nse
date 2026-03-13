local nmap = require "nmap"
local shortport = require "shortport"
local string = require "string"

description = [[
Checks if an X3 AdxSrv service is present and vulnerable to a directory disclosure 
vulnerability.

]]

---
-- @see 
-- @usage
-- nmap -p 50000 --script x3-adxsrv.nse <target>
--
-- @output
-- 50000/tcp open  
-- |x3-adxsrv-vuln: VULNERABLE
-- |_Directory returned-> C:\Sage\SafeX3\AdxAdmin

author = "@deadjakk"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "vuln"}

portrule = shortport.port_or_service ({50000,1818,1895,1819}, "Sage X3", {"tcp"})

action = function( host, port )

  local socket = nmap.new_socket()
  local status, err = socket:connect(host, port)
  if not status then 
      return
  end

  local auth = "\x09\x00"
  local adx_dir_msg = "\x07\x41\x44\x58\x44\x49\x52\x00"

  socket:set_timeout(5000)
  socket:send(auth)

  status, line = socket:receive_bytes(4)
  if not status then
      return 
  end
  -- checks for indicator of authorization
  if not string.sub(line,1,2) == "\x00\x00" then
     return 
  end

  socket:send(adx_dir_msg)
  local status, line = socket:receive_buf("AdxAdmin",true)
  if not status then
      return
  end
  if not line then
      return
  end
  if status then
    return "VULNERABLE\nDirectory returned-> " .. string.sub(line,5,-1)
  end
  return
end


