local nmap = require "nmap"
local shortport = require "shortport"
local string = require "string"

description = [[
Checks if an SSH server supports the obsolete and less secure SSH Protocol Version 1.
]]
author = "Brandon Enright"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe"}

---
-- @output
-- PORT   STATE SERVICE
-- 22/tcp open  ssh
-- |_sshv1: Server supports SSHv1
--
-- @xmloutput
-- true


portrule = shortport.ssh

action = function(host, port)
  local socket = nmap.new_socket()
  local result;
  local status = true;

  socket:connect(host, port)
  status, result = socket:receive_lines(1);

  if (not status) then
    socket:close()
    return
  end

  if (result == "TIMEOUT") then
    socket:close()
    return
  end

  if  not string.match(result, "^SSH%-.+\n$") then
    socket:close()
    return
  end

  socket:send("SSH-1.5-NmapNSE_1.0\n")

  -- should be able to consume at least 13 bytes
  -- key length is a 4 byte integer
  -- padding is between 1 and 8 bytes
  -- type is one byte
  -- key is at least several bytes
  status, result = socket:receive_bytes(13);

  if (not status) then
    socket:close()
    return
  end

  if (result == "TIMEOUT") then
    socket:close()
    return
  end

  if  not string.match(result, "^....[\0]+\002") then
    socket:close()
    return
  end

  socket:close();

  return true, "Server supports SSHv1"
end
