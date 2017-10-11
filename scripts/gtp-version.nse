local shortport = require "shortport"
local string = require "string"
local stdnse = require "stdnse"
local bin = require "bin"
local nmap = require "nmap"

-- nmap -sC --script=scripts/gtp-version.nse -sU -p 2152,2123 127.0.0.1
-- ...
-- PORT     STATE SERVICE
-- 2123/udp open  gtp-control
-- |_gtp-version:  v1
-- 2152/udp open  gtp-user
-- |_gtp-version:  v1


description = [[
Scans for GTPv1/v2 services using EchoRequest.
]]

author = "Guillaume Teissier <gteissier@gmx.com>"
license = "Same as Nmap - See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

portrule = shortport.port_or_service({2123, 2152}, "gtp", "udp")

local TIMEOUT = 3000

local ECHOREQUEST_V1 = bin.pack(">CCSISCC",
  -- GTPv1, and protocol type set to 1
  0x32,
  -- EchoRequest
  0x01,
  -- message length
  0x0004,
  -- Tunnel endpoint identifier
  0x00004200,
  -- sequence number
  0x1337,
  -- N-PDU number
  0x00,
  -- next extension header type
  0x00)

local ECHOREQUEST_V2 = bin.pack(">CCSCCCC",
  -- GTPv2
  0x40,
  -- EchoRequest
  0x01,
  -- message length
  0x0004,
  -- sequence number
  0xde, 0xfe, 0xc8, 0x00)


action = function(host, port)
  local socket = nmap.new_socket("udp")
  local mutex = nmap.mutex('gtp_udp')
  local s_status, _
  local r_status, data
  local supported = ""
  local answers = 0

  mutex "lock";

  socket:set_timeout(TIMEOUT)

  socket:bind(nil, port.number)
  s_status = socket:connect(host, port, "udp")
  if (not(s_status)) then
    mutex "done";
    return
  end

  s_status = socket:send(ECHOREQUEST_V1)
  if (not(s_status)) then
    mutex "done";
    return
  end

  r_status, data = socket:receive_bytes(2)
  if r_status then
    if data:len() >= 2 and data:sub(2,2) == '\x02' then
      supported = "v1"
      answers = answers + 1
    end
  end

  s_status = socket:send(ECHOREQUEST_V2)
  if (not(s_status)) then
    mutex "done";
    return
  end

  r_status, data = socket:receive_bytes(2)
  if r_status then
    if data:len() >= 2 and data:sub(2,2) == '\x02' then
      supported = supported .. " v2"
      answers = answers + 1
    end
  end

  socket:close()

  mutex "done";


  if answers > 0 then
    nmap.set_port_state(host, port, "open")
    return supported
  else
    return nil
  end
end
