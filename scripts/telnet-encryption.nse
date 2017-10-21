local bin = require "bin"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Determines whether the encryption option is supported on a remote telnet
server.  Some systems (including FreeBSD and the krb5 telnetd available in many
Linux distributions) implement this option incorrectly, leading to a remote
root vulnerability. This script currently only tests whether encryption is
supported, not for that particular vulnerability.

References:
* FreeBSD Advisory: http://lists.freebsd.org/pipermail/freebsd-announce/2011-December/001398.html
* FreeBSD Exploit: http://www.exploit-db.com/exploits/18280/
* RedHat Enterprise Linux Advisory: https://rhn.redhat.com/errata/RHSA-2011-1854.html
]]

---
-- @usage
-- nmap -p 23 <ip> --script telnet-encryption
--
-- @output
-- PORT   STATE SERVICE REASON
-- 23/tcp open  telnet  syn-ack
-- | telnet-encryption:
-- |_  Telnet server supports encryption
--
--

categories = {"safe", "discovery"}


portrule = shortport.port_or_service(23, 'telnet')

author = {"Patrik Karlsson", "David Fifield", "Fyodor"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

local COMMAND = {
  SubCommand = 0xFA,
  Will = 0xFB,
  Do = 0xFD,
  Dont = 0xFE,
  Wont = 0xFC,
}

local function processOptions(data)
  local pos = 1
  local result = {}
  while ( pos < #data ) do
    local iac, cmd, option
    pos, iac, cmd = bin.unpack("CC", data, pos)
    if ( 0xFF ~= iac ) then
      break
    end
    if ( COMMAND.SubCommand == cmd ) then
      repeat
        pos, iac = bin.unpack("C", data, pos)
      until( pos == #data or 0xFF == iac )
      pos, cmd = bin.unpack("C", data, pos)
      if ( not(cmd) == 0xF0 ) then
        return false, "Failed to parse options"
      end
    else
      pos, option = bin.unpack("H", data, pos)
      result[option] = result[option] or {}
      table.insert(result[option], cmd)
    end
  end
  return true, { done=( not(#data == pos - 1) ), cmds = result }
end

local function fail(err) return stdnse.format_output(false, err) end

action = function(host, port)

  local socket = nmap.new_socket()
  local status = socket:connect(host, port)
  local data = stdnse.fromhex( "FFFD26FFFB26")
  local result

  socket:set_timeout(7500)
  status, result = socket:send(data)
  if ( not(status) ) then
    return fail(("Failed to send packet: %s"):format(result))
  end

  repeat
    status, data = socket:receive()
    if ( not(status) ) then
      return fail(("Receiving packet: %s"):format(data))
    end
    status, result = processOptions(data)
    if ( not(status) ) then
      return fail("Failed to process telnet options")
    end
  until( result.done or result.cmds['26'] )

  for _, cmd in ipairs(result.cmds['26'] or {}) do
    if ( COMMAND.Will == cmd or COMMAND.Do == cmd ) then
      return "\n  Telnet server supports encryption"
    end
  end
  return "\n  Telnet server does not support encryption"
end
