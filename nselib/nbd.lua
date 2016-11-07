local bin = require "bin"
local bit = require "bit"
local match = require "match"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

_ENV = stdnse.module("nbd", stdnse.seeall)

---
-- An implementation of the Network Block Device protocol.
-- https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md
--
-- @author "Mak Kolybabi <mak@kolybabi.com>"
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

NBD_ALL_MAGIC_1 = string.char(0x4e, 0x42, 0x44, 0x4d, 0x41, 0x47, 0x49, 0x43)
NBD_OLD_MAGIC_2 = string.char(0x00, 0x00, 0x42, 0x02, 0x81, 0x86, 0x12, 0x53)
NBD_NEW_MAGIC_2 = string.char(0x49, 0x48, 0x41, 0x56, 0x45, 0x4F, 0x50, 0x54)

connect_new = function(sock)
  local status, flags = sock:receive_buf(match.numbytes(2), true)
  if not status then
    stdnse.debug1("Failed to receive handshake flags from server: %s", flags)
    sock:close()
    return false
  end

  local hflags, pos = (">I2"):unpack(flags)
  if pos ~= 3 then
    stdnse.debug1("Failed to unpack handshake flags from server.")
    sock:close()
    return false
  end

  sock:close()

  return {
    ["handshake_flags"] = hflags
  }
end

connect_old = function(sock)
  local status, size = sock:receive_buf(match.numbytes(8), true)
  if not status then
    stdnse.debug1("Failed to receive size of exported block device from server: %s", size)
    sock:close()
    return false
  end

  local size, pos = (">I8"):unpack(size)
  if pos ~= 9 then
    stdnse.debug1("Failed to unpack size of exported block device from server.")
    sock:close()
    return false
  end

  local status, flags = sock:receive_buf(match.numbytes(4), true)
  if not status then
    stdnse.debug1("Failed to receive flags from server: %s", flags)
    sock:close()
    return false
  end

  local flags, pos = (">I4"):unpack(flags)
  if pos ~= 5 then
    stdnse.debug1("Failed to unpack flags from server.")
    sock:close()
    return false
  end

  local status, pad = sock:receive_buf(match.numbytes(124), true)
  if not status then
    stdnse.debug1("Failed to receive zero pad from server: %s", pad)
    sock:close()
    return false
  end

  sock:close()

  return {
    ["flags"] = flags,
    ["size"] = size
  }
end

connect = function(host, port, options)
  local sock = nmap.new_socket()
  if not sock then
    stdnse.debug1("Failed to create socket.")
    return false
  end

  sock:set_timeout(10000)

  local status, err = sock:connect(host, port)
  if not sock then
    stdnse.debug1("Failed to connect socket: %s", err)
    return false
  end

  stdnse.sleep(1)

  local status, magic = sock:receive_buf(match.numbytes(8), true)
  if not status then
    stdnse.debug1("Failed to receive first 64 bits of magic from server: %s", magic)
    sock:close()
    return false
  end

  if magic ~= NBD_ALL_MAGIC_1 then
    stdnse.debug1("First 64 bits from server don't match expected magic: %s", stdnse.tohex(magic, {separator = ":"}))
    sock:close()
    return false
  end

  local status, magic = sock:receive_buf(match.numbytes(8), true)
  if not status then
    stdnse.debug1("Failed to receive second 64 bits of magic from server: %s", magic)
    return false
  end

  if magic == NBD_OLD_MAGIC_2 then
    stdnse.debug1("Service speaks old-style NBD protocol.")
    return connect_old(sock)
  end

  if magic == NBD_NEW_MAGIC_2 then
    stdnse.debug1("Service speaks new-style NBD protocol.")
    return connect_new(sock)
  end

  stdnse.debug1("Second 64 bits from server don't match any known protocol magic: %s", stdnse.tohex(magic, {separator = ":"}))
  sock:close()
  return false
end

return _ENV;
