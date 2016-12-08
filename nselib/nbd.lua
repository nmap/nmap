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

MAGIC_ALL_1    = string.char(0x4E, 0x42, 0x44, 0x4d, 0x41, 0x47, 0x49, 0x43)
MAGIC_OLD_2    = string.char(0x00, 0x00, 0x42, 0x02, 0x81, 0x86, 0x12, 0x53)
MAGIC_NEW_2    = string.char(0x49, 0x48, 0x41, 0x56, 0x45, 0x4F, 0x50, 0x54)
MAGIC_SRVR_OPT = string.char(0x00, 0x03, 0xE8, 0x89, 0x04, 0x55, 0x65, 0xA9)
MAGIC_CLNT_REQ = string.char(0x25, 0x60, 0x95, 0x13)
MAGIC_SRVR_REP = string.char(0x67, 0x44, 0x66, 0x98)

HANDSHAKE_FLAGS = {
  ["FIXED_NEWSTYLE"] = 0x0001,
  ["NO_ZEROES"]      = 0x0002,
}

CLIENT_FLAGS = {
  ["C_FIXED_NEWSTYLE"] = 0x00000001,
  ["C_NO_ZEROES"]      = 0x00000002,
}

TRANSMISSION_FLAGS = {
  ["HAS_FLAGS"]         = 0x0001,
  ["READ_ONLY"]         = 0x0002,
  ["SEND_FLUSH"]        = 0x0004,
  ["SEND_FUA"]          = 0x0008,
  ["ROTATIONAL"]        = 0x0010,
  ["SEND_TRIM"]         = 0x0020,
  ["SEND_WRITE_ZEROES"] = 0x0040, -- WRITE_ZEROES Extension
  ["SEND_DF"]           = 0x0080, -- STRUCTURED_REPLY Extension
}

OPTION_REQUEST_TYPES = {
  ["EXPORT_NAME"]      = 0x00000001,
  ["ABORT"]            = 0x00000002,
  ["LIST"]             = 0x00000003,
  ["PEEK_EXPORT"]      = 0x00000004, -- PEEK_EXPORT Extension
  ["STARTTLS"]         = 0x00000005,
  ["INFO"]             = 0x00000006, -- INFO Extension
  ["GO"]               = 0x00000007, -- INFO Extension
  ["STRUCTURED_REPLY"] = 0x00000008, -- STRUCTURED_REPLY Extension
  ["BLOCK_SIZE"]       = 0x00000009, -- INFO Extension
}

OPTION_REPLY_TYPES = {
  ["ACK"]                 = 0x00000001,
  ["SERVER"]              = 0x00000002,
  ["INFO"]                = 0x00000003, -- INFO Extension
  ["ERR_UNSUP"]           = 0xF0000001,
  ["ERR_POLICY"]          = 0xF0000002,
  ["ERR_INVALID"]         = 0xF0000003,
  ["ERR_PLATFORM"]        = 0xF0000004,
  ["ERR_TLS_REQD"]        = 0xF0000005,
  ["ERR_UNKNOWN"]         = 0xF0000006, -- INFO Extension
  ["ERR_SHUTDOWN"]        = 0xF0000007,
  ["ERR_BLOCK_SIZE_REQD"] = 0xF0000008, -- INFO Extension
}

COMMAND_REQUEST_FLAGS = {
  ["FUA"]     = 0x0001,
  ["NO_HOLE"] = 0x0002, -- WRITE_ZEROES Extension
  ["DF"]      = 0x0004, -- STRUCTURED_REPLY Extension
}

COMMAND_REQUEST_TYPES = {
  ["READ"]         = 0x0000,
  ["WRITE"]        = 0x0001,
  ["DISC"]         = 0x0002,
  ["FLUSH"]        = 0x0003,
  ["TRIM"]         = 0x0004,
  ["CACHE"]        = 0x0005, -- XNBD custom request types
  ["WRITE_ZEROES"] = 0x0006, -- WRITE_ZEROES Extension
}

ERROR_VALUES = {
  ["EPERM"]     = 0x00000001,
  ["EIO"]       = 0x00000005,
  ["ENOMEM"]    = 0x0000000C,
  ["EINVAL"]    = 0x00000016,
  ["ENOSPC"]    = 0x0000001C,
  ["EOVERFLOW"] = 0x0000004B,
  ["ESHUTDOWN"] = 0x0000006C,
}

--- Build an option request message.
--
-- @name nbd.option_request_build
--
-- @param name String naming the option.
-- @param options Table of options defined by the option.
--
-- @return status true on success, false on failure.
-- @return response String representing a raw message on success, or
--         containing the error message on failure.
option_request_build = function(name, options)
  assert(type(name) == "string")
  if not options then
    options = {}
  end
  assert(type(options) == "table")

  local payload = ""

  return MAGIC_NEW_2 .. (">I4I4"):pack(name, #payload) .. payload
end

--- Parses an option reply message.
--
-- @name nbd.option_reply_parse
--
-- @param buf String from which to parse the reply.
-- @param pos Position from which to start parsing.
--
-- @return pos String index on success, false on failure.
-- @return response Table representing a reply on success, string
--         containing the error message on failure.
option_reply_parse = function(buf, pos)
  assert(type(buf) == "string")

  if not pos or pos == 0 then
    pos = 1
  end
  assert(type(pos) == "number")
  assert(pos <= #buf)

  if pos + 20 > #buf then
    return false, "Buffer is too short to be parsed as an option reply."
  end

  local magic, otype, rtype, rlen, pos = (">I8I4I4I4"):unpack(buf, pos)

  if magic ~= MAGIC_SRVR_OPT then
    return false, ("First 64 bits of option reply don't match expected magic: %s"):format(stdnse.tohex(magic, {separator = ":"}))
  end

  local otype_name = OPTION_REQUEST_TYPES[otype]
  local rtype_name = OPTION_REPLY_TYPES[rtype]

  local res = {
    ["otype"]      = otype,
    ["otype_name"] = otype_name,
    ["rtype"]      = rtype,
    ["rtype_name"] = rtype_name,
  }

  if rlen == 0 then
    return res, pos
  end

  if otype_name == "ACK" then
    -- No payload.
  elseif otype_name == "SERVER" then
    if pos + rlen - 1 > #buf then
      return false, "Option reply payload length extends past end of buffer."
    end

    if rlen < 4 then
      return false, ("Option reply payload length must be 4 or greater, but is %d."):format(rlen)
    end

    local nlen, pos = (">I4"):unpack(buf, pos)
    if nlen > 0 then
      res["export_name"] = buf:sub(pos, pos + nlen - 1)
      pos = pos + nlen
    end
  elseif otype_name == "INFO" then
  end

  return res, pos
end

--- Builds a command request message.
--
-- @name nbd.command_request_build
--
-- @param name String naming the command.
-- @param options Table of options defined by the option.
--
-- @return status true on success, false on failure.
-- @return response String representing a raw message on success, or
--         containing the error message on failure.
command_request_build = function(name, options)
end

--- Parses a command reply message.
--
-- @name nbd.command_reply_parse
--
-- @param buf String from which to parse the reply.
-- @param pos Position from which to start parsing.
--
-- @return pos String index on success, false on failure.
-- @return response Table representing a reply on success, string
--         containing the error message on failure.
command_reply_parse = function(buf, pos)
end

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

  local status, req = option_build("NBD_OPT_LIST")
  if not status then
    stdnse.debug1("Failed to build option NBD_OPT_LIST.")
    sock:close()
    return false
  end

  local status, err = sock:send(req)
  if not status then
    stdnse.debug1("Failed to send list req: %s", err)
    sock:close()
    return false
  end

  local status, flags = sock:receive(req)
  if not status then
    stdnse.debug1("Failed to send list req.")
    sock:close()
    return false
  end

  -- if pos ~= 3 then
  --  stdnse.debug1("Service speaks new-style NBD protocol.")
  -- end

  -- for pos, name in pairs(NEW_STYLE_OPTIONS) do
  -- end

  -- If the service does not speak the fixed new-style protocol,
  -- indicated by not having the relevant option set, then we cannot
  -- efficiently enumerate the options the server supports. This is
  -- due to the original version of the new-style protocol terminating
  -- sessions with unknown options. This has since been replaced by
  -- option haggling.
  --
  -- Therefore, we only try to enumerate the options for fixed
  -- new-style connections, which support option haggling. if not
  -- options["fixed_new_style_protocol"] then return end

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
  stdnse.sleep(5)

  local sock = nmap.new_socket()
  if not sock then
    stdnse.debug1("Failed to create socket.")
    return false
  end

  sock:set_timeout(10000)

  local status, err = sock:connect(host, port)
  if not status then
    stdnse.debug1("Failed to connect socket: %s", err)
    return false
  end

  local status, magic = sock:receive_buf(match.numbytes(8), true)
  if not status then
    stdnse.debug1("Failed to receive first 64 bits of magic from server: %s", magic)
    sock:close()
    return false
  end

  if magic ~= MAGIC_ALL_1 then
    stdnse.debug1("First 64 bits from server don't match expected magic: %s", stdnse.tohex(magic, {separator = ":"}))
    sock:close()
    return false
  end

  local status, magic = sock:receive_buf(match.numbytes(8), true)
  if not status then
    stdnse.debug1("Failed to receive second 64 bits of magic from server: %s", magic)
    return false
  end

  if magic == MAGIC_OLD_2 then
    stdnse.debug1("Service speaks old-style NBD protocol.")
    return connect_old(sock)
  end

  if magic == MAGIC_NEW_2 then
    stdnse.debug1("Service speaks new-style NBD protocol.")
    return connect_new(sock)
  end

  stdnse.debug1("Second 64 bits from server don't match any known protocol magic: %s", stdnse.tohex(magic, {separator = ":"}))
  sock:close()
  return false
end

return _ENV;
