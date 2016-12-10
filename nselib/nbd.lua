local bin = require "bin"
local bit = require "bit"
local comm = require "comm"
local match = require "match"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local unittest = require "unittest"

_ENV = stdnse.module("nbd", stdnse.seeall)

---
-- An implementation of the Network Block Device protocol.
-- https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md
--
-- @author "Mak Kolybabi <mak@kolybabi.com>"
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

NBD = {
  magic = {
    init_passwd       = string.char(0x4E, 0x42, 0x44, 0x4d, 0x41, 0x47, 0x49, 0x43),
    cliserv_magic_old = string.char(0x00, 0x00, 0x42, 0x02, 0x81, 0x86, 0x12, 0x53),
    cliserv_magic_new = string.char(0x49, 0x48, 0x41, 0x56, 0x45, 0x4F, 0x50, 0x54),
    option            = string.char(0x00, 0x03, 0xE8, 0x89, 0x04, 0x55, 0x65, 0xA9),
    request           = string.char(0x25, 0x60, 0x95, 0x13),
    reply             = string.char(0x67, 0x44, 0x66, 0x98),
  },

  handshake_flags = {
    ["FIXED_NEWSTYLE"] = 0x0001,
    ["NO_ZEROES"]      = 0x0002,
  },

  client_flags = {
    ["C_FIXED_NEWSTYLE"] = 0x00000001,
    ["C_NO_ZEROES"]      = 0x00000002,
  },

  transmission_flags = {
    ["HAS_FLAGS"]         = 0x0001,
    ["READ_ONLY"]         = 0x0002,
    ["SEND_FLUSH"]        = 0x0004,
    ["SEND_FUA"]          = 0x0008,
    ["ROTATIONAL"]        = 0x0010,
    ["SEND_TRIM"]         = 0x0020,
    ["SEND_WRITE_ZEROES"] = 0x0040, -- WRITE_ZEROES Extension
    ["SEND_DF"]           = 0x0080, -- STRUCTURED_REPLY Extension
  },

  opt_req_types = {
    ["EXPORT_NAME"]      = 0x00000001,
    ["ABORT"]            = 0x00000002,
    ["LIST"]             = 0x00000003,
    ["PEEK_EXPORT"]      = 0x00000004, -- PEEK_EXPORT Extension
    ["STARTTLS"]         = 0x00000005,
    ["INFO"]             = 0x00000006, -- INFO Extension
    ["GO"]               = 0x00000007, -- INFO Extension
    ["STRUCTURED_REPLY"] = 0x00000008, -- STRUCTURED_REPLY Extension
    ["BLOCK_SIZE"]       = 0x00000009, -- INFO Extension
  },

  opt_rep_types = {
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
  },

  cmd_req_flags = {
    ["FUA"]     = 0x0001,
    ["NO_HOLE"] = 0x0002, -- WRITE_ZEROES Extension
    ["DF"]      = 0x0004, -- STRUCTURED_REPLY Extension
  },

  cmd_req_types = {
    ["READ"]         = 0x0000,
    ["WRITE"]        = 0x0001,
    ["DISC"]         = 0x0002,
    ["FLUSH"]        = 0x0003,
    ["TRIM"]         = 0x0004,
    ["CACHE"]        = 0x0005, -- XNBD custom request types
    ["WRITE_ZEROES"] = 0x0006, -- WRITE_ZEROES Extension
  },

  errors = {
    ["EPERM"]     = 0x00000001,
    ["EIO"]       = 0x00000005,
    ["ENOMEM"]    = 0x0000000C,
    ["EINVAL"]    = 0x00000016,
    ["ENOSPC"]    = 0x0000001C,
    ["EOVERFLOW"] = 0x0000004B,
    ["ESHUTDOWN"] = 0x0000006C,
  },
}

Comm = {
  --- Creates a new Client instance.
  --
  -- @name Comm.new
  --
  -- @param host Table as received by the action method.
  -- @param port Table as received by the action method.
  -- @param options Table.
  -- @return o Instance of Client.
  new = function(self, host, port, options)
    local o = {host = host, port = port, options = options or {}}
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  --- Connects to the NBD server.
  --
  -- @name Comm.connect
  --
  -- @return status true on success, false on failure.
  -- @return err string containing the error message on failure.
  connect = function(self, options)
    self.connect_options = options or {}
    assert(type(options) == "table")

    -- NBD servers send a response when we connect. We are using
    -- tryssl here as a precaution since there are several
    -- implementations of the protocol and no reason it can't be
    -- wrapped. IANA has rejected assigning another port for NBD over
    -- TLS.
    local sd, err, proto, rep = comm.tryssl(self.host, self.port, "", {recv_before = true})
    if not sd then
      return false, err
    end

    -- The socket connected successfully over whichever protocol.
    -- Store the connection information.
    self.socket = sd
    self.protocol = {ssl_tls = (proto == "ssl")}

    if #rep ~= 8 then
      stdnse.debug1("Failed to receive first 64 bits of magic from server: %s", rep)
      self.socket:close()
      return false
    end

    if rep ~= NBD.magic.init_passwd then
      stdnse.debug1("First 64 bits from server don't match expected magic: %s", stdnse.tohex(rep, {separator = ":"}))
      self.sock:close()
      return false
    end

    local status, rep = self.socket:receive_buf(match.numbytes(8), true)
    if not status then
      stdnse.debug1("Failed to receive second 64 bits of magic from server: %s", rep)
      return false
    end

    if rep == NBD.magic.cliserv_magic_new then
      self.protocol.negotiation = "newstyle"
      return self:connect_new(options)
    end

    if rep == NBD.magic.cliserv_magic_old then
      self.protocol.negotiation = "oldstyle"
      return self:connect_old(options)
    end

    self.protocol.negotiation = "unrecognized"
    stdnse.debug1("Second 64 bits from server don't match any known protocol magic: %s", stdnse.tohex(magic, {separator = ":"}))

    self.socket:close()
    return true
  end,

  reconnect = function(self)
    self:close()
    return self:connect(self.connect_options)
  end,

  attach = function(self, name)
    assert(self.protocol.negotiation == "newstyle" or self.protocol.negotiation == "fixed newstyle")
    assert(type(name) == "string")

    local req = self:build_opt_req("EXPORT_NAME", {export_name = name})

    local status, err = self.socket:send(req)
    if not status then
      stdnse.debug1("Failed to send attach request for '%s': %s", args.export_name, err)
      self:close()
      return
    end

    local status, size = self.socket:receive_buf(match.numbytes(8), true)
    if not status then
      stdnse.debug1("Failed to receive response to attach request for '%s': %s", name, size)
      self.socket:close()
      return
    end

    local size, pos = (">I8"):unpack(size)
    if pos ~= 9 then
      stdnse.debug1("Failed to unpack size of exported block device from server.")
      self.socket:close()
      return false
    end

    local status, flags = self.socket:receive_buf(match.numbytes(2), true)
    if not status then
      stdnse.debug1("Failed to receive transmission flags from server while attaching to export: %s", flags)
      self.socket:close()
      return false
    end

    local flags, pos = (">I2"):unpack(flags)
    if pos ~= 3 then
      stdnse.debug1("Failed to unpack transmission flags from server.")
      self.socket:close()
      return false
    end

    flags = self:parse_transmission_flags(flags)

    if self.protocol.zero_pad == "required" then
      local status, err = self.socket:receive_buf(match.numbytes(124), true)
      if not status then
	stdnse.debug1("Failed to receive zero pad from server while attaching to export: %s", err)
	self.socket:close()
	return false
      end
    end

    self.exports = self.exports or {}

    self.exports[name] = {
      size = size,
      flags = flags
    }

    return true
  end,

  --- Sends an MQTT control packet.
  --
  -- @name Comm.send
  --
  -- @param pkt String representing a raw control packet.
  -- @return status true on success, false on failure.
  -- @return err string containing the error message on failure.
  send = function(self, pkt)
  end,

  --- Receives an MQTT control packet.
  --
  -- @name Comm.receive
  --
  -- @return status True on success, false on failure.
  -- @return response String representing a raw control packet on
  --         success, string containing the error message on failure.
  receive = function(self)
  end,

  --- Disconnects from the NBD server.
  --
  -- @name Comm.close
  close = function(self)
    return self.socket:close()
  end,

  connect_new = function(self, options)
    assert(type(options) == "table")

    local status, flags = self.socket:receive_buf(match.numbytes(2), true)
    if not status then
      stdnse.debug1("Failed to receive handshake flags from server: %s", flags)
      self.socket:close()
      return false
    end

    -- Receive and parse the handshake flags from the server, and use
    -- them to build the client flags.
    local hflags, pos = (">I2"):unpack(flags)
    if pos ~= 3 then
      stdnse.debug1("Failed to unpack handshake flags from server.")
      self.socket:close()
      return false
    end

    local cflags = 0x0000

    if hflags & NBD.handshake_flags.FIXED_NEWSTYLE then
      cflags = cflags | NBD.client_flags.C_FIXED_NEWSTYLE
      self.protocol.negotiation = "fixed newstyle"
    end

    self.protocol.zero_pad = "required"
    if hflags & NBD.handshake_flags.NO_ZEROES then
      cflags = cflags | NBD.client_flags.C_NO_ZEROES
      self.protocol.zero_pad = "optional"
    end

    -- Send the client flags to the server.
    req = (">I4"):pack(cflags)

    local status, err = self.socket:send(req)
    if not status then
      stdnse.debug1("Failed to send client flags: %s", err)
      self.socket:close()
      return false
    end

    return true
  end,

  connect_old = function(self, options)
    assert(type(options) == "table")

    local status, size = self.socket:receive_buf(match.numbytes(8), true)
    if not status then
      stdnse.debug1("Failed to receive size of exported block device from server: %s", size)
      self.socket:close()
      return false
    end

    local size, pos = (">I8"):unpack(size)
    if pos ~= 9 then
      stdnse.debug1("Failed to unpack size of exported block device from server.")
      self.socket:close()
      return false
    end

    local status, flags = self.sock:receive_buf(match.numbytes(4), true)
    if not status then
      stdnse.debug1("Failed to receive flags from server: %s", flags)
      self.socket:close()
      return false
    end

    local flags, pos = (">I4"):unpack(flags)
    if pos ~= 5 then
      stdnse.debug1("Failed to unpack flags from server.")
      self.socket:close()
      return false
    end

    local status, pad = sock:receive_buf(match.numbytes(124), true)
    if not status then
      stdnse.debug1("Failed to receive zero pad from server: %s", pad)
      self.socket:close()
      return false
    end

    self.exports = {
      unnamed = {
	flags = flags,
	size = size
      }
    }

    return true
  end,

  receive_opt_rep = function(self)
    -- Receive the static header of the option.
    local status, hdr = sock:receive_buf(match.numbytes(20), true)
    if not status then
      stdnse.debug1("Failed to receive option reply header: %s", hdr)
      return false
    end

    local magic, _, _, len, pos = (">I8I4I4I4"):unpack(hdr)
    if pos ~= 20 then
      stdnse.debug1("Failed to parse option reply header during receive.")
      return false
    end

    if magic ~= NBD.magic.option then
      stdnse.debug1("First 64 bits of option reply don't match expected magic: %s", stdnse.tohex(magic, {separator = ":"}))
      return false
    end

    if rlen == 0 then
      return hdr
    end

    -- Receive the variable body of the option.
    local status, body = sock:receive_buf(match.numbytes(len), true)
    if not status then
      stdnse.debug1("Failed to receive option reply: %s", body)
      return false
    end

    return hdr .. body
  end,

  --- Build an option request message.
  --
  -- @name nbd.build_opt_req
  --
  -- @param name String naming the option.
  -- @param options Table of options defined by the option.
  --
  -- @return status true on success, false on failure.
  -- @return response String representing a raw message on success, or
  --         containing the error message on failure.
  build_opt_req = function(self, name, options)
    assert(type(name) == "string")
    local otype = NBD.opt_req_types[name]
    assert(otype)

    if not options then
      options = {}
    end
    assert(type(options) == "table")

    if name == "EXPORT_NAME" then
      assert(options.export_name)
      payload = options.export_name
    end

    return NBD.magic.cliserv_magic_new .. (">I4I4"):pack(otype, #payload) .. payload
  end,

  --- Parses an option reply message.
  --
  -- @name nbd.parse_opt_rep
  --
  -- @param buf String from which to parse the reply.
  -- @param pos Position from which to start parsing.
  --
  -- @return pos String index on success, false on failure.
  -- @return response Table representing a reply on success, string
  --         containing the error message on failure.
  parse_opt_rep = function(self, buf, pos)
    assert(type(buf) == "string")

    if not pos or pos == 0 then
      pos = 1
    end
    assert(type(pos) == "number")
    assert(pos <= #buf)

    if pos + 20 > #buf then
      stdnse.debug1("Buffer is too short to be parsed as an option reply.")
      return false
    end

    local magic, otype, rtype, len, pos = (">I8I4I4I4"):unpack(buf, pos)

    if magic ~= NDB.magic.option then
      stdnse.debug1("First 64 bits of option reply don't match expected magic: %s", stdnse.tohex(magic, {separator = ":"}))
      return false
    end

    local otype_name = NBD.opt_req_types[otype]
    local rtype_name = NBD.opt_rep_types[rtype]

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
  end,

  --- Builds a command request message.
  --
  -- @name nbd.build_cmd_req
  --
  -- @param name String naming the command.
  -- @param options Table of options defined by the option.
  --
  -- @return status true on success, false on failure.
  -- @return response String representing a raw message on success, or
  --         containing the error message on failure.
  build_cmd_req = function(self, name, options)
    assert(type(name) == "string")
    if not options then
      options = {}
    end
    assert(type(options) == "table")
  end,

  --- Parses a command reply message.
  --
  -- @name nbd.parse_cmd_rep
  --
  -- @param buf String from which to parse the reply.
  -- @param pos Position from which to start parsing.
  --
  -- @return pos String index on success, false on failure.
  -- @return response Table representing a reply on success, string
  --         containing the error message on failure.
  parse_cmd_rep = function(self, buf, pos)
    assert(type(buf) == "string")

    if not pos or pos == 0 then
      pos = 1
    end
    assert(type(pos) == "number")
    assert(pos <= #buf)
  end,

  parse_transmission_flags = function(self, flags)
    assert(type(flags) == "number")

    -- This flag must always be set according to the standard.
    if (flags & NBD.transmission_flags.HAS_FLAGS) == 0 then
      stdnse.debug1("Transmission flags were not in a valid format, skipping.")
      return {}
    end

    local tbl = {}
    for k, v in pairs(NBD.transmission_flags) do
      if (flags & v) ~= 0 then
	tbl[k] = true
      end
    end

    return tbl
  end,
}

return _ENV;
