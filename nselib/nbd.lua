local comm = require "comm"
local match = require "match"
local stdnse = require "stdnse"
local string = require "string"

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
    cmd_request       = string.char(0x25, 0x60, 0x95, 0x13),
    cmd_reply         = string.char(0x67, 0x44, 0x66, 0x98),
  },

  handshake_flags = {
    FIXED_NEWSTYLE = 0x0001,
    NO_ZEROES      = 0x0002,
  },

  client_flags = {
    C_FIXED_NEWSTYLE = 0x00000001,
    C_NO_ZEROES      = 0x00000002,
  },

  transmission_flags = {
    HAS_FLAGS         = 0x0001,
    READ_ONLY         = 0x0002,
    SEND_FLUSH        = 0x0004,
    SEND_FUA          = 0x0008,
    ROTATIONAL        = 0x0010,
    SEND_TRIM         = 0x0020,
    SEND_WRITE_ZEROES = 0x0040, -- WRITE_ZEROES Extension
    SEND_DF           = 0x0080, -- STRUCTURED_REPLY Extension
  },

  opt_req_types = {
    EXPORT_NAME      = 0x00000001,
    ABORT            = 0x00000002,
    LIST             = 0x00000003,
    PEEK_EXPORT      = 0x00000004, -- PEEK_EXPORT Extension
    STARTTLS         = 0x00000005,
    INFO             = 0x00000006, -- INFO Extension
    GO               = 0x00000007, -- INFO Extension
    STRUCTURED_REPLY = 0x00000008, -- STRUCTURED_REPLY Extension
    BLOCK_SIZE       = 0x00000009, -- INFO Extension
  },

  opt_rep_types = {
    ACK                 = 0x00000001,
    SERVER              = 0x00000002,
    INFO                = 0x00000003, -- INFO Extension
    ERR_UNSUP           = 0x80000001,
    ERR_POLICY          = 0x80000002,
    ERR_INVALID         = 0x80000003,
    ERR_PLATFORM        = 0x80000004,
    ERR_TLS_REQD        = 0x80000005,
    ERR_UNKNOWN         = 0x80000006, -- INFO Extension
    ERR_SHUTDOWN        = 0x80000007,
    ERR_BLOCK_SIZE_REQD = 0x80000008, -- INFO Extension
  },

  opt_rep_ext_types = {
    info = {
      EXPORT      = 0x0000,
      NAME        = 0x0001,
      DESCRIPTION = 0x0002,
      BLOCK_SIZE  = 0x0003,
    },
  },

  cmd_req_flags = {
    FUA     = 0x0001,
    NO_HOLE = 0x0002, -- WRITE_ZEROES Extension
    DF      = 0x0004, -- STRUCTURED_REPLY Extension
  },

  cmd_req_types = {
    READ         = 0x0000,
    WRITE        = 0x0001,
    DISC         = 0x0002,
    FLUSH        = 0x0003,
    TRIM         = 0x0004,
    CACHE        = 0x0005, -- XNBD custom request types
    WRITE_ZEROES = 0x0006, -- WRITE_ZEROES Extension
  },

  errors = {
    EPERM     = 0x00000001,
    EIO       = 0x00000005,
    ENOMEM    = 0x0000000C,
    EINVAL    = 0x00000016,
    ENOSPC    = 0x0000001C,
    EOVERFLOW = 0x0000004B,
    ESHUTDOWN = 0x0000006C,
  },
}

Comm = {
  --- Creates a new client instance.
  --
  -- @name Comm.new
  --
  -- @param host Table as received by the action method.
  -- @param port Table as received by the action method.
  --
  -- @return o Instance of Client.
  new = function(self, host, port)
    local o = {host = host, port = port, exports = {}}
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  --- Connects to the NBD server.
  --
  -- @name Comm.connect
  --
  -- @return status true on success, false on failure.
  connect = function(self)
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

    if #rep < 8 then
      stdnse.debug1("Failed to receive first 64 bits of magic from server: %s", rep)
      self:close()
      return false
    end

    -- We may have received 8-100+ bytes of data, depending on timing. To make
    -- the code simpler, we will seed a buffer to be used by this object's
    -- receive function until empty.
    self.receive_buffer = rep:sub(9)
    rep = rep:sub(1, 8)

    if rep ~= NBD.magic.init_passwd then
      stdnse.debug1("First 64 bits from server don't match expected magic: %s", stdnse.tohex(rep, {separator = ":"}))
      self:close()
      return false
    end

    local status, rep = self:receive(8)
    if not status then
      stdnse.debug1("Failed to receive second 64 bits of magic from server: %s", rep)
      return false
    end

    if rep == NBD.magic.cliserv_magic_new then
      self.protocol.negotiation = "newstyle"
      return self:connect_new()
    end

    if rep == NBD.magic.cliserv_magic_old then
      self.protocol.negotiation = "oldstyle"
      return self:connect_old()
    end

    self.protocol.negotiation = "unrecognized"
    stdnse.debug1("Second 64 bits from server don't match any known protocol magic: %s", stdnse.tohex(rep, {separator = ":"}))

    self:close()

    return true
  end,

  --- Cycles the connection to the server.
  --
  -- @name Comm.reconnect
  --
  -- @return status true on success, false on failure.
  reconnect = function(self)
    self:close()
    return self:connect(self.connect_options)
  end,

  --- Attaches to an named share on the server.
  --
  -- @name Comm.attach
  --
  -- @return status true on success, false on failure.
  attach = function(self, name)
    assert(self.protocol.negotiation == "newstyle" or self.protocol.negotiation == "fixed newstyle")
    assert(type(name) == "string")

    local req = self:build_opt_req("EXPORT_NAME", {export_name = name})

    local status, err = self:send(req)
    if not status then
      stdnse.debug1("Failed to send attach request for '%s': %s", name, err)
      self:close()
      return
    end

    local status, size = self:receive(8)
    if not status then
      stdnse.debug1("Failed to receive response to attach request for '%s': %s", name, size)
      self:close()
      return
    end

    local size, pos = (">I8"):unpack(size)
    if pos ~= 9 then
      stdnse.debug1("Failed to unpack size of exported block device from server.")
      self:close()
      return false
    end

    local status, tflags = self:receive(2)
    if not status then
      stdnse.debug1("Failed to receive transmission flags from server while attaching to export: %s", tflags)
      self:close()
      return false
    end

    local tflags, pos = (">I2"):unpack(tflags)
    if pos ~= 3 then
      stdnse.debug1("Failed to unpack transmission flags from server.")
      self:close()
      return false
    end

    tflags = self:parse_transmission_flags(tflags)

    if self.protocol.zero_pad == "required" then
      local status, err = self:receive(124)
      if not status then
        stdnse.debug1("Failed to receive zero pad from server while attaching to export: %s", err)
        self:close()
        return false
      end
    end

    self.exports[name] = {
      size = size,
      tflags = tflags,
    }

    return true
  end,

  --- Sends data to the server
  --
  -- @name Comm.send
  --
  -- @param pkt String containing the bytes to send.
  --
  -- @return status true on success, false on failure.
  -- @return err string containing the error message on failure.
  send = function(self, data)
    assert(type(data) == "string")

    return self.socket:send(data)
  end,

  --- Receives data from the server.
  --
  -- @name Comm.receive
  --
  -- @param len Number of bytes to receive.
  --
  -- @return status True on success, false on failure.
  -- @return response String representing bytes received on success,
  --         string containing the error message on failure.
  receive = function(self, len)
    assert(type(len) == "number")

    -- Try to answer this request from the buffer.
    if #self.receive_buffer >= len then
      local rep = self.receive_buffer:sub(1, len)
      self.receive_buffer = self.receive_buffer:sub(len + 1)
      return true, rep
    end

    return self.socket:receive_buf(match.numbytes(len), true)
  end,

  --- Disconnects from the server.
  --
  -- @name Comm.close
  close = function(self)
    assert(self.socket)
    self.socket:close()
    self.socket = nil
  end,

  --- Continue in-progress newstyle handshake with server.
  --
  -- @name Comm.connect_new
  --
  -- @param len Number of bytes to receive.
  --
  -- @return status True on success, false on failure.
  -- @return response String representing bytes received on success,
  --         string containing the error message on failure.
  connect_new = function(self)
    local status, flags = self:receive(2)
    if not status then
      stdnse.debug1("Failed to receive handshake flags from server: %s", flags)
      self:close()
      return false
    end

    -- Receive and parse the handshake flags from the server, and use
    -- them to build the client flags.
    local hflags, pos = (">I2"):unpack(flags)
    if pos ~= 3 then
      stdnse.debug1("Failed to unpack handshake flags from server.")
      self:close()
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
    local req = (">I4"):pack(cflags)

    local status, err = self:send(req)
    if not status then
      stdnse.debug1("Failed to send client flags: %s", err)
      self:close()
      return false
    end

    return true
  end,

  --- Continue in-progress oldstyle handshake with server.
  --
  -- @name Comm.connect_old
  --
  -- @return response String representing bytes received on success,
  --         string containing the error message on failure.
  connect_old = function(self)
    local status, size = self:receive(8)
    if not status then
      stdnse.debug1("Failed to receive size of exported block device from server: %s", size)
      self:close()
      return false
    end

    local size, pos = (">I8"):unpack(size)
    if pos ~= 9 then
      stdnse.debug1("Failed to unpack size of exported block device from server.")
      self:close()
      return false
    end

    local status, hflags = self:receive(4)
    if not status then
      stdnse.debug1("Failed to receive handshake flags from server: %s", hflags)
      self:close()
      return false
    end

    local hflags, pos = (">I4"):unpack(hflags)
    if pos ~= 5 then
      stdnse.debug1("Failed to unpack handshake flags from server.")
      self:close()
      return false
    end

    local status, pad = self:receive(124)
    if not status then
      stdnse.debug1("Failed to receive zero pad from server: %s", pad)
      self:close()
      return false
    end

    self.exports["(default)"] = {
      size = size,
      hflags = hflags,
    }

    return true
  end,

  --- Receives an option reply.
  --
  -- @name Comm.receive_opt_rep
  --
  -- @return reply Table representing option reply on success, false
  --         on failure.
  receive_opt_rep = function(self)
    -- Receive the static header of the option.
    local status, hdr = self:receive(20)
    if not status then
      stdnse.debug1("Failed to receive option reply header: %s", hdr)
      return false
    end

    local len, pos = (">I4"):unpack(hdr, 17)
    if pos ~= 21 then
      stdnse.debug1("Failed to parse option reply header during receive.")
      return false
    end

    local magic = hdr:sub(1, 8)
    if magic ~= NBD.magic.option then
      stdnse.debug1("First 64 bits of option reply don't match expected magic: %s", stdnse.tohex(magic, {separator = ":"}))
      return false
    end

    if len == 0 then
      return self:parse_opt_rep(hdr)
    end

    -- Receive the variable body of the option.
    local status, body = self:receive(len)
    if not status then
      stdnse.debug1("Failed to receive option reply: %s", body)
      return false
    end

    return self:parse_opt_rep(hdr .. body)
  end,

  --- Builds an option request.
  --
  -- @name Comm.build_opt_req
  --
  -- @param name String naming the option type.
  -- @param options Table containing options.
  --
  -- @return req String representing the option request.
  build_opt_req = function(self, name, options)
    assert(type(name) == "string")

    if not options then
      options = {}
    end
    assert(type(options) == "table")

    local otype = NBD.opt_req_types[name]
    assert(otype)

    local payload = ""

    if name == "EXPORT_NAME" then
      assert(options.export_name)
      payload = options.export_name
    end

    return NBD.magic.cliserv_magic_new .. (">I4s4"):pack(otype, payload)
  end,

  --- Parses an option reply.
  --
  -- @name Comm.parse_opt_rep
  --
  -- @param buf String to be parsed.
  -- @param rep Table representing the fields of the reply that have
  --        already been parsed by the caller.
  --
  -- @return reply Table representing option reply on success, false
  --         on failure.
  parse_opt_rep = function(self, buf)
    assert(type(buf) == "string")

    if 20 - 1 > #buf then
      stdnse.debug1("Buffer is too short to be parsed as an option reply.")
      return false
    end

    local magic, otype, rtype, rlen, pos = (">c8I4I4I4"):unpack(buf)

    if magic ~= NBD.magic.option then
      stdnse.debug1("First 64 bits of option reply don't match expected magic: %s", stdnse.tohex(magic, {separator = ":"}))
      return false
    end

    local otype_name = find_key(NBD.opt_req_types, otype)
    local rtype_name = find_key(NBD.opt_rep_types, rtype)

    local rep = {
      otype      = otype,
      otype_name = otype_name,
      rtype      = rtype,
      rtype_name = rtype_name,
    }

    if pos + rlen - 1 > #buf then
      stdnse.debug1("Option reply payload length extends past end of buffer.")
      return false
    end

    if rtype_name == "ACK" then
      return rep
    end

    if rtype_name == "SERVER" then
      if rlen < 4 then
        stdnse.debug1("SERVER option reply payload length must be 4 or greater, but is %d.", rlen)
        return false
      end

      local nlen, pos = (">I4"):unpack(buf, pos)
      if pos + nlen - 1 > #buf then
        stdnse.debug1("SERVER option reply payload name length extends past end of buffer.")
        return false
      end

      -- An empty name represents the default export.
      local name = ""
      if nlen > 0 then
        name = buf:sub(pos, pos + nlen - 1)
        pos = pos + nlen
      end
      rep.export_name = name

      return rep
    end

    return rep
  end,

  --- Parses the transmission flags describing an export.
  --
  -- @name Comm.parse_transmission_flags
  --
  -- @param flags Transmission flags sent by server.
  --
  -- @return Table of parsed flags as keys.
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

--- Finds a key corresponding with a value.
--
-- @name find_key
--
-- @param tbl Table in which to search.
-- @param val Value to search for.
--
-- @return key String on success, nil on failure
find_key = function(tbl, val)
  assert(type(tbl) == "table")
  assert(val ~= nil)

  for k, v in pairs(tbl) do
    if v == val then
      return k
    end
  end

  return nil
end

return _ENV;
